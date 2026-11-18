// Package members implements per-person identities and shared-vault
// membership (design D3: per-person keys in Phase 1).
//
// Responsibilities:
//   - Personal identity: an age X25519 key pair created on first run. The
//     private key is stored under the per-user config directory
//     (~/.config/vault/identity/, mode 0700/0600), sealed under a random
//     identity key that is itself wrapped once per unlocker (today the
//     personal passphrase; Touch ID later) exactly like vault.json wraps a
//     vault key. Export/import moves it between Macs.
//   - Fingerprints: three words and a number (e.g. MAPLE-RIVER-OTTER-4417) derived
//     from the public key, easy to read aloud for out-of-band checks.
//   - Join requests written to <vault>/requests/ by non-members.
//   - Approve: add a format.Unlocker of type "member" wrapping the vault key
//     to the requester's public key (rewrites vault.json only), after the
//     caller confirms the fingerprint the user checked.
//   - Remove: rotate the vault key, re-wrap it for the remaining unlockers,
//     and list the keys the removed member could have read.
//
// Authority: membership is whatever vault.json says. The members.json file
// next to it (who added whom, roles) is display metadata only and is never
// used for a security decision.
//
// Dependency rule: members imports crypto, format and audit. It does not
// import cli or agent; the CLI passes in an unlocked VaultKey.
//
// No error returned by this package contains key material, passphrases,
// file contents or user-supplied text; rejected input is described, not
// echoed.
//
// Owned by issue p2h.
package members

import (
	"errors"
	"fmt"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// Errors returned by this package. Messages are generic on purpose.
var (
	ErrNoIdentity          = errors.New("members: no identity on this machine yet")
	ErrIdentityExists      = errors.New("members: an identity already exists here")
	ErrInsecurePermissions = errors.New("members: identity files are readable by other users; fix their permissions (directory 0700, files 0600)")
	ErrMalformed           = errors.New("members: malformed file")
	ErrTooLarge            = errors.New("members: file too large")
	ErrInvalidName         = errors.New("members: invalid member name")
	ErrInvalidRecipient    = errors.New("members: invalid public key")
	ErrDuplicateName       = errors.New("members: that name is already used in this vault")
	ErrAlreadyMember       = errors.New("members: already a member of this vault")
	ErrRequestPending      = errors.New("members: a join request for this key is already pending")
	ErrNoRequest           = errors.New("members: no such join request")
	ErrNotMember           = errors.New("members: not a member of this vault")
	ErrFingerprintMismatch = errors.New("members: fingerprint does not match the request; do not approve")
	ErrPassphraseRequired  = errors.New("members: this vault has a passphrase unlocker; supply its passphrase wrapper so it survives the key rotation")
	ErrLastUnlocker        = errors.New("members: removing this member would leave the vault with no way to open it")
)

// MaxNameLen is the longest member name.
const MaxNameLen = 64

// ValidateMemberName checks a member name: 1-64 characters of a-z, 0-9, "-"
// and "_", starting with a letter or digit. Names become file names
// (requests/NAME.json) and unlocker labels, so the set is small and
// lower-case (macOS file systems are case-insensitive).
func ValidateMemberName(name string) error {
	if name == "" || len(name) > MaxNameLen {
		return fmt.Errorf("%w: must be 1-%d characters", ErrInvalidName, MaxNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '-' || c == '_') && i > 0:
		default:
			return fmt.Errorf("%w: use only a-z, 0-9, - and _, starting with a letter or digit", ErrInvalidName)
		}
	}
	return nil
}

// Role of a member in a vault.
type Role string

// Member roles.
const (
	RoleOwner  Role = "owner"
	RoleMember Role = "member"
)

// Identity is a person's public identity. Safe to share.
type Identity struct {
	Name        string
	Recipient   string // age X25519 recipient (public key)
	Fingerprint string // e.g. MAPLE-RIVER-OTTER-4417
}

// JoinRequest is a request file written by a non-member.
type JoinRequest struct {
	Identity Identity
	Created  time.Time
}

// Member is one entry of `vault member list`.
type Member struct {
	Identity Identity
	Role     Role
	Added    time.Time
	AddedBy  string
}

// Approve wraps key for req's identity and returns the unlocker to add to
// vault.json. It checks that the request's fingerprint belongs to its key.
// Most callers want ApproveRequest, which also confirms the fingerprint with
// what the user checked, updates the vault and removes the request.
func Approve(key *crypto.VaultKey, req JoinRequest) (format.Unlocker, error) {
	if err := ValidateMemberName(req.Identity.Name); err != nil {
		return format.Unlocker{}, err
	}
	fp, err := Fingerprint(req.Identity.Recipient)
	if err != nil {
		return format.Unlocker{}, err
	}
	if fp != req.Identity.Fingerprint {
		return format.Unlocker{}, ErrFingerprintMismatch
	}
	w, err := crypto.NewMemberWrapper(req.Identity.Name, req.Identity.Recipient)
	if err != nil {
		return format.Unlocker{}, ErrInvalidRecipient
	}
	return w.Wrap(key)
}
