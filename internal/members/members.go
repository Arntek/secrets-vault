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
//   - The signed membership log in vault.json (log.go): every change is a
//     record signed by a member of the state before it; Verify replays the
//     log from genesis and is the only way a vault.json is trusted.
//   - Trust pins (pin.go): the last verified head, kept per user outside
//     the shared folder; Classify tells extension, lost race and rollback
//     apart.
//   - Approve, Remove (with key rotation), Passwd: each appends a signed
//     record and re-wraps keys only for verified members.
//
// See docs/design/membership-auth.md.
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
	ErrIdentityUpgrade     = errors.New("members: this identity was made by an older version; unlock it once to upgrade it")
	ErrPreviouslyRemoved   = errors.New("members: this key was removed from the vault before; re-adding it needs --readd and the fingerprint typed again")
	ErrNotRotation         = errors.New("members: the vault key was not introduced by a verified rotation")
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

// Member roles (as stored in vault.json).
const (
	RoleOwner  = format.RoleOwner
	RoleMember = format.RoleMember
)

// Identity is a person's public identity. Safe to share.
type Identity struct {
	Name        string
	Recipient   string // age X25519 recipient (public key)
	SignKey     string // Ed25519 public key, lower-case hex
	Fingerprint string // e.g. MAPLE-RIVER-OTTER-4417, over both keys
}

// JoinRequest is a request file written by a non-member.
type JoinRequest struct {
	Identity Identity
	Created  time.Time
}

// Member is one entry of `vault member list`.
type Member struct {
	Identity Identity
	Role     string
	Added    time.Time
	AddedBy  string
}
