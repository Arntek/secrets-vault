// Package members implements per-person identities and shared-vault
// membership (design D3: per-person keys in Phase 1).
//
// Responsibilities:
//   - Personal identity: an age X25519 key pair created on first run. The
//     private half is stored on this Mac wrapped by the person's own
//     passphrase and Touch ID; export/import moves it between Macs.
//   - Fingerprints: three words and a number (e.g. MAPLE-RIVER-4417) derived
//     from the public key, easy to read aloud for out-of-band checks.
//   - Join requests written to <vault>/requests/ by non-members.
//   - Approve: add a format.Unlocker of type "member" wrapping the vault key
//     to the member's public key (rewrites vault.json only).
//   - Remove: rotate the vault key, re-encrypt every secret, re-wrap for the
//     remaining unlockers, and list keys the removed member could have read.
//
// Dependency rule: members imports crypto, format and audit. It does not
// import cli or agent; the CLI passes in an unlocked VaultKey.
//
// Owned by issue p2h.
package members

import (
	"errors"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// ErrNotImplemented is returned by stubs that later issues fill in.
var ErrNotImplemented = errors.New("members: not implemented")

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
	Fingerprint string // e.g. MAPLE-RIVER-4417
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

// Fingerprint derives the human-readable fingerprint of an age recipient.
func Fingerprint(recipient string) (string, error) {
	_ = recipient
	return "", ErrNotImplemented
}

// Approve wraps key for req's identity and returns the unlocker to add to
// vault.json. The caller confirms the fingerprint with the user first.
func Approve(key *crypto.VaultKey, req JoinRequest) (format.Unlocker, error) {
	_, _ = key, req
	return format.Unlocker{}, ErrNotImplemented
}
