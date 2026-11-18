// Package crypto owns every cryptographic operation in secrets-vault.
//
// Model (see docs/architecture.md):
//   - Each vault has one random 32-byte VaultKey that encrypts every secret.
//   - The VaultKey is wrapped once per unlocker (passphrase, Touch ID, member)
//     and stored in vault.json as a format.Unlocker. Adding or removing an
//     unlocker rewrites vault.json only; secret files are never re-encrypted,
//     except when a member is removed (key rotation, package members).
//   - Secrets are age-encrypted files (filippo.io/age, added by issue 6j5).
//     The passphrase unlocker uses age's scrypt recipient.
//
// Responsibilities:
//   - Generating, holding and zeroing VaultKeys.
//   - The KeyWrapper interface that every unlocker implements, plus the
//     passphrase and age-X25519 (member) wrappers.
//   - Encrypting and decrypting secret values with a VaultKey.
//
// Dependency rule: crypto imports format (for the Unlocker record) and the
// standard library / age only. It must not import cli, agent, members,
// touchid or audit. Package touchid implements KeyWrapper from the outside.
//
// Nothing in this package may log, print or include secret material
// (keys, passphrases, plaintext values) in an error message.
package crypto

import (
	"crypto/rand"
	"errors"
	"log/slog"

	"github.com/Arntek/secrets-vault/internal/format"
)

// KeySize is the length of a VaultKey in bytes.
const KeySize = 32

// ErrNotImplemented is returned by stubs that later issues fill in.
var ErrNotImplemented = errors.New("crypto: not implemented")

// ErrWrongKey is returned when an unlocker cannot open a wrapped key
// (wrong passphrase, wrong identity, tampered data). Callers must not be
// able to tell these cases apart.
var ErrWrongKey = errors.New("crypto: unable to unwrap vault key")

// VaultKey is the symmetric key for one vault. Hold it by pointer and call
// Destroy when done; never copy the array out.
type VaultKey struct {
	b [KeySize]byte
}

// NewVaultKey returns a fresh random vault key.
func NewVaultKey() (*VaultKey, error) {
	k := &VaultKey{}
	if _, err := rand.Read(k.b[:]); err != nil {
		return nil, err
	}
	return k, nil
}

// VaultKeyFromBytes copies b into a new VaultKey. The caller should zero b.
func VaultKeyFromBytes(b []byte) (*VaultKey, error) {
	if len(b) != KeySize {
		return nil, errors.New("crypto: vault key has wrong length")
	}
	k := &VaultKey{}
	copy(k.b[:], b)
	return k, nil
}

// Bytes exposes the key material for wrapping. Do not retain the slice.
func (k *VaultKey) Bytes() []byte { return k.b[:] }

// Destroy zeroes the key. Safe to call more than once.
func (k *VaultKey) Destroy() {
	if k == nil {
		return
	}
	clear(k.b[:])
}

// String never reveals key material, so a VaultKey that ends up in a log or
// fmt call prints a placeholder.
func (k *VaultKey) String() string { return "VaultKey(redacted)" }

// GoString implements fmt.GoStringer for %#v.
func (k *VaultKey) GoString() string { return k.String() }

// LogValue implements slog.LogValuer so structured logs show a placeholder.
func (k *VaultKey) LogValue() slog.Value { return slog.StringValue(k.String()) }

// KeyWrapper wraps and unwraps a VaultKey for one kind of unlocker.
// Implementations: passphrase and member (this package), touchid (package
// touchid). The returned format.Unlocker is stored in vault.json as-is.
type KeyWrapper interface {
	// Type reports which unlocker type this wrapper produces.
	Type() format.UnlockerType
	// Wrap encrypts key for this unlocker.
	Wrap(key *VaultKey) (format.Unlocker, error)
	// Unwrap opens u. It returns ErrWrongKey for any failure to decrypt.
	Unwrap(u format.Unlocker) (*VaultKey, error)
}

// Sealer encrypts and decrypts secret values with a vault key. Owned by
// issue 6j5.
type Sealer interface {
	Seal(key *VaultKey, plaintext []byte) ([]byte, error)
	Open(key *VaultKey, ciphertext []byte) ([]byte, error)
}

// NewPassphraseWrapper returns the scrypt passphrase KeyWrapper. Owned by
// issue 6j5.
func NewPassphraseWrapper(passphrase []byte) (KeyWrapper, error) {
	_ = passphrase
	return nil, ErrNotImplemented
}
