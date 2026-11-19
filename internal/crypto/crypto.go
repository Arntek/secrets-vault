// Package crypto owns every cryptographic operation in secrets-vault.
//
// Model (see docs/architecture.md):
//   - Each vault has one random 32-byte VaultKey that encrypts every secret.
//   - The VaultKey is wrapped once per unlocker (passphrase, Touch ID, member)
//     and stored in vault.json as a format.Unlocker. Adding or removing an
//     unlocker rewrites vault.json only; secret files are never re-encrypted,
//     except when a member is removed (key rotation, package members).
//   - Secrets are age-encrypted files (filippo.io/age). The file key of each
//     is wrapped in a custom "sv-vaultkey" stanza by a key derived with HKDF
//     from the VaultKey, a random salt and the key name, so a file only opens
//     under its own name (swapping two files is detected).
//   - The passphrase unlocker is an age file encrypted with age's scrypt
//     recipient; the member unlocker one encrypted to an age X25519 recipient.
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
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"github.com/Arntek/secrets-vault/internal/format"
)

// KeySize is the length of a VaultKey in bytes.
const KeySize = 32

// ErrDecrypt is returned when a secret file cannot be opened: wrong vault
// key, a file sealed for a different key name (swapped files), or
// corrupted or truncated data.
var ErrDecrypt = errors.New("crypto: unable to decrypt secret")

// ErrOtherKey wraps ErrDecrypt when a secret file was sealed with a
// different vault key (for example during or after a key rotation that has
// not fully synced).
var ErrOtherKey = fmt.Errorf("%w: sealed with a different vault key", ErrDecrypt)

// ErrTooLarge is returned for a secret value over MaxSecretSize.
var ErrTooLarge = errors.New("crypto: secret value too large")

// MaxSecretSize is the largest secret value Seal accepts.
const MaxSecretSize = 1 << 20 // 1 MiB

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

// ID returns a public fingerprint of the key: 16 bytes of HKDF-SHA256 output
// as lower-case hex. It reveals nothing about the key and is stored in
// vault.json (format.VaultFile.KeyID) and in every secret file.
func (k *VaultKey) ID() string {
	b, err := hkdf.Key(sha256.New, k.b[:], nil, infoKeyID, 16)
	if err != nil {
		panic("crypto: hkdf: " + err.Error()) // only fails for absurd lengths
	}
	return hex.EncodeToString(b)
}

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

// Sealer encrypts and decrypts secret values with a vault key. Get one
// with NewSealer, which binds it to a key name.
type Sealer interface {
	// Seal writes the unversioned (stanza v2) form: identity files use it.
	Seal(key *VaultKey, plaintext []byte) ([]byte, error)
	// SealVersion writes a secret file that carries version (1 to
	// format.MaxCounter) in its header (stanza v3, docs/design/index-auth.md).
	SealVersion(key *VaultKey, plaintext []byte, version uint32) ([]byte, error)
	Open(key *VaultKey, ciphertext []byte) ([]byte, error)
	// OpenVersion is Open that also returns the file's version (0 for a
	// file in the unversioned form).
	OpenVersion(key *VaultKey, ciphertext []byte) ([]byte, uint32, error)
}
