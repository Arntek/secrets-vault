package format

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"unicode"
	"unicode/utf8"
)

// MaxKeyNameLen is the longest allowed key name.
const MaxKeyNameLen = 128

// ErrInvalidKeyName is wrapped by every key-name validation error.
var ErrInvalidKeyName = errors.New("invalid key name")

// ValidateKeyName reports whether name is a valid key name.
//
// Key names become file names (secrets/NAME.age) and environment variable
// names (vault run -k NAME), so they are restricted to upper-case ASCII
// letters, digits and underscore, and must not start with a digit. Upper case
// only, because macOS file systems are case-insensitive by default: "foo" and
// "FOO" would otherwise collide on disk. This also rules out path separators,
// "..", NUL bytes and every other path-traversal trick.
//
// Error messages never echo the rejected name, in case a value was pasted
// where a name was expected.
func ValidateKeyName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty", ErrInvalidKeyName)
	}
	if len(name) > MaxKeyNameLen {
		return fmt.Errorf("%w: longer than %d characters", ErrInvalidKeyName, MaxKeyNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9':
			if i == 0 {
				return fmt.Errorf("%w: must not start with a digit", ErrInvalidKeyName)
			}
		default:
			return fmt.Errorf("%w: only A-Z, 0-9 and _ are allowed (position %d)", ErrInvalidKeyName, i+1)
		}
	}
	return nil
}

// SecretPath returns the path of the encrypted file for key name inside
// vaultDir. It validates the name first, so the result is always a direct
// child of vaultDir/secrets.
func SecretPath(vaultDir, name string) (string, error) {
	if err := ValidateKeyName(name); err != nil {
		return "", err
	}
	return filepath.Join(vaultDir, SecretsDir, name+SecretExt), nil
}

// Limits for the text fields of vault.json and index.json.
const (
	MaxVaultNameLen   = 64
	MaxLabelLen       = 128
	MaxRecipientLen   = 2048
	MaxWrappedKeyLen  = 4096
	MaxUnlockers      = 256
	MaxDescriptionLen = 1024
	MaxTagLen         = 64
	MaxTags           = 32
	MaxUpdatedByLen   = 128
	MaxIndexEntries   = 100000
)

// ValidateVaultName checks a vault's name: 1-64 characters of a-z, 0-9, "-"
// and "_", starting with a letter or digit.
func ValidateVaultName(name string) error {
	if name == "" || len(name) > MaxVaultNameLen {
		return fmt.Errorf("%w: vault name must be 1-%d characters", ErrMalformed, MaxVaultNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '-' || c == '_') && i > 0:
		default:
			return fmt.Errorf("%w: vault name may use only a-z, 0-9, - and _ (position %d)", ErrMalformed, i+1)
		}
	}
	return nil
}

// ValidateTag checks one index tag: 1-64 characters of a-z, 0-9, "-" and "_".
func ValidateTag(tag string) error {
	if tag == "" || len(tag) > MaxTagLen {
		return fmt.Errorf("%w: tag must be 1-%d characters", ErrMalformed, MaxTagLen)
	}
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return fmt.Errorf("%w: tag may use only a-z, 0-9, - and _ (position %d)", ErrMalformed, i+1)
		}
	}
	return nil
}

// idLen is the length of a vault ID or key ID: 16 bytes as lower-case hex.
const idLen = 32

// NewVaultID returns a fresh random vault ID.
func NewVaultID() (string, error) {
	var b [idLen / 2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// validateHexID checks a 32-character lower-case hex identifier.
func validateHexID(what, id string) error {
	if len(id) != idLen {
		return fmt.Errorf("%w: %s must be %d hex characters", ErrMalformed, what, idLen)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("%w: %s must be lower-case hex", ErrMalformed, what)
		}
	}
	return nil
}

// ValidateVaultID checks a vault ID as produced by NewVaultID.
func ValidateVaultID(id string) error { return validateHexID("vault id", id) }

// ValidateKeyID checks a key ID as produced by crypto.VaultKey.ID.
func ValidateKeyID(id string) error { return validateHexID("key id", id) }

// validateText checks a human-readable field shown in the terminal: valid
// UTF-8, at most max bytes, and no control or bidirectional-override
// characters (which could rewrite what `vault list` shows).
func validateText(what, s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("%w: %s longer than %d bytes", ErrMalformed, what, max)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrMalformed, what)
	}
	for _, r := range s {
		if unicode.IsControl(r) || isBidiControl(r) || r == utf8.RuneError {
			return fmt.Errorf("%w: %s contains control characters", ErrMalformed, what)
		}
	}
	return nil
}

func isBidiControl(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C
}

// validateRecipient checks a public identifier: printable ASCII, no spaces.
func validateRecipient(s string) error {
	if len(s) > MaxRecipientLen {
		return fmt.Errorf("%w: unlocker recipient longer than %d bytes", ErrMalformed, MaxRecipientLen)
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return fmt.Errorf("%w: unlocker recipient must be printable ASCII", ErrMalformed)
		}
	}
	return nil
}
