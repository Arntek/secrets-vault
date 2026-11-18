package format

import (
	"errors"
	"fmt"
	"path/filepath"
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
