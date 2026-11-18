//go:build darwin

package touchid

import "github.com/Arntek/secrets-vault/internal/crypto"

// The darwin implementation calls the Swift Secure Enclave helper. Owned by
// issue p1d.

func available() bool { return false }

func enroll(label, keyPath string) (*Device, error) {
	_, _ = label, keyPath
	return nil, ErrNotImplemented
}

func wrapper(d *Device) (crypto.KeyWrapper, error) {
	_ = d
	return nil, ErrNotImplemented
}
