//go:build !darwin

package touchid

import "github.com/Arntek/secrets-vault/internal/crypto"

func available() bool { return false }

func enroll(string, string) (*Device, error) { return nil, ErrUnsupported }

func wrapper(*Device) (crypto.KeyWrapper, error) { return nil, ErrUnsupported }
