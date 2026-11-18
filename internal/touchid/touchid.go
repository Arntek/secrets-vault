// Package touchid unlocks vaults with Touch ID through the Mac's Secure
// Enclave, as proven in spikes/phase0-touchid.
//
// How it works: `vault touchid on` creates a P-256 key inside the Secure
// Enclave, usable only after biometry (.biometryCurrentSet), stored as an
// opaque CryptoKit dataRepresentation blob in a normal file on this Mac (no
// Keychain, no entitlements, no paid Apple account: design D10). The vault
// key is wrapped to that enclave key and saved as a format.Unlocker of type
// "touchid". Unwrapping shows the Touch ID sheet.
//
// CryptoKit is Swift-only. The Swift side (swift/TouchIDBridge.swift) is
// built into a static library and linked through cgo; it only creates the
// enclave key, reads its public key and runs ECDH after a fingerprint.
// Everything else (ECIES-style wrapping with HKDF-SHA256 and AES-256-GCM,
// parsing, error mapping) is Go in this package and is tested with a fake
// enclave.
//
// The real enclave is compiled in only on darwin with cgo and the build
// tag "touchid" (the Makefile sets it on macOS after building the Swift
// library). Every other build compiles and returns ErrUnsupported, and the
// CLI falls back to the passphrase.
//
// Dependency rule: touchid imports crypto and format only.
//
// Owned by issue p1d.
package touchid

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Arntek/secrets-vault/internal/crypto"
)

// ErrUnsupported means Touch ID cannot be used in this environment: not
// macOS, built without Touch ID, no Secure Enclave, no fingerprint enrolled,
// no sensor reachable (lid closed), or an SSH session.
var ErrUnsupported = errors.New("touch ID is not available here")

// ErrNotImplemented is kept for API stability; nothing returns it now.
var ErrNotImplemented = errors.New("touchid: not implemented")

// ErrCancelled means the user dismissed the Touch ID sheet (or chose the
// passphrase instead). The CLI should fall back to the passphrase.
var ErrCancelled = errors.New("touch ID cancelled")

// ErrEnrolled means Enroll would overwrite an existing enclave key file.
var ErrEnrolled = errors.New("touchid: a Touch ID key already exists at that path")

// errAuthFailed is the enclave reporting a failed or invalid fingerprint
// check. Unwrap turns it into crypto.ErrWrongKey.
var errAuthFailed = errors.New("touchid: authentication failed")

// errBadKey is the enclave refusing a blob or public key.
var errBadKey = errors.New("touchid: enclave key unusable")

// maxBlobSize bounds how much of a key file is read. Real blobs are a few
// hundred bytes.
const maxBlobSize = 16 << 10

// Device is an enrolled Secure Enclave key on this Mac.
type Device struct {
	Label   string // e.g. the Mac's name, shown in `vault touchid list`
	KeyPath string // where the enclave key blob is stored on this Mac
}

// Available reports whether Touch ID can be used in this process.
func Available() bool { return availableWith(platform, os.Getenv) == nil }

// Enroll creates a new Secure Enclave key for this Mac and writes its blob
// to keyPath (mode 0600, parent directories 0700). It refuses to overwrite
// an existing file.
func Enroll(label, keyPath string) (*Device, error) {
	return enrollWith(platform, os.Getenv, label, keyPath)
}

// Wrapper returns the crypto.KeyWrapper for an enrolled device. Its Touch ID
// sheet does not name a vault; prefer WrapperForVault.
func Wrapper(d *Device) (crypto.KeyWrapper, error) { return WrapperForVault(d, "") }

// WrapperForVault returns the crypto.KeyWrapper for an enrolled device,
// naming vault (and the program that started this one) on the Touch ID
// sheet when unwrapping.
func WrapperForVault(d *Device, vault string) (crypto.KeyWrapper, error) {
	return wrapperWith(platform, os.Getenv, d, vault)
}

// platform is the real Secure Enclave. It stays nil (every entry point
// returns ErrUnsupported) unless touchid_darwin.go is compiled in: macOS,
// cgo enabled and the "touchid" build tag.
var platform enclave

// enclave is the boundary to the Secure Enclave. The real implementation is
// the Swift bridge (enclave_darwin.go); tests use a software fake.
type enclave interface {
	// check returns nil when the Secure Enclave and biometrics are usable,
	// else ErrUnsupported.
	check() error
	// create makes a new Touch ID-gated key and returns its blob and
	// uncompressed P-256 public key.
	create() (blob, pub []byte, err error)
	// publicKey loads blob and returns its public key. No Touch ID.
	publicKey(blob []byte) ([]byte, error)
	// agree shows the Touch ID sheet with reason and returns the ECDH
	// shared secret of blob's key and peer. Errors: ErrCancelled,
	// ErrUnsupported, errAuthFailed, errBadKey or another error.
	agree(blob, peer []byte, reason string) ([]byte, error)
	// parentProgram names the process that started this one, or "".
	parentProgram() string
}

// Status codes returned by the Swift bridge (swift/bridge.h).
const (
	statusOK         = 0
	statusNoEnclave  = 1
	statusNoBiometry = 2
	statusCancelled  = 3
	statusAuthFailed = 4
	statusBadKey     = 5
)

// statusError maps a bridge status code to this package's errors.
func statusError(code int) error {
	switch code {
	case statusOK:
		return nil
	case statusNoEnclave, statusNoBiometry:
		return ErrUnsupported
	case statusCancelled:
		return ErrCancelled
	case statusAuthFailed:
		return errAuthFailed
	case statusBadKey:
		return errBadKey
	default:
		return errors.New("touchid: Secure Enclave operation failed")
	}
}

// sshSession reports whether this process runs inside an SSH session, where
// nobody can touch the sensor.
func sshSession(getenv func(string) string) bool {
	for _, v := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		if getenv(v) != "" {
			return true
		}
	}
	return false
}

func availableWith(e enclave, getenv func(string) string) error {
	if e == nil || sshSession(getenv) {
		return ErrUnsupported
	}
	if err := e.check(); err != nil {
		return ErrUnsupported
	}
	return nil
}

func enrollWith(e enclave, getenv func(string) string, label, keyPath string) (*Device, error) {
	if err := availableWith(e, getenv); err != nil {
		return nil, err
	}
	if keyPath == "" {
		return nil, errors.New("touchid: key path is empty")
	}
	blob, _, err := e.create()
	if err != nil {
		if errors.Is(err, ErrUnsupported) {
			return nil, ErrUnsupported
		}
		return nil, errors.New("touchid: could not create Secure Enclave key")
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, fmt.Errorf("touchid: create key folder: %w", pathless(err))
	}
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path chosen by the CLI, not by vault data
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, ErrEnrolled
		}
		return nil, fmt.Errorf("touchid: write key file: %w", pathless(err))
	}
	_, werr := f.Write(blob)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(keyPath)
		return nil, fmt.Errorf("touchid: write key file: %w", pathless(werr))
	}
	return &Device{Label: label, KeyPath: keyPath}, nil
}

func wrapperWith(e enclave, getenv func(string) string, d *Device, vault string) (crypto.KeyWrapper, error) {
	if e == nil {
		return nil, ErrUnsupported
	}
	if d == nil || d.KeyPath == "" {
		return nil, errors.New("touchid: no enrolled device")
	}
	blob, err := readBlob(d.KeyPath)
	if err != nil {
		return nil, err
	}
	pub, err := e.publicKey(blob)
	if err != nil {
		if errors.Is(err, ErrUnsupported) {
			return nil, ErrUnsupported
		}
		return nil, errors.New("touchid: the Touch ID key file is not usable on this Mac")
	}
	if _, err := parsePublicKey(pub); err != nil {
		return nil, errors.New("touchid: the Touch ID key file is not usable on this Mac")
	}
	return &keyWrapper{
		e:      e,
		getenv: getenv,
		label:  d.Label,
		blob:   blob,
		pub:    pub,
		vault:  vault,
	}, nil
}

func readBlob(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- path chosen by the CLI, not by vault data
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errors.New("touchid: Touch ID is not set up on this Mac (key file missing)")
		}
		return nil, fmt.Errorf("touchid: read key file: %w", pathless(err))
	}
	defer func() { _ = f.Close() }()
	blob, err := io.ReadAll(io.LimitReader(f, maxBlobSize+1))
	if err != nil {
		return nil, fmt.Errorf("touchid: read key file: %w", pathless(err))
	}
	if len(blob) == 0 || len(blob) > maxBlobSize {
		return nil, errors.New("touchid: the Touch ID key file is not usable on this Mac")
	}
	return blob, nil
}

// pathless drops the file path from an os error, so error messages never
// echo a path the caller passed in.
func pathless(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
