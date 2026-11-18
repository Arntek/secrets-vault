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
// CryptoKit is Swift-only, so the Go side talks to a small Swift helper
// (bundled binary or C-interface library; decided in issue p1d).
//
// Responsibilities:
//   - Available: is Touch ID usable here (macOS, sensor present, not SSH)?
//   - Enroll a device and return a crypto.KeyWrapper for it.
//   - Implement crypto.KeyWrapper for UnlockerTouchID.
//
// On other platforms every function returns ErrUnsupported and the CLI
// falls back to the passphrase.
//
// Dependency rule: touchid imports crypto and format only.
//
// Owned by issue p1d.
package touchid

import (
	"errors"

	"github.com/Arntek/secrets-vault/internal/crypto"
)

// ErrUnsupported means Touch ID cannot be used in this environment.
var ErrUnsupported = errors.New("touch ID is not available here")

// ErrNotImplemented is returned by stubs that later issues fill in.
var ErrNotImplemented = errors.New("touchid: not implemented")

// ErrCancelled means the user dismissed the Touch ID sheet.
var ErrCancelled = errors.New("touch ID cancelled")

// Device is an enrolled Secure Enclave key on this Mac.
type Device struct {
	Label   string // e.g. the Mac's name, shown in `vault touchid list`
	KeyPath string // where the enclave key blob is stored on this Mac
}

// Available reports whether Touch ID can be used in this process.
func Available() bool { return available() }

// Enroll creates a new Secure Enclave key for this Mac.
func Enroll(label, keyPath string) (*Device, error) { return enroll(label, keyPath) }

// Wrapper returns the crypto.KeyWrapper for an enrolled device.
func Wrapper(d *Device) (crypto.KeyWrapper, error) { return wrapper(d) }
