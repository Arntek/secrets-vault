// Package agent is the memory-only unlock agent ("vault agent"), started
// automatically like ssh-agent, and the client the CLI uses to talk to it.
//
// Responsibilities:
//   - Holding unlocked crypto.VaultKeys in memory only, one per vault, each
//     with its own expiry (default 4h, allowed 5m to 24h). Keys are never
//     written to disk, swap-protected where the OS allows, and zeroed on
//     expiry, lock, or exit.
//   - Listening on a Unix socket (named pipe on Windows, Phase 2) that only
//     the current user can open: socket dir 0700, peer UID checked.
//   - Serving the Client operations below; nothing else.
//
// Dependency rule: agent imports crypto (for VaultKey) and format. It does
// not import cli, members or touchid: unlocking (Touch ID, passphrase) happens
// in the CLI process, which then hands the unwrapped key to the agent.
//
// Owned by issue 244.
package agent

import (
	"errors"
	"fmt"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
)

// TTL limits from the design ("Unlocking and the 4-hour window").
const (
	DefaultTTL = 4 * time.Hour
	MinTTL     = 5 * time.Minute
	MaxTTL     = 24 * time.Hour
)

// ErrNotImplemented is returned by stubs that later issues fill in.
var ErrNotImplemented = errors.New("agent: not implemented")

// ErrLocked means the agent holds no key for the vault (or it expired).
// The CLI maps this to exit code 3.
var ErrLocked = errors.New("vault is locked")

// ValidateTTL reports whether d is an allowed unlock window.
func ValidateTTL(d time.Duration) error {
	if d < MinTTL || d > MaxTTL {
		return fmt.Errorf("unlock time must be between %s and %s", MinTTL, MaxTTL)
	}
	return nil
}

// VaultStatus is one line of `vault status`.
type VaultStatus struct {
	VaultID   string
	Unlocked  bool
	ExpiresAt time.Time
}

// Client is how the CLI talks to the running agent. A Client returned by
// Dial starts the agent if it is not running.
type Client interface {
	// Unlock stores key for vaultID until ttl elapses. The agent takes
	// ownership of key; the caller must not use it afterwards.
	Unlock(vaultID string, key *crypto.VaultKey, ttl time.Duration) error
	// Key returns a copy of the unlocked key for vaultID, or ErrLocked.
	// The caller must Destroy it.
	Key(vaultID string) (*crypto.VaultKey, error)
	// Lock forgets the key for vaultID now.
	Lock(vaultID string) error
	// LockAll forgets every key.
	LockAll() error
	// Status reports every vault the agent knows about.
	Status() ([]VaultStatus, error)
	Close() error
}

// Dial connects to (and if needed starts) the agent for the current user.
func Dial() (Client, error) {
	return nil, ErrNotImplemented
}
