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
// Wiring for the CLI (issue rn5): the agent runs as a hidden subcommand. The
// CLI's Run must call agent.Run() when its first argument is agent.AgentArg
// ("__agent"); nothing else is needed in cmd/secrets-vault. Commands then
// use agent.Dial(), which starts that subcommand on demand.
//
// Owned by issue 244.
package agent

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
)

// TTL limits from the design ("Unlocking and the 4-hour window").
const (
	DefaultTTL = 4 * time.Hour
	MinTTL     = 5 * time.Minute
	MaxTTL     = 24 * time.Hour
)

// AgentArg is the hidden subcommand the CLI re-executes itself with to run
// the agent in the background (`secrets-vault __agent`).
const AgentArg = "__agent"

// DefaultIdleExit is how long the agent keeps running with no keys before
// it exits on its own.
const DefaultIdleExit = 3 * time.Minute

// MaxVaults caps how many vaults one agent holds keys for.
const MaxVaults = 256

// ErrLocked means the agent holds no key for the vault (or it expired).
// The CLI maps this to exit code 3.
var ErrLocked = errors.New("vault is locked")

// ErrUnsupported is returned on platforms without agent support (Windows,
// until Phase 2).
var ErrUnsupported = errors.New("agent: not supported on this platform")

// ErrPathTooLong is returned when the socket path would not fit in a Unix
// socket address (104 bytes on macOS).
var ErrPathTooLong = errors.New("agent: socket path too long")

// ErrAlreadyRunning is returned by Serve when a live agent already owns the
// socket.
var ErrAlreadyRunning = errors.New("agent: already running")

// ErrUnsafeDir is returned when the socket directory is not a private
// directory owned by the current user.
var ErrUnsafeDir = errors.New("agent: socket directory is not private to this user")

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
	// Status reports every vault the agent holds a key for. It never
	// includes key material.
	Status() ([]VaultStatus, error)
	Close() error
}

// Stopper is implemented by clients that can ask the agent to exit. The
// concrete client returned by Dial implements it: Stop(c) locks everything
// and then shuts the agent down.
type Stopper interface {
	Shutdown() error
}

// Stop locks every key and asks the agent to exit.
func Stop(c Client) error {
	s, ok := c.(Stopper)
	if !ok {
		return errors.New("agent: client cannot stop the agent")
	}
	if err := c.LockAll(); err != nil {
		return err
	}
	return s.Shutdown()
}

// ServerOptions configure Serve. The zero value is correct for production.
type ServerOptions struct {
	// Dir is the socket directory; default is DefaultDir().
	Dir string
	// Now is the clock; default time.Now. Tests inject a fake.
	Now func() time.Time
	// IdleExit is how long with no keys before the agent exits; default
	// DefaultIdleExit.
	IdleExit time.Duration
	// ReapInterval is how often expired keys are destroyed; default 5s.
	ReapInterval time.Duration
	// Logger receives lifecycle events (never key material or vault
	// names). Default: discard.
	Logger *slog.Logger
}

// DialOptions configure DialWith. The zero value is correct for production.
type DialOptions struct {
	// Dir is the socket directory; default is DefaultDir().
	Dir string
	// Exe and Args start the agent when it is not running; default is this
	// executable with AgentArg.
	Exe  string
	Args []string
	// Env is the agent process environment; default is this process's.
	Env []string
	// StartTimeout bounds waiting for a freshly started agent; default 3s.
	StartTimeout time.Duration
	// NoAutoStart makes DialWith fail instead of starting the agent.
	NoAutoStart bool
}

func (o ServerOptions) withDefaults() ServerOptions {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.IdleExit <= 0 {
		o.IdleExit = DefaultIdleExit
	}
	if o.ReapInterval <= 0 {
		o.ReapInterval = 5 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return o
}

// Dial connects to (and if needed starts) the agent for the current user.
func Dial() (Client, error) { return DialWith(DialOptions{}) }

// Run is the entry point of the hidden `__agent` subcommand: it serves until
// interrupted, idle, or told to shut down. It returns nil when another agent
// is already running.
func Run() error {
	ctx, stop := signalContext()
	defer stop()
	err := Serve(ctx, ServerOptions{})
	if errors.Is(err, ErrAlreadyRunning) {
		return nil
	}
	return err
}

// Internal errors mapped to wire status codes.
var errFull = errors.New("agent: too many vaults unlocked")
