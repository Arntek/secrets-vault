//go:build unix

package agent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
)

type client struct{ path string }

// DialWith connects to the agent, starting it if needed (unless
// opts.NoAutoStart). It verifies the socket directory is private first.
func DialWith(opts DialOptions) (Client, error) {
	dir := opts.Dir
	if dir == "" {
		d, err := DefaultDir()
		if err != nil {
			return nil, err
		}
		dir = d
	}
	if err := prepareDir(dir); err != nil {
		return nil, err
	}
	c := &client{path: filepath.Join(dir, sockName)}
	err := c.ping()
	if err == nil {
		return c, nil
	}
	if errors.Is(err, ErrWrongUser) || opts.NoAutoStart {
		return nil, err
	}
	if err := startAgent(opts); err != nil {
		return nil, err
	}
	timeout := opts.StartTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		if err := c.ping(); err == nil {
			return c, nil
		} else if errors.Is(err, ErrWrongUser) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, errors.New("agent: did not start in time")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func startAgent(opts DialOptions) error {
	exe, args := opts.Exe, opts.Args
	if exe == "" {
		e, err := os.Executable()
		if err != nil {
			return err
		}
		exe, args = e, []string{AgentArg}
	}
	cmd := exec.Command(exe, args...) // #nosec G204 -- our own executable with a fixed hidden argument (or a test-supplied one)
	cmd.Env = opts.Env
	if cmd.Env == nil {
		cmd.Env = CleanEnv(os.Environ())
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // survive the terminal closing
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("agent: start: %w", err)
	}
	return cmd.Process.Release()
}

// call performs one request/response exchange.
func (c *client) call(op Op, vault string, ttl time.Duration, key []byte) (status uint8, payload []byte, err error) {
	body, err := EncodeRequest(op, vault, ttl, key)
	if err != nil {
		return 0, nil, err
	}
	defer clear(body)
	conn, err := net.DialTimeout("unix", c.path, 2*time.Second)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	if err := checkPeer(conn); err != nil { // the agent must run as us too
		return 0, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := WriteFrame(conn, body); err != nil {
		return 0, nil, err
	}
	resp, err := ReadFrame(conn, MaxResponseSize)
	if err != nil {
		return 0, nil, err
	}
	return resp[0], resp[1:], nil
}

func statusErr(status uint8) error {
	switch status {
	case statusOK:
		return nil
	case statusLocked:
		return ErrLocked
	case statusBadTTL:
		return ValidateTTL(0)
	case statusFull:
		return errFull
	case statusBadRequest:
		return ErrBadMessage
	default:
		return errors.New("agent: internal error")
	}
}

func (c *client) simple(op Op, vault string) error {
	st, _, err := c.call(op, vault, 0, nil)
	if err != nil {
		return err
	}
	return statusErr(st)
}

func (c *client) ping() error { return c.simple(OpPing, "") }

func (c *client) Unlock(vaultID string, key *crypto.VaultKey, ttl time.Duration) error {
	defer key.Destroy() // ownership passed to us
	if !validVaultID(vaultID) {
		return errors.New("agent: invalid vault id")
	}
	if err := ValidateTTL(ttl); err != nil {
		return err
	}
	st, _, err := c.call(OpUnlock, vaultID, ttl, key.Bytes())
	if err != nil {
		return err
	}
	return statusErr(st)
}

func (c *client) Key(vaultID string) (*crypto.VaultKey, error) {
	if !validVaultID(vaultID) {
		return nil, errors.New("agent: invalid vault id")
	}
	st, p, err := c.call(OpKey, vaultID, 0, nil)
	if err != nil {
		return nil, err
	}
	defer clear(p)
	if err := statusErr(st); err != nil {
		return nil, err
	}
	kb, err := parseKeyPayload(p)
	if err != nil {
		return nil, err
	}
	return crypto.VaultKeyFromBytes(kb)
}

func (c *client) Lock(vaultID string) error {
	if !validVaultID(vaultID) {
		return errors.New("agent: invalid vault id")
	}
	return c.simple(OpLock, vaultID)
}

func (c *client) LockAll() error { return c.simple(OpLockAll, "") }

// Shutdown asks the agent to exit (it locks everything first).
func (c *client) Shutdown() error { return c.simple(OpShutdown, "") }

func (c *client) Status() ([]VaultStatus, error) {
	st, p, err := c.call(OpStatus, "", 0, nil)
	if err != nil {
		return nil, err
	}
	if err := statusErr(st); err != nil {
		return nil, err
	}
	return parseStatusPayload(p)
}

// Close is a no-op: each call uses its own short connection.
func (c *client) Close() error { return nil }

// agentEnvAllow lists the only variables the agent inherits. Everything else
// (notably secrets injected by `vault run`) is dropped, so a value can never
// linger in the long-lived agent process.
var agentEnvAllow = map[string]bool{"HOME": true, "PATH": true, "TMPDIR": true, "LANG": true}

// CleanEnv returns environ reduced to the agent allowlist: HOME, PATH, TMPDIR,
// LANG and the SECRETS_VAULT_* settings.
func CleanEnv(environ []string) []string {
	out := make([]string, 0, 8)
	for _, kv := range environ {
		k, _, ok := strings.Cut(kv, "=")
		if ok && (agentEnvAllow[k] || strings.HasPrefix(k, "SECRETS_VAULT_")) {
			out = append(out, kv)
		}
	}
	return out
}
