//go:build unix

package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

const (
	sockName = "agent.sock"
	lockName = "agent.lock"
	// maxSockPath is below the smallest sun_path (104 on macOS and BSD).
	maxSockPath = 100
	envDir      = "SECRETS_VAULT_AGENT_DIR"
)

// DefaultDir is the per-user directory holding the agent socket.
//
//	macOS: ~/Library/Caches/secrets-vault (stable across terminals and apps)
//	Linux: $XDG_RUNTIME_DIR/secrets-vault, else /tmp/secrets-vault-<uid>
//
// When that path is too long for a socket address, it falls back to
// <temp dir>/secrets-vault-<uid>.
//
// SECRETS_VAULT_AGENT_DIR overrides it (tests, unusual setups); the directory
// checks apply to it too.
func DefaultDir() (string, error) {
	if d := os.Getenv(envDir); d != "" {
		return d, nil
	}
	fallback := filepath.Join(os.TempDir(), "secrets-vault-"+strconv.Itoa(os.Geteuid()))
	var dir string
	switch {
	case runtime.GOOS == "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, "Library", "Caches", "secrets-vault")
	case os.Getenv("XDG_RUNTIME_DIR") != "":
		dir = filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "secrets-vault")
	default:
		dir = fallback
	}
	// A very long home folder would not fit in a socket address: use a short
	// per-user folder under the temp dir instead (prepareDir still requires
	// it to be 0700 and owned by this user).
	if len(filepath.Join(dir, sockName)) > maxSockPath {
		return fallback, nil
	}
	return dir, nil
}

// prepareDir creates dir (0700) if missing and verifies it is a real
// directory (not a symlink) owned by the current user with no group or other
// access. It refuses otherwise rather than "fixing" a directory someone else
// may control.
func prepareDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: path must be absolute", ErrUnsafeDir)
	}
	if len(filepath.Join(dir, sockName)) > maxSockPath {
		return fmt.Errorf("%w (%d bytes, max %d)", ErrPathTooLong, len(filepath.Join(dir, sockName)), maxSockPath)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return checkDir(dir, os.Geteuid())
}

// checkDir is the permission policy, separated for tests.
func checkDir(dir string, uid int) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	return checkDirInfo(fi, uid)
}

func checkDirInfo(fi fs.FileInfo, uid int) error {
	if !fi.IsDir() { // also rejects symlinks: Lstat does not follow them
		return fmt.Errorf("%w: not a directory", ErrUnsafeDir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: cannot read owner", ErrUnsafeDir)
	}
	if int(st.Uid) != uid {
		return fmt.Errorf("%w: owned by another user", ErrUnsafeDir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: mode %04o is too open (want 0700)", ErrUnsafeDir, fi.Mode().Perm())
	}
	return nil
}
