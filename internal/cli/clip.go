package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// clipClearDelay is how long a copied value stays on the clipboard.
var clipClearDelay = 30 * time.Second

// ClipClearArg is the hidden subcommand that clears the clipboard later.
const ClipClearArg = "__clipclear"

// clipboard is the system clipboard. Tests use a fake.
type clipboard interface {
	Write(value []byte) error
	Read() ([]byte, error)
	// ScheduleClear arranges for the clipboard to be emptied after delay,
	// but only if it still holds the value with this SHA-256 digest.
	ScheduleClear(digest [32]byte, delay time.Duration) error
}

type sysClipboard struct{}

func clipTools() (write, read []string, err error) {
	switch runtime.GOOS {
	case "darwin":
		return []string{"pbcopy"}, []string{"pbpaste"}, nil
	case "linux":
		for _, c := range []struct{ w, r []string }{
			{[]string{"wl-copy"}, []string{"wl-paste", "--no-newline"}},
			{[]string{"xclip", "-selection", "clipboard"}, []string{"xclip", "-selection", "clipboard", "-o"}},
			{[]string{"xsel", "--clipboard", "--input"}, []string{"xsel", "--clipboard", "--output"}},
		} {
			if _, err := exec.LookPath(c.w[0]); err == nil {
				return c.w, c.r, nil
			}
		}
	}
	return nil, nil, errors.New("no clipboard tool found on this system (macOS needs pbcopy)")
}

func (sysClipboard) Write(value []byte) error {
	w, _, err := clipTools()
	if err != nil {
		return err
	}
	cmd := exec.Command(w[0], w[1:]...) // #nosec G204 -- fixed tool names
	cmd.Stdin = bytes.NewReader(value)
	if err := cmd.Run(); err != nil {
		return errors.New("could not write to the clipboard")
	}
	return nil
}

func (sysClipboard) Read() ([]byte, error) {
	_, r, err := clipTools()
	if err != nil {
		return nil, err
	}
	out, err := exec.Command(r[0], r[1:]...).Output() // #nosec G204 -- fixed tool names
	if err != nil {
		return nil, errors.New("could not read the clipboard")
	}
	return out, nil
}

// ScheduleClear starts a detached copy of this program that sleeps, then
// clears the clipboard if it still holds the copied value. The digest goes
// over stdin, not the command line, so it never shows in a process list.
func (sysClipboard) ScheduleClear(digest [32]byte, delay time.Duration) error {
	exe, err := osExecutable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, ClipClearArg) // #nosec G204 -- this program, fixed argument
	detach(cmd)
	cmd.Stdin = strings.NewReader(hex.EncodeToString(digest[:]) + "\n" + delay.String() + "\n")
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// runClipClear is the hidden __clipclear subcommand.
func (a *app) runClipClear() int {
	digestHex, err := a.readLine()
	if err != nil {
		return ExitError
	}
	delayStr, _ := a.readLine()
	var want [32]byte
	b, err := hex.DecodeString(strings.TrimSpace(digestHex))
	if err != nil || len(b) != len(want) {
		return ExitError
	}
	copy(want[:], b)
	delay := clipClearDelay
	if d, err := time.ParseDuration(strings.TrimSpace(delayStr)); err == nil && d >= 0 && d <= time.Hour {
		delay = d
	}
	time.Sleep(delay)
	cur, err := a.clip.Read()
	if err != nil {
		return ExitError
	}
	got := sha256.Sum256(cur)
	clear(cur)
	if got == want {
		_ = a.clip.Write(nil)
	}
	return ExitOK
}

var _ io.Reader = (*bytes.Reader)(nil)
