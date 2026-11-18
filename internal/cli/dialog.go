package cli

import (
	"bytes"
	"context"
	"errors"
	"github.com/Arntek/secrets-vault/internal/testguard"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/Arntek/secrets-vault/internal/audit"
	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// The native password dialog for agents (macOS). When a command needs a
// vault passphrase, there is no terminal and Touch ID did not open the
// vault, the human gets a dialog naming the vault and the program asking.
// The passphrase comes back on osascript's stdout into memory only.

const (
	osascriptPath   = "/usr/bin/osascript"
	dialogKillAfter = 130 * time.Second // the dialog gives up itself after 120 s
	dialogMaxTries  = 3
)

// dialogScript is constant: the vault name, program name and message reach
// it only as arguments (argv), never spliced into the script, so no name can
// break out of it. Cancel and give-up both raise error -128 (exit 1).
const dialogScript = `on run argv
	set msg to item 1 of argv
	set r to display dialog msg with title "Secrets Vault" default answer "" with hidden answer buttons {"Cancel", "Unlock"} default button "Unlock" cancel button "Cancel" with icon caution giving up after 120
	if gave up of r then error number -128
	return text returned of r
end run`

// dialogRunner shows the dialog with msg and returns what was typed. Tests
// replace it; the real one is runOsascript.
type dialogRunner func(msg string) ([]byte, error)

var errDialogCancelled = errors.New("dialog cancelled")

// osascriptArgs builds the argument list: the constant script, then "--" so
// no value is ever read as an option, then the message.
func osascriptArgs(msg string) []string {
	return []string{"-e", dialogScript, "--", msg}
}

func runOsascript(msg string) ([]byte, error) {
	testguard.Forbid("password dialog (osascript)")
	ctx, cancel := context.WithTimeout(context.Background(), dialogKillAfter)
	defer cancel()
	cmd := exec.CommandContext(ctx, osascriptPath, osascriptArgs(msg)...) // #nosec G204 -- absolute path, message passed as an argument
	// Sized so a passphrase (at most maxPassphraseLen) never makes the
	// buffer grow and leave a copy behind.
	buf := bytes.NewBuffer(make([]byte, 0, 2*maxPassphraseLen))
	cmd.Stdout = buf
	if err := cmd.Run(); err != nil {
		clear(buf.Bytes())
		return nil, errDialogCancelled
	}
	out := buf.Bytes()
	p := append([]byte(nil), bytes.TrimSuffix(out, []byte("\n"))...)
	clear(out)
	return p, nil
}

// dialogMessage is the text shown. Program is the parent process name.
func dialogMessage(vault, program string, pid int, wrong bool) string {
	who := "A program"
	if program != "" {
		who = "The program “" + program + "”"
		if pid > 0 {
			who += " (process " + strconv.Itoa(pid) + ")"
		}
	}
	msg := who + " is asking to unlock the vault “" + vault + "” so it can use a key from it.\n\n" +
		"Type the vault passphrase to allow it, or choose Cancel to refuse."
	if wrong {
		msg = "That passphrase did not work. Try again.\n\n" + msg
	}
	return msg
}

// --- when to ask ---

// dialogSetting is the `dialog` config value. A true/false bool in
// config.toml (the documented form); the old "auto" and "off" strings are
// still read.
type dialogSetting bool

// UnmarshalTOML accepts true/false, or the older "auto"/"off" strings.
func (d *dialogSetting) UnmarshalTOML(v any) error {
	switch x := v.(type) {
	case bool:
		*d = dialogSetting(x)
		return nil
	case string:
		if b, ok := parseDialogWord(x); ok {
			*d = dialogSetting(b)
			return nil
		}
	}
	return errors.New("dialog must be true or false")
}

var _ toml.Unmarshaler = (*dialogSetting)(nil)

func parseDialogWord(s string) (bool, bool) {
	if strings.EqualFold(s, "auto") {
		return true, true
	}
	return parseBool(s)
}

func ptrDialog(b bool) *dialogSetting { d := dialogSetting(b); return &d }

// dialogEnabled is the effective setting: --no-dialog, then the vault's
// own setting, then the global one, then on for macOS and off elsewhere.
func (a *app) dialogEnabled(v *vaultRef) bool {
	if a.noDialog || a.dialog == nil || a.goos != "darwin" {
		return false
	}
	if v != nil && v.entry != nil && v.entry.Dialog != nil {
		return bool(*v.entry.Dialog)
	}
	if c, err := a.loadConfig(); err == nil && c.Dialog != nil {
		return bool(*c.Dialog)
	}
	return true
}

// dialogUnlockVault asks for the vault passphrase with the native dialog. It
// returns (nil, nil) when no dialog is allowed, was cancelled or could not
// be shown: the caller then reports "locked" (exit 3) as before. It never
// runs while a terminal can be asked: a command with a terminal on stdin
// uses the terminal prompt, and --passphrase-stdin reads stdin.
func (a *app) dialogUnlockVault(v *vaultRef, vf *format.VaultFile) (*crypto.VaultKey, error) {
	if a.interactive() || !a.dialogEnabled(v) {
		return nil, nil
	}
	program, pid := a.callerInfo()
	for try := 0; try < dialogMaxTries; try++ {
		p, err := a.dialog(dialogMessage(v.name, program, pid, try > 0))
		if err != nil || len(p) == 0 {
			clear(p)
			return nil, nil
		}
		k, err := a.tryPassphrase(vf, p)
		clear(p)
		if err != nil {
			return nil, err
		}
		if k != nil {
			a.recordVia(v.name, audit.ActionUnlock, "dialog")
			return k, nil
		}
	}
	return nil, nil
}

// --- the calling program ---

// callerInfo is the program that started this command and its process ID.
func (a *app) callerInfo() (string, int) {
	if a.caller != nil {
		return a.caller()
	}
	return "", 0
}

func realDialog() dialogRunner {
	if runtime.GOOS != "darwin" {
		return nil
	}
	return runOsascript
}
