package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func lockedEnv(t *testing.T) *testEnv {
	t.Helper()
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	e.set("EXAMPLE_KEY", "main", "VALUE_ONE")
	e.mustRun("lock", "--all")
	return e
}

func TestDialogUnlocksWhenNoTerminal(t *testing.T) {
	e := lockedEnv(t)
	e.dialog.answers = []string{testPass}
	r := e.mustRun("get", "EXAMPLE_KEY")
	if strings.TrimSpace(r.out) != "VALUE_ONE" {
		t.Fatalf("%s", r)
	}
	if len(e.dialog.msgs) != 1 {
		t.Fatalf("expected one dialog, got %d", len(e.dialog.msgs))
	}
	m := e.dialog.msgs[0]
	if !strings.Contains(m, "main") || !strings.Contains(m, "testprog") || !strings.Contains(m, "4242") {
		t.Fatalf("the dialog must name the vault and the program: %q", m)
	}
	notContains(t, "dialog message", m, testPass, "VALUE_ONE")
	notContains(t, "output", r.out+r.err, testPass)
	// The key is now held by the agent: no second dialog.
	e.mustRun("get", "EXAMPLE_KEY")
	if len(e.dialog.msgs) != 1 {
		t.Fatalf("an unlocked vault must not ask again")
	}
}

func TestDialogCancelFallsBackToExit3(t *testing.T) {
	e := lockedEnv(t)
	r := e.run("get", "EXAMPLE_KEY") // no scripted answer: Cancel
	expectCode(t, r, ExitLocked)
	if !strings.Contains(r.err, "locked") || !strings.Contains(r.err, "unlock main") {
		t.Fatalf("the usual exit 3 message: %s", r)
	}
	if len(e.dialog.msgs) != 1 {
		t.Fatalf("asked %d times", len(e.dialog.msgs))
	}
	// An empty answer is a refusal too.
	e.dialog.answers = []string{""}
	expectCode(t, e.run("get", "EXAMPLE_KEY"), ExitLocked)
}

func TestDialogWrongPassphraseRetriesThenGivesUp(t *testing.T) {
	e := lockedEnv(t)
	e.dialog.answers = []string{"wrong one", testPass}
	e.mustRun("get", "EXAMPLE_KEY")
	if len(e.dialog.msgs) != 2 || !strings.Contains(e.dialog.msgs[1], "did not work") {
		t.Fatalf("expected a retry that says so: %q", e.dialog.msgs)
	}
	e.mustRun("lock", "--all")
	e.dialog.msgs = nil
	e.dialog.answers = []string{"bad 1", "bad 2", "bad 3", testPass}
	expectCode(t, e.run("get", "EXAMPLE_KEY"), ExitLocked)
	if len(e.dialog.msgs) != dialogMaxTries {
		t.Fatalf("want %d tries, got %d", dialogMaxTries, len(e.dialog.msgs))
	}
}

func TestDialogNeverWhenATerminalIsThere(t *testing.T) {
	e := lockedEnv(t)
	e.dialog.answers = []string{testPass}
	e.term.stdinTTY = true
	e.term.queue(testPass)
	e.mustRun("get", "EXAMPLE_KEY")
	if len(e.dialog.msgs) != 0 {
		t.Fatalf("a terminal prompt must be used, not a dialog: %q", e.dialog.msgs)
	}
	// Even when the typed passphrase is wrong and the prompt gives up.
	e.term.stdinTTY = true
	e.mustRun("lock", "--all")
	e.term.queue("nope", "nope", "nope")
	expectCode(t, e.run("get", "EXAMPLE_KEY"), ExitError)
	if len(e.dialog.msgs) != 0 {
		t.Fatalf("no dialog after failed terminal prompts: %q", e.dialog.msgs)
	}
	// --passphrase-stdin is a way to ask too.
	e.term.stdinTTY = false
	e.mustRun("lock", "--all")
	e.mustRunIn(testPass+"\n", "get", "EXAMPLE_KEY", "--passphrase-stdin")
	if len(e.dialog.msgs) != 0 {
		t.Fatalf("no dialog with --passphrase-stdin: %q", e.dialog.msgs)
	}
}

func TestDialogOffSwitches(t *testing.T) {
	e := lockedEnv(t)
	e.dialog.answers = []string{testPass}
	expectCode(t, e.run("get", "EXAMPLE_KEY", "--no-dialog"), ExitLocked)
	e.mustRun("config", "set", "dialog", "false")
	expectCode(t, e.run("get", "EXAMPLE_KEY"), ExitLocked)
	e.mustRun("config", "set", "dialog", "true")
	e.mustRun("config", "set", "dialog", "off", "--vault", "main")
	expectCode(t, e.run("get", "EXAMPLE_KEY"), ExitLocked)
	e.mustRun("config", "set", "dialog", "true", "--vault", "main") // the vault's own setting wins
	e.mustRun("config", "set", "dialog", "false")
	e.mustRun("get", "EXAMPLE_KEY")
	if len(e.dialog.msgs) != 1 {
		t.Fatalf("only the last run should have shown the dialog: %d", len(e.dialog.msgs))
	}
	expectCode(t, e.run("config", "set", "dialog", "sometimes"), ExitUsage)
}

func TestDialogOnlyOnMac(t *testing.T) {
	e := lockedEnv(t)
	e.dialog.answers = []string{testPass}
	prev := testHook
	testHook = func(a *app) { prev(a); a.goos = "linux" }
	t.Cleanup(func() { testHook = prev })
	expectCode(t, e.run("get", "EXAMPLE_KEY"), ExitLocked)
	if len(e.dialog.msgs) != 0 {
		t.Fatal("no dialog off macOS")
	}
}

func TestDialogConfigFileForms(t *testing.T) {
	for in, want := range map[string]bool{
		"dialog = true\n": true, "dialog = false\n": false, "dialog = \"auto\"\n": true, "dialog = \"off\"\n": false,
	} {
		c, err := parseConfig([]byte(in))
		if err != nil || c.Dialog == nil || bool(*c.Dialog) != want {
			t.Errorf("%q: %v %v", in, c, err)
		}
	}
	if _, err := parseConfig([]byte("dialog = \"maybe\"\n")); err == nil {
		t.Error("a bad value must be refused")
	}
	if c, _ := parseConfig([]byte("")); c.Dialog != nil {
		t.Error("unset stays unset (on for macOS)")
	}
}

// The message and names travel as arguments, never inside the script.
func TestOsascriptArgsKeepNamesOutOfTheScript(t *testing.T) {
	evil := `x" & (do shell script "touch /tmp/pwned") & "` + "\\\\ \n -e 'oops'"
	args := osascriptArgs(dialogMessage(evil, evil, 1, false))
	if len(args) != 4 || args[0] != "-e" || args[1] != dialogScript || args[2] != "--" {
		t.Fatalf("shape: %q", args)
	}
	if strings.Contains(dialogScript, "touch") || !strings.Contains(args[3], evil) {
		t.Fatal("the name must be in the message argument only")
	}
	if strings.Count(dialogScript, "item 1 of argv") != 1 {
		t.Fatal("the script reads the message from argv")
	}
}

// Round-trip the same argument shape through the real osascript with a
// harmless script (no dialog): quotes, backslashes, newlines and a leading
// dash arrive as one intact argument and nothing runs.
func TestOsascriptArgvRoundTrip(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("osascript is macOS only")
	}
	marker := filepath.Join(t.TempDir(), "pwned")
	for _, msg := range []string{
		`-e "quoted" and \backslash\`,
		"line1\nline2",
		`" & (do shell script "touch ` + marker + `") & "`,
		`-- x`,
	} {
		out, err := exec.Command(osascriptPath, "-e", "on run argv\nreturn item 1 of argv\nend run", "--", msg).Output() // #nosec G204 -- test
		if err != nil {
			t.Fatalf("osascript: %v", err)
		}
		if got := strings.TrimSuffix(string(out), "\n"); got != msg {
			t.Fatalf("argument changed: %q -> %q", msg, got)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("injected AppleScript ran")
	}
}

func TestDialogMessage(t *testing.T) {
	m := dialogMessage("work", "python3", 99, false)
	for _, w := range []string{"work", "python3", "99"} {
		if !strings.Contains(m, w) {
			t.Fatalf("%q missing %q", m, w)
		}
	}
	if m := dialogMessage("work", "", 0, false); !strings.Contains(m, "work") {
		t.Fatal(m)
	}
}
