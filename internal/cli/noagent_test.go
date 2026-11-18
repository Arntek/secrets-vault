package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// The Windows flow, run on every OS: with no agent a vault cannot stay
// unlocked, so each command that needs a key asks for the passphrase, and
// with no console to ask on it exits 3.
func TestNoAgentFlowPromptsEachTime(t *testing.T) {
	e := newEnvNoAgent(t)
	dir := filepath.Join(e.home, "vaults", "main")
	expectCode(t, e.runIn(testPass+"\n"+testPass+"\n", "init", "main", "--path", dir, "--passphrase-stdin", "--as", testUser), 0)

	// No console and no passphrase on stdin: locked, exit 3, no value in the output.
	r := e.runIn("VALUE_ONE\n", "set", "EXAMPLE_API_KEY", "--desc", "Example key")
	expectCode(t, r, ExitLocked)
	notContains(t, "output", r.out+r.err, "VALUE_ONE")

	// With the passphrase on a console, set and get each ask for it.
	e.term.stdinTTY = true
	e.term.queue(testPass, "VALUE_ONE") // the passphrase, then the value
	expectCode(t, e.run("set", "EXAMPLE_API_KEY", "--desc", "Example key"), 0)
	e.term.queue(testPass)
	r = e.run("get", "EXAMPLE_API_KEY")
	expectCode(t, r, 0)
	if r.out != "VALUE_ONE\n" {
		t.Fatalf("get: %q", r.out)
	}
	if e.term.asked < 2 {
		t.Fatalf("expected a prompt per command, got %d", e.term.asked)
	}
}

func TestNoAgentUnlockAndLockSayWhy(t *testing.T) {
	e := newEnvNoAgent(t)
	e.initVault("main")
	r := e.runIn(testPass+"\n", "unlock", "main", "--passphrase-stdin")
	expectCode(t, r, ExitError)
	if !strings.Contains(r.err, "unlock agent") {
		t.Fatalf("unlock gives no reason: %s", r)
	}
	expectCode(t, e.run("lock"), 0)
}

func TestConfigBase(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		goos string
		env  map[string]string
		home string
		want string
	}{
		{"linux", nil, "/h", filepath.Join("/h", ".config")},
		{"darwin", map[string]string{"XDG_CONFIG_HOME": "/x"}, "/h", "/x"},
		{"windows", map[string]string{"LOCALAPPDATA": `C:\L`}, `C:\U`, `C:\L`},
		{"windows", map[string]string{"XDG_CONFIG_HOME": `D:\x`, "LOCALAPPDATA": `C:\L`}, `C:\U`, `D:\x`},
		{"windows", nil, "H", filepath.Join("H", "AppData", "Local")},
		{"linux", nil, "", ""},
		{"windows", nil, "", ""},
	}
	for _, c := range cases {
		if got := configBase(c.goos, env(c.env), c.home); got != c.want {
			t.Errorf("%s %v home=%q: got %q want %q", c.goos, c.env, c.home, got, c.want)
		}
	}
}
