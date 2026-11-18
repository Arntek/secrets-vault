package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Arntek/secrets-vault/internal/agent"
	"github.com/Arntek/secrets-vault/internal/format"
)

func skipWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs the unix agent and shell")
	}
}

func TestHelpUsesInvokedNameAndTable(t *testing.T) {
	e := newEnv(t)
	r := e.mustRun("help")
	for _, want := range []string{"sv <command>", "init NAME --path DIR", "run -k A [-k B] -- cmd args", "member approve|rm|list|requests", "Exit codes"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("help is missing %q", want)
		}
	}
	r = e.mustRun("help", "get")
	if !strings.Contains(r.out, "Usage: sv get NAME") {
		t.Errorf("command help: %s", r.out)
	}
	r = e.mustRun("get", "--help")
	if !strings.Contains(r.out, "Usage: sv get NAME") {
		t.Errorf("--help: %s", r.out)
	}
}

func TestUnknownCommandAndOptionAreNotEchoed(t *testing.T) {
	e := newEnv(t)
	canary := "SVCANARY_UNKNOWN_ARG_1"
	r := e.run(canary)
	expectCode(t, r, ExitUsage)
	notContains(t, "unknown command output", r.out+r.err, canary)
	r = e.run("list", "--"+canary)
	expectCode(t, r, ExitUsage)
	notContains(t, "unknown option output", r.out+r.err, canary)
	r = e.run("list", "extra-"+canary)
	expectCode(t, r, ExitUsage)
	notContains(t, "extra argument output", r.out+r.err, canary)
}

func TestInitSetListGetFlow(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	if _, err := os.Stat(filepath.Join(dir, "vault.json")); err != nil {
		t.Fatal(err)
	}
	// Nothing unlocked yet: writing asks for the vault to be unlocked.
	expectCode(t, e.runIn("VALUE_ONE", "set", "EXAMPLE_API_KEY"), ExitLocked)
	e.unlock("main")
	e.mustRunIn("VALUE_ONE\n", "set", "EXAMPLE_API_KEY", "--desc", "Example key")

	// get: piped stdout prints the plain value.
	r := e.mustRun("get", "EXAMPLE_API_KEY")
	if r.out != "VALUE_ONE\n" {
		t.Fatalf("plain get: %q", r.out)
	}
	if r := e.mustRun("get", "EXAMPLE_API_KEY", "-n"); r.out != "VALUE_ONE" {
		t.Fatalf("get -n: %q", r.out)
	}
	j := decodeJSON[map[string]any](t, e.mustRun("get", "EXAMPLE_API_KEY", "--json").out)
	if j["value"] != "VALUE_ONE" || j["vault"] != "main" {
		t.Fatalf("json get: %v", j)
	}
	// On a terminal the value is masked unless --reveal.
	e.term.stdoutTTY = true
	r = e.mustRun("get", "EXAMPLE_API_KEY")
	notContains(t, "masked get", r.out, "VALUE_ONE")
	if !strings.Contains(r.out, "--reveal") {
		t.Fatalf("masked output should hint at --reveal: %q", r.out)
	}
	jm := decodeJSON[map[string]any](t, e.mustRun("get", "EXAMPLE_API_KEY", "--json").out)
	if jm["value"] != nil || jm["masked"] != true {
		t.Fatalf("masked json: %v", jm)
	}
	if r := e.mustRun("get", "EXAMPLE_API_KEY", "--reveal"); r.out != "VALUE_ONE\n" {
		t.Fatalf("--reveal: %q", r.out)
	}
	e.term.stdoutTTY = false

	// list works from the index.
	r = e.mustRun("list")
	for _, want := range []string{"EXAMPLE_API_KEY", "main", "Example key", "1 vault", "1 key", "main 🔓"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("list is missing %q:\n%s", want, r.out)
		}
	}
	rows := decodeJSON[[]keyRow](t, e.mustRun("list", "--json").out)
	if len(rows) != 1 || rows[0].Name != "EXAMPLE_API_KEY" || rows[0].Locked {
		t.Fatalf("list json: %+v", rows)
	}

	// Lock, and list still works (index only); get now exits 3.
	e.mustRun("lock", "--all")
	rows = decodeJSON[[]keyRow](t, e.mustRun("list", "--json").out)
	if !rows[0].Locked {
		t.Fatal("list should show the vault locked")
	}
	r = e.run("get", "EXAMPLE_API_KEY")
	expectCode(t, r, ExitLocked)
	if !strings.Contains(r.err, "Vault 'main' is locked. Run: sv unlock main") {
		t.Fatalf("locked message: %q", r.err)
	}
}

func TestInitRefusesInsideGitRepoUnlessForced(t *testing.T) {
	e := newEnv(t)
	repo := filepath.Join(e.home, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := e.runIn(testPass+"\n", "init", "x", "--path", filepath.Join(repo, "vault"), "--passphrase-stdin")
	expectCode(t, r, ExitError)
	if !strings.Contains(r.err, "git repository") {
		t.Fatalf("message: %q", r.err)
	}
	if _, err := os.Stat(filepath.Join(repo, "vault")); err == nil {
		t.Fatal("the folder must not be created")
	}
	e.mustRunIn(testPass+"\n", "init", "x", "--path", filepath.Join(repo, "vault"), "--passphrase-stdin", "--force")
}

func TestInitValidationAndDuplicates(t *testing.T) {
	e := newEnv(t)
	expectCode(t, e.run("init", "x"), ExitUsage)                                                           // no --path
	expectCode(t, e.run("init", "Bad Name", "--path", e.home+"/v"), ExitUsage)                             // bad name
	expectCode(t, e.runIn("short\n", "init", "x", "--path", e.home+"/v", "--passphrase-stdin"), ExitError) // short passphrase
	expectCode(t, e.run("init", "x", "--path", e.home+"/v"), ExitError)                                    // no terminal, no passphrase
	e.initVault("main")
	r := e.runIn(testPass+"\n", "init", "main", "--path", e.home+"/other", "--passphrase-stdin")
	expectCode(t, r, ExitError)
	r = e.runIn(testPass+"\n", "init", "second", "--path", e.home+"/vaults/main", "--passphrase-stdin")
	expectCode(t, r, ExitError) // a vault is already in that folder
}

func TestInitInteractiveRepeatsPassphrase(t *testing.T) {
	e := newEnv(t)
	e.term.stdinTTY = true
	e.term.queue(testPass, "different passphrase")
	r := e.runIn("", "init", "main", "--path", e.home+"/v1")
	expectCode(t, r, ExitError)
	if !strings.Contains(r.err, "do not match") {
		t.Fatalf("%s", r)
	}
	e.term.queue(testPass, testPass)
	e.mustRun("init", "main", "--path", e.home+"/v1")
}

func TestSetRejectsValueArgumentAndEmpty(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	e.unlock("main")
	canary := "SVCANARY_ARG_VALUE_9"
	r := e.run("set", "EXAMPLE_API_KEY", canary)
	expectCode(t, r, ExitUsage)
	notContains(t, "set with value argument", r.out+r.err, canary)
	if !strings.Contains(r.err, "must not be given as an argument") {
		t.Fatalf("expected a clear error: %s", r)
	}
	r = e.run("set", "EXAMPLE_API_KEY", "--value", canary)
	expectCode(t, r, ExitUsage)
	notContains(t, "set --value", r.out+r.err, canary)
	expectCode(t, e.runIn("", "set", "EXAMPLE_API_KEY"), ExitError) // empty stdin
	expectCode(t, e.runIn("x", "set", "not_valid_name"), ExitUsage) // invalid name
	rows := decodeJSON[[]keyRow](t, e.mustRun("list", "--json").out)
	if len(rows) != 0 {
		t.Fatalf("nothing should have been saved: %+v", rows)
	}
}

func TestSetHiddenPromptOnTerminal(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	e.unlock("main")
	e.term.stdinTTY = true
	e.term.queue("typed value")
	r := e.mustRun("set", "EXAMPLE_API_KEY")
	if !strings.Contains(r.err, "Value (hidden)") {
		t.Fatalf("prompt: %s", r)
	}
	e.term.stdinTTY = false
	if got := e.mustRun("get", "EXAMPLE_API_KEY").out; got != "typed value\n" {
		t.Fatalf("%q", got)
	}
}

func TestSetUpdateKeepsDescriptionAndTags(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	e.unlock("main")
	e.set("EXAMPLE_API_KEY", "", "one")
	e.mustRun("tag", "EXAMPLE_API_KEY", "xero,reporting")
	e.mustRunIn("two", "set", "EXAMPLE_API_KEY")
	info := decodeJSON[map[string]any](t, e.mustRun("info", "EXAMPLE_API_KEY", "--json").out)
	if info["description"] != "test key example_api_key" {
		t.Fatalf("description lost: %v", info)
	}
	if tags, _ := info["tags"].([]any); len(tags) != 2 {
		t.Fatalf("tags lost: %v", info)
	}
	if got := e.mustRun("get", "EXAMPLE_API_KEY").out; got != "two\n" {
		t.Fatalf("%q", got)
	}
}

func TestExitCodesAndAmbiguousKeys(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("one")
	e.mustRunIn(testPass+"\n", "init", "two", "--path", filepath.Join(e.home, "vaults", "two"), "--passphrase-stdin")
	e.unlock("one")
	e.unlock("two")
	e.set("EXAMPLE_SHARED", "one", "from-one")
	e.set("EXAMPLE_SHARED", "two", "from-two")
	e.set("EXAMPLE_ONLY_ONE", "one", "solo")

	expectCode(t, e.run("get", "NO_SUCH_KEY"), ExitNotFound)
	expectCode(t, e.run("get", "EXAMPLE_SHARED"), ExitUsage)
	r := e.run("get", "EXAMPLE_SHARED")
	if !strings.Contains(r.err, "Use --vault") {
		t.Fatalf("ambiguity message: %s", r)
	}
	if got := e.mustRun("get", "EXAMPLE_SHARED", "--vault", "two").out; got != "from-two\n" {
		t.Fatalf("%q", got)
	}
	if got := e.mustRun("get", "EXAMPLE_ONLY_ONE").out; got != "solo\n" {
		t.Fatalf("%q", got)
	}
	expectCode(t, e.run("get", "EXAMPLE_ONLY_ONE", "--vault", "two"), ExitNotFound)
	expectCode(t, e.run("get", "EXAMPLE_ONLY_ONE", "--vault", "nosuch"), ExitError)
	expectCode(t, e.run("get", "lower_case"), ExitUsage)
	expectCode(t, e.run("get"), ExitUsage)
	// A key name that does not exist is not echoed back.
	r = e.run("get", "SVCANARY_MISSING_NAME")
	expectCode(t, r, ExitNotFound)
	notContains(t, "not found message", r.err, "SVCANARY_MISSING_NAME")

	// set without --vault goes to the existing key's vault, never the default.
	e.mustRunIn("updated", "set", "EXAMPLE_ONLY_ONE")
	if got := e.mustRun("get", "EXAMPLE_ONLY_ONE", "--vault", "one").out; got != "updated\n" {
		t.Fatalf("%q", got)
	}
	// A new key with two vaults and a default goes to the default vault.
	e.mustRunIn("fresh", "set", "EXAMPLE_NEW")
	if got := e.mustRun("get", "EXAMPLE_NEW", "--vault", "one").out; got != "fresh\n" {
		t.Fatalf("%q", got)
	}
}

func TestSetNeedsVaultWhenNoDefault(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("one")
	e.mustRunIn(testPass+"\n", "init", "two", "--path", filepath.Join(e.home, "vaults", "two"), "--passphrase-stdin")
	e.mustRun("config", "set", "default-vault", "two")
	e.unlock("two")
	e.mustRunIn("v", "set", "EXAMPLE_NEW")
	if got := e.mustRun("get", "EXAMPLE_NEW", "--vault", "two").out; got != "v\n" {
		t.Fatalf("%q", got)
	}
	// With no default and several vaults, a new key needs --vault.
	e.mustRun("detach", "two")
	e.mustRunIn(testPass+"\n", "init", "three", "--path", filepath.Join(e.home, "vaults", "three"), "--passphrase-stdin")
	cfg, _ := e.cfgText()
	cfg = strings.Replace(cfg, `default_vault = "three"`, "", 1)
	_ = os.WriteFile(e.cfg, []byte(cfg), 0o600)
	r := e.runIn("v", "set", "EXAMPLE_OTHER")
	expectCode(t, r, ExitUsage)
}

func (e *testEnv) cfgText() (string, error) {
	b, err := os.ReadFile(e.cfg)
	return string(b), err
}

func TestSearchInfoDescribeTag(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	e.unlock("main")
	e.set("SENDGRID_API_KEY", "", "a")
	e.set("XERO_CLIENT_SECRET", "", "b")
	e.mustRun("describe", "XERO_CLIENT_SECRET", "Xero app", "EBCFO Reporting")
	e.mustRun("tag", "XERO_CLIENT_SECRET", "xero,reporting")

	rows := decodeJSON[[]keyRow](t, e.mustRun("search", "xero", "--json").out)
	if len(rows) != 1 || rows[0].Name != "XERO_CLIENT_SECRET" || rows[0].Description != "Xero app EBCFO Reporting" {
		t.Fatalf("search: %+v", rows)
	}
	if rows = decodeJSON[[]keyRow](t, e.mustRun("search", "xero", "reporting", "--json").out); len(rows) != 1 {
		t.Fatalf("AND search: %+v", rows)
	}
	if rows = decodeJSON[[]keyRow](t, e.mustRun("search", "xero", "sendgrid", "--json").out); len(rows) != 0 {
		t.Fatalf("no match expected: %+v", rows)
	}
	if rows = decodeJSON[[]keyRow](t, e.mustRun("list", "--tag", "reporting", "--json").out); len(rows) != 1 {
		t.Fatalf("tag filter: %+v", rows)
	}
	if rows = decodeJSON[[]keyRow](t, e.mustRun("list", "--vault", "main", "--json").out); len(rows) != 2 {
		t.Fatalf("vault filter: %+v", rows)
	}
	r := e.mustRun("info", "XERO_CLIENT_SECRET")
	for _, want := range []string{"XERO_CLIENT_SECRET", "main", "Xero app EBCFO Reporting", "reporting, xero"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("info missing %q:\n%s", want, r.out)
		}
	}
	e.mustRun("tag", "XERO_CLIENT_SECRET", "xero", "--rm")
	info := decodeJSON[map[string]any](t, e.mustRun("info", "XERO_CLIENT_SECRET", "--json").out)
	if tags := info["tags"].([]any); len(tags) != 1 || tags[0] != "reporting" {
		t.Fatalf("after --rm: %v", info["tags"])
	}
	expectCode(t, e.run("tag", "XERO_CLIENT_SECRET", "Bad Tag"), ExitUsage)
	expectCode(t, e.run("info", "NO_SUCH_KEY"), ExitNotFound)
	// describe and tag work while the vault is locked.
	e.mustRun("lock", "--all")
	e.mustRun("describe", "SENDGRID_API_KEY", "now locked")
}

func TestListWorksWithoutAnyVaultAndDamagedIndex(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	r := e.mustRun("list")
	if !strings.Contains(r.out, "No keys") {
		t.Fatalf("%s", r)
	}
	if j := decodeJSON[[]keyRow](t, e.mustRun("list", "--json").out); len(j) != 0 {
		t.Fatalf("%v", j)
	}
	dir := e.initVault("main")
	e.unlock("main")
	e.set("EXAMPLE_API_KEY", "", "x")
	// A deleted index is rebuilt from secrets/ (descriptions are lost).
	if err := os.Remove(filepath.Join(dir, "index.json")); err != nil {
		t.Fatal(err)
	}
	rows := decodeJSON[[]keyRow](t, e.mustRun("list", "--json").out)
	if len(rows) != 1 || rows[0].Name != "EXAMPLE_API_KEY" {
		t.Fatalf("rebuilt index: %+v", rows)
	}
}

func TestMvRenameRm(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("one")
	e.mustRunIn(testPass+"\n", "init", "two", "--path", filepath.Join(e.home, "vaults", "two"), "--passphrase-stdin")
	e.unlock("one")
	e.unlock("two")
	e.set("EXAMPLE_API_KEY", "one", "moved-value")

	e.mustRun("mv", "EXAMPLE_API_KEY", "--to", "two")
	if got := e.mustRun("get", "EXAMPLE_API_KEY").out; got != "moved-value\n" {
		t.Fatalf("%q", got)
	}
	rows := decodeJSON[[]keyRow](t, e.mustRun("list", "--json").out)
	if len(rows) != 1 || rows[0].Vault != "two" || rows[0].Description != "test key example_api_key" {
		t.Fatalf("after mv: %+v", rows)
	}
	expectCode(t, e.run("mv", "EXAMPLE_API_KEY", "--to", "two"), ExitError) // already there
	expectCode(t, e.run("mv", "EXAMPLE_API_KEY"), ExitUsage)                // no --to

	e.mustRun("rename", "EXAMPLE_API_KEY", "EXAMPLE_RENAMED")
	if got := e.mustRun("get", "EXAMPLE_RENAMED").out; got != "moved-value\n" {
		t.Fatalf("%q", got)
	}
	expectCode(t, e.run("get", "EXAMPLE_API_KEY"), ExitNotFound)
	expectCode(t, e.run("rename", "EXAMPLE_RENAMED", "lower"), ExitUsage)
	e.set("EXAMPLE_OTHER", "two", "o")
	expectCode(t, e.run("rename", "EXAMPLE_RENAMED", "EXAMPLE_OTHER"), ExitError)

	// rm: needs --yes without a terminal; asks on a terminal.
	expectCode(t, e.run("rm", "EXAMPLE_RENAMED"), ExitError)
	e.term.stdinTTY = true
	expectCode(t, e.runIn("n\n", "rm", "EXAMPLE_RENAMED"), ExitError)
	e.mustRunIn("y\n", "rm", "EXAMPLE_RENAMED")
	e.term.stdinTTY = false
	expectCode(t, e.run("get", "EXAMPLE_RENAMED"), ExitNotFound)
	e.mustRun("rm", "EXAMPLE_OTHER", "--yes")
	// The deleted file went to the trash, not into thin air.
	tr, err := format.ListTrash(filepath.Join(e.home, "vaults", "two"))
	if err != nil || len(tr) < 2 {
		t.Fatalf("trash: %v %v", tr, err)
	}
	// rm on a locked vault is refused with exit 3.
	e.set("EXAMPLE_LAST", "two", "l")
	e.mustRun("lock", "two")
	expectCode(t, e.run("rm", "EXAMPLE_LAST", "--yes"), ExitLocked)
}

func TestRunEnvIsolationAndExitCode(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	e.unlock("main")
	e.set("EXAMPLE_KEY_A", "", "value-a")
	e.set("EXAMPLE_KEY_B", "", "value-b")
	e.set("EXAMPLE_KEY_C", "", "value-c")

	r := e.mustRun("run", "-k", "EXAMPLE_KEY_A", "-k", "EXAMPLE_KEY_B", "--", "env")
	if !strings.Contains(r.out, "EXAMPLE_KEY_A=value-a") || !strings.Contains(r.out, "EXAMPLE_KEY_B=value-b") {
		t.Fatalf("requested keys missing:\n%s", r.out)
	}
	notContains(t, "child environment", r.out, "value-c", "EXAMPLE_KEY_C")
	if !strings.Contains(r.out, "SV_UNRELATED=visible") {
		t.Fatalf("the ordinary environment should pass through:\n%s", r.out)
	}
	// The value does not appear in vault's own output beyond the child's.
	r = e.mustRun("run", "-k", "EXAMPLE_KEY_C", "--", "sh", "-c", `test "$EXAMPLE_KEY_C" = value-c`)
	if r.out != "" || r.err != "" {
		t.Fatalf("run should add no output: %s", r)
	}
	// The child's exit code passes through.
	expectCode(t, e.run("run", "-k", "EXAMPLE_KEY_A", "--", "sh", "-c", "exit 7"), 7)
	// A command that does not exist.
	expectCode(t, e.run("run", "-k", "EXAMPLE_KEY_A", "--", "/no/such/program"), 127)
	// A variable already in the environment is replaced by the vault's value.
	e.environ = append(e.environ, "EXAMPLE_KEY_A=stale")
	r = e.mustRun("run", "-k", "EXAMPLE_KEY_A", "--", "env")
	notContains(t, "run output", r.out, "stale")
	// Usage errors.
	expectCode(t, e.run("run", "--", "env"), ExitUsage)
	expectCode(t, e.run("run", "-k", "EXAMPLE_KEY_A"), ExitUsage)
	expectCode(t, e.run("run", "-k", "EXAMPLE_KEY_A", "env"), ExitUsage) // missing --
	expectCode(t, e.run("run", "-k", "NO_SUCH_KEY", "--", "env"), ExitNotFound)
	// A locked vault stops the run before the command starts.
	e.mustRun("lock", "--all")
	marker := filepath.Join(e.home, "ran")
	r = e.run("run", "-k", "EXAMPLE_KEY_A", "--", "touch", marker)
	expectCode(t, r, ExitLocked)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the command must not run when the vault is locked")
	}
}

func TestRunPassesStdinThrough(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	e.unlock("main")
	e.set("EXAMPLE_KEY_A", "", "value-a")
	r := e.mustRunIn("piped input", "run", "-k", "EXAMPLE_KEY_A", "--", "cat")
	if r.out != "piped input" {
		t.Fatalf("stdin pass-through: %q", r.out)
	}
}

func TestCopyClearsOnlyIfUnchanged(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	e.unlock("main")
	e.set("EXAMPLE_API_KEY", "", "copy-me")
	r := e.mustRun("copy", "EXAMPLE_API_KEY")
	notContains(t, "copy output", r.out+r.err, "copy-me")
	if string(e.clip.value) != "copy-me" {
		t.Fatalf("clipboard: %q", e.clip.value)
	}
	if len(e.clip.scheduled) != 1 || e.clip.scheduled[0] != 30*time.Second {
		t.Fatalf("scheduled: %v", e.clip.scheduled)
	}
	// The scheduled helper clears only when the clipboard still holds it.
	oldDelay := clipClearDelay
	clipClearDelay = 0
	defer func() { clipClearDelay = oldDelay }()
	stdin := func(d [32]byte) string { return hexOf(d) + "\n0s\n" }
	a := newApp("sv", strings.NewReader(stdin(e.clip.digests[0])), new(strings.Builder), new(strings.Builder))
	a.clip = e.clip
	if code := a.runClipClear(); code != 0 || len(e.clip.value) != 0 {
		t.Fatalf("clipboard should be cleared: code %d value %q", code, e.clip.value)
	}
	e.clip.value = []byte("something else the user copied")
	a = newApp("sv", strings.NewReader(stdin(e.clip.digests[0])), new(strings.Builder), new(strings.Builder))
	a.clip = e.clip
	a.runClipClear()
	if string(e.clip.value) != "something else the user copied" {
		t.Fatal("a changed clipboard must not be cleared")
	}
	e.clip.failWrite = true
	expectCode(t, e.run("copy", "EXAMPLE_API_KEY"), ExitError)
}

func hexOf(d [32]byte) string {
	const h = "0123456789abcdef"
	b := make([]byte, 0, 64)
	for _, x := range d {
		b = append(b, h[x>>4], h[x&15])
	}
	return string(b)
}

func TestUnlockForStatusAndConfig(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	expectCode(t, e.runIn(testPass+"\n", "unlock", "main", "--for", "1m", "--passphrase-stdin"), ExitUsage)
	expectCode(t, e.runIn(testPass+"\n", "unlock", "main", "--for", "forever", "--passphrase-stdin"), ExitUsage)
	expectCode(t, e.runIn("wrong passphrase\n", "unlock", "main", "--passphrase-stdin"), ExitError)
	e.mustRunIn(testPass+"\n", "unlock", "main", "--for", "30m", "--passphrase-stdin")
	st := decodeJSON[[]map[string]any](t, e.mustRun("status", "--json").out)
	if len(st) != 1 || st[0]["unlocked"] != true {
		t.Fatalf("status: %v", st)
	}
	if left := st[0]["seconds_left"].(float64); left < 25*60 || left > 31*60 {
		t.Fatalf("expected about 30 minutes left, got %v seconds", left)
	}
	r := e.mustRun("status")
	if !strings.Contains(r.out, "unlocked") || !strings.Contains(r.out, "left") {
		t.Fatalf("%s", r)
	}
	e.mustRun("lock", "main")
	st = decodeJSON[[]map[string]any](t, e.mustRun("status", "--json").out)
	if st[0]["unlocked"] != false {
		t.Fatalf("status after lock: %v", st)
	}
	// Per-vault and global defaults.
	e.mustRun("config", "set", "default-ttl", "6h")
	e.mustRun("config", "set", "default-ttl", "2h", "--vault", "main")
	e.mustRunIn(testPass+"\n", "unlock", "main", "--passphrase-stdin")
	st = decodeJSON[[]map[string]any](t, e.mustRun("status", "--json").out)
	if left := st[0]["seconds_left"].(float64); left < 110*60 || left > 121*60 {
		t.Fatalf("per-vault ttl should win: %v seconds left", left)
	}
	expectCode(t, e.run("config", "set", "default-ttl", "4m"), ExitUsage)
	expectCode(t, e.run("config", "set", "default-ttl", "25h"), ExitUsage)
	expectCode(t, e.run("config", "set", "nonsense", "1"), ExitUsage)
	expectCode(t, e.run("config", "set", "touch-every-read", "maybe"), ExitUsage)
	expectCode(t, e.run("config", "set", "dialog", "sometimes"), ExitUsage)
	e.mustRun("config", "set", "touch-every-read", "true", "--vault", "main")
	e.mustRun("config", "set", "dialog", "off")
	cfg := decodeJSON[map[string]any](t, e.mustRun("config", "list", "--json").out)
	if cfg["default_ttl"] != "6h" || cfg["dialog"] != "off" {
		t.Fatalf("config list: %v", cfg)
	}
	expectCode(t, e.run("config", "set", "default-vault", "nosuch"), ExitError)
	expectCode(t, e.run("config"), ExitUsage)
}

func TestTouchEveryReadAsksEachTime(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.touch.avail = true
	e.initVault("main")
	e.mustRunIn(testPass+"\n", "unlock", "main", "--passphrase-stdin")
	e.set("EXAMPLE_API_KEY", "", "v")
	e.mustRun("touchid", "on", "main")
	e.mustRun("config", "set", "touch-every-read", "true", "--vault", "main")
	before := e.touch.unwraps
	e.mustRun("get", "EXAMPLE_API_KEY")
	e.mustRun("get", "EXAMPLE_API_KEY")
	if e.touch.unwraps-before != 2 {
		t.Fatalf("expected a Touch ID check on every read, got %d", e.touch.unwraps-before)
	}
}

func TestPasswd(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	e.unlock("main")
	e.set("EXAMPLE_API_KEY", "", "keep-me")
	e.mustRun("lock", "--all")
	// Wrong old passphrase changes nothing.
	expectCode(t, e.runIn("not the passphrase\nnew passphrase two\n", "passwd", "main", "--passphrase-stdin"), ExitError)
	e.mustRunIn(testPass+"\nnew passphrase two\n", "passwd", "main", "--passphrase-stdin")
	expectCode(t, e.runIn(testPass+"\n", "unlock", "main", "--passphrase-stdin"), ExitError)
	e.mustRunIn("new passphrase two\n", "unlock", "main", "--passphrase-stdin")
	if got := e.mustRun("get", "EXAMPLE_API_KEY").out; got != "keep-me\n" {
		t.Fatalf("secrets must survive a passphrase change: %q", got)
	}
}

func TestInteractiveUnlockPromptsOnTerminal(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	e.unlock("main")
	e.set("EXAMPLE_API_KEY", "", "v")
	e.mustRun("lock", "--all")
	e.term.stdinTTY = true
	e.term.queue("wrong one", testPass)
	r := e.mustRun("get", "EXAMPLE_API_KEY")
	if r.out != "v\n" || !strings.Contains(r.err, "Wrong passphrase") {
		t.Fatalf("%s", r)
	}
	// Unlocked now: no more prompts.
	asked := e.term.asked
	e.mustRun("get", "EXAMPLE_API_KEY")
	if e.term.asked != asked {
		t.Fatal("an unlocked vault must not prompt")
	}
	// Three wrong attempts give up.
	e.mustRun("lock", "--all")
	e.term.queue("bad one one", "bad two two", "bad three three")
	expectCode(t, e.run("get", "EXAMPLE_API_KEY"), ExitError)
}

func TestTouchIDFlow(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.touch.avail = true

	// init offers Touch ID on a terminal; the default answer is yes.
	e.term.stdinTTY = true
	e.term.queue(testPass, testPass)
	e.mustRunIn("\n", "init", "main", "--path", filepath.Join(e.home, "vaults", "main"))
	e.term.stdinTTY = false
	list := decodeJSON[[]map[string]any](t, e.mustRun("touchid", "list", "--json").out)
	if len(list) != 1 || list[0]["this_mac"] != true {
		t.Fatalf("touchid list: %v", list)
	}
	if !strings.Contains(e.mustRun("touchid", "list").out, "(this Mac)") {
		t.Fatal("touchid list should mark this Mac")
	}

	// Unlocking uses Touch ID: no passphrase needed even without a terminal.
	e.mustRun("unlock", "main")
	e.set("EXAMPLE_API_KEY", "", "touch-value")
	e.mustRun("lock", "--all")
	if got := e.mustRun("get", "EXAMPLE_API_KEY").out; got != "touch-value\n" {
		t.Fatalf("%q", got)
	}
	if e.touch.unwraps == 0 {
		t.Fatal("Touch ID was not used")
	}

	// Cancelling the sheet falls back to the passphrase.
	e.mustRun("lock", "--all")
	e.touch.cancel = true
	expectCode(t, e.run("get", "EXAMPLE_API_KEY"), ExitLocked) // no terminal, so locked
	r := e.runIn(testPass+"\n", "get", "EXAMPLE_API_KEY", "--passphrase-stdin")
	if r.code != 0 || r.out != "touch-value\n" {
		t.Fatalf("fallback to passphrase: %s", r)
	}
	e.touch.cancel = false

	// off removes this Mac's unlocker; the passphrase still works.
	e.mustRun("touchid", "off", "main")
	if l := decodeJSON[[]map[string]any](t, e.mustRun("touchid", "list", "--json").out); len(l) != 0 {
		t.Fatalf("after off: %v", l)
	}
	expectCode(t, e.run("touchid", "off", "main"), ExitError)
	e.mustRun("lock", "--all")
	expectCode(t, e.run("get", "EXAMPLE_API_KEY"), ExitLocked)
	e.unlock("main")
	// on again (the device key is reused).
	e.mustRun("touchid", "on", "main")
	if l := decodeJSON[[]map[string]any](t, e.mustRun("touchid", "list", "main", "--json").out); len(l) != 1 {
		t.Fatalf("after on: %v", l)
	}
	// Without Touch ID available, `on` fails cleanly.
	e.touch.avail = false
	expectCode(t, e.run("touchid", "on", "main"), ExitError)
	expectCode(t, e.run("touchid"), ExitUsage)
	expectCode(t, e.run("touchid", "sideways"), ExitUsage)
}

func TestKeyPinningRefusesChangedKey(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.mustRun("lock", "--all")
	// Someone with folder access swaps in a different vault.json.
	other := filepath.Join(e.home, "evil")
	e2 := newEnv(t)
	e2.initVault("evil")
	_ = other
	evilJSON, err := os.ReadFile(filepath.Join(e2.home, "vaults", "evil", "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	e.activate()
	vf, _ := format.ReadVaultFile(dir)
	if err := os.WriteFile(filepath.Join(dir, "vault.json"), evilJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	r := e.runIn(testPass+"\n", "unlock", "main", "--passphrase-stdin")
	expectCode(t, r, ExitError)
	if !strings.Contains(r.err, "--accept-key-change") {
		t.Fatalf("expected the accept hint: %s", r)
	}
	_ = vf
}

func TestVaultsDetachAndAttachOwnVault(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("EXAMPLE_API_KEY", "", "v")
	r := e.mustRun("vaults")
	if !strings.Contains(r.out, "main *") || !strings.Contains(r.out, "unlocked") {
		t.Fatalf("%s", r.out)
	}
	vs := decodeJSON[[]map[string]any](t, e.mustRun("vaults", "--json").out)
	if len(vs) != 1 || vs[0]["keys"].(float64) != 1 {
		t.Fatalf("vaults json: %v", vs)
	}
	e.mustRun("detach", "main")
	if r := e.mustRun("vaults"); !strings.Contains(r.out, "No vaults") {
		t.Fatalf("%s", r.out)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.json")); err != nil {
		t.Fatal("detach must not touch the files")
	}
	expectCode(t, e.run("detach", "main"), ExitError)
	// attach registers it again under a new name (no identity needed with --no-request).
	e.mustRun("attach", "again", dir, "--no-request")
	expectCode(t, e.run("attach", "again", dir, "--no-request"), ExitError)
	expectCode(t, e.run("attach", "third", dir, "--no-request"), ExitError) // same vault, other name
	expectCode(t, e.run("attach", "nothing", filepath.Join(e.home, "empty"), "--no-request"), ExitError)
	e.unlock("again")
	if got := e.mustRun("get", "EXAMPLE_API_KEY").out; got != "v\n" {
		t.Fatalf("%q", got)
	}
}

func TestAliases(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	bin := filepath.Dir(e.exe)
	e.path = bin + string(os.PathListSeparator) + "/usr/bin"
	r := e.mustRun("alias", "add", "kv")
	if !strings.Contains(r.out, "kv") {
		t.Fatal(r.out)
	}
	if target, err := os.Readlink(filepath.Join(bin, "kv")); err != nil || target != "secrets-vault" {
		t.Fatalf("symlink target %q err %v", target, err)
	}
	l := decodeJSON[[]map[string]any](t, e.mustRun("alias", "list", "--json").out)
	if len(l) != 1 || l[0]["name"] != "kv" || l[0]["exists"] != true {
		t.Fatalf("%v", l)
	}
	e.mustRun("alias", "add", "kv") // idempotent
	e.mustRun("alias", "rm", "kv")
	if _, err := os.Lstat(filepath.Join(bin, "kv")); err == nil {
		t.Fatal("alias should be gone")
	}
	expectCode(t, e.run("alias", "rm", "kv"), ExitError)
	expectCode(t, e.run("alias", "rm", "secrets-vault"), ExitUsage)
	expectCode(t, e.run("alias", "add", "Bad Name"), ExitUsage)
	expectCode(t, e.run("alias", "add", "secrets-vault"), ExitUsage)

	// Another program called "vault" earlier on PATH: refused unless --force.
	other := filepath.Join(e.home, "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "vault"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.path = other + string(os.PathListSeparator) + bin
	r = e.run("alias", "add", "vault")
	expectCode(t, r, ExitError)
	if !strings.Contains(r.err, "already used by another program") || !strings.Contains(r.err, "--force") {
		t.Fatalf("%s", r)
	}
	if _, err := os.Lstat(filepath.Join(bin, "vault")); err == nil {
		t.Fatal("must not be created without --force")
	}
	e.mustRun("alias", "add", "vault", "--force")
	if _, err := os.Lstat(filepath.Join(bin, "vault")); err != nil {
		t.Fatal("--force should create it")
	}
	// If our folder comes first on PATH there is no conflict.
	e.mustRun("alias", "rm", "vault")
	e.path = bin + string(os.PathListSeparator) + other
	e.mustRun("alias", "add", "vault")
	// A real file of that name is never overwritten, even with --force.
	if err := os.WriteFile(filepath.Join(bin, "sv2"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectCode(t, e.run("alias", "add", "sv2"), ExitError)
	if b, _ := os.ReadFile(filepath.Join(bin, "sv2")); string(b) != "x" {
		t.Fatal("a regular file was overwritten")
	}
}

func TestAgentGoneMeansLockedNotCrash(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	e.unlock("main")
	e.set("EXAMPLE_API_KEY", "", "v")
	cl, err := agent.DialWith(agent.DialOptions{Dir: e.agentDir, NoAutoStart: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Stop(cl); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	expectCode(t, e.run("get", "EXAMPLE_API_KEY"), ExitLocked)
	if r := e.mustRun("status"); !strings.Contains(r.out, "locked") {
		t.Fatalf("%s", r)
	}
	e.mustRun("lock", "--all") // nothing to lock is not an error
}

func TestVersionAndHelpFlags(t *testing.T) {
	e := newEnv(t)
	if r := e.mustRun("--version"); !strings.HasPrefix(r.out, "secrets-vault ") {
		t.Fatal(r.out)
	}
	expectCode(t, e.run(), ExitUsage)
	_ = exec.ErrNotFound
}
