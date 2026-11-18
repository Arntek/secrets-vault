package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arntek/secrets-vault/internal/leaktest"
)

func TestPrimeWorksWithNoVaultsAndWithEveryVaultLocked(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	r := e.mustRun("prime")
	for _, want := range []string{"Rules:", "`sv run -k NAME", "5: the vault failed verification", "Stop and tell the human", "none registered", "does not enforce"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("prime output missing %q:\n%s", want, r.out)
		}
	}
	e.initVault("work")
	e.mustRun("lock", "--all")
	r = e.mustRun("prime")
	if !strings.Contains(r.out, "work: locked") {
		t.Errorf("locked vault not shown:\n%s", r.out)
	}
	e.unlock("work")
	r = e.mustRun("prime")
	if !strings.Contains(r.out, "work: unlocked, ") || !strings.Contains(r.out, " left") {
		t.Errorf("unlocked vault with time left not shown:\n%s", r.out)
	}
}

func TestPrimeJSONShape(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("work")
	e.unlock("work")
	var got struct {
		Command   string            `json:"command"`
		Rules     []string          `json:"rules"`
		ExitCodes map[string]string `json:"exit_codes"`
		Vaults    []struct {
			Name        string `json:"name"`
			State       string `json:"state"`
			SecondsLeft int    `json:"seconds_left"`
		} `json:"vaults"`
	}
	if err := json.Unmarshal([]byte(e.mustRun("prime", "--json").out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Command != "sv" || len(got.Rules) != 6 || got.ExitCodes["5"] == "" || len(got.Vaults) != 1 ||
		got.Vaults[0].Name != "work" || got.Vaults[0].State != "unlocked" || got.Vaults[0].SecondsLeft <= 0 {
		t.Fatalf("unexpected: %+v", got)
	}
	expectCode(t, e.run("prime", "extra"), ExitUsage)
}

// A canary value in an unlocked vault must not appear in anything prime (or
// setup) writes anywhere.
func TestPrimeAndSetupLeakNothing(t *testing.T) {
	skipWindows(t)
	h := leaktest.New(t)
	e := newEnvAt(t, filepath.Join(h.HomeDir, "owner"))
	canary, pass := h.Canary(), h.Canary()
	ok := func(stdin string, args ...string) {
		t.Helper()
		if code := e.runTo(h.Stdout, h.Stderr, stdin, args...); code != 0 {
			t.Fatalf("%v exited %d", args, code)
		}
	}
	ok(pass+"\n"+pass+"\n", "init", "work", "--path", filepath.Join(e.home, "vaults", "work"), "--passphrase-stdin", "--as", "owner", "--desc", "work keys")
	ok(pass+"\n", "unlock", "work", "--passphrase-stdin")
	ok(canary, "set", "EXAMPLE_KEY", "--vault", "work", "--desc", "example")
	ok("", "prime")
	ok("", "prime", "--json")
	ok("", "setup", "claude", "--claude-md")
	ok("", "setup", "agents", "--path", e.home)
	ok("", "setup", "claude", "--claude-md", "--remove")
	h.Check()
}

func TestSetupClaudeAddsSkillAndRespectsClaudeConfigDir(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	cfg := filepath.Join(t.TempDir(), "cfgdir")
	t.Setenv("CLAUDE_CONFIG_DIR", cfg)
	r := e.mustRun("setup", "claude")
	skill := filepath.Join(cfg, "skills", "vault", "SKILL.md")
	b, err := os.ReadFile(skill)
	if err != nil {
		t.Fatalf("%v\n%s", err, r)
	}
	s := string(b)
	if !strings.HasPrefix(s, "---\nname: vault\ndescription: ") || !strings.Contains(s, "Run `sv prime`") {
		t.Fatalf("skill content:\n%s", s)
	}
	if !strings.Contains(r.out, "not enforced") {
		t.Errorf("honest caveat missing: %s", r.out)
	}
	if _, err := os.Stat(filepath.Join(e.home, ".claude")); err == nil {
		t.Fatal("wrote to HOME/.claude although CLAUDE_CONFIG_DIR is set")
	}
	if _, err := os.Stat(filepath.Join(cfg, "CLAUDE.md")); err == nil {
		t.Fatal("CLAUDE.md written without --claude-md")
	}
	e.mustRun("setup", "claude") // idempotent
	if b2, _ := os.ReadFile(skill); string(b2) != s {
		t.Fatal("second run changed the skill")
	}
	r = e.mustRun("setup", "claude", "--remove")
	if !strings.Contains(r.out, "removed") {
		t.Errorf("%s", r.out)
	}
	if _, err := os.Stat(filepath.Join(cfg, "skills", "vault")); err == nil {
		t.Fatal("skill folder left behind")
	}
}

func TestSetupClaudeMDRemoveLeavesFileByteIdentical(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	md := filepath.Join(e.home, ".claude", "CLAUDE.md")
	orig := "# My rules\n\n- be brief\n"
	if err := os.MkdirAll(filepath.Dir(md), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(md, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	e.mustRun("setup", "claude", "--claude-md")
	b, _ := os.ReadFile(md)
	if !strings.HasPrefix(string(b), orig) || !strings.Contains(string(b), "<!-- secrets-vault:start -->") || !strings.Contains(string(b), "run `sv prime`") {
		t.Fatalf("block not appended:\n%s", b)
	}
	e.mustRun("setup", "claude", "--claude-md", "--remove")
	if b, _ := os.ReadFile(md); string(b) != orig {
		t.Fatalf("not byte-identical after remove: %q", b)
	}
	if fi, _ := os.Stat(md); fi.Mode().Perm() != 0o600 {
		t.Fatalf("permissions changed: %v", fi.Mode())
	}
}

func TestSetupDryRunShowsDiffAndWritesNothing(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	r := e.mustRun("setup", "claude", "--claude-md", "--dry-run")
	if !strings.Contains(r.out, "would be created") || !strings.Contains(r.out, "+<!-- secrets-vault:start -->") || !strings.Contains(r.out, "+name: vault") {
		t.Fatalf("no diff:\n%s", r.out)
	}
	if _, err := os.Stat(filepath.Join(e.home, ".claude")); err == nil {
		t.Fatal("dry run wrote something")
	}
}

func TestSetupRefusesSymlinkAndEditedBlock(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	proj := t.TempDir()
	real := filepath.Join(proj, "real.md")
	if err := os.WriteFile(real, []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(proj, "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
	r := e.run("setup", "agents", "--path", proj)
	expectCode(t, r, ExitError)
	if !strings.Contains(r.err, "symlink") {
		t.Errorf("reason not given: %s", r.err)
	}
	if b, _ := os.ReadFile(real); string(b) != "mine\n" {
		t.Fatal("wrote through the symlink")
	}

	proj2 := t.TempDir()
	e.mustRun("setup", "agents", "--path", proj2)
	f := filepath.Join(proj2, "AGENTS.md")
	b, _ := os.ReadFile(f)
	if err := os.WriteFile(f, []byte(strings.Replace(string(b), "API keys", "API keys (edited)", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	r = e.run("setup", "agents", "--path", proj2)
	expectCode(t, r, ExitError)
	if !strings.Contains(r.err, "edited by hand") || !strings.Contains(r.err, "--force") {
		t.Errorf("no warning: %s", r.err)
	}
	e.mustRun("setup", "agents", "--path", proj2, "--force")
	e.mustRun("setup", "agents", "--path", proj2, "--remove")
	if _, err := os.Stat(f); err == nil {
		t.Fatal("AGENTS.md created by us should be gone")
	}
}

func TestSetupUsageErrors(t *testing.T) {
	e := newEnv(t)
	for _, args := range [][]string{{"setup"}, {"setup", "nope"}, {"setup", "claude", "extra"}, {"setup", "claude", "--path", "x"}, {"setup", "agents", "--claude-md"}} {
		expectCode(t, e.run(args...), ExitUsage)
	}
	r := e.run("setup", "agents", "--path", filepath.Join(t.TempDir(), "missing"))
	expectCode(t, r, ExitError)
}
