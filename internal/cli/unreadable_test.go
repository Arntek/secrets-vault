package cli

import (
	"os"
	"strings"
	"testing"
)

// tz0: one vault folder the program cannot read (macOS privacy blocking a
// cloud folder, simulated with chmod 000) must never turn a missing key into
// a plain error (exit 1) or into "not found" (exit 4) while the key could be
// in that vault.
func TestUnreadableVaultNeverLooksLikeNotFound(t *testing.T) {
	skipWindows(t)
	if os.Getuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	e := newEnv(t)
	e.initVault("hv")
	blocked := e.initVault("blocked")
	e.unlock("hv")
	e.set("HK", "hv", "readable-value")
	if err := os.Chmod(blocked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })

	// Found in a readable vault: works, with a warning about the other one.
	r := e.mustRun("get", "HK")
	if r.out != "readable-value\n" || !strings.Contains(r.err, "blocked") {
		t.Fatalf("get HK: %s", r)
	}
	// Not found in any readable vault: exit 5 naming the vault and the reason.
	for _, args := range [][]string{{"get", "MISSING_KEY"}, {"info", "MISSING_KEY"}, {"run", "-k", "MISSING_KEY", "--", "true"}, {"copy", "MISSING_KEY"}} {
		r := e.run(args...)
		expectCode(t, r, ExitUnverified)
		for _, want := range []string{"key not found in the readable vaults", "blocked", "may be there", "operation not permitted"} {
			if !strings.Contains(r.err, want) {
				t.Fatalf("%v: stderr lacks %q:\n%s", args, want, r)
			}
		}
		if strings.Contains(r.err, e.home) {
			t.Fatalf("%v: a path leaked:\n%s", args, r)
		}
	}
	// list: results on stdout, the warning on stderr (printed after them).
	r = e.mustRun("list")
	if !strings.Contains(r.out, "HK") || !strings.Contains(r.err, "blocked") {
		t.Fatalf("list: %s", r)
	}
	// Every vault readable again: a missing key is exit 4.
	if err := os.Chmod(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	expectCode(t, e.run("get", "MISSING_KEY"), ExitNotFound)
}
