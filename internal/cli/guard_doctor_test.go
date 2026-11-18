package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arntek/secrets-vault/internal/crypto"
)

// The write guard fails closed on items it cannot account for (a secret
// sealed under an unknown key, a rotation folder for an unknown key). doctor
// explains them; --set-aside-unknown clears them after a typed confirmation,
// by renaming into quarantine/ (never deleting), and the vault works again.
func TestDoctorExplainsAndSetsAsideUnknownItems(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("team")
	e.unlock("team")
	e.set("REAL_KEY", "team", "real-value")

	// A secret sealed under a key this vault never had, and a rotation folder
	// for an unknown key id.
	other, err := crypto.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.WriteSecretVersion(dir, "PLANTED_KEY", other, []byte("attacker-sealed"), 1); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, "secrets", ".sv-rotate-"+strings.Repeat("ab", 16))
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}

	// The guard blocks writes and points at doctor; reads still work.
	r := e.runIn("x", "set", "NEW_KEY", "--vault", "team")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "signs of a newer state") || !strings.Contains(r.err, "doctor team") {
		t.Fatalf("set: %s", r)
	}
	if got := e.mustRun("get", "REAL_KEY").out; got != "real-value\n" {
		t.Fatalf("reads must still work: %q", got)
	}

	// doctor explains: which items, why, and the two possible causes.
	d := e.mustRun("doctor", "team").out
	for _, want := range []string{"refuses changes", "PLANTED_KEY", "a key-rotation folder for a key this vault's history never had",
		"another member's newer change", "planted", "--set-aside-unknown"} {
		if !strings.Contains(d, want) {
			t.Fatalf("doctor lacks %q:\n%s", want, d)
		}
	}
	if strings.Contains(d, "looks healthy") {
		t.Fatalf("doctor says healthy:\n%s", d)
	}
	js := decodeJSON[map[string]any](t, e.mustRun("doctor", "team", "--json").out)
	if wg := js["write_guard"].(map[string]any); wg["blocking"] != true || len(wg["unknown_files"].([]any)) != 1 {
		t.Fatalf("doctor --json: %v", js)
	}

	// No confirmation, no terminal: refused, nothing moved.
	expectCode(t, e.run("doctor", "team", "--set-aside-unknown"), ExitUsage)
	// A typed confirmation that is wrong: refused, nothing moved.
	e.term.stdinTTY = true
	r = e.runIn("yes\n", "doctor", "team", "--set-aside-unknown")
	e.term.stdinTTY = false
	expectCode(t, r, ExitError)
	if _, err := os.Stat(filepath.Join(dir, "secrets", "PLANTED_KEY.age")); err != nil {
		t.Fatal("the file moved without a confirmation")
	}
	expectCode(t, e.runIn("x", "set", "NEW_KEY", "--vault", "team"), ExitUnverified)

	// The typed phrase works.
	e.term.stdinTTY = true
	r = e.runIn(checkedPhrase+"\n", "doctor", "team", "--set-aside-unknown")
	e.term.stdinTTY = false
	expectCode(t, r, 0)
	if _, err := os.Stat(filepath.Join(dir, "secrets", "PLANTED_KEY.age")); err == nil {
		t.Fatal("the planted file is still in secrets/")
	}
	if _, err := os.Stat(staging); err == nil {
		t.Fatal("the planted staging folder is still there")
	}
	// Moved, not deleted.
	moved, _ := filepath.Glob(filepath.Join(dir, "quarantine", "*", "*"))
	moved2, _ := filepath.Glob(filepath.Join(dir, "quarantine", "*"))
	if len(moved)+len(moved2) < 2 {
		t.Fatalf("quarantine holds %v %v", moved, moved2)
	}
	// Writes work again, and the action is in the log.
	e.mustRunIn("fresh", "set", "NEW_KEY", "--vault", "team")
	if !strings.Contains(e.mustRun("log").out, "set-aside") {
		t.Fatalf("log lacks the set-aside:\n%s", e.mustRun("log").out)
	}
	if !strings.Contains(e.mustRun("doctor", "team").out, "looks healthy") {
		t.Fatalf("doctor not healthy after the set-aside:\n%s", e.mustRun("doctor", "team").out)
	}

	// The script flag.
	if err := crypto.WriteSecretVersion(dir, "PLANTED_TWO", other, []byte("x"), 1); err != nil {
		t.Fatal(err)
	}
	e.mustRun("doctor", "team", "--set-aside-unknown", "--yes-checked-with-members")
	e.mustRunIn("again", "set", "ANOTHER_KEY", "--vault", "team")
}
