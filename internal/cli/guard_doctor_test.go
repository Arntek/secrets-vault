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
		"another member's newer change", "planted", "--set-aside-unknown", "state code"} {
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

	code := decodeJSON[map[string]any](t, e.mustRun("trust", "team", "--json").out)["state_code"].(string)
	// No terminal (an agent, a script): refused, with no hint of how to get
	// past it, whatever flags are given.
	for _, args := range [][]string{{"doctor", "team", "--set-aside-unknown"}, {"doctor", "team", "--set-aside-unknown", "--expect", code}} {
		r = e.run(args...)
		expectCode(t, r, ExitUsage)
		if !strings.Contains(r.err, "needs a person at a terminal") || strings.Contains(r.err, "--expect") || strings.Contains(r.err, "status") {
			t.Fatalf("%v: %s", args, r)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets", "PLANTED_KEY.age")); err != nil {
		t.Fatal("the file moved without a person at a terminal")
	}
	atTerminal := func(typed string) result {
		e.term.stdinTTY = true
		defer func() { e.term.stdinTTY = false }()
		return e.runIn(typed+"\n", "doctor", "team", "--set-aside-unknown")
	}
	// A code the folder does not reach (a rolled-back or out-of-date folder
	// is behind the current code), or one that is not a code: refused,
	// nothing moved.
	expectCode(t, atTerminal("team@99 ABLE-ABLE-ABLE-ABLE-ABLE-ABLE"), ExitUnverified)
	expectCode(t, atTerminal("nonsense"), ExitUsage)
	if _, err := os.Stat(filepath.Join(dir, "secrets", "PLANTED_KEY.age")); err != nil {
		t.Fatal("the file moved for a code the folder does not reach")
	}
	expectCode(t, e.runIn("x", "set", "NEW_KEY", "--vault", "team"), ExitUnverified)

	// The person types the current code another member read out: junk on an
	// up-to-date folder is set aside.
	r = atTerminal(code)
	expectCode(t, r, 0)
	if !strings.Contains(r.err, "exactly what a removal you have not seen yet looks like") {
		t.Fatalf("the warning is missing: %s", r)
	}
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

	// A second round, same gate.
	if err := crypto.WriteSecretVersion(dir, "PLANTED_TWO", other, []byte("x"), 1); err != nil {
		t.Fatal(err)
	}
	code = decodeJSON[map[string]any](t, e.mustRun("trust", "team", "--json").out)["state_code"].(string)
	expectCode(t, atTerminal(code), 0)
	e.mustRunIn("again", "set", "ANOTHER_KEY", "--vault", "team")
}

// ue1.18: setting items aside needs the current state code from another
// member. A removed member who restores the old folder but leaves a newer
// file behind (which blocks the stale writer's change) cannot get that block
// cleared on a Mac that never saw the removal: the folder is behind the code.
func TestSetAsideRefusesARolledBackFolder(t *testing.T) {
	skipWindows(t)
	alice, bob, carol := newEnv(t), newEnv(t), newEnv(t)
	vdir := alice.initVault("team")
	alice.unlock("team")
	alice.set("API_KEY", "", "old-value")
	join(t, alice, bob, "team", vdir, "bob")
	join(t, alice, carol, "team", vdir, "carol")
	snap := filepath.Join(t.TempDir(), "snap")
	copyTree(t, vdir, snap)

	r := alice.mustRunIn(testPass+"\n", "member", "rm", "team", "carol", "--yes", "--folder-access-removed", "--passphrase-stdin")
	code := strings.TrimSpace(r.out[strings.LastIndex(r.out, ": ")+2:])
	alice.set("NEW_K2", "", "x")
	// carol restores her old vault.json but leaves the newer file.
	copyFile(t, filepath.Join(snap, "vault.json"), filepath.Join(vdir, "vault.json"))
	copyFile(t, filepath.Join(snap, "secrets", "API_KEY.age"), filepath.Join(vdir, "secrets", "API_KEY.age"))

	// bob (who never saw the removal) is refused when he saves something...
	bob.mustRun("lock", "--all")
	bob.mustRunIn(personalPass+"\n", "get", "API_KEY", "--passphrase-stdin") // unlocks, reads the old folder
	r = bob.runIn("bob-new", "set", "BOB_NEW", "--vault", "team")
	expectCode(t, r, ExitUnverified)
	// ...and cannot clear the block with the state code alice gave: his
	// folder is behind it, so nothing is set aside.
	bob.term.stdinTTY = true
	r = bob.runIn(code+"\n", "doctor", "team", "--set-aside-unknown")
	bob.term.stdinTTY = false
	expectCode(t, r, ExitUnverified)
	if _, err := os.Stat(filepath.Join(vdir, "secrets", "NEW_K2.age")); err != nil {
		t.Fatal("the newer file was moved from a rolled-back folder")
	}
	if _, err := os.Stat(filepath.Join(vdir, "quarantine")); err == nil {
		t.Fatal("something was set aside")
	}
}
