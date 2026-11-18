package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arntek/secrets-vault/internal/format"
)

// Tests for docs/design/index-auth.md, through the CLI: one per threat.

func snapshotDir(e *testEnv) string { return filepath.Join(filepath.Dir(e.cfg), "index") }

func forgetSnapshots(t *testing.T, e *testEnv) {
	t.Helper()
	if err := os.RemoveAll(snapshotDir(e)); err != nil {
		t.Fatal(err)
	}
}

func editIndex(t *testing.T, dir string, fn func(string) string) {
	t.Helper()
	p := filepath.Join(dir, "index.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(fn(string(b))), 0o600); err != nil {
		t.Fatal(err)
	}
}

func listRows(t *testing.T, e *testEnv, args ...string) []keyRow {
	t.Helper()
	return decodeJSON[[]keyRow](t, e.mustRun(append([]string{"list", "--json"}, args...)...).out)
}

// A1: a relabelled entry never shows as truth, locked or unlocked.
func TestIndexAuthRelabel(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "the-value")
	e.mustRun("lock", "--all")
	rows := listRows(t, e)
	if len(rows) != 1 || !rows[0].Verified || rows[0].IndexState != "verified" || rows[0].PendingChange {
		t.Fatalf("clean locked list: %+v", rows)
	}
	editIndex(t, dir, func(s string) string { return strings.Replace(s, "test key api_key", "attacker label", 1) })
	rows = listRows(t, e)
	if len(rows) != 1 || rows[0].Description != "test key api_key" || !rows[0].PendingChange || rows[0].IndexState != "pending-changes" {
		t.Fatalf("relabelled locked list: %+v", rows)
	}
	if out := e.mustRun("list").out; strings.Contains(out, "attacker label") {
		t.Fatalf("the attacker's label was shown: %s", out)
	}
	info := decodeJSON[map[string]any](t, e.mustRun("info", "API_KEY", "--json").out)
	if info["description"] != "test key api_key" || info["verified"] != true {
		t.Fatalf("info: %v", info)
	}
	// Unlocked: the entry fails its MAC, the key is rebuilt from what this
	// machine verified, and the value still reads.
	if got := e.mustRunIn(testPass+"\n", "get", "API_KEY", "--passphrase-stdin").out; got != "the-value\n" {
		t.Fatalf("get after a relabel: %q", got)
	}
	e.mustRun("describe", "API_KEY", "fresh label")
	rows = listRows(t, e)
	if rows[0].Description != "fresh label" || rows[0].IndexState != "verified" {
		t.Fatalf("after a legitimate describe: %+v", rows)
	}
}

// A2: a planted entry or file never makes another vault answer, and never
// reaches a value.
func TestIndexAuthPlantedNames(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("one")
	dirTwo := filepath.Join(e.home, "vaults", "two")
	e.mustRunIn(testPass+"\n"+testPass+"\n", "init", "two", "--path", dirTwo, "--passphrase-stdin")
	e.unlock("one")
	e.unlock("two")
	e.set("SHARED_NAME", "one", "real-value")
	e.set("OTHER_KEY", "two", "other")
	// Plant SHARED_NAME in vault two: an entry (bad MAC) and a junk file.
	editIndex(t, dirTwo, func(s string) string {
		return strings.Replace(s, `"entries": [`, `"entries": [
    {"name": "SHARED_NAME", "description": "plant", "updated": "2026-11-20T10:00:00Z", "version": 1, "rev": 1, "mac": "`+strings.Repeat("0", 64)+`"},`, 1)
	})
	_ = os.WriteFile(filepath.Join(dirTwo, "secrets", "SHARED_NAME.age"), []byte("junk"), 0o600)
	// Verified beats unverified: no ambiguity, the real vault answers.
	if got := e.mustRun("get", "SHARED_NAME").out; got != "real-value\n" {
		t.Fatalf("planted name changed the answer: %q", got)
	}
	// A name planted where no real one exists never yields a value.
	editIndex(t, dirTwo, func(s string) string {
		return strings.Replace(s, `"entries": [`, `"entries": [
    {"name": "ONLY_PLANTED", "description": "plant", "updated": "2026-11-20T10:00:00Z", "version": 1, "rev": 1, "mac": "`+strings.Repeat("0", 64)+`"},`, 1)
	})
	_ = os.WriteFile(filepath.Join(dirTwo, "secrets", "ONLY_PLANTED.age"), []byte("junk"), 0o600)
	r := e.run("get", "ONLY_PLANTED")
	if r.code == 0 {
		t.Fatalf("a planted name gave a value: %s", r)
	}
	// Planted in both vaults, both unverified: declared ambiguous, clearly.
	e.mustRun("lock", "--all")
	forgetSnapshots(t, e)
	r = e.run("get", "SHARED_NAME")
	expectCode(t, r, ExitUsage)
	if !strings.Contains(r.err, "unverified") {
		t.Fatalf("ambiguity message: %s", r)
	}
}

// A3/A5/IM1 through the CLI, on a machine that never verified anything
// newer (no snapshot): a single file rolled back is refused, with or
// without an index.
func TestIndexAuthSingleFileRollback(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "old-value")
	oldFile, _ := os.ReadFile(filepath.Join(dir, "secrets", "API_KEY.age"))
	e.set("API_KEY", "", "new-value")
	good, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	put := func() { _ = os.WriteFile(filepath.Join(dir, "secrets", "API_KEY.age"), oldFile, 0o600) }

	put()
	forgetSnapshots(t, e)
	r := e.run("get", "API_KEY")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "older than the index says") {
		t.Fatalf("%s", r)
	}
	notContains(t, "output", r.out+r.err, "old-value")
	// IM1: deleting the index, or downgrading it to version 1, is no way around it.
	for name, damage := range map[string]func(){
		"deleted": func() { _ = os.Remove(filepath.Join(dir, "index.json")) },
		"v1": func() {
			_ = os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{"version":1,"entries":[{"name":"API_KEY","updated":"2026-11-20T10:00:00Z"}]}`), 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			forgetSnapshots(t, e) // a machine that never verified anything
			damage()
			defer func() { _ = os.WriteFile(filepath.Join(dir, "index.json"), good, 0o600) }()
			r := e.run("get", "API_KEY")
			expectCode(t, r, ExitUnverified)
			if !strings.Contains(r.err, "missing or damaged") {
				t.Fatalf("%s", r)
			}
			notContains(t, "output", r.out+r.err, "old-value")
		})
	}
	// Writing the key again is the repair.
	e.mustRunIn("repaired", "set", "API_KEY")
	if got := e.mustRun("get", "API_KEY").out; got != "repaired\n" {
		t.Fatalf("%q", got)
	}
}

// A4/A6: an old index (and, for A6, its file) is refused on a machine that
// saw the newer state.
func TestIndexAuthConsistentRollbackNeedsSnapshot(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "old-value")
	oldFile, _ := os.ReadFile(filepath.Join(dir, "secrets", "API_KEY.age"))
	oldIdx, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	e.set("API_KEY", "", "new-value")
	_ = os.WriteFile(filepath.Join(dir, "secrets", "API_KEY.age"), oldFile, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "index.json"), oldIdx, 0o600)
	r := e.run("get", "API_KEY")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "older than what this machine has verified") {
		t.Fatalf("%s", r)
	}
	notContains(t, "output", r.out+r.err, "old-value")
	// A machine that never saw the newer state accepts it: the documented
	// residual risk, the same limit as the stale-writer gap.
	forgetSnapshots(t, e)
	if got := e.mustRun("get", "API_KEY").out; got != "old-value\n" {
		t.Fatalf("residual risk case changed behaviour: %q", got)
	}
}

// IS1: a deleted key's file coming back is refused.
func TestIndexAuthResurrectedFile(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "v")
	file, _ := os.ReadFile(filepath.Join(dir, "secrets", "API_KEY.age"))
	e.mustRun("rm", "API_KEY", "--yes")
	expectCode(t, e.run("get", "API_KEY"), ExitNotFound)
	_ = os.WriteFile(filepath.Join(dir, "secrets", "API_KEY.age"), file, 0o600)
	// A deleted name is not a key: the file coming back is never read...
	r := e.run("get", "API_KEY")
	expectCode(t, r, ExitUnverified)
	notContains(t, "output", r.out+r.err, "\nv\n")
	// ...and doctor says what it is.
	if out := e.mustRun("doctor", "main").out; !strings.Contains(out, "deleted, but its file is back") {
		t.Fatalf("doctor: %s", out)
	}
	// A new value under the same name is fine and starts above the old version.
	e.mustRunIn("again", "set", "API_KEY")
	if got := e.mustRun("get", "API_KEY").out; got != "again\n" {
		t.Fatalf("%q", got)
	}
}

// IS2: a listed key whose file is gone is exit 5, not "not found".
func TestIndexAuthMissingFile(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "v")
	_ = os.Remove(filepath.Join(dir, "secrets", "API_KEY.age"))
	r := e.run("get", "API_KEY")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "file is missing") {
		t.Fatalf("%s", r)
	}
}

// Unlisted files are reported by doctor and adopted only on request.
func TestIndexAuthDoctorAdopt(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "v")
	e.set("LOST_ENTRY", "", "lost")
	forgetSnapshots(t, e)
	editIndex(t, dir, func(s string) string {
		var doc struct {
			Version int              `json:"version"`
			VaultID string           `json:"vault_id"`
			Entries []map[string]any `json:"entries"`
		}
		if err := json.Unmarshal([]byte(s), &doc); err != nil {
			t.Fatal(err)
		}
		kept := doc.Entries[:0]
		for _, en := range doc.Entries {
			if en["name"] != "LOST_ENTRY" { // keep the others, MACs untouched
				kept = append(kept, en)
			}
		}
		doc.Entries = kept
		b, _ := json.Marshal(doc)
		return string(b)
	})
	expectCode(t, e.run("get", "LOST_ENTRY"), ExitUnverified) // a file with no signed entry: never "not found" (ue1.13)
	r := e.mustRun("doctor", "main")
	if !strings.Contains(r.out, "File LOST_ENTRY has no signed entry") || !strings.Contains(r.out, "--adopt LOST_ENTRY") {
		t.Fatalf("doctor: %s", r)
	}
	expectCode(t, e.run("doctor", "main", "--adopt", "LOST_ENTRY"), ExitError) // needs --yes without a terminal
	e.mustRun("doctor", "main", "--adopt", "LOST_ENTRY", "--yes")
	if got := e.mustRun("get", "LOST_ENTRY").out; got != "lost\n" {
		t.Fatalf("after adopt: %q", got)
	}
	expectCode(t, e.run("doctor", "main", "--adopt", "API_KEY", "--yes"), ExitError) // not unlisted
	// A file that doesn't open under the vault key is never adopted.
	_ = os.WriteFile(filepath.Join(dir, "secrets", "JUNK_FILE.age"), []byte("junk"), 0o600)
	expectCode(t, e.run("doctor", "main", "--adopt", "JUNK_FILE", "--yes"), ExitError)
}

// An index conflict copy is merged by the next write and called safe to
// delete by doctor.
func TestIndexAuthConflictCopy(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("AAA", "", "a")
	other, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	e.set("BBB", "", "b")
	// Another machine (same vault, offline) wrote CCC into its own index.
	conflict := filepath.Join(dir, "index (Dan's conflicted copy 2026-11-20).json")
	_ = os.WriteFile(conflict, other, 0o600)
	r := e.mustRun("doctor", "main")
	if !strings.Contains(r.out, "safe to delete") {
		t.Fatalf("a copy already contained in the index: %s", r)
	}
	_ = r
}

// ue1.12 item 1: index-only commands honour an unmet expectation.
func TestIndexOnlyCommandsHonourExpectation(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "v")
	vf, _ := format.ReadVaultFile(dir)
	pinPath := filepath.Join(filepath.Dir(e.cfg), "trust", vf.ID+".json")
	oldPin, _ := os.ReadFile(pinPath)
	oldVault, _ := os.ReadFile(filepath.Join(dir, "vault.json"))
	e.mustRunIn(testPass+"\nsecond passphrase\n", "passwd", "main", "--passphrase-stdin")
	st := decodeJSON[[]struct {
		Head struct {
			StateCode string `json:"state_code"`
		} `json:"head"`
	}](t, e.mustRun("status", "--json").out)
	code := st[0].Head.StateCode
	// This machine is back at the old state (as if it had been offline) and
	// is given the code of the new one that the folder doesn't have.
	_ = os.WriteFile(pinPath, oldPin, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "vault.json"), oldVault, 0o600)
	r := e.run("trust", "main", "--expect", code)
	expectCode(t, r, ExitUnverified)
	// Index-only commands used to answer from this folder with exit 0.
	for _, args := range [][]string{{"info", "API_KEY"}, {"info", "API_KEY", "--json"}} {
		r := e.run(args...)
		expectCode(t, r, ExitUnverified)
		notContains(t, "output", r.out, "test key api_key")
	}
	r = e.mustRun("list", "--json")
	entries := decodeJSON[[]map[string]any](t, r.out)
	if len(entries) != 1 || entries[0]["vault"] != "main" || entries[0]["error"] == nil || entries[0]["name"] != nil {
		t.Fatalf("list --json = %s", r.out)
	}
	if out := e.run("search", "api"); strings.Contains(out.out, "API_KEY") {
		t.Fatalf("search answered from a quarantined folder: %s", out)
	}
}

// ue1.12 item 2: a structurally malformed vault.json exits 5, like a
// signed-history mismatch.
func TestMalformedVaultJSONExits5(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "v")
	good, _ := os.ReadFile(filepath.Join(dir, "vault.json"))
	for name, bad := range map[string][]byte{
		"truncated": good[:len(good)/2],
		"junk":      []byte("{{{"),
		"unknown":   bytes.Replace(good, []byte(`"unlockers"`), []byte(`"unlockerz"`), 1),
	} {
		_ = os.WriteFile(filepath.Join(dir, "vault.json"), bad, 0o600)
		for _, args := range [][]string{{"get", "API_KEY"}, {"info", "API_KEY"}, {"unlock", "main"}} {
			r := e.run(args...)
			if r.code != ExitUnverified {
				t.Errorf("%s: %v exit %d, want %d:\n%s", name, args, r.code, ExitUnverified, r)
			}
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "vault.json"), good, 0o600)
	e.mustRun("get", "API_KEY")
}

// ue1.12 item 3: doctor says that an unusable staging folder can't be
// finished (members_test's planted-staging test checks the quarantine).
func TestDoctorSaysUnusableStagingCannotBeFinished(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "real")
	e.mustRunIn(testPass+"\nrotated passphrase\n", "passwd", "main", "--passphrase-stdin")
	vf, _ := format.ReadVaultFile(dir)
	stage := filepath.Join(dir, "secrets", ".sv-rotate-"+vf.KeyID)
	_ = os.MkdirAll(stage, 0o700)
	_ = os.WriteFile(filepath.Join(stage, "API_KEY.age"), []byte("junk"), 0o600)
	_ = os.WriteFile(filepath.Join(stage, "MANIFEST"), []byte("secrets-vault rotation v1\nkey "+vf.KeyID+"\nAPI_KEY.age\n"), 0o600)
	out := e.mustRun("doctor", "main").out
	if !strings.Contains(out, "cannot be finished") || !strings.Contains(out, "--quarantine-staging") || strings.Contains(out, "the next change finishes it") {
		t.Fatalf("doctor: %s", out)
	}
	// Locked, it can't tell and says so without promising.
	e.mustRun("lock", "--all")
	out = e.mustRun("doctor", "main").out
	if !strings.Contains(out, "If its files are intact") || !strings.Contains(out, "--quarantine-staging") {
		t.Fatalf("locked doctor: %s", out)
	}
}

// --- format 2: a vault made by the build before this change ---

// oldMain builds the secrets-vault of commit 773be93 (the build that made
// format-2 vaults) once per test binary, or skips.
var oldMainBin, oldMainDir string

func buildOldMain(t *testing.T) string {
	t.Helper()
	if oldMainBin != "" {
		return oldMainBin
	}
	for _, tool := range []string{"git", "go", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("git", "-C", root, "cat-file", "-e", "773be93^{commit}").Run(); err != nil {
		t.Skip("commit 773be93 (the format-2 build) is not in this checkout")
	}
	src, err := os.MkdirTemp("", "svold-src")
	if err != nil {
		t.Fatal(err)
	}
	oldMainDir = src // removed by TestMain
	arch := exec.Command("git", "-C", root, "archive", "773be93")
	untar := exec.Command("tar", "-x", "-C", src)
	pipe, _ := arch.StdoutPipe()
	untar.Stdin = pipe
	if err := untar.Start(); err != nil {
		t.Fatal(err)
	}
	if err := arch.Run(); err != nil {
		t.Skipf("cannot export 773be93: %v", err)
	}
	if err := untar.Wait(); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(src, "old-secrets-vault")
	build := exec.Command("go", "build", "-o", bin, "./cmd/secrets-vault")
	build.Dir = src
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-mod=mod")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build 773be93: %v\n%s", err, out)
	}
	oldMainBin = bin
	return bin
}

// runOld runs the old build in e's environment.
func (e *testEnv) runOld(bin, stdin string, args ...string) result {
	e.t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "HOME="+e.home, "XDG_CONFIG_HOME="+filepath.Join(e.home, "xdg"), EnvConfig+"="+e.cfg, "SECRETS_VAULT_AGENT_DIR="+e.agentDir)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			e.t.Fatal(err)
		}
	}
	return result{code, out.String(), errb.String()}
}

func fileHashes(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	out := map[string][32]byte{}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(dir, p)
			out[rel] = sha256.Sum256(b)
		}
		return nil
	})
	return out
}

// The upgrade path v0.1.0 users take: a vault made by the previous build
// (format 2) reads as before, refuses writes with one clear line, and
// `upgrade` makes it format 3 in one step with only the identity unlock.
func TestUpgradeVaultMadeByMain(t *testing.T) {
	skipWindows(t)
	old := buildOldMain(t)
	e := newEnv(t)
	dir := filepath.Join(e.home, "vaults", "main")
	if r := e.runOld(old, testPass+"\n"+testPass+"\n", "init", "main", "--path", dir, "--passphrase-stdin", "--as", testUser); r.code != 0 {
		t.Fatalf("old init: %s", r)
	}
	if r := e.runOld(old, testPass+"\n", "unlock", "main", "--passphrase-stdin"); r.code != 0 {
		t.Fatalf("old unlock: %s", r)
	}
	if r := e.runOld(old, "legacy-value", "set", "LEGACY_KEY", "--desc", "made by main"); r.code != 0 {
		t.Fatalf("old set: %s", r)
	}
	_ = e.runOld(old, "", "lock", "--all")
	if vf, err := format.ReadVaultFile(dir); err != nil || vf.Version != 2 {
		t.Fatalf("the old build did not make a format-2 vault: %v %+v", err, vf)
	}

	// Reads work as before, with a notice.
	r := e.run("list")
	if !strings.Contains(r.out, "LEGACY_KEY") || !strings.Contains(r.err, "upgrade main") {
		t.Fatalf("list: %s", r)
	}
	r = e.runIn(testPass+"\n", "get", "LEGACY_KEY", "--passphrase-stdin")
	if r.code != 0 || r.out != "legacy-value\n" || !strings.Contains(r.err, "upgrade main") {
		t.Fatalf("get: %s", r)
	}
	// Every write refuses with one line naming the command and the build hint.
	before := fileHashes(t, dir)
	for _, args := range [][]string{{"set", "NEW_KEY"}, {"rm", "LEGACY_KEY", "--yes"}, {"describe", "LEGACY_KEY", "x"}, {"passwd", "main"}} {
		r := e.runIn(testPass+"\nnew passphrase\nnew passphrase\n", append(args, "--passphrase-stdin")...)
		if r.code == 0 || !strings.Contains(r.err, "upgrade main") || !strings.Contains(r.err, "brew upgrade secrets-vault") {
			t.Fatalf("%v on a format-2 vault: %s", args, r)
		}
	}
	if after := fileHashes(t, dir); len(after) != len(before) {
		t.Fatalf("a refused write changed files")
	} else {
		for k, v := range before {
			if after[k] != v {
				t.Fatalf("a refused write changed %s", k)
			}
		}
	}
	// Upgrade: one command, the identity unlock only.
	r = e.runIn(testPass+"\n", "upgrade", "main", "--yes", "--passphrase-stdin")
	if r.code != 0 || !strings.Contains(r.out, "Upgraded 'main'") {
		t.Fatalf("upgrade: %s", r)
	}
	vf, err := format.ReadVaultFile(dir)
	if err != nil || vf.Version != 3 || len(vf.Log) != 2 {
		t.Fatalf("after upgrade: %v %+v", err, vf)
	}
	e.mustRun("lock", "--all")
	rows := listRows(t, e)
	if len(rows) != 1 || rows[0].Description != "made by main" || !rows[0].Verified || rows[0].IndexState != "verified" {
		t.Fatalf("after upgrade: %+v", rows)
	}
	if got := e.mustRunIn(testPass+"\n", "get", "LEGACY_KEY", "--passphrase-stdin").out; got != "legacy-value\n" {
		t.Fatalf("%q", got)
	}
	e.mustRunIn("fresh", "set", "NEW_KEY")
	if got := e.mustRun("get", "NEW_KEY").out; got != "fresh\n" {
		t.Fatalf("%q", got)
	}
	// Running it again is harmless.
	if r := e.mustRun("upgrade", "main"); !strings.Contains(r.out, "already") {
		t.Fatalf("second upgrade: %s", r)
	}
	// The old build refuses the upgraded vault and changes nothing.
	snap := fileHashes(t, dir)
	for _, args := range [][]string{{"list"}, {"get", "LEGACY_KEY"}, {"info", "LEGACY_KEY"}, {"unlock", "main"}} {
		r := e.runOld(old, testPass+"\n", append(args, "--passphrase-stdin")...)
		if r.code == 0 && args[0] != "list" {
			t.Errorf("old build %v succeeded on a format-3 vault: %s", args, r)
		}
		notContains(t, "old build output", r.out+r.err, "legacy-value", "fresh")
	}
	for _, args := range [][]string{{"set", "OLD_WRITE"}, {"rm", "LEGACY_KEY", "--yes"}, {"describe", "LEGACY_KEY", "x"}} {
		if r := e.runOld(old, "x\n"+testPass+"\n", append(args, "--passphrase-stdin")...); r.code == 0 {
			t.Errorf("old build %v succeeded on a format-3 vault: %s", args, r)
		}
	}
	for k, v := range fileHashes(t, dir) {
		if snap[k] != v {
			t.Errorf("the old build changed %s", k)
		}
	}
	// A downgrade by a folder writer (vault.json back to version 2, record
	// kept): the old build can't use it and the new one refuses it.
	b, _ := os.ReadFile(filepath.Join(dir, "vault.json"))
	downgraded := bytes.Replace(b, []byte(`"version": 3`), []byte(`"version": 2`), 1)
	_ = os.WriteFile(filepath.Join(dir, "vault.json"), downgraded, 0o600)
	snap = fileHashes(t, dir)
	for _, args := range [][]string{{"get", "LEGACY_KEY"}, {"unlock", "main"}, {"set", "OLD_WRITE"}} {
		if r := e.runOld(old, "x\n"+testPass+"\n", append(args, "--passphrase-stdin")...); r.code == 0 {
			t.Errorf("old build %v succeeded on a downgraded vault: %s", args, r)
		}
	}
	for k, v := range fileHashes(t, dir) {
		if snap[k] != v {
			t.Errorf("the old build changed %s in a downgraded vault", k)
		}
	}
	r = e.runIn(testPass+"\n", "get", "LEGACY_KEY", "--passphrase-stdin")
	expectCode(t, r, ExitUnverified)
}

// A rotation re-seals the index: keys stay readable and verified, and the
// snapshot follows the new key.
func TestIndexAuthSurvivesRotation(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "v1")
	e.set("OTHER_KEY", "", "v2")
	e.mustRun("rm", "OTHER_KEY", "--yes")
	e.mustRunIn(testPass+"\nsecond passphrase\n", "passwd", "main", "--passphrase-stdin")
	e.mustRun("lock", "--all")
	rows := listRows(t, e)
	if len(rows) != 1 || !rows[0].Verified || rows[0].IndexState != "verified" || rows[0].Description != "test key api_key" {
		t.Fatalf("after rotation: %+v", rows)
	}
	if got := e.mustRunIn(testPass+"\n", "get", "API_KEY", "--passphrase-stdin").out; got != "v1\n" {
		t.Fatalf("%q", got)
	}
	// The deleted key's tombstone survives while its trashed copy does.
	b, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	if !strings.Contains(string(b), `"deleted": true`) {
		t.Fatalf("tombstone lost at rotation although a trashed copy exists: %s", b)
	}
	// An entry made under the previous key (a removed member's) fails.
}

// IS3 / Security note 1: a snapshot that is not on the verified chain never
// vouches, and an accepted rollback and a detach both forget it.
func TestIndexSnapshotAnchoringAndReset(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "v")
	vf, _ := format.ReadVaultFile(dir)
	snapFile := filepath.Join(snapshotDir(e), vf.ID+".json")
	good, err := os.ReadFile(snapFile)
	if err != nil {
		t.Fatalf("no snapshot was saved: %v", err)
	}
	// A snapshot whose pin head is not in the chain is treated as absent:
	// with the index deleted the key is NOT vouched for.
	var doc map[string]any
	_ = json.Unmarshal(good, &doc)
	doc["pin_head"] = strings.Repeat("0", 64)
	fb, _ := json.Marshal(doc)
	_ = os.WriteFile(snapFile, fb, 0o600)
	_ = os.Remove(filepath.Join(dir, "index.json"))
	expectCode(t, e.run("get", "API_KEY"), ExitUnverified)
	r := e.run("list", "--json")
	if rows := decodeJSON[[]keyRow](t, r.out); len(rows) != 0 {
		t.Fatalf("a stale snapshot listed keys: %+v", rows)
	}
	// The genuine snapshot vouches.
	_ = os.WriteFile(snapFile, good, 0o600)
	if got := e.mustRun("get", "API_KEY").out; got != "v\n" {
		t.Fatalf("%q", got)
	}
	// detach forgets it.
	e.mustRun("detach", "main")
	if _, err := os.Stat(snapFile); err == nil {
		t.Fatal("detach left the snapshot")
	}
}

// IS8: a name that only unverified entries claim never causes an unlock
// prompt for a vault the person didn't name.
func TestUnverifiedResolutionDoesNotPrompt(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("one")
	e.mustRunIn(testPass+"\n"+testPass+"\n", "init", "two", "--path", filepath.Join(e.home, "vaults", "two"), "--passphrase-stdin")
	e.mustRun("lock", "--all")
	forgetSnapshots(t, e)
	for _, d := range []string{"one", "two"} {
		editIndex(t, filepath.Join(e.home, "vaults", d), func(s string) string {
			return strings.Replace(s, `"entries": []`, `"entries": [
    {"name": "CLAIMED", "updated": "2026-11-20T10:00:00Z", "version": 1, "rev": 1, "mac": "`+strings.Repeat("0", 64)+`"}]`, 1)
		})
	}
	asked := e.term.asked
	r := e.run("get", "CLAIMED")
	expectCode(t, r, ExitUsage)
	if e.term.asked != asked {
		t.Fatal("asked for a passphrase")
	}
	if !strings.Contains(r.err, "--vault") {
		t.Fatalf("%s", r)
	}
}

// The first pin of a format-2 vault says so, so that comparing state codes
// catches a chain cut off before an upgrade (Security note 3).
func TestHeadLineNamesLegacyFormat(t *testing.T) {
	skipWindows(t)
	old := buildOldMain(t)
	e := newEnv(t)
	dir := filepath.Join(e.home, "vaults", "main")
	if r := e.runOld(old, testPass+"\n"+testPass+"\n", "init", "main", "--path", dir, "--passphrase-stdin", "--as", testUser); r.code != 0 {
		t.Fatalf("old init: %s", r)
	}
	// A second machine attaches: its first pin shows the format.
	f := newEnv(t)
	f.mustRunIn(testPass+"\n"+testPass+"\n", "attach", "main", dir, "--passphrase-stdin", "--as", "second")
	r := f.runIn(testPass+"\n"+testPass+"\n", "unlock", "main", "--passphrase-stdin")
	if !strings.Contains(r.out+r.err, "format 2 (not upgraded)") {
		t.Fatalf("%s", r)
	}
}

func dropIndexEntry(t *testing.T, dir, name string) {
	t.Helper()
	editIndex(t, dir, func(s string) string {
		var doc struct {
			Version int              `json:"version"`
			VaultID string           `json:"vault_id"`
			Entries []map[string]any `json:"entries"`
		}
		if err := json.Unmarshal([]byte(s), &doc); err != nil {
			t.Fatal(err)
		}
		kept := doc.Entries[:0]
		for _, en := range doc.Entries {
			if en["name"] != name {
				kept = append(kept, en)
			}
		}
		doc.Entries = kept
		b, _ := json.Marshal(doc)
		return string(b)
	})
}

// ue1.13: a name missing from an otherwise valid index is never "not
// found": with this machine's record it is a key (readable once unlocked,
// repaired by the next write); without, it is exit 5.
func TestMissingEntryIsNotNotFound(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("A_KEY", "", "a1")
	e.set("A_KEY", "", "a2")
	e.set("B_KEY", "", "b")
	dropIndexEntry(t, dir, "A_KEY")
	// Locked: still listed from the snapshot, flagged as changed.
	e.mustRun("lock", "--all")
	var found bool
	for _, r := range listRows(t, e) {
		if r.Name == "A_KEY" {
			found = r.Verified && r.PendingChange
		}
	}
	if !found {
		t.Fatalf("A_KEY not listed from the snapshot: %s", e.mustRun("list", "--json").out)
	}
	if got := e.mustRunIn(testPass+"\n", "get", "A_KEY", "--passphrase-stdin").out; got != "a2\n" {
		t.Fatalf("get with the snapshot: %q", got)
	}
	e.mustRun("info", "A_KEY")
	if out := e.mustRun("doctor", "main").out; !strings.Contains(out, "A_KEY: missing from the index") {
		t.Fatalf("doctor: %s", out)
	}
	// Without the snapshot (a fresh Mac): exit 5 and doctor says so.
	forgetSnapshots(t, e)
	r := e.run("get", "A_KEY")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "no signed entry") {
		t.Fatalf("%s", r)
	}
	if out := e.mustRun("doctor", "main").out; !strings.Contains(out, "File A_KEY has no signed entry") {
		t.Fatalf("doctor: %s", out)
	}
}

// ue1.14: a rotation while the folder's index doesn't verify rebuilds it
// from this machine's own record instead of writing an empty one.
func TestRotationRebuildsIndexFromSnapshot(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("A_KEY", "", "a")
	e.set("B_KEY", "", "b")
	e.mustRun("rm", "B_KEY", "--yes")
	// A folder writer breaks the index just before a rotation.
	_ = os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{"version":2,"vault_id":"`+mustVaultID(t, dir)+`","entries":[]}`), 0o600)
	e.mustRunIn(testPass+"\nsecond passphrase\n", "passwd", "main", "--passphrase-stdin")
	e.mustRun("lock", "--all")
	rows := listRows(t, e)
	if len(rows) != 1 || rows[0].Name != "A_KEY" || rows[0].Description != "test key a_key" || !rows[0].Verified {
		t.Fatalf("after a rotation over a broken index: %+v", rows)
	}
	if got := e.mustRunIn(testPass+"\n", "get", "A_KEY", "--passphrase-stdin").out; got != "a\n" {
		t.Fatalf("%q", got)
	}
	// The tombstone came through (B_KEY stays deleted).
	b, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	if !strings.Contains(string(b), `"deleted": true`) {
		t.Fatalf("tombstone lost: %s", b)
	}
}

func mustVaultID(t *testing.T, dir string) string {
	t.Helper()
	vf, err := format.ReadVaultFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	return vf.ID
}

// A tombstone the folder's index lost is written back by the next write.
func TestRepairingWriteKeepsTombstone(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("A_KEY", "", "a")
	e.set("B_KEY", "", "b")
	e.mustRun("rm", "B_KEY", "--yes")
	_ = os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{"version":2,"vault_id":"`+mustVaultID(t, dir)+`","entries":[]}`), 0o600)
	e.mustRunIn("c", "set", "C_KEY")
	b, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	if !strings.Contains(string(b), `"B_KEY"`) || !strings.Contains(string(b), `"deleted": true`) {
		t.Fatalf("the tombstone was dropped: %s", b)
	}
}

// ue1.15: a stale file sealed under a retired key doesn't block a rotation.
func TestStaleOldKeyFileDoesNotBlockRotation(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "v")
	old, _ := os.ReadFile(filepath.Join(dir, "secrets", "API_KEY.age"))
	e.mustRunIn(testPass+"\nsecond passphrase\n", "passwd", "main", "--passphrase-stdin")
	// Someone copies an old-epoch file back in under another name.
	_ = os.WriteFile(filepath.Join(dir, "secrets", "STALE_OLDKEY.age"), old, 0o600)
	r := e.runIn(testPass+"\nthird passphrase\n", "passwd", "main", "--passphrase-stdin")
	if r.code != 0 {
		t.Fatalf("a stale file blocked the rotation: %s", r)
	}
	if !strings.Contains(r.err, "STALE_OLDKEY") || !strings.Contains(r.err, "older vault key") || !strings.Contains(r.err, "quarantine/") {
		t.Fatalf("the stale file was not reported: %s", r)
	}
	// Set aside, byte for byte, not deleted.
	moved, _ := filepath.Glob(filepath.Join(dir, "quarantine", "secrets", "STALE_OLDKEY.*.age"))
	if len(moved) != 1 {
		t.Fatalf("quarantined: %v", moved)
	}
	if after, _ := os.ReadFile(moved[0]); !bytes.Equal(after, old) {
		t.Fatal("the quarantined file was changed")
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets", "STALE_OLDKEY.age")); err == nil {
		t.Fatal("the stale file is still in secrets/")
	}
	if got := e.mustRun("get", "API_KEY").out; got != "v\n" {
		t.Fatalf("%q", got)
	}
}
