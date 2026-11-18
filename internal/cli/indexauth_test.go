package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/Arntek/secrets-vault/internal/crypto"
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
	if !strings.Contains(r.err, "STALE_OLDKEY") || !strings.Contains(r.err, "quarantine/") {
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

// ue1.15 bypass: no file content a folder writer can make may block a
// rotation: a current-key file copied under another name, a truncated file,
// garbage. Each is set aside byte for byte, named, and the rest rotates.
func TestUnopenableFilesNeverBlockRotation(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("B_KEY", "", "bee")
	e.set("C_KEY", "", "sea")
	e.set("D_KEY", "", "dee")
	sec := func(n string) string { return filepath.Join(dir, "secrets", n+".age") }
	b, _ := os.ReadFile(sec("B_KEY"))
	c, _ := os.ReadFile(sec("C_KEY"))
	_ = os.WriteFile(sec("ZZZ_PLANT"), b, 0o600)        // current key, wrong name
	_ = os.WriteFile(sec("C_KEY"), c[:len(c)/2], 0o600) // truncated
	_ = os.WriteFile(sec("GARBAGE_FILE"), []byte("zzz"), 0o600)
	r := e.runIn(testPass+"\nsecond passphrase\n", "passwd", "main", "--passphrase-stdin", "--json")
	if r.code != 0 {
		t.Fatalf("passwd blocked: %s", r)
	}
	q := decodeJSON[map[string]any](t, r.out)["quarantined"].([]any)
	if len(q) != 3 {
		t.Fatalf("--json quarantined = %v", q)
	}
	for _, n := range []string{"ZZZ_PLANT", "C_KEY", "GARBAGE_FILE"} {
		if !strings.Contains(r.err, n) {
			t.Errorf("%s not named in the warning: %s", n, r.err)
		}
		if _, err := os.Stat(sec(n)); err == nil {
			t.Errorf("%s still in secrets/", n)
		}
		if m, _ := filepath.Glob(filepath.Join(dir, "quarantine", "secrets", n+".*.age")); len(m) != 1 {
			t.Errorf("%s not quarantined: %v", n, m)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "quarantine", "secrets", "C_KEY.*.age")); len(m) == 1 {
		if got, _ := os.ReadFile(m[0]); !bytes.Equal(got, c[:len(c)/2]) {
			t.Error("the quarantined file changed")
		}
	}
	// The rest rotated; the damaged live key is exit 5, never 4.
	for k, v := range map[string]string{"B_KEY": "bee\n", "D_KEY": "dee\n"} {
		if got := e.mustRun("get", k).out; got != v {
			t.Fatalf("%s = %q", k, got)
		}
	}
	expectCode(t, e.run("get", "C_KEY"), ExitUnverified)
	if out := e.mustRun("doctor", "main").out; !strings.Contains(out, "Key C_KEY: listed, but the file is missing") {
		t.Fatalf("doctor: %s", out)
	}
}

// ue1.14: a tombstone the writer stripped is written back even when the
// trashed file was copied back into secrets/.
func TestTombstoneWrittenBackWithFileResurrected(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("B_KEY", "", "b")
	file, _ := os.ReadFile(filepath.Join(dir, "secrets", "B_KEY.age"))
	e.mustRun("rm", "B_KEY", "--yes")
	dropIndexEntry(t, dir, "B_KEY")
	_ = os.WriteFile(filepath.Join(dir, "secrets", "B_KEY.age"), file, 0o600)
	e.mustRunIn("o", "set", "OTHERW")
	b, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	if !strings.Contains(string(b), `"B_KEY"`) || !strings.Contains(string(b), `"deleted": true`) {
		t.Fatalf("tombstone not written back: %s", b)
	}
	forgetSnapshots(t, e)
	expectCode(t, e.run("get", "B_KEY"), ExitUnverified)
}

// A symlinked quarantine folder is never written through, and never blocks
// a rotation either: it is renamed aside and a real one is made.
func TestQuarantineSymlinkIsRenamedAside(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "v")
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "quarantine"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(dir, "quarantine", "secrets")); err != nil {
		t.Skip("symlinks unavailable")
	}
	_ = os.WriteFile(filepath.Join(dir, "secrets", "JUNK_FILE.age"), []byte("junk"), 0o600)
	r := e.runIn(testPass+"\nsecond passphrase\n", "passwd", "main", "--passphrase-stdin")
	if r.code != 0 {
		t.Fatalf("a planted quarantine link blocked passwd: %s", r)
	}
	if m, _ := filepath.Glob(filepath.Join(elsewhere, "*")); len(m) != 0 {
		t.Fatalf("a file was written through the link: %v", m)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "quarantine-bad-*")); len(m) != 1 {
		t.Fatalf("the link was not renamed aside: %v", m)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "quarantine", "secrets", "JUNK_FILE.*.age")); len(m) != 1 {
		t.Fatalf("the junk file was not quarantined into a fresh folder: %v", m)
	}
}

// Property test (ue1.15, class level): whatever a folder writer plants in
// the vault folder, passwd completes for the files that verify, nothing
// outside the vault folder is written, nothing is deleted, and the old key
// opens nothing written afterwards. member rm calls the same set-aside
// step (setAsideConflicts) before the same rotation.
func TestRotationNeverBlockedByPlantedFiles(t *testing.T) {
	skipWindows(t)
	seeds := 25
	if n, err := strconv.Atoi(os.Getenv("SV_PROP_SEEDS")); err == nil && n > 0 {
		seeds = n // a longer local run
	}
	if testing.Short() {
		seeds = 5
	}
	for seed := 0; seed < seeds; seed++ {
		t.Run("seed"+itoa(seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(int64(seed)))
			e := newEnv(t)
			dir := e.initVault("main")
			e.unlock("main")
			e.set("B_KEY", "", "bee")
			e.set("C_KEY", "", "sea")
			sec := func(n string) string { return filepath.Join(dir, "secrets", n) }
			epoch1B, _ := os.ReadFile(sec("B_KEY.age"))
			e.mustRunIn(testPass+"\nfirst rotation\n", "passwd", "main", "--passphrase-stdin")
			b, _ := os.ReadFile(sec("B_KEY.age"))
			oldIDs := map[string]string{}
			for _, n := range []string{"B_KEY", "C_KEY"} {
				ct, _ := os.ReadFile(sec(n + ".age"))
				oldIDs[n] = keyIDOfFile(t, ct)
			}
			outside := t.TempDir()
			keep := filepath.Join(outside, "keep")
			_ = os.WriteFile(keep, []byte("outside data"), 0o600)
			fifo := func(p string) {
				if err := syscall.Mkfifo(p, 0o600); err != nil {
					_ = os.WriteFile(p, []byte("fifo stand-in"), 0o600)
				}
			}
			plants := []func(){
				func() { _ = os.WriteFile(sec("B_KEY (alice's conflicted copy 2026-11-18).age"), []byte("junk"), 0o600) },
				func() { _ = os.WriteFile(sec("C_KEY (conflicted copy).age"), epoch1B, 0o600) },
				func() {
					_ = os.WriteFile(filepath.Join(dir, "vault (bob's conflicted copy).json"), []byte("{}"), 0o600)
				},
				func() { _ = os.WriteFile(filepath.Join(dir, "index (conflicted copy).json"), []byte("garbage"), 0o600) },
				func() { _ = os.Mkdir(sec("EVIL_DIR.age"), 0o700) },
				func() { _ = os.Symlink(keep, sec("EVIL_LINK.age")) },
				func() { _ = os.Symlink(outside, sec("EVIL_DIRLINK.age")) },
				func() { fifo(sec("EVIL_FIFO.age")) },
				func() { _ = os.WriteFile(sec("TRUNC.age"), b[:len(b)/2], 0o600) },
				func() { _ = os.WriteFile(sec("RENAMED_COPY.age"), b, 0o600) },
				func() { _ = os.WriteFile(sec("GARBAGE.age"), []byte("zzz"), 0o600) },
				func() { _ = os.WriteFile(sec("OLD_EPOCH.age"), epoch1B, 0o600) },
				func() { _ = os.Symlink(outside, filepath.Join(dir, "quarantine")) },
				func() {
					_ = os.MkdirAll(filepath.Join(dir, "quarantine"), 0o700)
					_ = os.Symlink(outside, filepath.Join(dir, "quarantine", "secrets"))
				},
				func() { _ = os.Symlink(outside, sec(".trash")) },
				func() { _ = os.Symlink(outside, filepath.Join(dir, "requests")) },
				func() { _ = os.Symlink(outside, sec(".sv-rotate-abababababababababababababababab")) },
				func() { _ = os.Mkdir(sec("X (conflicted copy).age"), 0o700) },
				func() {
					_ = os.MkdirAll(sec(".trash"), 0o700)
					_ = os.WriteFile(filepath.Join(sec(".trash"), "junk-file.age"), []byte("j"), 0o600)
				},
			}
			rng.Shuffle(len(plants), func(i, j int) { plants[i], plants[j] = plants[j], plants[i] })
			n := 1 + rng.Intn(len(plants))
			preexisting := regularHashes(t, dir)
			for _, p := range plants[:n] {
				p()
			}
			// What the plants added (regular files), which must survive; some
			// plants write through an earlier plant's link, so note what is
			// outside now too.
			before := map[[32]byte]bool{}
			for h := range regularHashes(t, dir) {
				if !preexisting[h] {
					before[h] = true
				}
			}
			outsideBefore := dirNames(t, outside)
			r := e.runIn(testPass+"\nsecond rotation\n", "passwd", "main", "--passphrase-stdin")
			if r.code != 0 {
				t.Fatalf("passwd blocked with %d plants: %s", n, r)
			}
			// Nothing outside the vault folder was written.
			if now := dirNames(t, outside); !reflect.DeepEqual(now, outsideBefore) {
				t.Fatalf("something was written outside the vault: %v -> %v", outsideBefore, now)
			}
			if got, _ := os.ReadFile(keep); string(got) != "outside data" {
				t.Fatal("a symlink target was modified")
			}
			// Nothing deleted: every planted regular file's bytes are still in the vault folder.
			after := regularHashes(t, dir)
			for h := range before {
				if _, ok := after[h]; !ok {
					t.Fatal("a regular file's content is gone from the vault folder")
				}
			}
			// The keys that verify are rotated and readable; the old key opens none of them.
			for k, v := range map[string]string{"B_KEY": "bee\n", "C_KEY": "sea\n"} {
				if got := e.mustRun("get", k).out; got != v {
					t.Fatalf("%s = %q", k, got)
				}
				ct, _ := os.ReadFile(sec(k + ".age"))
				if keyIDOfFile(t, ct) == oldIDs[k] {
					t.Fatalf("%s is still sealed under the old key", k)
				}
			}
		})
	}
}

func keyIDOfFile(t *testing.T, ct []byte) string {
	t.Helper()
	id, err := crypto.KeyIDOf(ct)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// regularHashes returns the SHA-256 of every regular file under dir (by
// Lstat; links are not followed).
func regularHashes(t *testing.T, dir string) map[[32]byte]bool {
	t.Helper()
	out := map[[32]byte]bool{}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil {
			out[sha256.Sum256(b)] = true
		}
		return nil
	})
	return out
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// The same through member rm: a worst-case pile of plants can't stop the
// removal of a member.
func TestMemberRemoveNeverBlockedByPlantedFiles(t *testing.T) {
	skipWindows(t)
	owner, dan := newEnv(t), newEnv(t)
	vdir := owner.initVault("team")
	owner.unlock("team")
	owner.set("TEAM_KEY", "", "team-value")
	join(t, owner, dan, "team", vdir, "dan")
	outside := t.TempDir()
	keep := filepath.Join(outside, "keep")
	_ = os.WriteFile(keep, []byte("outside data"), 0o600)
	b, _ := os.ReadFile(filepath.Join(vdir, "secrets", "TEAM_KEY.age"))
	sec := func(n string) string { return filepath.Join(vdir, "secrets", n) }
	_ = os.WriteFile(sec("TEAM_KEY (alice's conflicted copy).age"), []byte("junk"), 0o600)
	_ = os.WriteFile(filepath.Join(vdir, "vault (bob's conflicted copy).json"), []byte("{}"), 0o600)
	_ = os.Mkdir(sec("EVIL_DIR.age"), 0o700)
	_ = os.Symlink(keep, sec("EVIL_LINK.age"))
	_ = syscall.Mkfifo(sec("EVIL_FIFO.age"), 0o600)
	_ = os.WriteFile(sec("RENAMED_COPY.age"), b, 0o600)
	_ = os.WriteFile(sec("TRUNC.age"), b[:len(b)/2], 0o600)
	_ = os.Symlink(outside, sec(".trash"))
	_ = os.Symlink(outside, filepath.Join(vdir, "requests"))
	_ = os.Symlink(outside, filepath.Join(vdir, "quarantine"))
	before := dirNames(t, outside)
	r := owner.runIn(testPass+"\n", "member", "rm", "team", "dan", "--yes", "--folder-access-removed", "--passphrase-stdin")
	if r.code != 0 {
		t.Fatalf("member rm blocked: %s", r)
	}
	if now := dirNames(t, outside); !reflect.DeepEqual(now, before) {
		t.Fatalf("something was written outside the vault: %v -> %v", before, now)
	}
	if got := owner.mustRun("get", "TEAM_KEY").out; got != "team-value\n" {
		t.Fatalf("%q", got)
	}
	if out := owner.mustRun("member", "list", "team").out; strings.Contains(out, "dan") {
		t.Fatalf("dan is still a member: %s", out)
	}
	ct, _ := os.ReadFile(sec("TEAM_KEY.age"))
	if id, _ := crypto.KeyIDOf(ct); id == keyIDOfFile(t, b) {
		t.Fatal("TEAM_KEY is still sealed under the old key")
	}
}

// Read-only commands never rename anything: a bad folder is reported (exit
// 5 or an error entry), and only the rotation commands set it aside.
func TestReadOnlyCommandsDoNotSetFoldersAside(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "v")
	outside := t.TempDir()
	trash := filepath.Join(dir, "secrets", ".trash")
	if err := os.Symlink(outside, trash); err != nil {
		t.Skip("symlinks unavailable")
	}
	for _, args := range [][]string{{"get", "API_KEY"}, {"info", "API_KEY"}, {"list"}, {"list", "--json"}, {"search", "api"}, {"status"}, {"member", "list", "main"}, {"member", "log", "main"}} {
		r := e.run(args...)
		if args[0] == "get" || args[0] == "info" || (args[0] == "member") {
			if r.code != ExitUnverified {
				t.Errorf("%v: exit %d, want %d: %s", args, r.code, ExitUnverified, r)
			}
		}
		if fi, err := os.Lstat(trash); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%v renamed the bad folder", args)
		}
		if m, _ := filepath.Glob(filepath.Join(dir, "quarantine-bad-*")); len(m) != 0 {
			t.Fatalf("%v set a folder aside", args)
		}
	}
	// Writes that aren't rotations refuse too, and don't rename either.
	for _, args := range [][]string{{"describe", "API_KEY", "x"}, {"tag", "API_KEY", "t"}, {"rm", "API_KEY", "--yes"}} {
		expectCode(t, e.run(args...), ExitUnverified)
	}
	expectCode(t, e.runIn("n", "set", "NEW_KEY"), ExitUnverified)
	if m, _ := filepath.Glob(filepath.Join(dir, "quarantine-bad-*")); len(m) != 0 {
		t.Fatal("a non-rotation write set a folder aside")
	}
}

// Where a rotation still refuses, every write refuses with it (exit 5), so
// nobody can add secrets that a member pending removal could read.
func TestRefusedRotationMeansRefusedWrites(t *testing.T) {
	skipWindows(t)
	writes := func(t *testing.T, e *testEnv) {
		t.Helper()
		for _, args := range [][]string{{"describe", "API_KEY", "x"}, {"tag", "API_KEY", "t"}, {"rm", "API_KEY", "--yes"}, {"rename", "API_KEY", "OTHER_NAME"}} {
			if r := e.runIn(testPass+"\n", append(args, "--passphrase-stdin")...); r.code != ExitUnverified {
				t.Errorf("%v: exit %d, want %d: %s", args, r.code, ExitUnverified, r)
			}
		}
		if r := e.runIn(testPass+"\nn", "set", "NEW_KEY", "--passphrase-stdin"); r.code != ExitUnverified {
			t.Errorf("set: exit %d, want %d: %s", r.code, ExitUnverified, r)
		}
		if r := e.runIn(testPass+"\nnew passphrase\n", "passwd", "main", "--passphrase-stdin"); r.code != ExitUnverified {
			t.Errorf("passwd: exit %d, want %d: %s", r.code, ExitUnverified, r)
		}
	}
	setup := func(t *testing.T) (*testEnv, string) {
		e := newEnv(t)
		dir := e.initVault("main")
		e.unlock("main")
		e.set("API_KEY", "", "v")
		return e, dir
	}
	t.Run("secrets is a link", func(t *testing.T) {
		e, dir := setup(t)
		elsewhere := t.TempDir()
		_ = os.Rename(filepath.Join(dir, "secrets"), filepath.Join(elsewhere, "real"))
		if err := os.Symlink(filepath.Join(elsewhere, "real"), filepath.Join(dir, "secrets")); err != nil {
			t.Skip("symlinks unavailable")
		}
		writes(t, e)
	})
	t.Run("the vault folder is a link", func(t *testing.T) {
		e, dir := setup(t)
		elsewhere := filepath.Join(t.TempDir(), "moved")
		if err := os.Rename(dir, elsewhere); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, dir); err != nil {
			t.Skip("symlinks unavailable")
		}
		writes(t, e)
	})
	t.Run("a verified newer vault.json copy", func(t *testing.T) {
		e, dir := setup(t)
		vf, _ := format.ReadVaultFile(dir)
		pinPath := filepath.Join(filepath.Dir(e.cfg), "trust", vf.ID+".json")
		e.mustRunIn(testPass+"\nsecond passphrase\n", "passwd", "main", "--passphrase-stdin")
		v1, _ := os.ReadFile(filepath.Join(dir, "vault.json"))
		pin1, _ := os.ReadFile(pinPath)
		e.mustRunIn(testPass+"\nthird passphrase\n", "passwd", "main", "--passphrase-stdin")
		v2, _ := os.ReadFile(filepath.Join(dir, "vault.json"))
		// The folder is at seq 1 with a conflict copy at seq 2.
		_ = os.WriteFile(filepath.Join(dir, "vault.json"), v1, 0o600)
		_ = os.WriteFile(pinPath, pin1, 0o600)
		_ = os.WriteFile(filepath.Join(dir, "vault (Dan's conflicted copy).json"), v2, 0o600)
		writes(t, e)
	})
}
