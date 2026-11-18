package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arntek/secrets-vault/internal/format"
)

const personalPass = "personal passphrase 1"

// myFingerprint returns e's identity fingerprint (from member list).
func (e *testEnv) fingerprintOf(vault, name string) string {
	e.t.Helper()
	l := decodeJSON[map[string]any](e.t, e.mustRun("member", "list", vault, "--json").out)
	for _, m := range l["members"].([]any) {
		mm := m.(map[string]any)
		if mm["name"] == name {
			return mm["fingerprint"].(string)
		}
	}
	e.t.Fatalf("%s is not a member of %s", name, vault)
	return ""
}

func (e *testEnv) requestFingerprint(vault, name string) string {
	e.t.Helper()
	j := decodeJSON[map[string]any](e.t, e.mustRun("member", "requests", vault, "--json").out)
	for _, r := range j["requests"].([]any) {
		rr := r.(map[string]any)
		if rr["name"] == name {
			return rr["fingerprint"].(string)
		}
	}
	e.t.Fatalf("no request from %s", name)
	return ""
}

// join has p attach to owner's vault and owner approve them; p then
// confirms the owner's fingerprint on first use.
func join(t *testing.T, owner, p *testEnv, vault, dir, name string) {
	t.Helper()
	p.mustRunIn(personalPass+"\n", "attach", vault, dir, "--as", name, "--passphrase-stdin")
	fp := owner.requestFingerprint(vault, name)
	owner.mustRunIn(testPass+"\n", "member", "approve", vault, name, "--fingerprint", fp, "--passphrase-stdin")
	ownerFP := owner.fingerprintOf(vault, testUser)
	p.mustRunIn(personalPass+"\n", "unlock", vault, "--passphrase-stdin", "--signer-fingerprint", ownerFP)
}

// TestMembersFlowThroughCLI: two people, two identities, one shared folder:
// attach -> join request -> approve (typed fingerprint) -> first use (typed
// fingerprint of the approver) -> read, then removal with rotation.
func TestMembersFlowThroughCLI(t *testing.T) {
	skipWindows(t)
	owner := newEnv(t)
	dan := newEnv(t)
	vdir := owner.initVault("team")
	owner.unlock("team")
	owner.set("EXAMPLE_TEAM_KEY", "", "team-secret-value")

	// Dan attaches: first run creates his identity and files a signed request.
	r := dan.runIn(personalPass+"\n", "attach", "team", vdir, "--as", "dan", "--passphrase-stdin")
	expectCode(t, r, 0)
	if !strings.Contains(r.out, "not a member") || !strings.Contains(r.out, "Ask a member to approve fingerprint") {
		t.Fatalf("attach output: %s", r)
	}
	stranger := newEnv(t)
	expectCode(t, stranger.run("attach", "team", vdir), ExitError)
	expectCode(t, dan.runIn(personalPass+"\n", "get", "EXAMPLE_TEAM_KEY", "--passphrase-stdin"), ExitError)

	fp := owner.requestFingerprint("team", "dan")
	if !strings.Contains(owner.mustRun("status").out, "1 join request") {
		t.Fatal("status should show the pending request")
	}
	// G4: the fingerprint is typed, never shown for a y/N.
	if strings.Contains(owner.mustRun("member", "requests", "team").out, fp) {
		t.Fatal("requests table must not show the fingerprint to compare against")
	}
	expectCode(t, owner.run("member", "approve", "team", "dan"), ExitError) // no terminal
	expectCode(t, owner.runIn(testPass+"\n", "member", "approve", "team", "dan", "--fingerprint", "WRONG-WORD-ZERO-0000", "--passphrase-stdin"), ExitError)
	owner.term.stdinTTY = true
	owner.term.queue(testPass)
	r = owner.runIn("ACID-ACID-ACID-0000\n", "member", "approve", "team", "dan")
	expectCode(t, r, ExitError)
	if l := decodeJSON[map[string]any](t, owner.mustRun("member", "list", "team", "--json").out); len(l["members"].([]any)) != 1 {
		t.Fatalf("nothing should have been approved: %v", l)
	}
	owner.term.queue(testPass)
	r = owner.mustRunIn(strings.ToLower(strings.ReplaceAll(fp, "-", " "))+"\n", "member", "approve", "team", "dan")
	owner.term.stdinTTY = false
	ownerFP := owner.fingerprintOf("team", testUser)
	if !strings.Contains(r.out, ownerFP) {
		t.Fatalf("approve should give the approver's fingerprint to read out: %s", r)
	}

	// Dan's first use: he must type the approver's fingerprint.
	r = dan.runIn(personalPass+"\n", "get", "EXAMPLE_TEAM_KEY", "--passphrase-stdin")
	expectCode(t, r, ExitError)
	if !strings.Contains(r.err, "added to 'team' by "+testUser) {
		t.Fatalf("first use must ask who added him: %s", r)
	}
	expectCode(t, dan.runIn(personalPass+"\n", "get", "EXAMPLE_TEAM_KEY", "--passphrase-stdin", "--signer-fingerprint", fp), ExitError) // his own, not the approver's
	r = dan.runIn(personalPass+"\n", "get", "EXAMPLE_TEAM_KEY", "--passphrase-stdin", "--signer-fingerprint", ownerFP)
	if r.code != 0 || r.out != "team-secret-value\n" {
		t.Fatalf("dan's read: %s", r)
	}
	if got := dan.mustRun("get", "EXAMPLE_TEAM_KEY").out; got != "team-secret-value\n" {
		t.Fatalf("%q", got)
	}
	dan.mustRunIn("from-dan", "set", "EXAMPLE_DAN_KEY", "--vault", "team")
	if got := owner.mustRun("get", "EXAMPLE_DAN_KEY").out; got != "from-dan\n" {
		t.Fatalf("%q", got)
	}
	ml := decodeJSON[map[string]any](t, owner.mustRun("member", "list", "team", "--json").out)
	if len(ml["members"].([]any)) != 2 {
		t.Fatalf("member list: %v", ml)
	}
	if evs := decodeJSON[[]struct{ Action, Member string }](t, owner.mustRun("log", "--json").out); !hasMemberEvent(evs, "member-add", "dan") {
		t.Fatalf("approving dan must be in the read log: %v", evs)
	}
	logOut := owner.mustRun("member", "log", "team").out
	if !strings.Contains(logOut, "add-member") || !strings.Contains(logOut, "genesis") {
		t.Fatalf("member log: %s", logOut)
	}

	// Removal: folder access confirmation, --yes, rotation, passphrase dropped.
	expectCode(t, owner.run("member", "rm", "team", "dan", "--yes"), ExitError) // no folder-access confirmation
	expectCode(t, owner.run("member", "rm", "team", "nobody", "--yes", "--folder-access-removed"), ExitError)
	r = owner.mustRunIn(testPass+"\n", "member", "rm", "team", "dan", "--yes", "--folder-access-removed", "--passphrase-stdin")
	for _, want := range []string{"EXAMPLE_TEAM_KEY", "EXAMPLE_DAN_KEY", "Rotate them", "no longer opens", "State code", "shared folder"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("removal output missing %q:\n%s", want, r.out)
		}
	}
	if evs := decodeJSON[[]struct{ Action, Member string }](t, owner.mustRun("log", "--json").out); !hasMemberEvent(evs, "member-remove", "dan") {
		t.Fatalf("removing dan must be in the read log: %v", evs)
	}
	if got := owner.mustRun("get", "EXAMPLE_TEAM_KEY").out; got != "team-secret-value\n" {
		t.Fatalf("%q", got)
	}
	// ue1.6: the old vault passphrase no longer opens it.
	owner.mustRun("lock", "--all")
	vf, _ := format.ReadVaultFile(vdir)
	if len(vf.UnlockersOf(format.UnlockerPassphrase)) != 0 {
		t.Fatal("passphrase unlocker kept")
	}
	// Dan is locked out.
	dan.mustRun("lock", "--all")
	r = dan.runIn(personalPass+"\n", "get", "EXAMPLE_TEAM_KEY", "--passphrase-stdin")
	if r.code == 0 {
		t.Fatalf("a removed member must not read: %s", r)
	}
	notContains(t, "removed member's output", r.out+r.err, "team-secret-value")
	expectCode(t, dan.run("unlock", "team", "--accept-key-change"), ExitUsage) // that flag is gone
}

// TestUE11RegressionCLI is the security finding ue1.1 end to end: mallory,
// who can write the shared folder but is not a member, plants a member
// unlocker named "bob" for her own key; alice then removes carol. It must
// now fail for mallory: the vault refuses to open, nothing is re-wrapped.
func TestUE11RegressionCLI(t *testing.T) {
	skipWindows(t)
	alice, bob, carol, mallory := newEnv(t), newEnv(t), newEnv(t), newEnv(t)
	vdir := alice.initVault("team")
	alice.unlock("team")
	alice.set("API_KEY", "", "secret-value")
	join(t, alice, bob, "team", vdir, "bob")
	join(t, alice, carol, "team", vdir, "carol")

	// Mallory gets her own age recipient by filing a request, then deletes it.
	mallory.mustRunIn(personalPass+"\n", "attach", "team", vdir, "--as", "mallory", "--passphrase-stdin")
	reqData, err := os.ReadFile(filepath.Join(vdir, "requests", "mallory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rf struct{ Body []byte }
	_ = json.Unmarshal(reqData, &rf)
	var body struct {
		Recipient string `json:"recipient"`
		SignKey   string `json:"sign_key"`
	}
	_ = json.Unmarshal(rf.Body, &body)
	_ = os.Remove(filepath.Join(vdir, "requests", "mallory.json"))

	// Plant: a member entry and unlocker named "bob" with her keys, the
	// wrapped key copied from a real entry (as in the PoC).
	vf, _ := format.ReadVaultFile(vdir)
	for i := range vf.Members {
		if vf.Members[i].Name == "bob" {
			vf.Members = append(vf.Members, format.Member{Name: "bobby", Recipient: body.Recipient, SignKey: body.SignKey, Role: format.RoleMember})
		}
	}
	format.SortMembers(vf.Members)
	var planted format.Unlocker
	for _, u := range vf.Unlockers {
		if u.Label == "bob" {
			planted = u
		}
	}
	planted.Label, planted.Recipient = "bobby", body.Recipient
	vf.Unlockers = append(vf.Unlockers, planted)
	data, _ := json.MarshalIndent(vf, "", "  ")
	if err := os.WriteFile(filepath.Join(vdir, "vault.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	r := alice.runIn(testPass+"\n", "member", "rm", "team", "carol", "--yes", "--folder-access-removed", "--passphrase-stdin")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "changed outside secrets-vault") {
		t.Fatalf("alice should be told vault.json was tampered with: %s", r)
	}
	after, _ := os.ReadFile(filepath.Join(vdir, "vault.json"))
	if string(after) != string(data) {
		t.Fatal("the tampered vault.json was rewritten")
	}
	r = mallory.runIn(personalPass+"\n", "get", "API_KEY", "--passphrase-stdin")
	if r.code == 0 {
		t.Fatalf("mallory read a secret: %s", r)
	}
	notContains(t, "mallory's output", r.out+r.err, "secret-value")
}

// Attacker 4 / ue1.2 through the CLI: a removed member restores the old
// folder; machines that saw the removal refuse, the state code refuses,
// and a leftover file blocks writes.
func TestRollbackRefusedCLI(t *testing.T) {
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
	code := r.out[strings.LastIndex(r.out, ": ")+2:]
	code = strings.TrimSpace(code)
	alice.set("API_KEY", "", "new-value")
	alice.set("AFTER", "", "x")

	honest := filepath.Join(t.TempDir(), "honest")
	copyTree(t, vdir, honest)
	// carol restores vault.json and API_KEY from her snapshot.
	copyFile(t, filepath.Join(snap, "vault.json"), filepath.Join(vdir, "vault.json"))
	copyFile(t, filepath.Join(snap, "secrets", "API_KEY.age"), filepath.Join(vdir, "secrets", "API_KEY.age"))

	// alice saw the removal: hard refusal, no prompt, no flag.
	alice.mustRun("lock", "--all")
	r = alice.runIn(testPass+"\n", "get", "API_KEY", "--passphrase-stdin")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "older than, or different from") || strings.Contains(r.err, "expected") {
		t.Fatalf("rollback message: %s", r)
	}
	// bob never saw the removal: the folder matches his pin...
	bob.mustRun("lock", "--all")
	if got := bob.runIn(personalPass+"\n", "get", "API_KEY", "--passphrase-stdin"); got.code != 0 || got.out != "old-value\n" {
		t.Fatalf("bob's read: %s", got)
	}
	// ...but the write guard sees AFTER under a newer key and refuses.
	r = bob.runIn("bob-new", "set", "BOB_NEW", "--vault", "team")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "newer state") {
		t.Fatalf("write guard: %s", r)
	}
	if _, err := os.Stat(filepath.Join(vdir, "secrets", "BOB_NEW.age")); err == nil {
		t.Fatal("bob's write went through")
	}
	// And alice's state code makes bob's machine refuse carol's state, and
	// keep refusing it afterwards (ue1.9), reads included.
	r = bob.runIn("", "trust", "team", "--expect", code)
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "behind the state code you were given") {
		t.Fatalf("%s", r)
	}
	r = bob.runIn(personalPass+"\n", "get", "API_KEY", "--passphrase-stdin")
	expectCode(t, r, ExitUnverified)
	notContains(t, "bob's output after the refused code", r.out+r.err, "old-value")
	expectCode(t, bob.runIn("bob-new", "set", "BOB_NEW", "--vault", "team"), ExitUnverified)
	// When the honest folder returns, the expectation is met and cleared.
	copyFile(t, filepath.Join(honest, "vault.json"), filepath.Join(vdir, "vault.json"))
	copyFile(t, filepath.Join(honest, "secrets", "API_KEY.age"), filepath.Join(vdir, "secrets", "API_KEY.age"))
	if got := bob.mustRunIn(personalPass+"\n", "get", "API_KEY", "--passphrase-stdin").out; got != "new-value\n" {
		t.Fatalf("after the honest state returned: %q", got)
	}
}

// M1 through the CLI: a vault.json for another vault ID is refused.
func TestSubstitutedVaultRefused(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.mustRun("lock", "--all")
	e2 := newEnv(t)
	e2.initVault("evil")
	evilJSON, err := os.ReadFile(filepath.Join(e2.home, "vaults", "evil", "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	e.activate()
	if err := os.WriteFile(filepath.Join(dir, "vault.json"), evilJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	r := e.runIn(testPass+"\n", "unlock", "main", "--passphrase-stdin")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "different vault") {
		t.Fatalf("expected the different-vault refusal: %s", r)
	}
}

// M3: a pinned v2 vault replaced by a v1 file is refused, not migrated; a
// genuine personal v1 vault is upgraded once, with the passphrase.
func TestMigrationAndDowngrade(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	vf, _ := format.ReadVaultFile(dir)
	v1 := map[string]any{"version": 1, "id": vf.ID, "name": "main", "key_id": vf.KeyID, "unlockers": vf.UnlockersOf(format.UnlockerPassphrase)}
	data, _ := json.Marshal(v1)
	if err := os.WriteFile(filepath.Join(dir, "vault.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	e.mustRun("lock", "--all")
	r := e.runIn(testPass+"\n", "unlock", "main", "--passphrase-stdin")
	expectCode(t, r, ExitError)
	if !strings.Contains(r.err, "downgrade") {
		t.Fatalf("downgrade: %s", r)
	}

	// A fresh machine with a genuine v1 vault: upgraded once.
	f := newEnv(t)
	fdir := filepath.Join(f.home, "old")
	if err := os.MkdirAll(filepath.Join(fdir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fdir, "vault.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fdir, "index.json"), []byte(`{"version":1,"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f.mustRun("attach", "old", fdir, "--no-request")
	// This person's identity (created along with a scratch vault).
	f.mustRunIn(personalPass+"\n"+personalPass+"\n", "init", "scratch", "--path", filepath.Join(f.home, "scratch"), "--passphrase-stdin", "--as", "fresh")
	r = f.runIn(testPass+"\n"+personalPass+"\n", "unlock", "old", "--passphrase-stdin")
	if r.code != 0 || !strings.Contains(r.err, "Upgraded 'old'") {
		t.Fatalf("migration: %s", r)
	}
	got, _ := format.ReadVaultFile(fdir)
	if got.Version != format.VaultVersion || got.Members[0].Name != "fresh" || got.ID != vf.ID {
		t.Fatalf("migrated file: %+v", got)
	}
	// A shared v1 vault is refused outright.
	g := newEnv(t)
	gdir := filepath.Join(g.home, "shared")
	_ = os.MkdirAll(filepath.Join(gdir, "secrets"), 0o700)
	shared := map[string]any{"version": 1, "id": vf.ID, "name": "shared", "key_id": vf.KeyID,
		"unlockers": append(vf.UnlockersOf(format.UnlockerPassphrase), format.Unlocker{Type: format.UnlockerMember, Label: "x", Recipient: vf.Members[0].Recipient, WrappedKey: []byte("w"), Created: vf.Unlockers[0].Created})}
	sd, _ := json.Marshal(shared)
	_ = os.WriteFile(filepath.Join(gdir, "vault.json"), sd, 0o600)
	g.mustRun("attach", "shared", gdir, "--no-request")
	r = g.runIn(testPass+"\n", "unlock", "shared", "--passphrase-stdin")
	expectCode(t, r, ExitError)
	if !strings.Contains(r.err, "share it again") {
		t.Fatalf("shared v1: %s", r)
	}
}

// ue1.6 through the CLI: passwd rotates; --keep-passphrase is explicit.
func TestPassphrasePolicyCLI(t *testing.T) {
	skipWindows(t)
	alice, dan := newEnv(t), newEnv(t)
	vdir := alice.initVault("team")
	alice.unlock("team")
	alice.set("K", "", "v")
	before, _ := format.ReadVaultFile(vdir)
	r := alice.mustRunIn(testPass+"\nnew vault passphrase\n", "passwd", "team", "--passphrase-stdin")
	if !strings.Contains(r.out, "vault key replaced") {
		t.Fatalf("passwd: %s", r)
	}
	after, _ := format.ReadVaultFile(vdir)
	if after.KeyID == before.KeyID {
		t.Fatal("passwd did not rotate")
	}
	join(t, alice, dan, "team", vdir, "dan")
	expectCode(t, alice.runIn(testPass+"\nx\n", "passwd", "team", "--no-rotate", "--passphrase-stdin"), ExitUsage) // shared: must rotate
	r = alice.mustRunIn(testPass+"\nnew vault passphrase\n", "member", "rm", "team", "dan", "--yes", "--folder-access-removed", "--keep-passphrase", "--passphrase-stdin")
	if !strings.Contains(r.out, "passphrase was kept") {
		t.Fatalf("keep: %s", r)
	}
	if !strings.Contains(alice.mustRun("member", "log", "team").out, "kept") {
		t.Fatal("kept policy not in the log")
	}
}

// Touch ID protects the identity, so it survives a rotation.
func TestTouchIDOnIdentity(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.touch.avail = true
	e.term.stdinTTY = true
	e.term.queue(testPass, testPass, testPass, testPass)
	e.mustRunIn("\n", "init", "main", "--path", filepath.Join(e.home, "vaults", "main"), "--as", testUser) // Enter: Touch ID yes
	e.term.stdinTTY = false
	st := decodeJSON[map[string]any](t, e.mustRun("touchid", "status", "--json").out)
	if st["touchid"] != true {
		t.Fatalf("touchid status: %v", st)
	}
	e.mustRun("unlock", "main") // Touch ID, no passphrase
	e.set("K", "", "touch-value")
	e.mustRunIn("rotated passphrase\n", "passwd", "main", "--passphrase-stdin")
	e.mustRun("lock", "--all")
	before := e.touch.unwraps
	if got := e.mustRun("get", "K").out; got != "touch-value\n" {
		t.Fatalf("after rotation: %q", got)
	}
	if e.touch.unwraps == before {
		t.Fatal("Touch ID was not used after the rotation")
	}
	e.mustRun("touchid", "off")
	e.mustRun("lock", "--all")
	expectCode(t, e.run("get", "K"), ExitLocked)
	e.mustRunIn(testPass+"\n", "touchid", "on", "--passphrase-stdin")
	e.touch.avail = false
	expectCode(t, e.run("touchid", "on"), ExitError)
	expectCode(t, e.run("touchid"), ExitUsage)
}

func TestTrustAndRebuild(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("K", "", "v")
	r := e.mustRun("trust", "main", "--json")
	j := decodeJSON[map[string]any](t, r.out)
	code := j["state_code"].(string)
	e.mustRun("trust", "main", "--expect", code)
	expectCode(t, e.run("trust", "main", "--accept-rollback"), ExitError) // nothing to accept
	myFP := e.fingerprintOf("main", testUser)
	// ue1.9: a code the folder doesn't meet is remembered; every command
	// refuses the vault until it is met, or the rollback is accepted.
	r = e.run("trust", "main", "--expect", "main@0 ABLE-ABLE-ABLE-ABLE-ABLE-ABLE")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "behind the state code you were given") {
		t.Fatalf("%s", r)
	}
	expectCode(t, e.run("get", "K"), ExitUnverified)
	expectCode(t, e.runIn("x", "set", "K2"), ExitUnverified)
	expectCode(t, e.run("trust", "main", "--accept-rollback", "--signer-fingerprint", "ACID-ACID-ACID-0000"), ExitError)
	e.mustRun("trust", "main", "--accept-rollback", "--signer-fingerprint", myFP)
	if got := e.mustRun("get", "K").out; got != "v\n" {
		t.Fatalf("after accepting: %q", got)
	}
	// Rebuild: new vault ID, same secrets, only member is me.
	oldVF, _ := format.ReadVaultFile(dir)
	e.mustRunIn(testPass+"\nrebuilt passphrase\n", "rebuild", "main", "--yes", "--passphrase-stdin")
	newVF, _ := format.ReadVaultFile(dir)
	if newVF.ID == oldVF.ID || len(newVF.Log) != 1 {
		t.Fatalf("rebuild: %+v", newVF)
	}
	if got := e.mustRun("get", "K").out; got != "v\n" {
		t.Fatalf("after rebuild: %q", got)
	}
}

func TestMemberRemoveAsksOnTerminal(t *testing.T) {
	skipWindows(t)
	owner := newEnv(t)
	dan := newEnv(t)
	vdir := owner.initVault("team")
	owner.unlock("team")
	join(t, owner, dan, "team", vdir, "dan")
	owner.term.stdinTTY = true
	expectCode(t, owner.runIn("n\n", "member", "rm", "team", "dan"), ExitError) // folder access not removed
	owner.term.queue(testPass)
	expectCode(t, owner.runIn("y\nn\n", "member", "rm", "team", "dan"), ExitError) // declined
	if l := decodeJSON[map[string]any](t, owner.mustRun("member", "list", "team", "--json").out); len(l["members"].([]any)) != 2 {
		t.Fatalf("declined removal must change nothing: %v", l)
	}
	owner.term.queue(testPass)
	owner.mustRunIn("y\ny\n", "member", "rm", "team", "dan")
}

func TestIdentityExportImportAndSecondMac(t *testing.T) {
	skipWindows(t)
	owner := newEnv(t)
	mac1 := newEnv(t)
	mac2 := newEnv(t)
	vdir := owner.initVault("team")
	owner.unlock("team")
	owner.set("EXAMPLE_TEAM_KEY", "", "team-secret-value")
	join(t, owner, mac1, "team", vdir, "dan")

	file := filepath.Join(mac1.home, "identity.export")
	expectCode(t, mac2.run("identity", "export", file), ExitError) // no identity there yet
	mac1.mustRunIn(personalPass+"\n"+"transfer passphrase 1\n", "identity", "export", file, "--passphrase-stdin")
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("export file: %v %v", fi, err)
	}
	expectCode(t, mac1.runIn(personalPass+"\n"+"transfer passphrase 1\n", "identity", "export", file, "--passphrase-stdin"), ExitError) // never overwrites
	expectCode(t, mac2.runIn("wrong transfer pass\nnew personal pass 22\n", "identity", "import", file, "--passphrase-stdin"), ExitError)
	mac2.mustRunIn("transfer passphrase 1\nmac two passphrase 2\n", "identity", "import", file, "--passphrase-stdin")

	// Same person on a second Mac: no fingerprint question (dan was added by
	// the owner, so it IS asked: dan types the owner's fingerprint).
	ownerFP := owner.fingerprintOf("team", testUser)
	r := mac2.runIn("", "attach", "team", vdir)
	expectCode(t, r, ExitError)
	mac2.mustRun("detach", "team")
	r = mac2.mustRun("attach", "team", vdir, "--signer-fingerprint", ownerFP)
	if !strings.Contains(r.out, "Registered 'team' (1 keys)") || strings.Contains(r.out, "not a member") {
		t.Fatalf("second Mac attach: %s", r)
	}
	if got := mac2.runIn("mac two passphrase 2\n", "get", "EXAMPLE_TEAM_KEY", "--passphrase-stdin"); got.out != "team-secret-value\n" {
		t.Fatalf("second Mac read: %s", got)
	}
	// The owner's own second Mac: genesis signed by the owner, so no
	// fingerprint question, but the head is shown (S2).
	ofile := filepath.Join(owner.home, "owner.export")
	owner.mustRunIn(testPass+"\n"+"transfer passphrase 2\n", "identity", "export", ofile, "--passphrase-stdin")
	omac2 := newEnv(t)
	omac2.mustRunIn("transfer passphrase 2\nowner mac two pass\n", "identity", "import", ofile, "--passphrase-stdin")
	r = omac2.mustRun("attach", "team", vdir)
	if !strings.Contains(r.err, "Trusting vault 'team' at team@") {
		t.Fatalf("owner second Mac first pin: %s", r)
	}
	// In --json mode too, on stderr (Security's request).
	omac3 := newEnv(t)
	omac3.mustRunIn("transfer passphrase 2\nowner mac three pass\n", "identity", "import", ofile, "--passphrase-stdin")
	r = omac3.mustRun("attach", "team", vdir, "--json")
	if !strings.Contains(r.err, "state_code_checked: false") {
		t.Fatalf("--json first pin must still say it was unchecked: %s", r)
	}
	expectCode(t, mac2.run("identity", "bogus", file), ExitUsage)
}

func TestAttachFilesPendingRequestOnce(t *testing.T) {
	skipWindows(t)
	owner := newEnv(t)
	dan := newEnv(t)
	vdir := owner.initVault("team")
	dan.mustRunIn(personalPass+"\n", "attach", "team", vdir, "--as", "dan", "--passphrase-stdin")
	dan.mustRun("detach", "team")
	r := dan.mustRunIn(personalPass+"\n", "attach", "team", vdir, "--passphrase-stdin") // request already pending
	if !strings.Contains(r.out, "already waiting") {
		t.Fatalf("%s", r)
	}
	reqs := decodeJSON[map[string]any](t, owner.mustRun("member", "requests", "team", "--json").out)
	if len(reqs["requests"].([]any)) != 1 {
		t.Fatalf("one request expected: %v", reqs)
	}
	// Interactive first-time attach asks for a name and passphrase.
	eve := newEnv(t)
	eve.term.stdinTTY = true
	eve.term.queue(personalPass, personalPass)
	eve.mustRunIn("eve\nn\n", "attach", "team", vdir)
	if !strings.Contains(owner.mustRun("member", "requests", "team").out, "eve") {
		t.Fatal("eve's request should be listed")
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Attacker 6 / ue1.4 through the CLI: a planted staging folder is never
// moved over real secrets: not by read-only commands, and not by a write
// unless every staged file opens under the verified key.
func TestPlantedStagingNeverOverwrites(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("API_KEY", "", "real")
	e.mustRunIn(testPass+"\nrotated passphrase\n", "passwd", "main", "--passphrase-stdin")
	vf, _ := format.ReadVaultFile(dir)
	before, _ := os.ReadFile(filepath.Join(dir, "secrets", "API_KEY.age"))
	stage := filepath.Join(dir, "secrets", ".sv-rotate-"+vf.KeyID)
	if err := os.MkdirAll(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(stage, "API_KEY.age"), []byte("attacker junk"), 0o600)
	_ = os.WriteFile(filepath.Join(stage, "MANIFEST"), []byte("secrets-vault rotation v1\nkey "+vf.KeyID+"\nAPI_KEY.age\n"), 0o600)

	e.mustRun("info", "API_KEY")
	e.mustRun("get", "API_KEY")
	e.mustRun("list")
	if after, _ := os.ReadFile(filepath.Join(dir, "secrets", "API_KEY.age")); string(after) != string(before) {
		t.Fatal("a read-only command moved staged files")
	}
	r := e.runIn("new", "set", "OTHER")
	expectCode(t, r, ExitError)
	if after, _ := os.ReadFile(filepath.Join(dir, "secrets", "API_KEY.age")); string(after) != string(before) {
		t.Fatal("a write moved a staged file that does not open under the key")
	}
	if !strings.Contains(r.err, "doctor main --quarantine-staging") {
		t.Fatalf("the refusal should offer the way out: %s", r)
	}
	// ue1.10: doctor moves it aside (never deletes), then writes work.
	if !strings.Contains(e.mustRun("doctor", "main").out, "--quarantine-staging") {
		t.Fatal("doctor should report the folder")
	}
	r = e.mustRun("doctor", "main", "--quarantine-staging")
	if !strings.Contains(r.out, "moved aside to quarantine/") {
		t.Fatalf("doctor: %s", r)
	}
	q, _ := filepath.Glob(filepath.Join(dir, "quarantine", "sv-rotate-"+vf.KeyID+"-*", "API_KEY.age"))
	if len(q) != 1 {
		t.Fatalf("quarantined files: %v", q)
	}
	e.mustRunIn("new", "set", "OTHER")
	if after, _ := os.ReadFile(filepath.Join(dir, "secrets", "API_KEY.age")); string(after) != string(before) {
		t.Fatal("API_KEY changed")
	}
	// A staging folder for a key the chain never had blocks writes, and
	// doctor moves that aside too.
	_ = os.MkdirAll(filepath.Join(dir, "secrets", ".sv-rotate-abababababababababababababababab"), 0o700)
	r = e.runIn("new", "set", "OTHER")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "newer state") || !strings.Contains(r.err, "--quarantine-staging") {
		t.Fatalf("%s", r)
	}
	e.mustRun("doctor", "main", "--quarantine-staging")
	e.mustRunIn("newer", "set", "OTHER")
	// A symlinked secrets folder is refused.
	elsewhere := t.TempDir()
	_ = os.Rename(filepath.Join(dir, "secrets"), filepath.Join(elsewhere, "real"))
	if err := os.Symlink(filepath.Join(elsewhere, "real"), filepath.Join(dir, "secrets")); err != nil {
		t.Fatal(err)
	}
	r = e.runIn("new", "set", "OTHER")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "symlink") {
		t.Fatalf("%s", r)
	}
}

// ue1.8 A: an older build rewrites config.toml (dropping fields it doesn't
// know). The vault ID lives in registry.toml, which older builds never
// touch, so M1 still holds; and if the registered ID is lost anyway while
// this machine trusts a vault in that folder, it refuses rather than
// trusting on first use.
func TestRegistryIDSurvivesOldBuilds(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("K", "", "v")
	cfg, err := os.ReadFile(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfg), "id =") {
		t.Fatalf("the vault ID must not be in config.toml: %s", cfg)
	}
	// An old build's save: same content, re-encoded (simulated by a rewrite).
	if err := os.WriteFile(e.cfg, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	// M1 still holds: a vault.json for another vault is refused.
	e2 := newEnv(t)
	e2.initVault("evil")
	evil, _ := os.ReadFile(filepath.Join(e2.home, "vaults", "evil", "vault.json"))
	e.activate()
	good, _ := os.ReadFile(filepath.Join(dir, "vault.json"))
	_ = os.WriteFile(filepath.Join(dir, "vault.json"), evil, 0o600)
	r := e.runIn(testPass+"\n", "get", "K", "--passphrase-stdin")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "different vault") {
		t.Fatalf("%s", r)
	}
	_ = os.WriteFile(filepath.Join(dir, "vault.json"), good, 0o600)
	// The registered ID lost (registry.toml removed): refuse, don't TOFU.
	_ = os.Remove(filepath.Join(filepath.Dir(e.cfg), "registry.toml"))
	_ = os.WriteFile(filepath.Join(dir, "vault.json"), evil, 0o600)
	r = e.runIn(testPass+"\n", "get", "K", "--passphrase-stdin")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "lost its record") {
		t.Fatalf("%s", r)
	}
	_ = os.WriteFile(filepath.Join(dir, "vault.json"), good, 0o600)
	expectCode(t, e.runIn(testPass+"\n", "get", "K", "--passphrase-stdin"), ExitUnverified) // even for the genuine file
	// detach + attach registers it again (and finds the existing pin).
	e.mustRun("detach", "main")
	e.mustRun("attach", "main", dir)
	if got := e.mustRunIn(testPass+"\n", "get", "K", "--passphrase-stdin").out; got != "v\n" {
		t.Fatalf("after re-attach: %q", got)
	}
}

// ue1.8: a vault.json newer than this build tells the user how to upgrade.
func TestNewerVaultMessage(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	data, _ := os.ReadFile(filepath.Join(dir, "vault.json"))
	data = []byte(strings.Replace(string(data), `"version": 3`, `"version": 4`, 1))
	_ = os.WriteFile(filepath.Join(dir, "vault.json"), data, 0o600)
	r := e.runIn(testPass+"\n", "unlock", "main", "--passphrase-stdin")
	expectCode(t, r, ExitError)
	if !strings.Contains(r.err, "vault 'main' was saved by a newer secrets-vault") || !strings.Contains(r.err, "brew upgrade secrets-vault") {
		t.Fatalf("%s", r)
	}
	f := newEnv(t)
	r = f.run("attach", "x", dir)
	if !strings.Contains(r.err, "brew upgrade secrets-vault") {
		t.Fatalf("attach: %s", r)
	}
}

// ue1.10: a tampered vault is never reported as "key not found", and list
// --json names it with an error instead of leaving it out; a first-use pin
// is in the --json output.
func TestTamperedVaultNotKeyNotFound(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	dir := e.initVault("main")
	e.unlock("main")
	e.set("K", "", "v")
	vf, _ := format.ReadVaultFile(dir)
	vf.Unlockers[0].WrappedKey[3] ^= 1
	data, _ := json.MarshalIndent(vf, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "vault.json"), data, 0o600)
	for _, args := range [][]string{{"get", "K"}, {"info", "K"}, {"rm", "K", "--yes"}, {"get", "MISSING"}} {
		r := e.run(args...)
		expectCode(t, r, ExitUnverified)
		if !strings.Contains(r.err, "changed outside secrets-vault") {
			t.Fatalf("%v: %s", args, r)
		}
	}
	l := decodeJSON[[]map[string]any](t, e.mustRun("list", "--json").out)
	if len(l) != 1 || l[0]["vault"] != "main" || l[0]["error"] == nil {
		t.Fatalf("list --json: %v", l)
	}

	// First pin in --json: on stdout too, with head, signer and members.
	f := newEnv(t)
	g := newEnv(t)
	gdir := g.initVault("team")
	ofile := filepath.Join(g.home, "id.export")
	g.mustRunIn(testPass+"\ntransfer passphrase 9\n", "identity", "export", ofile, "--passphrase-stdin")
	f.mustRunIn("transfer passphrase 9\nsecond mac pass\n", "identity", "import", ofile, "--passphrase-stdin")
	out := decodeJSON[map[string]any](t, f.mustRun("attach", "team", gdir, "--json").out)
	fp, _ := out["first_pin"].(map[string]any)
	if out["state_code_checked"] != false || fp == nil || fp["signed_by"] != testUser || len(fp["members"].([]any)) != 1 {
		t.Fatalf("attach --json: %v", out)
	}
}

func hasMemberEvent(evs []struct{ Action, Member string }, action, member string) bool {
	for _, e := range evs {
		if e.Action == action && e.Member == member {
			return true
		}
	}
	return false
}
