package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

func TestSharingFlow(t *testing.T) {
	alice, bob, carol := newPerson(t, "alice"), newPerson(t, "bob"), newPerson(t, "carol")
	v := newVault(t, alice)
	putSecret(t, v.dir, v.key, "API_KEY", "v1")
	v.join(t, alice, bob)
	v.join(t, bob, carol) // any member may approve

	for _, p := range []*person{alice, bob, carol} {
		k, err := openAs(t, v.dir, p)
		if err != nil || !bytes.Equal(k.Bytes(), v.key.Bytes()) {
			t.Fatalf("%s cannot open: %v", p.pub.Name, err)
		}
	}
	ov, err := Inspect(v.dir, v.c)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Member{}
	for _, m := range ov.Members {
		got[m.Identity.Name] = m
	}
	if got["alice"].Role != RoleOwner || got["alice"].AddedBy != "alice" || got["bob"].AddedBy != "alice" || got["carol"].AddedBy != "bob" {
		t.Fatalf("members: %+v", ov.Members)
	}
	if got["carol"].Identity.Fingerprint != carol.pub.Fingerprint || !ov.HasPassphrase || len(ov.Warnings) != 0 {
		t.Fatalf("overview: %+v", ov)
	}

	res := v.remove(t, alice, "carol")
	if !slices.Equal(res.ExposedKeys, []string{"API_KEY"}) || res.Removed.Identity.Name != "carol" || res.Passphrase != format.PassDropped {
		t.Fatalf("remove result: %+v", res)
	}
	if _, err := openAs(t, v.dir, carol); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatal("removed member can still open the vault")
	}
	if k, err := openAs(t, v.dir, bob); err != nil || !bytes.Equal(k.Bytes(), v.key.Bytes()) {
		t.Fatalf("bob after removal: %v", err)
	}
	// ue1.6: the passphrase was dropped by default.
	if v.c.HasPassphrase() {
		t.Fatal("passphrase kept by default")
	}
	if got, err := crypto.ReadSecret(v.dir, "API_KEY", v.key); err != nil || string(got) != "v1" {
		t.Fatalf("secret after rotation: %q %v", got, err)
	}
	if v.c.Records[len(v.c.Records)-1].Passphrase != format.PassDropped {
		t.Fatal("policy not recorded")
	}
}

// TestUE11Regression is issue ue1.1 end to end at the package level:
// mallory, who can write the folder but is not a member, plants a member
// unlocker named "bob" for her own key. The vault no longer verifies, so
// the next removal can't wrap the rotated key for her.
func TestUE11Regression(t *testing.T) {
	alice, bob, carol, mallory := newPerson(t, "alice"), newPerson(t, "bob"), newPerson(t, "carol"), newPerson(t, "mallory")
	v := newVault(t, alice)
	v.join(t, alice, bob)
	v.join(t, alice, carol)
	putSecret(t, v.dir, v.key, "API_KEY", "secret")

	var vf map[string]any
	_ = json.Unmarshal(mustReadFile(t, format.VaultFilePath(v.dir)), &vf)
	us := vf["unlockers"].([]any)
	planted := map[string]any{}
	for _, x := range us {
		if x.(map[string]any)["label"] == "bob" {
			for k, val := range x.(map[string]any) {
				planted[k] = val
			}
		}
	}
	planted["label"] = "bob"
	planted["recipient"] = mallory.pub.Recipient
	vf["unlockers"] = append(us, planted)
	data, _ := json.MarshalIndent(vf, "", "  ")
	mustWriteFile(t, format.VaultFilePath(v.dir), data)

	if _, _, err := Load(v.dir, v.c.File.ID); err == nil {
		t.Fatal("vault with a planted unlocker verified")
	}
	// Even with the stale verified chain in hand, the rotation refuses:
	// vault.json no longer parses as a consistent file, and it is not the
	// bytes that were verified (CAS).
	if _, err := Remove(v.dir, v.c, v.key, alice.un, "carol", RotateOptions{Now: t0}); err == nil {
		t.Fatal("remove over a tampered vault succeeded")
	}
	// The vault key in vault.json was never wrapped for mallory.
	var raw format.VaultFile
	_ = json.Unmarshal(mustReadFile(t, format.VaultFilePath(v.dir)), &raw)
	if _, err := crypto.Unlock(&raw, mallory.wrapper(t)); err == nil {
		t.Fatal("mallory can open the vault")
	}
}

// Attacker 1: every kind of edit by a non-member is refused at Load.
func TestAttacker1Planting(t *testing.T) {
	alice, bob, mallory := newPerson(t, "alice"), newPerson(t, "bob"), newPerson(t, "mallory")
	v := newVault(t, alice)
	v.join(t, alice, bob)
	orig := mustReadFile(t, format.VaultFilePath(v.dir))
	edits := map[string]func(vf *format.VaultFile){
		"plant non-member unlocker": func(vf *format.VaultFile) {
			vf.Members = append(vf.Members, format.Member{Name: "mallory", Recipient: mallory.pub.Recipient, SignKey: mallory.pub.SignKey, Role: RoleMember})
			format.SortMembers(vf.Members)
			u := vf.Unlockers[1]
			u.Label, u.Recipient = "mallory", mallory.pub.Recipient
			vf.Unlockers = append(vf.Unlockers, u)
		},
		"swap bob's recipient": func(vf *format.VaultFile) {
			for i := range vf.Members {
				if vf.Members[i].Name == "bob" {
					vf.Members[i].Recipient = mallory.pub.Recipient
				}
			}
			for i := range vf.Unlockers {
				if vf.Unlockers[i].Label == "bob" {
					vf.Unlockers[i].Recipient = mallory.pub.Recipient
				}
			}
		},
		"relabel": func(vf *format.VaultFile) {
			for i := range vf.Members {
				if vf.Members[i].Name == "bob" {
					vf.Members[i].Name = "bobby"
				}
			}
			for i := range vf.Unlockers {
				if vf.Unlockers[i].Label == "bob" {
					vf.Unlockers[i].Label = "bobby"
				}
			}
		},
		"promote to owner": func(vf *format.VaultFile) {
			for i := range vf.Members {
				vf.Members[i].Role = RoleOwner
			}
		},
		"edit a wrapped key": func(vf *format.VaultFile) { vf.Unlockers[0].WrappedKey[3] ^= 1 },
		"drop the log tail":  func(vf *format.VaultFile) { vf.Log = vf.Log[:1] },
		"forge a record by mallory": func(vf *format.VaultFile) {
			vf.Log[1].By = "mallory"
		},
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			vf, err := format.ParseVaultFile(orig)
			if err != nil {
				t.Fatal(err)
			}
			edit(vf)
			data, err := json.Marshal(vf)
			if err != nil {
				t.Fatal(err)
			}
			mustWriteFile(t, format.VaultFilePath(v.dir), data)
			if _, _, err := Load(v.dir, v.c.File.ID); err == nil {
				t.Fatal("tampered vault.json verified")
			}
		})
	}
	mustWriteFile(t, format.VaultFilePath(v.dir), orig)
	if _, _, err := Load(v.dir, v.c.File.ID); err != nil {
		t.Fatal(err)
	}
}

// forgedVault builds a whole vault.json signed by mallory: genesis by
// mallory, then mallory "adds" each victim. id "" means a fresh vault ID.
func forgedVault(t *testing.T, mallory *person, id string, victims ...*person) (*format.VaultFile, *crypto.VaultKey) {
	t.Helper()
	key, _ := crypto.NewVaultKey()
	mw, _ := mallory.un.MemberWrapper()
	vf, err := crypto.NewVaultFile("team", key, []crypto.KeyWrapper{mw})
	if err != nil {
		t.Fatal(err)
	}
	if id != "" {
		vf.ID = id
	}
	if err := Genesis(vf, mallory.un, t0); err != nil {
		t.Fatal(err)
	}
	c, err := Verify(vf, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range victims {
		w, _ := crypto.NewMemberWrapper(p.pub.Name, p.pub.Recipient)
		u, _ := w.Wrap(key)
		m := format.Member{Name: p.pub.Name, Recipient: p.pub.Recipient, SignKey: p.pub.SignKey, Role: RoleMember}
		next, err := c.Append(mallory.un, Change{Op: format.OpAddMember, Member: &m, KeyID: key.ID(), Unlockers: append(slices.Clone(c.File.Unlockers), u), Time: t0})
		if err != nil {
			t.Fatal(err)
		}
		if c, err = Verify(next, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	return c.File, key
}

// Attacker 2: whole-file substitution with the same or a new vault ID.
func TestAttacker2Substitution(t *testing.T) {
	alice, mallory := newPerson(t, "alice"), newPerson(t, "mallory")
	v := newVault(t, alice)
	pin := pinOf(v.c)

	// Same ID: a valid chain, but not containing the pinned head.
	forged, _ := forgedVault(t, mallory, v.c.File.ID, alice)
	c, err := Verify(forged, nil, v.c.File.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := Classify(c, pin); got.Outcome != Rollback {
		t.Fatalf("same-id substitution classified %v", got.Outcome)
	}
	// New ID (M1): refused because it isn't the registered vault.
	fresh, _ := forgedVault(t, mallory, "", alice)
	if _, err := Verify(fresh, nil, v.c.File.ID); !errors.Is(err, ErrOtherVault) {
		t.Fatalf("fresh-id substitution = %v", err)
	}
	// First use: alice was added by mallory, not by herself, so the CLI
	// asks for mallory's fingerprint (design section 7).
	if by, _, ok := c.WhoAdded(alice.pub.Recipient, alice.pub.SignKey); !ok || by != "mallory" {
		t.Fatalf("WhoAdded = %q %v", by, ok)
	}
	// M2: mallory can't make a genesis that names alice as its owner.
	key, _ := crypto.NewVaultKey()
	aw, _ := alice.un.MemberWrapper()
	vf, _ := crypto.NewVaultFile("team", key, []crypto.KeyWrapper{aw})
	if err := Genesis(vf, alice.un, t0); err != nil {
		t.Fatal(err)
	}
	vf.Log[0].By = "mallory"
	vf.Log[0].Sig, _ = mallory.un.Sign(recordDomain, vf.Log[0].Body)
	if _, err := Verify(vf, nil, ""); !errors.Is(err, ErrTampered) {
		t.Fatalf("genesis signed by someone else = %v", err)
	}
}

// Attacker 3: a removed member signs a change on top of the head, or forks
// from before their removal.
func TestAttacker3RemovedMember(t *testing.T) {
	alice, bob, carol, mallory := newPerson(t, "alice"), newPerson(t, "bob"), newPerson(t, "carol"), newPerson(t, "mallory")
	v := newVault(t, alice)
	v.join(t, alice, bob)
	v.join(t, alice, carol)
	before := v.c
	oldKey := v.key
	v.remove(t, alice, "carol")
	pin := pinOf(v.c)

	// On top of the head: carol is not a member any more.
	if _, err := v.c.Append(carol.un, Change{Op: format.OpSetUnlocker, KeyID: v.c.File.KeyID, Unlockers: v.c.File.Unlockers}); !errors.Is(err, ErrNotMember) {
		t.Fatalf("removed member appended: %v", err)
	}
	forged := *v.c.File
	entry, _ := signRecord(carol.un, &format.Record{Seq: len(v.c.Records), Prev: v.c.Head().Head, VaultID: v.c.File.ID, Time: t0,
		Op: format.OpSetUnlocker, KeyID: v.c.File.KeyID, MembersHash: v.c.Head().MembersHash, UnlockersHash: v.c.Head().UnlockersHash})
	forged.Log = append(slices.Clone(forged.Log), entry)
	if _, err := Verify(&forged, nil, ""); !errors.Is(err, ErrTampered) {
		t.Fatalf("record by a removed member verified: %v", err)
	}
	// Fork from before the removal, using the old key she knows.
	w, _ := crypto.NewMemberWrapper("mallory", mallory.pub.Recipient)
	u, _ := w.Wrap(oldKey)
	m := format.Member{Name: "mallory", Recipient: mallory.pub.Recipient, SignKey: mallory.pub.SignKey, Role: RoleMember}
	fork, err := before.Append(carol.un, Change{Op: format.OpAddMember, Member: &m, KeyID: oldKey.ID(), Unlockers: append(slices.Clone(before.File.Unlockers), u)})
	if err != nil {
		t.Fatal(err)
	}
	fc, err := Verify(fork, nil, v.c.File.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := Classify(fc, pin); got.Outcome != Rollback {
		t.Fatalf("removed member's fork classified %v", got.Outcome)
	}
}

// Attacker 4: rollback to an older valid vault.json (+ secrets), and the
// state code.
func TestAttacker4Rollback(t *testing.T) {
	alice, bob, carol := newPerson(t, "alice"), newPerson(t, "bob"), newPerson(t, "carol")
	v := newVault(t, alice)
	v.join(t, alice, bob)
	v.join(t, alice, carol)
	putSecret(t, v.dir, v.key, "API_KEY", "old")
	snapshot := filepath.Join(t.TempDir(), "snap")
	copyDir(t, v.dir, snapshot)
	bobPin := pinOf(v.c) // bob last saw this state

	v.remove(t, alice, "carol")
	code := StateCode(v.c, v.c.Head().Seq)
	alicePin := pinOf(v.c)
	putSecret(t, v.dir, v.key, "API_KEY", "new")
	putSecret(t, v.dir, v.key, "AFTER", "x")

	// carol restores her snapshot of vault.json and the API_KEY file, but
	// leaves AFTER behind (a sloppy rollback).
	mustWriteFile(t, format.VaultFilePath(v.dir), mustReadFile(t, format.VaultFilePath(snapshot)))
	sp, _ := format.SecretPath(snapshot, "API_KEY")
	dp, _ := format.SecretPath(v.dir, "API_KEY")
	mustWriteFile(t, dp, mustReadFile(t, sp))

	rolled, _, err := Load(v.dir, v.c.File.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := Classify(rolled, alicePin); got.Outcome != Rollback {
		t.Fatalf("alice (saw the removal) classified %v", got.Outcome)
	}
	// bob's pin is the rolled-back state itself: indistinguishable...
	if got := Classify(rolled, bobPin); got.Outcome != Same {
		t.Fatalf("bob classified %v", got.Outcome)
	}
	// ...but the write guard finds AFTER, sealed under a key the rolled-back
	// chain never had, and blocks writes.
	rep, err := CheckFolder(v.dir, rolled)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Blocking() || !slices.Equal(rep.Unknown, []string{"AFTER"}) {
		t.Fatalf("write guard: %+v", rep)
	}
	// And the state code from alice refuses carol's state.
	if err := MatchStateCode(rolled, code); !errors.Is(err, ErrBehindCode) {
		t.Fatalf("state code on rolled-back folder = %v", err)
	}
	if err := MatchStateCode(v.c, code); err != nil {
		t.Fatalf("state code on the real state = %v", err)
	}
	full := "team@" + strings.Fields(code)[0][len("team@"):] + " " + v.c.Head().Head
	if err := MatchStateCode(v.c, full); err != nil {
		t.Fatalf("full-hash code = %v", err)
	}
	if err := MatchStateCode(v.c, "nonsense"); !errors.Is(err, ErrBadCode) {
		t.Fatalf("bad code = %v", err)
	}
	// S1: six words.
	if words := strings.Split(strings.Fields(code)[1], "-"); len(words) != 6 {
		t.Fatalf("state code %q", code)
	}
}

// Exposure report: after the honest state returns, a secret written under
// the rolled-back (retired) key is named.
func TestExposureReport(t *testing.T) {
	alice, carol := newPerson(t, "alice"), newPerson(t, "carol")
	v := newVault(t, alice)
	v.join(t, alice, carol)
	oldKey := v.key
	v.remove(t, alice, "carol")
	putSecret(t, v.dir, oldKey, "STALE", "written by bob under the old key")
	rep, err := CheckFolder(v.dir, v.c)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Blocking() || len(rep.Retired) != 1 || rep.Retired[0].Name != "STALE" || rep.Retired[0].Removed != "carol" {
		t.Fatalf("report: %+v", rep)
	}
}

// A newer sync-conflict copy of vault.json blocks writes.
func TestWriteGuardNewerCopy(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	v := newVault(t, alice)
	old := mustReadFile(t, format.VaultFilePath(v.dir))
	oldChain := v.c
	v.join(t, alice, bob)
	mustWriteFile(t, filepath.Join(v.dir, "vault (alice's conflicted copy 2026-11-20).json"), mustReadFile(t, format.VaultFilePath(v.dir)))
	mustWriteFile(t, format.VaultFilePath(v.dir), old)
	rep, err := CheckFolder(v.dir, oldChain)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.NewerCopy || !rep.Blocking() {
		t.Fatalf("report: %+v", rep)
	}
}

// Attacker 5: request tampering, replay into another vault, swap after the
// check, re-adding a removed key (G7).
func TestAttacker5Requests(t *testing.T) {
	alice, bob, mallory := newPerson(t, "alice"), newPerson(t, "bob"), newPerson(t, "mallory")
	v := newVault(t, alice)
	if err := WriteRequest(v.dir, bob.un, t0); err != nil {
		t.Fatal(err)
	}
	path, _ := RequestPath(v.dir, "bob")
	orig := mustReadFile(t, path)
	req, err := ReadRequest(v.dir, v.c.File.ID, "bob")
	if err != nil || req.Identity.Fingerprint != bob.pub.Fingerprint || req.Identity.SignKey != bob.pub.SignKey {
		t.Fatalf("request: %+v %v", req, err)
	}

	// Edit the body (swap in mallory's age key): the signature breaks.
	var rf requestFile
	_ = json.Unmarshal(orig, &rf)
	rf.Body = bytes.Replace(rf.Body, []byte(bob.pub.Recipient), []byte(mallory.pub.Recipient), 1)
	edited, _ := json.Marshal(rf)
	if _, err := ParseRequest(edited, v.c.File.ID); !errors.Is(err, ErrMalformed) {
		t.Fatalf("edited request = %v", err)
	}
	// Mallory signs a request pairing bob's age key with her signing key:
	// valid signature, but a different fingerprint than bob reads out.
	var b requestBody
	_ = json.Unmarshal(orig, &rf)
	_ = json.Unmarshal(rf.Body, &b)
	b.SignKey = mallory.pub.SignKey
	body, _ := json.Marshal(b)
	sig, _ := mallory.un.Sign(requestDomain, body)
	mixed, _ := json.Marshal(requestFile{Version: requestVersion, Body: body, Sig: sig})
	mr, err := ParseRequest(mixed, v.c.File.ID)
	if err != nil || mr.Identity.Fingerprint == bob.pub.Fingerprint {
		t.Fatalf("mixed-key request: %+v %v", mr, err)
	}
	// Copied into another vault: refused.
	other := newVault(t, alice)
	if _, err := ParseRequest(orig, other.c.File.ID); !errors.Is(err, ErrMalformed) {
		t.Fatalf("request for another vault = %v", err)
	}
	// Swapped after the approver checked bob's fingerprint: refused.
	mustWriteFile(t, path, mixed)
	if _, _, err := ApproveRequest(v.dir, v.c, v.key, alice.un, "bob", bob.pub.Fingerprint, false, t0); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("swapped request approved: %v", err)
	}
	mustWriteFile(t, path, orig)
	// A wrong or old-format fingerprint is refused; typing it loosely works.
	if _, _, err := ApproveRequest(v.dir, v.c, v.key, alice.un, "bob", "DUTCH-PREDICT-1767", false, t0); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("old two-word fingerprint = %v", err)
	}
	loose := strings.ToLower(strings.ReplaceAll(bob.pub.Fingerprint, "-", " "))
	c, m, err := ApproveRequest(v.dir, v.c, v.key, alice.un, "bob", loose, false, t0)
	if err != nil || m.AddedBy != "alice" {
		t.Fatalf("approve: %+v %v", m, err)
	}
	v.c = c
	if _, err := ReadRequest(v.dir, v.c.File.ID, "bob"); !errors.Is(err, ErrNoRequest) {
		t.Fatal("request not deleted")
	}
	// G7: bob removed, then his old request replayed.
	v.remove(t, alice, "bob")
	mustWriteFile(t, path, orig)
	if _, _, err := ApproveRequest(v.dir, v.c, v.key, alice.un, "bob", bob.pub.Fingerprint, false, t0); !errors.Is(err, ErrPreviouslyRemoved) {
		t.Fatalf("re-add of a removed key = %v", err)
	}
	if c, _, err := ApproveRequest(v.dir, v.c, v.key, alice.un, "bob", bob.pub.Fingerprint, true, t0); err != nil {
		t.Fatalf("explicit re-add = %v", err)
	} else {
		v.c = c
	}
}

// Attacker 7 (ue1.6): after member rm (default) or passwd, the old
// passphrase plus an old copy of vault.json opens nothing written later.
func TestPassphraseAfterRemoveAndPasswd(t *testing.T) {
	alice, carol := newPerson(t, "alice"), newPerson(t, "carol")
	v := newVault(t, alice)
	v.join(t, alice, carol)
	oldVF := v.c.File
	v.remove(t, alice, "carol")
	if _, err := crypto.Unlock(v.c.File, pass(t, vaultPass)); err == nil {
		t.Fatal("old passphrase still opens after removal")
	}
	// Keeping it is explicit and recorded.
	v2 := newVault(t, alice)
	v2.join(t, alice, carol)
	res, err := Remove(v2.dir, v2.c, v2.key, alice.un, "carol", RotateOptions{Passphrase: format.PassKept, Keep: pass(t, vaultPass), Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	if res.Chain.Records[len(res.Chain.Records)-1].Passphrase != format.PassKept || !res.Chain.HasPassphrase() {
		t.Fatal("kept passphrase not recorded")
	}
	if _, err := Remove(v2.dir, res.Chain, res.NewKey, alice.un, "alice", RotateOptions{Passphrase: format.PassKept, Keep: pass(t, "wrong"), Now: t0}); err == nil {
		t.Fatal("kept a passphrase that was not proved")
	}
	// passwd rotates: a secret written after it doesn't open with the key
	// from the old vault.json + old passphrase.
	v3 := newVault(t, alice)
	old := v3.c.File
	r3, err := Passwd(v3.dir, v3.c, v3.key, alice.un, pass(t, "new passphrase"), true, RotateOptions{Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	putSecret(t, v3.dir, r3.NewKey, "LATER", "x")
	oldKey, err := crypto.Unlock(old, pass(t, vaultPass))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.ReadSecret(v3.dir, "LATER", oldKey); err == nil {
		t.Fatal("old passphrase + old vault.json reads a later secret")
	}
	if k, err := crypto.Unlock(r3.Chain.File, pass(t, "new passphrase")); err != nil || k.ID() != r3.NewKey.ID() {
		t.Fatalf("new passphrase: %v", err)
	}
	// --no-rotate keeps the key and records a set-unlocker.
	r4, err := Passwd(v3.dir, r3.Chain, r3.NewKey, alice.un, pass(t, "third"), false, RotateOptions{Now: t0})
	if err != nil || r4.NewKey != nil || r4.Chain.File.KeyID != r3.NewKey.ID() {
		t.Fatalf("no-rotate passwd: %+v %v", r4, err)
	}
	_ = oldVF
}

// A forged passphrase policy (or a passphrase unlocker the last record
// dropped) fails verification.
func TestPassphrasePolicyCannotBeFaked(t *testing.T) {
	alice, carol := newPerson(t, "alice"), newPerson(t, "carol")
	v := newVault(t, alice)
	v.join(t, alice, carol)
	withPass := v.c.File
	v.remove(t, alice, "carol")
	vf := *v.c.File
	vf.Unlockers = append(slices.Clone(vf.Unlockers), withPass.UnlockersOf(format.UnlockerPassphrase)[0])
	if _, err := Verify(&vf, nil, ""); !errors.Is(err, ErrTampered) {
		t.Fatalf("re-added passphrase verified: %v", err)
	}
	vf = *v.c.File
	vf.Log = slices.Clone(vf.Log)
	last := &vf.Log[len(vf.Log)-1]
	last.Body = bytes.Replace(last.Body, []byte(`"dropped"`), []byte(`"kept"`), 1)
	if _, err := Verify(&vf, nil, ""); !errors.Is(err, ErrTampered) {
		t.Fatalf("edited policy verified: %v", err)
	}
}

// M1 at the Load level: a vault.json with another ID is refused.
func TestLoadRegisteredID(t *testing.T) {
	alice := newPerson(t, "alice")
	v := newVault(t, alice)
	other := newVault(t, alice)
	if _, _, err := Load(v.dir, other.c.File.ID); !errors.Is(err, ErrOtherVault) {
		t.Fatalf("Load with another registered id = %v", err)
	}
}

// Attacker 8 / M3 is decided by the CLI (it needs the legacy pin); here:
// Load reports version 1 as ErrOldFormat and never verifies it.
func TestLoadV1(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "v")
	key, _ := crypto.NewVaultKey()
	vf, _ := crypto.NewVaultFile("old", key, []crypto.KeyWrapper{pass(t, vaultPass)})
	vf.Version = 1
	if err := os.MkdirAll(format.SecretsPath(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(vf)
	mustWriteFile(t, format.VaultFilePath(dir), data)
	_, got, err := Load(dir, "")
	if !errors.Is(err, ErrOldFormat) || got == nil || got.Version != 1 {
		t.Fatalf("Load v1 = %v", err)
	}
	if _, _, err := Load(dir, "ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrOtherVault) {
		t.Fatalf("Load v1 with another id = %v", err)
	}
}

// G2 and Security N1: lost races are told apart from harmful forks.
func TestClassifyRaces(t *testing.T) {
	alice, bob, carol, dan, mallory := newPerson(t, "alice"), newPerson(t, "bob"), newPerson(t, "carol"), newPerson(t, "dan"), newPerson(t, "mallory")
	v := newVault(t, alice)
	v.join(t, alice, bob)
	v.join(t, alice, carol)
	v.join(t, alice, dan)
	base := v.c
	putSecret(t, v.dir, v.key, "A", "a")
	snapshot := filepath.Join(t.TempDir(), "snap")
	copyDir(t, v.dir, snapshot)

	// alice removes carol (her machine's pin: own = [that record]).
	v.remove(t, alice, "carol")
	alicePin := pinOf(v.c, v.c.LastEntry())

	// Extension: anything on top of alice's head.
	if got := Classify(v.c, pinOf(base)); got.Outcome != Extension {
		t.Fatalf("extension = %v", got.Outcome)
	}

	// N1: carol (still a member in base) races with an add-member of her
	// second identity.
	w, _ := crypto.NewMemberWrapper("mallory", mallory.pub.Recipient)
	m := format.Member{Name: "mallory", Recipient: mallory.pub.Recipient, SignKey: mallory.pub.SignKey, Role: RoleMember}
	baseKey, _ := openAs(t, snapshot, alice)
	u, _ := w.Wrap(baseKey)
	evil, err := base.Append(carol.un, Change{Op: format.OpAddMember, Member: &m, KeyID: baseKey.ID(), Unlockers: append(slices.Clone(base.File.Unlockers), u)})
	if err != nil {
		t.Fatal(err)
	}
	ec, _ := Verify(evil, nil, "")
	if got := Classify(ec, alicePin); got.Outcome != Rollback {
		t.Fatalf("N1 fork = %v", got.Outcome)
	}
	// Signed by the removed person, even a harmless op: refused.
	harmless, _ := base.Append(carol.un, Change{Op: format.OpRemoveUnlocker, KeyID: baseKey.ID(), Unlockers: base.File.Unlockers[:len(base.File.Unlockers)]})
	if harmless != nil {
		hc, _ := Verify(harmless, nil, "")
		if got := Classify(hc, alicePin); got.Outcome != Rollback {
			t.Fatalf("race signed by the removed member = %v", got.Outcome)
		}
	}
	// An honest race: bob removed dan at the same time.
	bobDir := filepath.Join(t.TempDir(), "bob")
	copyDir(t, snapshot, bobDir)
	br, err := Remove(bobDir, base, baseKey, bob.un, "dan", RotateOptions{Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	got := Classify(br.Chain, alicePin)
	if got.Outcome != LostRace || got.Diverge != base.Head().Seq || len(got.Lost) != 1 || got.Lost[0].Member.Name != "carol" {
		t.Fatalf("honest race = %+v", got)
	}
	// The pinned state missing with nothing of ours: rollback.
	if got := Classify(br.Chain, pinOf(v.c)); got.Outcome != Rollback {
		t.Fatalf("missing pin without own = %v", got.Outcome)
	}
	// A passphrase replaced in the winning branch: refused.
	pw, err := Passwd(bobDir, br.Chain, br.NewKey, bob.un, pass(t, "bob's new"), true, RotateOptions{Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	if got := Classify(pw.Chain, alicePin); got.Outcome != Rollback {
		t.Fatalf("race with a replaced passphrase = %v", got.Outcome)
	}
}

// N1 and design section 10: a lost removal race is re-applied, and files
// alice moved under her losing key K3 are re-sealed to the re-applied
// rotation's key K4, never to the winner's key.
func TestRebaseLostRemoval(t *testing.T) {
	alice, bob, carol, dan := newPerson(t, "alice"), newPerson(t, "bob"), newPerson(t, "carol"), newPerson(t, "dan")
	v := newVault(t, alice)
	v.join(t, alice, bob)
	v.join(t, alice, carol)
	v.join(t, alice, dan)
	putSecret(t, v.dir, v.key, "X", "x value")
	putSecret(t, v.dir, v.key, "Y", "y value")
	base, baseKey := v.c, v.key
	bobDir := filepath.Join(t.TempDir(), "bob")
	copyDir(t, v.dir, bobDir)

	pending := NewPendingStore(filepath.Join(t.TempDir(), "pending"))
	ar, err := Remove(v.dir, base, baseKey, alice.un, "carol", RotateOptions{Now: t0, Pending: pending})
	if err != nil {
		t.Fatal(err)
	}
	k3 := ar.NewKey
	alicePin := pinOf(ar.Chain, ar.Chain.LastEntry())
	br, err := Remove(bobDir, base, baseKey, bob.un, "dan", RotateOptions{Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	k2 := br.NewKey
	// Sync: bob's vault.json wins; X comes from bob (K2), Y stays alice's (K3).
	mustWriteFile(t, format.VaultFilePath(v.dir), mustReadFile(t, format.VaultFilePath(bobDir)))
	bx, _ := format.SecretPath(bobDir, "X")
	ax, _ := format.SecretPath(v.dir, "X")
	mustWriteFile(t, ax, mustReadFile(t, bx))

	winner, _, err := Load(v.dir, base.File.ID)
	if err != nil {
		t.Fatal(err)
	}
	cl := Classify(winner, alicePin)
	if cl.Outcome != LostRace {
		t.Fatalf("classify = %v (%s)", cl.Outcome, cl.Reason)
	}
	// The write guard sees Y under an unknown key until the rebase.
	if rep, _ := CheckFolder(v.dir, winner); !rep.Blocking() {
		t.Fatal("K3 file not flagged before the rebase")
	}
	wk, err := crypto.Unlock(winner.File, alice.wrapper(t))
	if err != nil || wk.ID() != k2.ID() {
		t.Fatalf("alice opens the winner: %v", err)
	}
	keys, err := pending.Load(base.File.ID, alice.un)
	if err != nil || len(keys) != 1 || keys[0].ID() != k3.ID() {
		t.Fatalf("pending keys: %v %v", keys, err)
	}
	rb, err := Rebase(v.dir, winner, wk, alice.un, cl.Lost, keys, nil, pending, t0)
	if err != nil {
		t.Fatal(err)
	}
	k4 := rb.Key
	if k4.ID() == k2.ID() || k4.ID() == k3.ID() || len(rb.Written) != 1 {
		t.Fatalf("rebase result: key %s, written %d", k4.ID(), len(rb.Written))
	}
	head := rb.Chain.Head()
	if _, ok := head.Member("carol"); ok {
		t.Fatal("carol still a member after the rebase")
	}
	if _, ok := head.Member("dan"); ok {
		t.Fatal("bob's removal of dan lost")
	}
	for _, n := range []string{"X", "Y"} {
		ct, _ := format.ReadSecretFile(v.dir, n)
		if id, _ := crypto.KeyIDOf(ct); id != k4.ID() {
			t.Fatalf("%s sealed under %s, want K4", n, id)
		}
		if _, err := crypto.ReadSecret(v.dir, n, k2); err == nil {
			t.Fatalf("%s opens under the winner's key", n)
		}
	}
	if rep, _ := CheckFolder(v.dir, rb.Chain); rep.Blocking() || len(rep.Retired) != 0 {
		t.Fatalf("guard after rebase: %+v", rep)
	}
	if _, err := openAs(t, v.dir, carol); err == nil {
		t.Fatal("carol opens the vault")
	}
}

func TestLease(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	v := newVault(t, alice)
	v.join(t, alice, bob)
	if err := WriteLease(v.dir, v.c, bob.un, t0); err != nil {
		t.Fatal(err)
	}
	var held *LeaseHeldError
	if _, err := Remove(v.dir, v.c, v.key, alice.un, "bob", RotateOptions{Now: t0.Add(time.Minute)}); !errors.As(err, &held) || held.By != "bob" {
		t.Fatalf("remove under bob's lease = %v", err)
	}
	// Stale, or forged by a non-member: no obstacle.
	if err := CheckLease(v.dir, v.c, "alice", t0.Add(LeaseTTL+time.Minute)); err != nil {
		t.Fatalf("stale lease = %v", err)
	}
	mallory := newPerson(t, "mallory")
	if err := WriteLease(v.dir, v.c, mallory.un, t0); err != nil {
		t.Fatal(err)
	}
	if err := CheckLease(v.dir, v.c, "alice", t0); err != nil {
		t.Fatalf("forged lease = %v", err)
	}
	// Our own lease is ours.
	_ = WriteLease(v.dir, v.c, alice.un, t0)
	if err := CheckLease(v.dir, v.c, "alice", t0); err != nil {
		t.Fatalf("own lease = %v", err)
	}
	res, err := Remove(v.dir, v.c, v.key, alice.un, "bob", RotateOptions{Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := format.ReadLease(v.dir); err == nil {
		t.Fatal("lease not removed after rotation")
	}
	_ = res
}

func TestWarnings(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	v := newVault(t, alice)
	ov, err := Inspect(v.dir, v.c)
	if err != nil {
		t.Fatal(err)
	}
	if len(ov.Warnings) != 1 || !strings.Contains(ov.Warnings[0].Message, "second trusted member") {
		t.Fatalf("warnings: %+v", ov.Warnings)
	}
	v.join(t, alice, bob)
	if ov, _ := Inspect(v.dir, v.c); len(ov.Warnings) != 0 {
		t.Fatalf("warnings with two members: %+v", ov.Warnings)
	}
}

func TestRemoveRefusals(t *testing.T) {
	alice := newPerson(t, "alice")
	v := newVault(t, alice)
	if _, err := Remove(v.dir, v.c, v.key, alice.un, "nobody", RotateOptions{}); !errors.Is(err, ErrNotMember) {
		t.Fatalf("unknown member = %v", err)
	}
	if _, err := Remove(v.dir, v.c, v.key, alice.un, "alice", RotateOptions{}); !errors.Is(err, ErrLastUnlocker) {
		t.Fatalf("last member = %v", err)
	}
	other, _ := crypto.NewVaultKey()
	if _, err := Remove(v.dir, v.c, other, alice.un, "alice", RotateOptions{}); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("wrong key = %v", err)
	}
	// Conflict copies stop a rotation.
	bob := newPerson(t, "bob")
	v.join(t, alice, bob)
	putSecret(t, v.dir, v.key, "A", "a")
	mustWriteFile(t, filepath.Join(format.SecretsPath(v.dir), "A (bob's conflicted copy 2026-11-20).age"), []byte("x"))
	if _, err := Remove(v.dir, v.c, v.key, alice.un, "bob", RotateOptions{}); !errors.Is(err, crypto.ErrConflicts) {
		t.Fatalf("conflicts = %v", err)
	}
}

// G3: at the cap, membership changes are refused.
func TestLogFull(t *testing.T) {
	alice := newPerson(t, "alice")
	v := newVault(t, alice)
	c := *v.c
	file := *c.File
	file.Log = make([]format.LogEntry, format.MaxLogEntries)
	c.File = &file
	if _, err := c.Append(alice.un, Change{Op: format.OpSetUnlocker, KeyID: file.KeyID, Unlockers: file.Unlockers}); !errors.Is(err, ErrLogFull) {
		t.Fatalf("append at the cap = %v", err)
	}
}

func TestPinRoundTrip(t *testing.T) {
	alice := newPerson(t, "alice")
	v := newVault(t, alice)
	store := NewTrustStore(filepath.Join(t.TempDir(), "trust"))
	if p, err := store.Load(v.c.File.ID); p != nil || err != nil {
		t.Fatalf("missing pin = %v %v", p, err)
	}
	pin := pinOf(v.c, v.c.LastEntry())
	if err := store.Save(pin); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(v.c.File.ID)
	if err != nil || got.Head != pin.Head || got.Seq != pin.Seq || len(got.Own) != 1 {
		t.Fatalf("load = %+v %v", got, err)
	}
	if err := store.Delete(v.c.File.ID); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(pin)
	for name, bad := range map[string][]byte{
		"bad head":     bytes.Replace(data, []byte(pin.Head), []byte(strings.Repeat("z", 64)), 1),
		"bad version":  bytes.Replace(data, []byte(`"version":1`), []byte(`"version":2`), 1),
		"own mismatch": bytes.Replace(data, []byte(`"seq":0`), []byte(`"seq":1`), 1),
		"extra":        bytes.Replace(data, []byte(`"version":1`), []byte(`"version":1,"x":1`), 1),
	} {
		if _, err := ParsePin(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func FuzzParsePin(f *testing.F) {
	alice := newPerson(f, "alice")
	v := newVault(f, alice)
	data, _ := json.Marshal(pinOf(v.c, v.c.LastEntry()))
	f.Add(data)
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParsePin(data)
		if err != nil {
			return
		}
		if format.ValidateVaultID(p.VaultID) != nil || len(p.Own) > MaxOwn {
			t.Fatal("accepted a bad pin")
		}
	})
}

func FuzzVerify(f *testing.F) {
	alice, bob := newPerson(f, "alice"), newPerson(f, "bob")
	v := newVault(f, alice)
	v.join(f, alice, bob)
	f.Add(mustReadFile(f, format.VaultFilePath(v.dir)))
	f.Fuzz(func(t *testing.T, data []byte) {
		vf, err := format.ParseVaultFile(data)
		if err != nil || vf.Version != format.VaultVersion {
			return
		}
		c, err := Verify(vf, data, "")
		if err != nil {
			return
		}
		// Anything that verifies is internally consistent.
		if format.MembersDigest(vf.Members) != c.Head().MembersHash || vf.KeyID != c.Head().KeyID {
			t.Fatal("verified an inconsistent file")
		}
	})
}

func FuzzParseLeaseFile(f *testing.F) {
	alice := newPerson(f, "alice")
	v := newVault(f, alice)
	_ = WriteLease(v.dir, v.c, alice.un, t0)
	data, _ := format.ReadLease(v.dir)
	f.Add(data)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParseLeaseFile(data)
		_, _, _ = parseLease(data, v.c)
	})
}
