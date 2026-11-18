package members

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// TestTwoIdentitySharing walks the design's Arnold-and-Dan story with
// alice and bob: request, a refused wrong fingerprint, approval, the new
// member reading, then removal and rotation.
func TestTwoIdentitySharing(t *testing.T) {
	alice := newPerson(t, "alice")
	bob := newPerson(t, "bob")

	// Alice owns a shared vault with two secrets, one of them trashed.
	dir, aliceKey := newSharedVault(t, alice, pass(t, "recovery phrase"))
	if _, err := AddSelf(dir, aliceKey, alice.pub); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("AddSelf twice: %v", err)
	}
	putSecret(t, dir, aliceKey, "API_TOKEN", "value-one")
	putSecret(t, dir, aliceKey, "OLD_TOKEN", "value-two")
	if _, err := format.TrashSecret(dir, "OLD_TOKEN", t0); err != nil {
		t.Fatal(err)
	}

	// Bob cannot open the vault yet.
	if _, err := openAs(t, dir, bob); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("bob opened the vault before approval: %v", err)
	}

	// Bob files a request; Alice sees it with the fingerprint to compare aloud.
	if err := WriteRequest(dir, bob.pub, t0); err != nil {
		t.Fatal(err)
	}
	ov, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ov.Requests) != 1 || ov.Requests[0].Identity.Fingerprint != bob.pub.Fingerprint {
		t.Fatalf("requests: %+v", ov.Requests)
	}
	if len(ov.Members) != 1 {
		t.Fatalf("members before approval: %+v", ov.Members)
	}

	// A wrong fingerprint (mistyped, or someone else's) is refused and changes nothing.
	vfBefore, _ := os.ReadFile(format.VaultFilePath(dir))
	for _, wrong := range []string{"", "MAPLE-RIVER-OTTER-4417", "MAPLE-RIVER-4417", alice.pub.Fingerprint, bob.pub.Fingerprint + " ", bob.pub.Fingerprint[:len(bob.pub.Fingerprint)-1]} {
		if _, err := ApproveRequest(dir, aliceKey, "bob", wrong, "alice"); !errors.Is(err, ErrFingerprintMismatch) {
			t.Fatalf("fingerprint %q: err = %v", wrong, err)
		}
	}
	if after, _ := os.ReadFile(format.VaultFilePath(dir)); !bytes.Equal(vfBefore, after) {
		t.Fatal("vault.json changed after refused approvals")
	}
	if _, err := ReadRequest(dir, "bob"); err != nil {
		t.Fatal("request vanished after refused approval")
	}
	// A wrong vault key cannot approve either.
	stranger, _ := crypto.NewVaultKey()
	if _, err := ApproveRequest(dir, stranger, "bob", bob.pub.Fingerprint, "alice"); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("stranger key: %v", err)
	}

	// Approve with the right fingerprint (typed lower-case, normalised by the CLI).
	m, err := ApproveRequest(dir, aliceKey, "bob", NormalizeFingerprint(" "+toLower(bob.pub.Fingerprint)), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if m.Identity != bob.pub || m.Role != RoleMember || m.AddedBy != "alice" || m.Added.IsZero() {
		t.Fatalf("approved member: %+v", m)
	}
	if _, err := ReadRequest(dir, "bob"); !errors.Is(err, ErrNoRequest) {
		t.Fatal("request file not deleted")
	}

	// The vault now lists both; bob's entry records who added him and when.
	members, err := List(dir)
	if err != nil || len(members) != 2 {
		t.Fatalf("list: %v %v", members, err)
	}
	if members[0].Identity.Name != "alice" || members[0].Role != RoleOwner || members[1].Identity.Name != "bob" || members[1].AddedBy != "alice" {
		t.Fatalf("members: %+v", members)
	}
	vf, _ := format.ReadVaultFile(dir)
	if len(vf.UnlockersOf(format.UnlockerMember)) != 2 || len(vf.UnlockersOf(format.UnlockerPassphrase)) != 1 {
		t.Fatalf("unlockers: %+v", vf.Unlockers)
	}

	// Bob unwraps the vault key and reads Alice's secret; secret files were not rewritten.
	bobKey, err := openAs(t, dir, bob)
	if err != nil {
		t.Fatalf("bob cannot open after approval: %v", err)
	}
	if !bytes.Equal(bobKey.Bytes(), aliceKey.Bytes()) {
		t.Fatal("bob has a different vault key")
	}
	if got, err := crypto.ReadSecret(dir, "API_TOKEN", bobKey); err != nil || string(got) != "value-one" {
		t.Fatalf("bob read: %q %v", got, err)
	}
	// Approving again is refused (already a member).
	if _, err := ApproveRequest(dir, aliceKey, "bob", bob.pub.Fingerprint, "alice"); !errors.Is(err, ErrNoRequest) {
		t.Fatalf("approve twice: %v", err)
	}

	// Remove bob. Rotation needs the recovery passphrase wrapper.
	if _, err := Remove(dir, aliceKey, "bob"); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("remove without passphrase wrapper: %v", err)
	}
	if _, err := Remove(dir, aliceKey, "nobody", pass(t, "recovery phrase")); !errors.Is(err, ErrNotMember) {
		t.Fatalf("remove stranger: %v", err)
	}
	am, _ := crypto.NewMemberWrapper("alice", alice.pub.Recipient)
	if _, err := Remove(dir, aliceKey, "bob", am); err == nil {
		t.Fatal("member wrapper accepted in rewrap")
	}
	res, err := Remove(dir, aliceKey, "bob", pass(t, "recovery phrase"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed.Identity != bob.pub || res.NewKey == nil || len(res.Dropped) != 0 {
		t.Fatalf("result: %+v", res)
	}
	if want := []string{"API_TOKEN", "OLD_TOKEN"}; !slices.Equal(res.ExposedKeys, want) {
		t.Fatalf("exposed keys %v, want %v (trash included)", res.ExposedKeys, want)
	}
	if bytes.Equal(res.NewKey.Bytes(), aliceKey.Bytes()) {
		t.Fatal("vault key did not change")
	}

	// Bob's identity no longer unwraps anything, and his old key opens no secret.
	if _, err := openAs(t, dir, bob); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("bob still opens the vault: %v", err)
	}
	if _, err := crypto.ReadSecret(dir, "API_TOKEN", bobKey); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("bob's old key still reads: %v", err)
	}
	// New secrets written after removal are out of his reach too.
	putSecret(t, dir, res.NewKey, "NEW_TOKEN", "value-three")
	if _, err := crypto.ReadSecret(dir, "NEW_TOKEN", bobKey); err == nil {
		t.Fatal("bob's old key reads a new secret")
	}
	// Alice (member) and the recovery passphrase still work, and see all values.
	aliceNow, err := openAs(t, dir, alice)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"API_TOKEN": "value-one", "NEW_TOKEN": "value-three"} {
		if got, err := crypto.ReadSecret(dir, name, aliceNow); err != nil || string(got) != want {
			t.Fatalf("alice read %s: %q %v", name, got, err)
		}
	}
	vf, _ = format.ReadVaultFile(dir)
	if k, err := crypto.Unlock(vf, pass(t, "recovery phrase")); err != nil || !bytes.Equal(k.Bytes(), res.NewKey.Bytes()) {
		t.Fatalf("recovery passphrase: %v", err)
	}
	// Listing shows only alice, and bob's metadata is gone.
	if members, _ := List(dir); len(members) != 1 || members[0].Identity.Name != "alice" {
		t.Fatalf("members after removal: %+v", members)
	}
	if meta, _ := readMeta(dir); len(meta.Members) != 1 {
		t.Fatalf("members.json after removal: %+v", meta)
	}
	// The vault folder is clean: no leftover staging or temp files.
	if c, _ := format.FindConflicts(dir); len(c) != 0 {
		t.Fatalf("conflicts: %v", c)
	}
	if p, _ := format.PendingRotations(dir); len(p) != 0 {
		t.Fatalf("pending rotations: %v", p)
	}
	// Bob can ask to rejoin: a fresh request is accepted again.
	if err := WriteRequest(dir, bob.pub, t0); err != nil {
		t.Fatalf("rejoin request: %v", err)
	}
}

func toLower(s string) string { return string(bytes.ToLower([]byte(s))) }

func TestApproveRefusals(t *testing.T) {
	alice, bob, carol := newPerson(t, "alice"), newPerson(t, "bob"), newPerson(t, "carol")
	dir, key := newSharedVault(t, alice)

	if _, err := ApproveRequest(dir, key, "bob", bob.pub.Fingerprint, "alice"); !errors.Is(err, ErrNoRequest) {
		t.Fatalf("no request: %v", err)
	}
	if err := WriteRequest(dir, bob.pub, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveRequest(dir, key, "bob", bob.pub.Fingerprint, "Not A Name"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("bad approver: %v", err)
	}
	if _, err := ApproveRequest(dir, key, "../bob", bob.pub.Fingerprint, "alice"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("path in name: %v", err)
	}
	// A request edited in the shared folder to carry carol's key is rejected on read.
	p := filepath.Join(dir, "requests", "bob.json")
	orig, _ := os.ReadFile(p)
	tampered := bytes.Replace(orig, []byte(bob.pub.Recipient), []byte(carol.pub.Recipient), 1)
	mustWrite(t, p, tampered)
	if _, err := ApproveRequest(dir, key, "bob", bob.pub.Fingerprint, "alice"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("tampered request: %v", err)
	}
	if _, err := ApproveRequest(dir, key, "bob", carol.pub.Fingerprint, "alice"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("tampered request with carol's fingerprint: %v", err)
	}
	// Even a fully consistent forgery (carol's key AND fingerprint) is stopped
	// by the person checking the fingerprint against bob's real one.
	forged := bytes.Replace(tampered, []byte(bob.pub.Fingerprint), []byte(carol.pub.Fingerprint), 1)
	mustWrite(t, p, forged)
	if _, err := ApproveRequest(dir, key, "bob", bob.pub.Fingerprint, "alice"); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("consistent forgery: %v", err)
	}
	if vf, _ := format.ReadVaultFile(dir); len(vf.UnlockersOf(format.UnlockerMember)) != 1 {
		t.Fatal("a refused approval added an unlocker")
	}

	// A request squatting an existing member's name is refused on approval.
	mustWrite(t, p, orig)
	impostor := JoinRequest{Identity: Identity{Name: "alice", Recipient: carol.pub.Recipient, Fingerprint: carol.pub.Fingerprint}}
	if _, err := Approve(key, impostor); err != nil {
		t.Fatal(err) // the pure helper does not know the vault
	}
	if _, err := addMember(dir, key, impostor.Identity, RoleMember, "alice"); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("name collision: %v", err)
	}
	if _, err := Approve(key, JoinRequest{Identity: Identity{Name: "x", Recipient: carol.pub.Recipient, Fingerprint: "WRONG-WORDS-0000"}}); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("pure Approve with bad fingerprint: %v", err)
	}
}

func TestApproveStaleRequestForExistingMember(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	dir, key := newSharedVault(t, alice)
	_ = WriteRequest(dir, bob.pub, t0)
	reqPath := filepath.Join(dir, "requests", "bob.json")
	saved, _ := os.ReadFile(reqPath)
	if _, err := ApproveRequest(dir, key, "bob", bob.pub.Fingerprint, "alice"); err != nil {
		t.Fatal(err)
	}
	// An old synced copy of the request reappears.
	mustWrite(t, reqPath, saved)
	if _, err := ApproveRequest(dir, key, "bob", bob.pub.Fingerprint, "alice"); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("stale request: %v", err)
	}
	if _, err := ReadRequest(dir, "bob"); !errors.Is(err, ErrNoRequest) {
		t.Fatal("stale request not cleaned up")
	}
}

func mustRead2(t testing.TB, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(format.VaultFilePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRemoveRefusals(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	dir, key := newSharedVault(t, alice)
	_ = WriteRequest(dir, bob.pub, t0)
	_, _ = ApproveRequest(dir, key, "bob", bob.pub.Fingerprint, "alice")

	// Wrong vault key.
	stranger, _ := crypto.NewVaultKey()
	if _, err := Remove(dir, stranger, "bob"); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("wrong key: %v", err)
	}
	// Removing the last way in is refused, and nothing changes.
	if _, err := Remove(dir, key, "bob"); err != nil { // alice stays
		t.Fatal(err)
	}
	newKey, _ := openAs(t, dir, alice)
	before := mustRead2(t, dir)
	if _, err := Remove(dir, newKey, "alice"); !errors.Is(err, ErrLastUnlocker) {
		t.Fatalf("remove last member: %v", err)
	}
	if !bytes.Equal(before, mustRead2(t, dir)) {
		t.Fatal("vault.json changed by a refused removal")
	}
}

func TestRemoveRefusesWithConflicts(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	dir, key := newSharedVault(t, alice)
	_ = WriteRequest(dir, bob.pub, t0)
	_, _ = ApproveRequest(dir, key, "bob", bob.pub.Fingerprint, "alice")
	putSecret(t, dir, key, "A_KEY", "v")
	mustWrite(t, filepath.Join(dir, "secrets", "A_KEY (conflicted copy).age"), []byte("x"))
	if _, err := Remove(dir, key, "bob"); !errors.Is(err, crypto.ErrConflicts) {
		t.Fatalf("conflicts: %v", err)
	}
	// Bob is still a member: nothing was committed.
	if m, _ := List(dir); len(m) != 2 {
		t.Fatal("removal half-applied")
	}
}

func TestRemoveDropsOtherDevicesTouchID(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	here := fakeTouchID{pass(t, "enclave-a")}
	dir, key := newSharedVault(t, alice, here)
	// Another Mac's Touch ID unlocker (a different wrapper this Mac does not hold).
	vf, _ := format.ReadVaultFile(dir)
	u, err := fakeTouchID{pass(t, "enclave-b")}.Wrap(key)
	if err != nil {
		t.Fatal(err)
	}
	u.Label, u.Recipient = "other-mac", "se-key-other"
	vf.Unlockers = append(vf.Unlockers, u)
	_ = format.WriteVaultFile(dir, vf)
	_ = WriteRequest(dir, bob.pub, t0)
	_, _ = ApproveRequest(dir, key, "bob", bob.pub.Fingerprint, "alice")

	res, err := Remove(dir, key, "bob", here)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Dropped) != 1 || res.Dropped[0].Label != "other-mac" || res.Dropped[0].WrappedKey != nil {
		t.Fatalf("dropped: %+v", res.Dropped)
	}
	vf, _ = format.ReadVaultFile(dir)
	if len(vf.UnlockersOf(format.UnlockerTouchID)) != 1 {
		t.Fatalf("unlockers: %+v", vf.Unlockers)
	}
}

func TestWarnings(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	has := func(ov *Overview, code string) bool {
		return slices.ContainsFunc(ov.Warnings, func(w Warning) bool { return w.Code == code })
	}
	// One member, no passphrase: warn.
	dir, key := newSharedVault(t, alice)
	ov, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !has(ov, WarnSoleMemberNoRecovery) || ov.HasPassphrase {
		t.Fatalf("expected the sole-member warning: %+v", ov)
	}
	// A second member clears it.
	_ = WriteRequest(dir, bob.pub, t0)
	_, _ = ApproveRequest(dir, key, "bob", bob.pub.Fingerprint, "alice")
	if ov, _ = Inspect(dir); has(ov, WarnSoleMemberNoRecovery) {
		t.Fatal("warned with two members")
	}
	// One member with a passphrase: no warning.
	dir2, _ := newSharedVault(t, alice, pass(t, "recovery"))
	if ov, _ = Inspect(dir2); has(ov, WarnSoleMemberNoRecovery) || !ov.HasPassphrase {
		t.Fatalf("warned despite passphrase: %+v", ov)
	}
}

func TestMembersFileIsOnlyMetadata(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	dir, key := newSharedVault(t, alice)
	_ = WriteRequest(dir, bob.pub, t0)
	_, _ = ApproveRequest(dir, key, "bob", bob.pub.Fingerprint, "alice")

	// A forged members.json cannot add members or change who can open the vault.
	forged := []byte(`{"version":1,"members":[{"name":"mallory","recipient":"` + newRecipient(t) + `","role":"owner","added":"2026-01-01T00:00:00Z"}]}`)
	mustWrite(t, filepath.Join(dir, MembersFileName), forged)
	ms, err := List(dir)
	if err != nil || len(ms) != 2 {
		t.Fatalf("list: %+v %v", ms, err)
	}
	for _, m := range ms {
		if m.Identity.Name == "mallory" {
			t.Fatal("members.json added a member")
		}
		if m.Role != RoleMember || m.AddedBy != "" {
			t.Fatalf("metadata for unrelated keys applied: %+v", m)
		}
	}
	// A corrupt members.json degrades to defaults with a warning, not an error.
	mustWrite(t, filepath.Join(dir, MembersFileName), []byte("garbage"))
	ov, err := Inspect(dir)
	if err != nil || len(ov.Members) != 2 {
		t.Fatalf("inspect with corrupt metadata: %v", err)
	}
	if !slices.ContainsFunc(ov.Warnings, func(w Warning) bool { return w.Code == WarnMemberNotesUnreadable }) {
		t.Fatal("no warning for unreadable members.json")
	}
	// And the next approval rewrites it cleanly.
	carol := newPerson(t, "carol")
	_ = WriteRequest(dir, carol.pub, t0)
	if _, err := ApproveRequest(dir, key, "carol", carol.pub.Fingerprint, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := readMeta(dir); err != nil {
		t.Fatalf("members.json not repaired: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, MembersFileName)); errors.Is(err, fs.ErrNotExist) {
		t.Fatal("no members.json")
	}
}

func TestParseMembersFileRejects(t *testing.T) {
	r := newRecipient(t)
	good := `{"version":1,"members":[{"name":"alice","recipient":"` + r + `","role":"owner","added_by":"bob","added":"2026-01-01T00:00:00Z"}]}`
	if err := ParseMembersFile([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"role":      `{"version":1,"members":[{"name":"alice","recipient":"` + r + `","role":"god","added":"2026-01-01T00:00:00Z"}]}`,
		"name":      `{"version":1,"members":[{"name":"Alice","recipient":"` + r + `","role":"owner","added":"2026-01-01T00:00:00Z"}]}`,
		"recipient": `{"version":1,"members":[{"name":"alice","recipient":"age1x","role":"owner","added":"2026-01-01T00:00:00Z"}]}`,
		"duplicate": `{"version":1,"members":[{"name":"a","recipient":"` + r + `","role":"owner","added":"2026-01-01T00:00:00Z"},{"name":"b","recipient":"` + r + `","role":"member","added":"2026-01-01T00:00:00Z"}]}`,
		"added_by":  `{"version":1,"members":[{"name":"alice","recipient":"` + r + `","role":"owner","added_by":"../x","added":"2026-01-01T00:00:00Z"}]}`,
		"unknown":   `{"version":1,"members":[],"x":1}`,
		"version":   `{"version":9,"members":[]}`,
	} {
		if err := ParseMembersFile([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func FuzzParseMembersFile(f *testing.F) {
	r := newRecipient(f)
	f.Add([]byte(`{"version":1,"members":[{"name":"alice","recipient":"` + r + `","role":"owner","added":"2026-01-01T00:00:00Z"}]}`))
	f.Add([]byte(`{"version":1,"members":[]}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		err := ParseMembersFile(data)
		if err != nil && len(data) > 12 && bytes.Contains([]byte(err.Error()), data) {
			t.Fatal("error echoes input")
		}
	})
}
