package crypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/Arntek/secrets-vault/internal/format"
)

var tIdx = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

// putEntry seals an entry under key and returns it.
func putEntry(key *VaultKey, vaultID, name string, version, rev uint32, deleted bool) format.IndexEntry {
	e := format.IndexEntry{Name: name, Description: "d " + name, Tags: []string{"a", "b"}, Updated: tIdx, UpdatedBy: "me", Version: version, Rev: rev, Deleted: deleted}
	SealEntry(key, vaultID, &e)
	return e
}

func writeIdx(t *testing.T, v *testVault, entries ...format.IndexEntry) {
	t.Helper()
	vf, _ := format.ReadVaultFile(v.dir)
	if err := format.WriteIndex(v.dir, &format.Index{Version: format.IndexVersion, VaultID: vf.ID, Entries: entries}); err != nil {
		t.Fatal(err)
	}
}

func readIdx(t *testing.T, v *testVault, key *VaultKey) (map[string]format.IndexEntry, int) {
	t.Helper()
	vf, _ := format.ReadVaultFile(v.dir)
	raw, err := format.ReadIndexRaw(v.dir)
	if err != nil {
		t.Fatal(err)
	}
	_, entries, dropped, ok := VerifiedEntries(raw, vf.ID, key)
	if !ok {
		t.Fatal("index does not verify as a version-2 index")
	}
	out := map[string]format.IndexEntry{}
	for _, e := range entries {
		out[e.Name] = e
	}
	return out, dropped
}

func TestStanzaV3Version(t *testing.T) {
	k := mustKey(t)
	s := mustSealer(t, "A")
	ct, err := s.SealVersion(k, []byte("v"), 7)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := VersionOf(ct); err != nil || v != 7 {
		t.Fatalf("VersionOf = %d, %v", v, err)
	}
	if id, err := KeyIDOf(ct); err != nil || id != k.ID() {
		t.Fatalf("KeyIDOf v3 = %q, %v", id, err)
	}
	pt, v, err := s.OpenVersion(k, ct)
	if err != nil || v != 7 || string(pt) != "v" {
		t.Fatalf("OpenVersion = %q %d %v", pt, v, err)
	}
	// A file in the unversioned form reports version 0.
	old, _ := s.Seal(k, []byte("v"))
	if v, err := VersionOf(old); err != nil || v != 0 {
		t.Fatalf("VersionOf unversioned = %d, %v", v, err)
	}
	if _, v, err := s.OpenVersion(k, old); err != nil || v != 0 {
		t.Fatalf("OpenVersion unversioned = %d, %v", v, err)
	}
	// The version is authenticated: changing it in the header breaks the file.
	forged := bytes.Replace(ct, []byte(" 7\n"), []byte(" 8\n"), 1)
	if bytes.Equal(forged, ct) {
		t.Fatal("test did not alter the header")
	}
	if _, err := s.Open(k, forged); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("forged version opened: %v", err)
	}
	// Out-of-range versions are refused when sealing.
	for _, bad := range []uint32{0, format.MaxCounter + 1} {
		if _, err := s.SealVersion(k, nil, bad); !errors.Is(err, ErrVersionRange) {
			t.Fatalf("SealVersion(%d) = %v", bad, err)
		}
	}
	// The name is still bound: another name doesn't open it.
	if _, err := mustSealer(t, "B").Open(k, ct); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("opened under another name: %v", err)
	}
}

func TestHeaderOfRejectsBadVersions(t *testing.T) {
	k := mustKey(t)
	ct, _ := mustSealer(t, "A").SealVersion(k, []byte("v"), 7)
	for _, v := range []string{"0", "07", "-1", "2147483648", "4294967296", "x", "", "7 7"} {
		bad := bytes.Replace(ct, []byte(" 7\n"), []byte(" "+v+"\n"), 1)
		if _, _, err := HeaderOf(bad); err == nil {
			t.Errorf("HeaderOf accepted version %q", v)
		}
	}
	for _, bad := range [][]byte{nil, []byte("age-encryption.org/v1\n-> sv-vaultkey3 abc\n"), []byte("age-encryption.org/v1\n-> sv-vaultkey3 " + k.ID() + " AAAA\n")} {
		if _, _, err := HeaderOf(bad); err == nil {
			t.Errorf("HeaderOf accepted %q", bad)
		}
	}
}

func FuzzHeaderOf(f *testing.F) {
	k, _ := NewVaultKey()
	s, _ := NewSealer("A")
	v3, _ := s.SealVersion(k, []byte("x"), 5)
	v2, _ := s.Seal(k, []byte("x"))
	f.Add(v3)
	f.Add(v2)
	f.Add([]byte("age-encryption.org/v1\n-> sv-vaultkey3 "))
	f.Fuzz(func(t *testing.T, data []byte) {
		id, ver, err := HeaderOf(data)
		if err != nil {
			return
		}
		if format.ValidateKeyID(id) != nil || ver > format.MaxCounter {
			t.Fatalf("accepted bad header: %q %d", id, ver)
		}
	})
}

// Old builds (stanza types v1 and v2 only) can't open a versioned file.
func TestOldBuildCannotOpenV3Files(t *testing.T) {
	k := mustKey(t)
	ct, _ := mustSealer(t, "A").SealVersion(k, []byte("v"), 1)
	old := oldV2Identity{&vaultKeyIdentity{key: k, name: "A"}}
	if _, err := age.Decrypt(bytes.NewReader(ct), old); err == nil {
		t.Fatal("a build before format 3 could open a versioned file")
	}
	v2, _ := mustSealer(t, "A").Seal(k, []byte("v"))
	if _, err := age.Decrypt(bytes.NewReader(v2), old); err != nil {
		t.Fatalf("test identity can't open its own format: %v", err)
	}
}

type oldV2Identity struct{ v *vaultKeyIdentity }

func (o oldV2Identity) Unwrap(st []*age.Stanza) ([]byte, error) {
	if len(st) != 1 || (st[0].Type != stanzaType && st[0].Type != stanzaTypeV1) {
		return nil, age.ErrIncorrectIdentity
	}
	return o.v.Unwrap(st)
}

func TestEntryMAC(t *testing.T) {
	k, other := mustKey(t), mustKey(t)
	e := putEntry(k, "v1", "NAME", 3, 4, false)
	if !VerifyEntry(k, "v1", &e) {
		t.Fatal("own MAC fails")
	}
	if VerifyEntry(other, "v1", &e) {
		t.Fatal("another key verifies")
	}
	if VerifyEntry(k, "v2", &e) {
		t.Fatal("another vault id verifies")
	}
	mutations := map[string]func(*format.IndexEntry){
		"name":        func(x *format.IndexEntry) { x.Name = "OTHER" },
		"version":     func(x *format.IndexEntry) { x.Version++ },
		"rev":         func(x *format.IndexEntry) { x.Rev++ },
		"deleted":     func(x *format.IndexEntry) { x.Deleted = true },
		"description": func(x *format.IndexEntry) { x.Description = "x" },
		"tags":        func(x *format.IndexEntry) { x.Tags = []string{"b", "a"} },
		"tag count":   func(x *format.IndexEntry) { x.Tags = x.Tags[:1] },
		"updated":     func(x *format.IndexEntry) { x.Updated = x.Updated.Add(time.Second) },
		"updated_by":  func(x *format.IndexEntry) { x.UpdatedBy = "mallory" },
	}
	for name, mut := range mutations {
		c := e
		c.Tags = append([]string(nil), e.Tags...)
		mut(&c)
		if VerifyEntry(k, "v1", &c) {
			t.Errorf("a changed %s still verifies", name)
		}
	}
	// Field boundaries are unambiguous.
	a, b := e, e
	a.Description, a.UpdatedBy = "ab", "c"
	b.Description, b.UpdatedBy = "a", "bc"
	if EntryMAC(k, "v1", &a) == EntryMAC(k, "v1", &b) {
		t.Fatal("ambiguous encoding")
	}
	// After a rotation (a new key) old MACs fail.
	nk := mustKey(t)
	if VerifyEntry(nk, "v1", &e) {
		t.Fatal("entry verifies under a rotated key")
	}
	if len(NameTag(k, "A")) != 64 || NameTag(k, "A") == NameTag(k, "B") || NameTag(k, "A") == NameTag(nk, "A") {
		t.Fatal("name tag not a keyed tag")
	}
}

func TestVerifiedEntries(t *testing.T) {
	k := mustKey(t)
	good := putEntry(k, "vid", "GOOD", 1, 1, false)
	bad := putEntry(k, "vid", "BAD", 1, 1, false)
	bad.Description = "forged"
	dup1 := putEntry(k, "vid", "DUP", 1, 1, false)
	dup2 := putEntry(k, "vid", "DUP", 2, 2, false)
	plant := putEntry(k, "vid", "DUP", 9, 9, false)
	plant.MAC = strings.Repeat("0", 64)
	// MarshalIndex refuses duplicates, so build the file by hand.
	var parts []string
	for _, e := range []format.IndexEntry{good, bad, dup1, dup2, plant} {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, string(b))
	}
	data := []byte(`{"version":2,"entries":[` + strings.Join(parts, ",") + `]}`)
	_, entries, dropped, ok := VerifiedEntries(data, "vid", k)
	if !ok || dropped != 2 || len(entries) != 2 {
		t.Fatalf("%v %d %+v", ok, dropped, entries)
	}
	for _, e := range entries {
		if e.Name == "DUP" && e.Rev != 2 {
			t.Fatalf("a verified duplicate must keep the higher rev: %+v", e)
		}
	}
	// A version-1 index and another vault's index are not accepted.
	v1 := []byte(`{"version":1,"entries":[]}`)
	if _, _, _, ok := VerifiedEntries(v1, "vid", k); ok {
		t.Fatal("v1 index accepted")
	}
	other, _ := format.MarshalIndex(&format.Index{Version: 2, VaultID: "ffffffffffffffffffffffffffffffff", Entries: []format.IndexEntry{}})
	if _, _, _, ok := VerifiedEntries(other, "vid", k); ok {
		t.Fatal("another vault's index accepted")
	}
}

func TestRotateReSealsIndex(t *testing.T) {
	v := newVault(t)
	vf, _ := format.ReadVaultFile(v.dir)
	for _, n := range []string{"A", "B"} {
		if err := WriteSecretVersion(v.dir, n, v.key, []byte(n), 3); err != nil {
			t.Fatal(err)
		}
	}
	forged := putEntry(v.key, vf.ID, "FORGED", 1, 1, false)
	forged.Description = "tampered"
	writeIdx(t, v,
		putEntry(v.key, vf.ID, "A", 3, 5, false),
		putEntry(v.key, vf.ID, "B", 3, 2, false),
		putEntry(v.key, vf.ID, "TOMB", 4, 6, true),
		forged)
	dropped := 0
	opt := v.rotateTo(t, v.pw)
	opt.IndexDropped = &dropped
	nk, err := Rotate(v.dir, v.key, opt)
	if err != nil {
		t.Fatal(err)
	}
	got, d := readIdx(t, v, nk)
	if d != 0 || dropped != 1 {
		t.Fatalf("dropped in new index %d, reported %d", d, dropped)
	}
	if len(got) != 2 || got["A"].Rev != 5 || got["A"].Version != 3 || got["B"].Rev != 2 {
		t.Fatalf("counters changed or entries lost: %+v", got)
	}
	if _, ok := got["FORGED"]; ok {
		t.Fatal("forged entry carried over")
	}
	if _, ok := got["TOMB"]; ok {
		t.Fatal("a tombstone with no file left was kept")
	}
	// Under the old key nothing verifies any more.
	raw, _ := format.ReadIndexRaw(v.dir)
	if _, entries, _, _ := VerifiedEntries(raw, vf.ID, v.key); len(entries) != 0 {
		t.Fatal("old key still verifies the index")
	}
	// The files kept their versions.
	for _, n := range []string{"A", "B"} {
		ct, _ := format.ReadSecretFile(v.dir, n)
		if ver, _ := VersionOf(ct); ver != 3 {
			t.Fatalf("%s version after rotation = %d", n, ver)
		}
	}
}

// A tombstone is dropped only when no file under any key, live or trashed,
// is left for the name (Security note 2), and a pre-rotation copy brought
// back afterwards is refused by its key id.
func TestRotateKeepsTombstoneWithTrashedCopy(t *testing.T) {
	v := newVault(t)
	vf, _ := format.ReadVaultFile(v.dir)
	if err := WriteSecretVersion(v.dir, "TRASHED", v.key, []byte("x"), 2); err != nil {
		t.Fatal(err)
	}
	preRotation, _ := format.ReadSecretFile(v.dir, "TRASHED")
	if _, err := format.TrashSecret(v.dir, "TRASHED", tIdx); err != nil {
		t.Fatal(err)
	}
	writeIdx(t, v, putEntry(v.key, vf.ID, "TRASHED", 2, 3, true), putEntry(v.key, vf.ID, "GONE", 1, 2, true))
	nk, err := Rotate(v.dir, v.key, v.rotateTo(t, v.pw))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := readIdx(t, v, nk)
	if _, ok := got["TRASHED"]; !ok {
		t.Fatal("tombstone with a trashed copy was dropped")
	}
	if _, ok := got["GONE"]; ok {
		t.Fatal("tombstone with nothing left was kept")
	}
	// The pre-rotation copy, put back, opens under neither the new key nor
	// carries the new key id.
	if err := format.WriteSecretFile(v.dir, "TRASHED", preRotation); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecret(v.dir, "TRASHED", nk); !errors.Is(err, ErrOtherKey) {
		t.Fatalf("pre-rotation copy under the new key = %v", err)
	}
}

// IM2: an entry MAC'd under a retired key is never carried into a new key.
func TestRotateDropsRetiredKeyEntries(t *testing.T) {
	v := newVault(t)
	vf, _ := format.ReadVaultFile(v.dir)
	if err := WriteSecretVersion(v.dir, "A", v.key, []byte("a"), 1); err != nil {
		t.Fatal(err)
	}
	writeIdx(t, v, putEntry(v.key, vf.ID, "A", 1, 1, false))
	k0 := v.key
	k1, err := Rotate(v.dir, k0, v.rotateTo(t, v.pw))
	if err != nil {
		t.Fatal(err)
	}
	// A member removed in an earlier epoch (holding k0) plants entries.
	planted := putEntry(k0, vf.ID, "PLANT", 1, 1, false)
	cur, _ := readIdx(t, v, k1)
	writeIdx(t, v, cur["A"], planted)
	if err := WriteSecretVersion(v.dir, "PLANT", k1, []byte("p"), 1); err != nil {
		t.Fatal(err)
	}
	dropped := 0
	opt := v.rotateTo(t, v.pw)
	opt.IndexDropped = &dropped
	k2, err := Rotate(v.dir, k1, opt)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := readIdx(t, v, k2)
	if _, ok := got["PLANT"]; ok {
		t.Fatal("an entry under a retired key was re-MAC'd into the new key")
	}
	if dropped != 1 || got["A"].Name != "A" {
		t.Fatalf("dropped %d, entries %+v", dropped, got)
	}
}

// A lost-race repair carries the loser's own trusted entries, not the
// folder's index under a retired key.
func TestRotateTrustedEntries(t *testing.T) {
	v := newVault(t)
	vf, _ := format.ReadVaultFile(v.dir)
	if err := WriteSecretVersion(v.dir, "MINE", v.key, []byte("m"), 4); err != nil {
		t.Fatal(err)
	}
	writeIdx(t, v) // the folder's index lost it
	opt := v.rotateTo(t, v.pw)
	opt.TrustedEntries = []format.IndexEntry{{Name: "MINE", Description: "kept", Updated: tIdx, Version: 4, Rev: 6}}
	nk, err := Rotate(v.dir, v.key, opt)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := readIdx(t, v, nk)
	if e := got["MINE"]; e.Description != "kept" || e.Rev != 6 || e.Version != 4 || !VerifyEntry(nk, vf.ID, &e) {
		t.Fatalf("%+v", got)
	}
}

// A rebuild gives the vault a new ID: entries are sealed for the new ID.
func TestRotateNewVaultIDReSealsIndex(t *testing.T) {
	v := newVault(t)
	old, _ := format.ReadVaultFile(v.dir)
	_ = WriteSecretVersion(v.dir, "A", v.key, []byte("a"), 2)
	writeIdx(t, v, putEntry(v.key, old.ID, "A", 2, 3, false))
	opt := v.rotateTo(t, v.pw)
	inner := opt.Next
	opt.NewVaultID = true
	opt.Next = func(nk *VaultKey) (*format.VaultFile, error) {
		vf, err := inner(nk)
		if err != nil {
			return nil, err
		}
		vf.ID, _ = format.NewVaultID()
		return vf, nil
	}
	nk, err := Rotate(v.dir, v.key, opt)
	if err != nil {
		t.Fatal(err)
	}
	nv, _ := format.ReadVaultFile(v.dir)
	if nv.ID == old.ID {
		t.Fatal("vault id unchanged")
	}
	got, _ := readIdx(t, v, nk)
	if got["A"].Name != "A" {
		t.Fatalf("%+v", got)
	}
}

// A format-2 vault rotated into format 3 (rebuild) stamps its files and
// builds the authenticated index from the legacy one.
func TestRotateLegacyIntoV3(t *testing.T) {
	v := newVault(t)
	vf, _ := format.ReadVaultFile(v.dir)
	vf.Version = format.LegacyVaultVersion
	_ = format.WriteVaultFile(v.dir, vf)
	_ = WriteSecret(v.dir, "OLD", v.key, []byte("o"))
	_ = WriteSecret(v.dir, "NOENTRY", v.key, []byte("n"))
	legacy := `{"version": 1, "entries": [{"name": "OLD", "description": "legacy label", "updated": "2026-11-20T10:00:00Z"}, {"name": "NOFILE", "updated": "2026-11-20T10:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(v.dir, "index.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	opt := v.rotateTo(t, v.pw)
	inner := opt.Next
	opt.Next = func(nk *VaultKey) (*format.VaultFile, error) {
		next, err := inner(nk)
		if next != nil {
			next.Version = format.VaultVersion // the rebuilt vault is format 3
		}
		return next, err
	}
	nk, err := Rotate(v.dir, v.key, opt)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := readIdx(t, v, nk)
	if got["OLD"].Description != "legacy label" || got["OLD"].Version != 1 || got["OLD"].Rev != 1 {
		t.Fatalf("%+v", got)
	}
	if _, ok := got["NOFILE"]; ok {
		t.Fatal("entry without a file carried over")
	}
	ct, _ := format.ReadSecretFile(v.dir, "OLD")
	if ver, _ := VersionOf(ct); ver != 1 {
		t.Fatalf("file version = %d", ver)
	}
}

func TestRecoverRotationChecksStagedIndex(t *testing.T) {
	v := newVault(t)
	vf, _ := format.ReadVaultFile(v.dir)
	s, _ := format.BeginStaging(v.dir, v.key.ID())
	good := putEntry(v.key, vf.ID, "A", 1, 1, false)
	bad := good
	bad.Description = "forged"
	data, _ := format.MarshalIndex(&format.Index{Version: 2, VaultID: vf.ID, Entries: []format.IndexEntry{bad}})
	_ = s.AddIndex(data)
	_ = s.Finish()
	before, _ := format.ReadIndexRaw(v.dir)
	if done, err := RecoverRotation(v.dir, v.key); done || err == nil {
		t.Fatalf("a staged index with a forged entry was committed: %v %v", done, err)
	}
	if err := VerifyStaged(v.dir, v.key); err == nil {
		t.Fatal("VerifyStaged accepted a forged staged index")
	}
	if now, _ := format.ReadIndexRaw(v.dir); !bytes.Equal(before, now) {
		t.Fatal("index replaced by a planted staged one")
	}
	_ = format.AbandonStaging(v.dir, v.key.ID())
	// A genuine one is moved to the vault root.
	s, _ = format.BeginStaging(v.dir, v.key.ID())
	data, _ = format.MarshalIndex(&format.Index{Version: 2, VaultID: vf.ID, Entries: []format.IndexEntry{good}})
	_ = s.AddIndex(data)
	_ = s.Finish()
	if done, err := RecoverRotation(v.dir, v.key); !done || err != nil {
		t.Fatalf("%v %v", done, err)
	}
	if got, _ := readIdx(t, v, v.key); got["A"].Name != "A" {
		t.Fatalf("%+v", got)
	}
}

func TestUpgradeToV3(t *testing.T) {
	v := newVault(t)
	if err := format.WriteSecretFile(v.dir, "OLD1", v1Seal(t, v.key, "OLD1", "one")); err != nil {
		t.Fatal(err)
	}
	_ = WriteSecret(v.dir, "OLD2", v.key, []byte("two"))
	_ = WriteSecretVersion(v.dir, "NEW", v.key, []byte("new"), 5)
	_ = WriteSecret(v.dir, "TRASH", v.key, []byte("t"))
	if _, err := format.TrashSecret(v.dir, "TRASH", tIdx); err != nil {
		t.Fatal(err)
	}
	n, err := UpgradeToV3(v.dir, v.key)
	if err != nil || n != 3 {
		t.Fatalf("UpgradeToV3 = %d, %v", n, err)
	}
	for name, want := range map[string]uint32{"OLD1": 1, "OLD2": 1, "NEW": 5} {
		got, ver, err := ReadSecretVersion(v.dir, name, v.key)
		if err != nil || ver != want {
			t.Fatalf("%s: version %d, %v (%q)", name, ver, err, got)
		}
	}
	if n, err := UpgradeToV3(v.dir, v.key); err != nil || n != 0 {
		t.Fatalf("second run = %d, %v", n, err)
	}
	// A file that doesn't open under the key stops the upgrade with an error.
	_ = WriteSecret(v.dir, "OTHER", mustKey(t), []byte("x"))
	if _, err := UpgradeToV3(v.dir, v.key); err == nil {
		t.Fatal("upgraded a file sealed under another key")
	}
}
