package index

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

var t0 = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

const vid = "0123456789abcdef0123456789abcdef"

// env is one vault folder with a vault key. Only secrets/ and index.json
// are needed: package index doesn't read vault.json.
type env struct {
	t   *testing.T
	dir string
	key *crypto.VaultKey
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	k, err := crypto.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, dir: dir, key: k}
	if err := format.WriteIndex(dir, &format.Index{Version: format.IndexVersion, VaultID: vid, Entries: []format.IndexEntry{}}); err != nil {
		t.Fatal(err)
	}
	return e
}

// session returns a Session with the given snapshot (nil: none).
func (e *env) session(snap *Snapshot) *Session {
	return &Session{Dir: e.dir, VaultID: vid, Key: e.key, Snap: snap, PinSeq: 0, PinHead: strings.Repeat("a", 64), Now: func() time.Time { return t0 }}
}

// set writes a secret file and its entry, the way `set` does, and returns
// the new snapshot.
func (e *env) set(s *Session, name, value, desc string) *Snapshot {
	e.t.Helper()
	v, err := s.Load()
	if err != nil {
		e.t.Fatal(err)
	}
	ver, err := v.NextVersion(name)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := crypto.WriteSecretVersion(e.dir, name, e.key, []byte(value), ver); err != nil {
		e.t.Fatal(err)
	}
	res, err := s.Commit(v, Edit{Name: name, Apply: func(cur *format.IndexEntry) (format.IndexEntry, error) {
		en := format.IndexEntry{}
		if cur != nil && !cur.Deleted {
			en = *cur
		}
		en.Description, en.Version, en.Deleted, en.Updated = desc, max(ver, en.Version), false, t0
		return en, nil
	}})
	if err != nil {
		e.t.Fatal(err)
	}
	return res.Snapshot
}

// read reads a secret through the index like the CLI does.
func (e *env) read(s *Session, name string) (string, KeyInfo) {
	e.t.Helper()
	v, err := s.Load()
	if err != nil {
		e.t.Fatal(err)
	}
	val, ver, err := crypto.ReadSecretVersion(e.dir, name, e.key)
	if err != nil {
		return "", v.Verdict(name, 0, false)
	}
	k := v.Verdict(name, ver, true)
	if !k.Readable() {
		return "", k
	}
	return string(val), k
}

func (e *env) indexBytes() []byte {
	b, err := os.ReadFile(filepath.Join(e.dir, "index.json"))
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

func (e *env) writeIndexRaw(s string) {
	if err := os.WriteFile(filepath.Join(e.dir, "index.json"), []byte(s), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) secretBytes(name string) []byte {
	b, err := format.ReadSecretFile(e.dir, name)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

func (e *env) putSecretBytes(name string, b []byte) {
	if err := format.WriteSecretFile(e.dir, name, b); err != nil {
		e.t.Fatal(err)
	}
}

func status(t *testing.T, k KeyInfo, want Status) {
	t.Helper()
	if k.Status != want {
		t.Fatalf("status = %d, want %d (%s)", k.Status, want, k.Describe())
	}
}

func TestRoundTrip(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	e.set(s, "API_KEY", "v1", "the key")
	val, k := e.read(s, "API_KEY")
	if val != "v1" || k.Status != StatusOK || k.Entry.Description != "the key" {
		t.Fatalf("%q %+v", val, k)
	}
	e.set(s, "API_KEY", "v2", "the key")
	val, k = e.read(s, "API_KEY")
	if val != "v2" || k.Entry.Version != 2 || k.Entry.Rev != 2 {
		t.Fatalf("%q %+v", val, k)
	}
}

// A1: an edited label fails its MAC: the entry is dropped; without a
// snapshot the file is unlisted, with one it is rebuilt with the label this
// machine verified.
func TestA1RelabelledEntry(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	snap := e.set(s, "API_KEY", "v1", "production key")
	raw := string(e.indexBytes())
	e.writeIndexRaw(strings.Replace(raw, "production key", "test key only", 1))

	_, k := e.read(e.session(nil), "API_KEY")
	status(t, k, StatusUnlisted)
	v, _ := e.session(nil).Load()
	if v.Dropped != 1 {
		t.Fatalf("dropped = %d", v.Dropped)
	}
	// With the snapshot: the label this machine verified comes back.
	val, k := e.read(e.session(snap), "API_KEY")
	if val != "v1" || k.Status != StatusReconstructed || k.Entry.Description != "production key" {
		t.Fatalf("%q %+v", val, k)
	}
}

// A2: a planted entry fails its MAC; a junk file is not a key.
func TestA2PlantedEntryAndFile(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	e.set(s, "REAL", "v", "real")
	raw := string(e.indexBytes())
	planted := strings.Replace(raw, `"entries": [`, `"entries": [
    {"name": "EVIL", "description": "plant", "updated": "2026-11-20T10:00:00Z", "version": 1, "rev": 1, "mac": "`+strings.Repeat("0", 64)+`"},`, 1)
	e.writeIndexRaw(planted)
	e.putSecretBytes("JUNK", []byte("not an age file"))
	v, err := e.session(nil).Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Keys["EVIL"]; ok {
		t.Fatal("planted entry accepted")
	}
	if k := v.Keys["JUNK"]; k == nil || k.Status != StatusUnlisted {
		t.Fatalf("junk file: %+v", k)
	}
	if got := v.Names(); len(got) != 1 || got[0] != "REAL" {
		t.Fatalf("names = %v", got)
	}
	if v.Dropped != 1 {
		t.Fatalf("dropped = %d", v.Dropped)
	}
}

// A3: a deleted entry leaves an unlisted file; a snapshot rebuilds it.
func TestA3DeletedEntry(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	snap := e.set(s, "API_KEY", "v1", "x")
	e.writeIndexRaw(`{"version": 2, "vault_id": "` + vid + `", "entries": []}`)
	_, k := e.read(e.session(nil), "API_KEY")
	status(t, k, StatusUnlisted)
	val, k := e.read(e.session(snap), "API_KEY")
	if val != "v1" || k.Status != StatusReconstructed {
		t.Fatalf("%q %d", val, k.Status)
	}
	// The next write repairs the folder's index (re-sealed, rev above the snapshot's).
	e.set(e.session(snap), "OTHER", "o", "o")
	val, k = e.read(e.session(nil), "API_KEY")
	if val != "v1" || k.Status != StatusOK {
		t.Fatalf("after repair: %q %d", val, k.Status)
	}
}

// A4: an index older than the snapshot is refused entry by entry.
func TestA4OldIndex(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	snap := e.set(s, "API_KEY", "v1", "first label")
	old := e.indexBytes()
	snap = e.set(e.session(snap), "API_KEY", "v1", "second label") // describe-style change: rev up
	e.writeIndexRaw(string(old))
	_, k := e.read(e.session(snap), "API_KEY")
	status(t, k, StatusEntryOlder)
	if !errors.Is(k.Err(), ErrEntryOlder) {
		t.Fatal(k.Err())
	}
}

// A5: one secret file rolled back to an older valid version is refused on a
// machine with no snapshot at all.
func TestA5SingleFileRollback(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	e.set(s, "API_KEY", "old", "x")
	oldFile := e.secretBytes("API_KEY")
	e.set(s, "API_KEY", "new", "x")
	e.putSecretBytes("API_KEY", oldFile)
	val, k := e.read(e.session(nil), "API_KEY")
	if val != "" || k.Status != StatusFileOlder || !errors.Is(k.Err(), ErrFileOlder) {
		t.Fatalf("%q %+v", val, k)
	}
	// Writing the key again is the repair.
	e.set(e.session(nil), "API_KEY", "newer", "x")
	if val, k := e.read(e.session(nil), "API_KEY"); val != "newer" || k.Status != StatusOK {
		t.Fatalf("%q %d", val, k.Status)
	}
}

// A6: index and file rolled back together: refused on a machine that saw
// the newer state, accepted (documented residual risk) on one that didn't.
func TestA6ConsistentRollback(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	e.set(s, "API_KEY", "old", "x")
	oldFile, oldIdx := e.secretBytes("API_KEY"), e.indexBytes()
	snap := e.set(s, "API_KEY", "new", "x")
	e.putSecretBytes("API_KEY", oldFile)
	e.writeIndexRaw(string(oldIdx))
	if val, k := e.read(e.session(snap), "API_KEY"); val != "" || k.Status != StatusEntryOlder {
		t.Fatalf("with snapshot: %q %d", val, k.Status)
	}
	if val, k := e.read(e.session(nil), "API_KEY"); val != "old" || k.Status != StatusOK {
		t.Fatalf("without snapshot (residual risk): %q %d", val, k.Status)
	}
}

// IM1: deleting or downgrading index.json is not a way around A5.
func TestIM1DamagedIndex(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	e.set(s, "API_KEY", "old", "x")
	oldFile := e.secretBytes("API_KEY")
	snap := e.set(s, "API_KEY", "new", "x")
	e.putSecretBytes("API_KEY", oldFile)
	damage := map[string]func(){
		"deleted": func() { _ = os.Remove(filepath.Join(e.dir, "index.json")) },
		"v1 index": func() {
			e.writeIndexRaw(`{"version": 1, "entries": [{"name": "API_KEY", "updated": "2026-11-20T10:00:00Z"}]}`)
		},
		"garbage": func() { e.writeIndexRaw("{{{") },
		"other vault": func() {
			e.writeIndexRaw(strings.Replace(string(e.indexBytes()), vid, "ffffffffffffffffffffffffffffffff", 1))
		},
	}
	for name, do := range damage {
		t.Run(name, func(t *testing.T) {
			saved := e.indexBytes()
			t.Cleanup(func() { e.writeIndexRaw(string(saved)) })
			do()
			// No snapshot: nothing is readable.
			val, k := e.read(e.session(nil), "API_KEY")
			if val != "" || k.Status != StatusDamaged || !errors.Is(k.Err(), ErrIndexDamaged) {
				t.Fatalf("no snapshot: %q %+v", val, k)
			}
			v, _ := e.session(nil).Load()
			if !v.Damaged {
				t.Fatal("not flagged damaged")
			}
			// A snapshot that vouches: the file is older than the snapshot's
			// version, so still refused.
			if val, k := e.read(e.session(snap), "API_KEY"); val != "" || k.Status != StatusFileOlder {
				t.Fatalf("stale file with snapshot: %q %d", val, k.Status)
			}
		})
	}
	// With the current file the snapshot vouches and the key is readable.
	e.set(e.session(snap), "API_KEY", "current", "x")
	snap2, _ := e.session(snap).Load()
	_ = snap2
}

func TestIM1SnapshotVouches(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	snap := e.set(s, "API_KEY", "v1", "label")
	_ = os.Remove(filepath.Join(e.dir, "index.json"))
	val, k := e.read(e.session(snap), "API_KEY")
	if val != "v1" || k.Status != StatusReconstructed || k.Entry.Description != "label" {
		t.Fatalf("%q %+v", val, k)
	}
}

// IS1/IS6: a deleted key's file coming back is refused, also when the
// tombstone itself is gone and only the snapshot remembers it.
func TestTombstoneResurrection(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	snap := e.set(s, "API_KEY", "v1", "x")
	file := e.secretBytes("API_KEY")
	v, _ := s.Load()
	res, err := s.Commit(v, tombstone("API_KEY", v.Floor("API_KEY")))
	if err != nil {
		t.Fatal(err)
	}
	snap = res.Snapshot
	_ = os.Remove(filepath.Join(e.dir, "secrets", "API_KEY.age"))
	// The file reappears (a trashed copy moved back).
	e.putSecretBytes("API_KEY", file)
	if _, k := e.read(e.session(snap), "API_KEY"); k.Status != StatusResurrected {
		t.Fatalf("with tombstone: %d", k.Status)
	}
	// Tombstone removed from the folder's index: the snapshot still knows.
	e.writeIndexRaw(`{"version": 2, "vault_id": "` + vid + `", "entries": []}`)
	if _, k := e.read(e.session(snap), "API_KEY"); k.Status != StatusResurrected {
		t.Fatalf("tombstone only in the snapshot: %d", k.Status)
	}
	// Without any memory it is just an unlisted file.
	if _, k := e.read(e.session(nil), "API_KEY"); k.Status != StatusUnlisted {
		t.Fatalf("no memory: %d", k.Status)
	}
}

func tombstone(name string, floor uint32) Edit {
	return Edit{Name: name, Apply: func(cur *format.IndexEntry) (format.IndexEntry, error) {
		en := format.IndexEntry{Version: max(floor, 1), Deleted: true, Updated: t0}
		return en, nil
	}}
}

// IS2: an entry whose file is missing is refused.
func TestMissingFile(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	e.set(s, "API_KEY", "v", "x")
	_ = os.Remove(filepath.Join(e.dir, "secrets", "API_KEY.age"))
	_, k := e.read(e.session(nil), "API_KEY")
	if k.Status != StatusFileMissing || !errors.Is(k.Err(), ErrFileMissing) {
		t.Fatalf("%+v", k)
	}
}

// IS4: a planted duplicate (bad MAC) never knocks out the real entry.
func TestPlantedDuplicate(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	e.set(s, "API_KEY", "v", "real")
	raw := string(e.indexBytes())
	e.writeIndexRaw(strings.Replace(raw, `"entries": [`, `"entries": [
    {"name": "API_KEY", "description": "plant", "updated": "2026-11-20T10:00:00Z", "version": 9, "rev": 9, "mac": "`+strings.Repeat("1", 64)+`"},`, 1))
	val, k := e.read(e.session(nil), "API_KEY")
	if val != "v" || k.Entry.Description != "real" {
		t.Fatalf("%q %+v", val, k)
	}
	// A malformed entry doesn't reject the file either.
	e.writeIndexRaw(strings.Replace(raw, `"entries": [`, `"entries": [ {"name": "bad name"}, 42,`, 1))
	if val, _ := e.read(e.session(nil), "API_KEY"); val != "v" {
		t.Fatalf("with junk entries: %q", val)
	}
}

// IndexBehind: a file newer than its entry is readable (the index lags).
func TestIndexBehind(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	e.set(s, "API_KEY", "v1", "x")
	if err := crypto.WriteSecretVersion(e.dir, "API_KEY", e.key, []byte("v2"), 2); err != nil {
		t.Fatal(err)
	}
	val, k := e.read(e.session(nil), "API_KEY")
	if val != "v2" || k.Status != StatusIndexBehind {
		t.Fatalf("%q %d", val, k.Status)
	}
}

// IS7: counters never wrap.
func TestCounterLimit(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	e.set(s, "API_KEY", "v", "x")
	if err := crypto.WriteSecretVersion(e.dir, "API_KEY", e.key, []byte("v"), format.MaxCounter); err != nil {
		t.Fatal(err)
	}
	v, _ := s.Load()
	if _, err := v.NextVersion("API_KEY"); !errors.Is(err, ErrCounterLimit) {
		t.Fatalf("NextVersion = %v", err)
	}
	if _, err := crypto.NewSealer("A"); err != nil {
		t.Fatal(err)
	}
	sl, _ := crypto.NewSealer("A")
	if _, err := sl.SealVersion(e.key, nil, format.MaxCounter+1); !errors.Is(err, crypto.ErrVersionRange) {
		t.Fatalf("SealVersion past the limit = %v", err)
	}
	// A rev at the limit refuses the change.
	en := format.IndexEntry{Name: "REV", Version: 1, Rev: format.MaxCounter, Updated: t0}
	crypto.SealEntry(e.key, vid, &en)
	if err := format.WriteIndex(e.dir, &format.Index{Version: 2, VaultID: vid, Entries: []format.IndexEntry{en}}); err != nil {
		t.Fatal(err)
	}
	e.putSecretBytes("REV", mustSeal(t, e.key, "REV", 1))
	v, _ = s.Load()
	_, err := s.Commit(v, Edit{Name: "REV", Apply: func(cur *format.IndexEntry) (format.IndexEntry, error) { c := *cur; return c, nil }})
	if !errors.Is(err, ErrCounterLimit) {
		t.Fatalf("Commit at the rev limit = %v", err)
	}
}

func mustSeal(t *testing.T, k *crypto.VaultKey, name string, ver uint32) []byte {
	t.Helper()
	s, _ := crypto.NewSealer(name)
	b, err := s.SealVersion(k, []byte("x"), ver)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Concurrent writers: different keys are all kept; the same key is flagged.
func TestConcurrentWriters(t *testing.T) {
	e := newEnv(t)
	var wg sync.WaitGroup
	names := []string{"AAA", "BBB", "CCC", "DDD", "EEE", "FFF"}
	for _, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := e.session(nil)
			v, err := s.Load()
			if err != nil {
				t.Error(err)
				return
			}
			ver, _ := v.NextVersion(n)
			if err := crypto.WriteSecretVersion(e.dir, n, e.key, []byte(n), ver); err != nil {
				t.Error(err)
				return
			}
			_, err = s.Commit(v, Edit{Name: n, Apply: func(cur *format.IndexEntry) (format.IndexEntry, error) {
				return format.IndexEntry{Description: n, Version: ver, Updated: t0}, nil
			}})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	v, err := e.session(nil).Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Names(); len(got) != len(names) {
		t.Fatalf("lost entries: %v", got)
	}
	for _, n := range names {
		if val, k := e.read(e.session(nil), n); val != n || k.Status != StatusOK {
			t.Fatalf("%s: %q %d", n, val, k.Status)
		}
	}
}

func TestConcurrentSameKeyIsReported(t *testing.T) {
	e := newEnv(t)
	sa, sb := e.session(nil), e.session(nil)
	e.set(sa, "API_KEY", "base", "x")
	va, _ := sa.Load()
	vb, _ := sb.Load()
	// A commits first; B's compare-and-swap then fails and reloads.
	if _, err := sa.Commit(va, Edit{Name: "API_KEY", Apply: func(c *format.IndexEntry) (format.IndexEntry, error) {
		en := *c
		en.Description = "from A"
		return en, nil
	}}); err != nil {
		t.Fatal(err)
	}
	res, err := sb.Commit(vb, Edit{Name: "API_KEY", Apply: func(c *format.IndexEntry) (format.IndexEntry, error) {
		en := *c
		en.Description = "from B"
		return en, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Concurrent) != 1 || res.Concurrent[0] != "API_KEY" {
		t.Fatalf("concurrent = %v", res.Concurrent)
	}
}

// A sync-conflict copy of the index is merged when its entries verify, and
// never when they don't.
func TestConflictCopyMerge(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	e.set(s, "AAA", "a", "a")
	copyIdx := e.indexBytes()
	e.set(s, "BBB", "b", "b")
	// Machine 2 saw only AAA, then added CCC: its index is the "conflicted copy".
	e2 := newEnv(t)
	e2.key = e.key
	e2.set(e2.session(nil), "AAA", "a", "a")
	e2.set(e2.session(nil), "CCC", "c", "c")
	// Both machines' files are in the folder.
	e.putSecretBytes("CCC", e2.secretBytes("CCC"))
	conflict := filepath.Join(e.dir, "index (Dan's conflicted copy 2026-11-20).json")
	if err := os.WriteFile(conflict, e2.indexBytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = copyIdx
	// A forged conflict copy: valid structure, bad MACs.
	forged := strings.Replace(string(e2.indexBytes()), `"CCC"`, `"EVIL"`, 1)
	if err := os.WriteFile(filepath.Join(e.dir, "index (conflicted copy).json"), []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	e.putSecretBytes("EVIL", mustSeal(t, e.key, "EVIL", 1))
	e.set(s, "DDD", "d", "d") // any write merges
	v, _ := e.session(nil).Load()
	got := v.Names()
	want := map[string]bool{"AAA": true, "BBB": true, "CCC": true, "DDD": true}
	if len(got) != 4 {
		t.Fatalf("names = %v", got)
	}
	for _, n := range got {
		if !want[n] {
			t.Fatalf("unexpected %s in %v", n, got)
		}
	}
}

// Locked: verified rows come from the snapshot; folder changes are flagged.
func TestLockedView(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	snap := e.set(s, "AAA", "a", "verified label")
	lv, err := Locked(e.dir, false, snap)
	if err != nil {
		t.Fatal(err)
	}
	if lv.State != StateVerified || len(lv.Rows) != 1 || !lv.Rows[0].Verified {
		t.Fatalf("%+v", lv)
	}
	// Relabelled in the folder: the snapshot's label is shown, flagged pending.
	e.writeIndexRaw(strings.Replace(string(e.indexBytes()), "verified label", "attacker label", 1))
	lv, _ = Locked(e.dir, false, snap)
	if lv.State != StatePending || lv.PendingChanges != 1 || lv.Rows[0].Entry.Description != "verified label" || !lv.Rows[0].Pending {
		t.Fatalf("%+v", lv)
	}
	// A name the folder adds: unverified.
	e.writeIndexRaw(strings.Replace(string(e.indexBytes()), `"entries": [`, `"entries": [
    {"name": "NEW", "description": "claimed", "updated": "2026-11-20T10:00:00Z", "version": 1, "rev": 1, "mac": "`+strings.Repeat("2", 64)+`"},`, 1))
	lv, _ = Locked(e.dir, false, snap)
	var found bool
	for _, r := range lv.Rows {
		if r.Entry.Name == "NEW" {
			found = true
			if r.Verified {
				t.Fatal("a new name shown as verified")
			}
		}
	}
	if !found {
		t.Fatal("new name not listed")
	}
	// No snapshot: everything unverified.
	lv, _ = Locked(e.dir, false, nil)
	if lv.State != StateNever {
		t.Fatalf("state = %s", lv.State)
	}
	for _, r := range lv.Rows {
		if r.Verified {
			t.Fatal("verified without a snapshot")
		}
	}
	// Deleted index with a snapshot: still listed from the snapshot.
	_ = os.Remove(filepath.Join(e.dir, "index.json"))
	lv, _ = Locked(e.dir, false, snap)
	if !lv.Damaged || len(lv.Rows) != 1 || !lv.Rows[0].Verified {
		t.Fatalf("%+v", lv)
	}
}

// A planted duplicate name in the folder never shows twice.
func TestLockedDuplicateUnverified(t *testing.T) {
	e := newEnv(t)
	dup := `{"version": 2, "vault_id": "` + vid + `", "entries": [
    {"name": "X", "updated": "2026-11-20T10:00:00Z", "version": 1, "rev": 1, "mac": "` + strings.Repeat("3", 64) + `"},
    {"name": "X", "updated": "2026-11-20T10:00:00Z", "version": 1, "rev": 2, "mac": "` + strings.Repeat("4", 64) + `"}]}`
	e.writeIndexRaw(dup)
	lv, _ := Locked(e.dir, false, nil)
	if len(lv.Rows) != 0 {
		t.Fatalf("%+v", lv.Rows)
	}
}

// Private index: the snapshot is label-free.
func TestPrivateSnapshotHasNoLabels(t *testing.T) {
	e := newEnv(t)
	if err := format.WriteIndex(e.dir, &format.Index{Version: 2, VaultID: vid, Private: true, Entries: []format.IndexEntry{}}); err != nil {
		t.Fatal(err)
	}
	s := e.session(nil)
	snap := e.set(s, "SECRET_NAME", "v", "secret description")
	if !snap.Private || len(snap.Entries) != 1 {
		t.Fatalf("%+v", snap)
	}
	en := snap.Entries[0]
	if en.Name != "" || en.Description != "" || en.NameTag == "" {
		t.Fatalf("private snapshot has labels: %+v", en)
	}
	st := NewStore(t.TempDir())
	if err := st.Save(snap); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(st.dir, vid+".json"))
	if strings.Contains(string(b), "SECRET_NAME") || strings.Contains(string(b), "secret description") {
		t.Fatal("labels reached the snapshot file")
	}
	// It still detects rollback of an entry.
	old := e.indexBytes()
	snap = e.set(e.session(snap), "SECRET_NAME", "v", "changed")
	e.writeIndexRaw(string(old))
	if _, k := e.read(e.session(snap), "SECRET_NAME"); k.Status != StatusEntryOlder {
		t.Fatalf("private rollback: %d", k.Status)
	}
	// And locked listing shows nothing.
	if lv, _ := Locked(e.dir, false, snap); lv.State != StatePrivate || len(lv.Rows) != 0 {
		t.Fatalf("%+v", lv)
	}
}

func TestSnapshotAnchored(t *testing.T) {
	snap := &Snapshot{PinSeq: 3, PinHead: "h3", KeyID: "k1"}
	chain := map[int]string{0: "h0", 3: "h3"}
	headAt := func(s int) (string, bool) { h, ok := chain[s]; return h, ok }
	known := func(id string) bool { return id == "k1" }
	if !snap.Anchored(headAt, known) {
		t.Fatal("not anchored")
	}
	if (&Snapshot{PinSeq: 3, PinHead: "other", KeyID: "k1"}).Anchored(headAt, known) {
		t.Fatal("anchored with the wrong head")
	}
	if (&Snapshot{PinSeq: 9, PinHead: "h3", KeyID: "k1"}).Anchored(headAt, known) {
		t.Fatal("anchored beyond the chain")
	}
	if (&Snapshot{PinSeq: 3, PinHead: "h3", KeyID: "other"}).Anchored(headAt, known) {
		t.Fatal("anchored with an unknown key")
	}
	if (*Snapshot)(nil).Anchored(headAt, known) {
		t.Fatal("nil anchored")
	}
}

func TestSnapshotStoreRoundTrip(t *testing.T) {
	e := newEnv(t)
	snap := e.set(e.session(nil), "AAA", "a", "d")
	st := NewStore(filepath.Join(t.TempDir(), "index"))
	if got, err := st.Load(vid); err != nil || got != nil {
		t.Fatalf("empty store: %v %v", got, err)
	}
	if err := st.Save(snap); err != nil {
		t.Fatal(err)
	}
	got, err := st.Load(vid)
	if err != nil || len(got.Entries) != 1 || got.Entries[0].Name != "AAA" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := st.Delete(vid); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Load(vid); got != nil {
		t.Fatal("not deleted")
	}
}

// Tombstones are dropped from the snapshot at a rotation only when no file
// under any key, live or trashed, is left (Security note 2).
func TestSnapshotTombstonePruneAtRotation(t *testing.T) {
	e := newEnv(t)
	s := e.session(nil)
	e.set(s, "GONE", "x", "x")
	e.set(s, "TRASHED", "x", "x")
	v, _ := s.Load()
	res, err := s.Commit(v, tombstone("GONE", v.Floor("GONE")), tombstone("TRASHED", v.Floor("TRASHED")))
	if err != nil {
		t.Fatal(err)
	}
	// TRASHED keeps a copy in the trash, GONE has nothing left.
	if _, err := format.TrashSecret(e.dir, "TRASHED", t0); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(e.dir, "secrets", "GONE.age"))
	nk, _ := crypto.NewVaultKey()
	s2 := &Session{Dir: e.dir, VaultID: vid, Key: nk, Snap: res.Snapshot, PinHead: strings.Repeat("a", 64), Now: s.Now}
	out := s2.advance(map[string]format.IndexEntry{}, false, nil)
	names := map[string]bool{}
	for _, en := range out.Entries {
		names[en.Name] = true
	}
	if names["GONE"] || !names["TRASHED"] {
		t.Fatalf("after rotation: %v", names)
	}
}

func FuzzParseSnapshot(f *testing.F) {
	e := &env{t: &testing.T{}}
	_ = e
	f.Add([]byte(`{"version":1,"vault_id":"` + vid + `","key_id":"` + vid + `","pin_seq":0,"pin_head":"` + strings.Repeat("a", 64) + `","verified":"2026-11-20T10:00:00Z","entries":[]}`))
	f.Add([]byte(`{"version":1,"entries":[{"name":"A"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := ParseSnapshot(data)
		if err != nil {
			if s != nil {
				t.Fatal("partly filled snapshot with an error")
			}
			return
		}
		seen := map[string]bool{}
		for _, en := range s.Entries {
			id := en.Name + en.NameTag
			if seen[id] {
				t.Fatal("accepted a duplicate name")
			}
			seen[id] = true
		}
	})
}
