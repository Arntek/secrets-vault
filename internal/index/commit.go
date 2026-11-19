package index

import (
	"errors"
	"slices"
	"strings"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// maxAttempts bounds the compare-and-swap retry loop.
const maxAttempts = 10

// ErrBusy means index.json kept changing under every attempt.
var ErrBusy = errors.New("the index kept changing while saving; run the command again")

// Edit changes one entry. Apply receives the current verified entry (nil if
// there is none) and returns the new one: the caller sets description,
// tags, updated, updated_by, version and deleted; Commit sets name, rev and
// the MAC. Apply runs again on a fresh entry if the write has to be
// retried, so it must be a pure function of its argument.
type Edit struct {
	Name  string
	Apply func(cur *format.IndexEntry) (format.IndexEntry, error)
}

// Result is what a successful Commit returns.
type Result struct {
	View *View
	// Snapshot is the new local snapshot to save.
	Snapshot *Snapshot
	// Concurrent names edited keys that someone else changed at the same
	// moment (the last write wins; the caller tells the person).
	Concurrent []string
	// Merged counts entries taken from sync-conflict copies of index.json.
	Merged int
	// Healed names entries rebuilt from this machine's snapshot.
	Healed []string
}

// Commit applies edits to the index with the compare-and-swap write loop
// (design "Concurrent writers"): every other key's entry is carried over
// as read (merge, not last-write-wins), entries rebuilt from the snapshot
// and entries merged from verified conflict copies are re-sealed, and a
// lost compare-and-swap reloads and re-applies only the edits.
//
// v is a view from Load. The vault must be at format 3.
func (s *Session) Commit(v *View, edits ...Edit) (*Result, error) {
	if s.Legacy || v.Legacy {
		return nil, errors.New("index: the vault must be upgraded first")
	}
	base := map[string]uint32{} // rev each edited key had when first read
	for _, e := range edits {
		if k, ok := v.carry[e.Name]; ok {
			base[e.Name] = k.Rev
		}
	}
	var concurrent []string
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			nv, err := s.Load()
			if err != nil {
				return nil, err
			}
			v = nv
			for _, e := range edits {
				if k, ok := v.carry[e.Name]; ok && k.Rev > base[e.Name] && !slices.Contains(concurrent, e.Name) {
					concurrent = append(concurrent, e.Name)
				}
			}
		}
		res, err := s.commitOnce(v, edits)
		if errors.Is(err, format.ErrIndexChanged) {
			continue
		}
		if err != nil {
			return nil, err
		}
		res.Concurrent = concurrent
		return res, nil
	}
	return nil, ErrBusy
}

func (s *Session) commitOnce(v *View, edits []Edit) (*Result, error) {
	res := &Result{}
	entries := make(map[string]format.IndexEntry, len(v.carry))
	for n, e := range v.carry {
		entries[n] = e
	}
	resealed := map[string]bool{}
	for n := range v.reconstructed {
		resealed[n] = true
		res.Healed = append(res.Healed, n)
	}
	// Heal entries that the folder's index holds at an older rev than this
	// machine verified, if their file is not older than the snapshot.
	for _, n := range v.older {
		if sn, ok := s.Snap.Get(n, s.Key); ok && sn.Deleted {
			e := sn.entry()
			e.Name = n
			if e.Updated.IsZero() {
				e.Updated = s.Snap.Verified
			}
			entries[n] = e
			resealed[n] = true
			continue
		}
		if sn, ok := s.Snap.Get(n, s.Key); ok && !sn.Deleted && v.present[n] {
			if fv := v.fileVersion(n); fv >= sn.Version {
				e := sn.entry()
				e.Name, e.Version = n, max(sn.Version, fv)
				if e.Updated.IsZero() {
					e.Updated = s.Snap.Verified
				}
				entries[n] = e
				resealed[n] = true
				res.Healed = append(res.Healed, n)
			}
		}
	}
	// A tombstone this machine verified but the folder's index lost is
	// written back, not dropped (a deleted key stays deleted).
	if s.Snap != nil && !s.Snap.Private {
		for _, sn := range s.Snap.Entries {
			if _, ok := entries[sn.Name]; ok || !sn.Deleted {
				continue
			}
			e := sn.entry()
			if e.Updated.IsZero() {
				e.Updated = s.Snap.Verified
			}
			entries[sn.Name] = e
			resealed[sn.Name] = true
		}
	}
	res.Merged = s.mergeConflicts(v, entries, resealed)
	for _, ed := range edits {
		var cur *format.IndexEntry
		if e, ok := entries[ed.Name]; ok {
			c := e
			cur = &c
		}
		ne, err := ed.Apply(cur)
		if err != nil {
			return nil, err
		}
		ne.Name = ed.Name
		if ne.Version > format.MaxCounter {
			return nil, ErrCounterLimit
		}
		entries[ed.Name] = ne
		resealed[ed.Name] = true
	}
	out := &format.Index{Version: format.IndexVersion, VaultID: s.VaultID, Private: v.Private, Entries: make([]format.IndexEntry, 0, len(entries))}
	for n, e := range entries {
		if resealed[n] {
			rev := e.Rev
			if sn, ok := s.Snap.Get(n, s.Key); ok {
				rev = max(rev, sn.Rev)
			}
			if k, ok := v.carry[n]; ok {
				rev = max(rev, k.Rev)
			}
			if rev >= format.MaxCounter {
				return nil, ErrCounterLimit
			}
			e.Rev = rev + 1
			crypto.SealEntry(s.Key, s.VaultID, &e)
			entries[n] = e
		}
		out.Entries = append(out.Entries, e)
	}
	if err := format.WriteIndexCAS(s.Dir, out, v.Raw); err != nil {
		return nil, err
	}
	nv := &View{s: s, Private: v.Private, Keys: map[string]*KeyInfo{}, carry: entries, reconstructed: map[string]bool{}, present: v.present}
	for n, e := range entries {
		st := statusPending
		if e.Deleted {
			st = StatusDeleted
		}
		nv.Keys[n] = &KeyInfo{Name: n, Entry: e, Status: st}
	}
	if raw, err := format.ReadIndexRaw(s.Dir); err == nil {
		nv.Raw = raw
	}
	res.View = nv
	res.Snapshot = s.advance(entries, v.Private, nil)
	return res, nil
}

// mergeConflicts takes entries from sync-conflict copies of index.json that
// verify under the current key (IM2: nothing under a retired key), when
// their rev is higher (or the key is new) and the file is not older than
// the entry. It returns how many entries it took.
func (s *Session) mergeConflicts(v *View, entries map[string]format.IndexEntry, resealed map[string]bool) int {
	conflicts, err := format.FindConflicts(s.Dir)
	if err != nil {
		return 0
	}
	taken := 0
	for _, c := range conflicts {
		if c.Kind != format.ConflictSyncCopy || c.Original != format.IndexFileName {
			continue
		}
		raw, err := format.ReadIndexCopy(s.Dir, c.Path)
		if err != nil {
			continue
		}
		_, cands, _, ok := crypto.VerifiedEntries(raw, s.VaultID, s.Key)
		if !ok {
			continue
		}
		for _, e := range cands {
			if sn, ok := s.Snap.Get(e.Name, s.Key); ok && (e.Rev < sn.Rev || e.Version < sn.Version) {
				continue
			}
			if cur, have := entries[e.Name]; have && e.Rev <= cur.Rev {
				continue
			}
			if e.Deleted == v.present[e.Name] {
				continue // a tombstone with a live file, or a live entry with no file
			}
			if !e.Deleted && v.fileVersion(e.Name) < e.Version {
				continue
			}
			entries[e.Name] = e
			resealed[e.Name] = true
			taken++
		}
	}
	return taken
}

// Observe returns the snapshot after this machine verified v: the highest
// rev and version seen per name, with the display fields of the newest
// entry. It is what a read-only command saves after Load.
func (s *Session) Observe(v *View) *Snapshot {
	return s.advance(v.carry, v.Private, nil)
}

// RaiseFloor returns a snapshot like Observe's, with name's version floor
// raised to version: used when a read finds a file newer than its entry
// (StatusIndexBehind), which proves that version exists.
func (s *Session) RaiseFloor(v *View, name string, version uint32) *Snapshot {
	return s.advance(v.carry, v.Private, map[string]uint32{name: version})
}

func (s *Session) advance(entries map[string]format.IndexEntry, private bool, raise map[string]uint32) *Snapshot {
	snap := &Snapshot{Version: snapshotVersion, VaultID: s.VaultID, KeyID: s.Key.ID(), PinSeq: s.PinSeq, PinHead: s.PinHead, Verified: s.now(), Private: private}
	byID := map[string]SnapEntry{}
	idOf := func(name string) string {
		if private {
			return crypto.NameTag(s.Key, name)
		}
		return name
	}
	if s.Snap != nil && s.Snap.Private == private {
		for _, e := range s.Snap.Entries {
			byID[e.Name+e.NameTag] = e
		}
	}
	for n, e := range entries {
		if e.MAC == "" {
			continue // rebuilt from the snapshot, not sealed yet
		}
		id := idOf(n)
		ne := SnapEntry{Rev: e.Rev, Version: e.Version, Deleted: e.Deleted, MAC: e.MAC}
		if private {
			ne.NameTag = id
		} else {
			ne.Name, ne.Description, ne.Tags, ne.Updated, ne.UpdatedBy = n, e.Description, e.Tags, e.Updated, e.UpdatedBy
		}
		if old, had := byID[id]; had && old.Rev > e.Rev {
			ne = old
			ne.Version = max(old.Version, e.Version)
		}
		byID[id] = ne
	}
	for n, ver := range raise {
		if old, ok := byID[idOf(n)]; ok && ver > old.Version {
			old.Version = ver
			byID[idOf(n)] = old
		}
	}
	rotated := s.Snap != nil && s.Snap.KeyID != s.Key.ID()
	var present map[string]bool
	if rotated && !private {
		present = s.allNames()
	}
	for _, e := range byID {
		if rotated && !private && e.Deleted && !present[e.Name] {
			continue // IS1: tombstones go at a rotation, once no file is left
		}
		snap.Entries = append(snap.Entries, e)
	}
	slices.SortFunc(snap.Entries, func(a, b SnapEntry) int { return strings.Compare(a.Name+a.NameTag, b.Name+b.NameTag) })
	if snap.Entries == nil {
		snap.Entries = []SnapEntry{}
	}
	return snap
}

// allNames lists every secret name, live or trashed.
func (s *Session) allNames() map[string]bool {
	out := map[string]bool{}
	if live, err := format.ListSecrets(s.Dir); err == nil {
		for _, f := range live {
			out[f.Name] = true
		}
	}
	if tr, err := format.ListTrash(s.Dir); err == nil {
		for _, t := range tr {
			out[t.Name] = true
		}
	}
	return out
}
