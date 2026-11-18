package index

import (
	"slices"
	"strings"
	"time"

	"github.com/Arntek/secrets-vault/internal/format"
)

// What `list`, `info`, `search` and name resolution may show without the
// vault key (design "While locked"). Nothing here can be verified, so rows
// come from the snapshot where it has the name, and everything the folder
// adds or changes is flagged.

// Index states of a locked vault.
const (
	StateVerified = "verified"
	StatePending  = "pending-changes"
	StateNever    = "unverified"
	StatePrivate  = "private"
	StateLegacy   = "legacy"
)

// LockedRow is one key as a locked command may show it.
type LockedRow struct {
	Entry format.IndexEntry
	// Verified is true when the row is exactly what this machine verified
	// before (same MAC), false for a name the folder added.
	Verified bool
	// Pending is true when the folder holds a different entry for this name
	// than the snapshot; Entry then shows the snapshot's (verified) values.
	Pending bool
}

// LockedView is the answer for one locked vault.
type LockedView struct {
	Rows  []LockedRow
	State string
	// PendingChanges counts folder entries that are new, changed or
	// missing compared with the snapshot.
	PendingChanges int
	// LastVerified is when the snapshot was made (zero if never).
	LastVerified time.Time
	// Damaged: the folder's index could not be read; rows are the snapshot's.
	Damaged bool
}

// Locked builds the view without a key. snap must already be anchored (nil
// if none). legacy comes from the verified chain (format 2): the old index
// is shown as it always was, flagged legacy.
func Locked(dir string, legacy bool, snap *Snapshot) (*LockedView, error) {
	lv := &LockedView{State: StateNever}
	var folder []format.IndexEntry
	private := false
	damaged := false
	raw, rerr := format.ReadIndexRaw(dir)
	switch {
	case rerr != nil:
		damaged = true
	default:
		idx, _, err := format.ParseIndexTolerant(raw)
		if err != nil {
			damaged = true
		} else {
			folder, private = idx.Entries, idx.Private
		}
	}
	if legacy {
		lv.State = StateLegacy
		old, err := format.ReadIndex(dir)
		if err != nil {
			old = nil
		}
		idx, _, err := format.RebuildIndex(dir, old)
		if err != nil {
			return nil, err
		}
		for _, e := range idx.Entries {
			lv.Rows = append(lv.Rows, LockedRow{Entry: e})
		}
		return lv, nil
	}
	if snap != nil {
		lv.LastVerified = snap.Verified
		private = private || snap.Private
	}
	if private {
		lv.State = StatePrivate
		return lv, nil
	}
	lv.Damaged = damaged
	if damaged && snap != nil {
		// The folder's index is gone or unreadable: what this machine last
		// verified is still the best answer, flagged as changed.
		for _, e := range snap.Entries {
			if !e.Deleted {
				lv.Rows = append(lv.Rows, LockedRow{Entry: fromSnap(e.Name, e), Verified: true, Pending: true})
			}
		}
		slices.SortFunc(lv.Rows, func(a, b LockedRow) int { return strings.Compare(a.Entry.Name, b.Entry.Name) })
		lv.State = StatePending
		return lv, nil
	}
	// Group the folder's entries by name; a name that appears twice is
	// resolved to the copy the snapshot knows, if any.
	byName := map[string][]format.IndexEntry{}
	for _, e := range folder {
		byName[e.Name] = append(byName[e.Name], e)
	}
	snapBy := map[string]SnapEntry{}
	if snap != nil {
		for _, e := range snap.Entries {
			snapBy[e.Name] = e
		}
	}
	for name, es := range byName {
		sn, known := snapBy[name]
		if known {
			same := slices.ContainsFunc(es, func(e format.IndexEntry) bool { return e.MAC == sn.MAC && e.Rev == sn.Rev })
			if same {
				if !sn.Deleted {
					lv.Rows = append(lv.Rows, LockedRow{Entry: fromSnap(name, sn), Verified: true})
				}
				continue
			}
			lv.PendingChanges++
			if !sn.Deleted {
				lv.Rows = append(lv.Rows, LockedRow{Entry: fromSnap(name, sn), Verified: true, Pending: true})
			}
			continue
		}
		if len(es) == 1 && !es[0].Deleted {
			lv.PendingChanges++
			lv.Rows = append(lv.Rows, LockedRow{Entry: es[0]})
		} else if len(es) == 1 {
			lv.PendingChanges++
		}
		// Several unverified entries for one name: none is shown.
	}
	for name, sn := range snapBy {
		if _, ok := byName[name]; !ok && !sn.Deleted {
			lv.PendingChanges++
			// Not shown: the folder no longer lists it.
			_ = name
		}
	}
	slices.SortFunc(lv.Rows, func(a, b LockedRow) int { return strings.Compare(a.Entry.Name, b.Entry.Name) })
	switch {
	case snap == nil:
		lv.State = StateNever
	case lv.PendingChanges > 0 || damaged:
		lv.State = StatePending
	default:
		lv.State = StateVerified
	}
	return lv, nil
}

func fromSnap(name string, sn SnapEntry) format.IndexEntry {
	e := sn.entry()
	e.Name = name
	return e
}
