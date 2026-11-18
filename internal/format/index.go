package format

import (
	"errors"
	"io/fs"
	"slices"
	"strings"
)

// NewIndex returns an empty index at the current version.
func NewIndex() *Index {
	return &Index{Version: IndexVersion, Entries: []IndexEntry{}}
}

// Get returns the entry for name.
func (idx *Index) Get(name string) (IndexEntry, bool) {
	for _, e := range idx.Entries {
		if e.Name == name {
			return e, true
		}
	}
	return IndexEntry{}, false
}

// Upsert adds e or replaces the entry with the same name, keeping entries
// sorted by name. It does not validate e; WriteIndex does.
func (idx *Index) Upsert(e IndexEntry) {
	i, found := slices.BinarySearchFunc(idx.Entries, e.Name, func(x IndexEntry, n string) int { return strings.Compare(x.Name, n) })
	if found {
		idx.Entries[i] = e
		return
	}
	// The slice may not be sorted if it came from a hand-edited file.
	for j := range idx.Entries {
		if idx.Entries[j].Name == e.Name {
			idx.Entries[j] = e
			return
		}
	}
	idx.Entries = slices.Insert(idx.Entries, i, e)
}

// Remove deletes the entry for name and reports whether it existed.
func (idx *Index) Remove(name string) bool {
	before := len(idx.Entries)
	idx.Entries = slices.DeleteFunc(idx.Entries, func(e IndexEntry) bool { return e.Name == name })
	return len(idx.Entries) != before
}

// RebuildIndex makes an index that matches the files in secrets/. Entries
// in old whose file exists keep their metadata; files with no entry get a
// bare entry (no description) dated by the file's modification time;
// entries with no file are dropped. old may be nil (for example when
// index.json is missing or fails to parse). changed reports whether the
// result differs from old.
func RebuildIndex(vaultDir string, old *Index) (idx *Index, changed bool, err error) {
	files, err := ListSecrets(vaultDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	idx = NewIndex()
	if old == nil {
		old = NewIndex()
		changed = true
	} else {
		idx.Private = old.Private
	}
	kept := 0
	for _, f := range files {
		if e, ok := old.Get(f.Name); ok {
			idx.Entries = append(idx.Entries, e)
			kept++
			continue
		}
		idx.Entries = append(idx.Entries, IndexEntry{Name: f.Name, Updated: f.Modified})
		changed = true
	}
	if kept != len(old.Entries) {
		changed = true
	}
	return idx, changed, nil
}
