package index

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// The local snapshot (design "The local snapshot (pin)"): what this machine
// last verified of a vault's index, kept outside the synced folder next to
// the trust pins. It is the only defence against a consistent rollback of
// index and file together, and it is what a locked `list` shows.

const (
	snapshotVersion = 1
	maxSnapshotSize = 16 << 20
)

// SnapEntry is one entry as last verified. A private index stores the
// label-free form: NameTag in place of Name, and no description, tags or
// attribution.
type SnapEntry struct {
	Name        string    `json:"name,omitempty"`
	NameTag     string    `json:"name_tag,omitempty"`
	Rev         uint32    `json:"rev"`
	Version     uint32    `json:"version"`
	Deleted     bool      `json:"deleted,omitempty"`
	MAC         string    `json:"mac"`
	Description string    `json:"description,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Updated     time.Time `json:"updated,omitempty"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
}

// Snapshot is one vault's local index snapshot.
type Snapshot struct {
	Version int    `json:"version"`
	VaultID string `json:"vault_id"`
	// KeyID is the vault key the entries were verified under.
	KeyID string `json:"key_id"`
	// PinSeq and PinHead are the trust pin's head when this was verified
	// (IS3): a snapshot whose head is not on the verified chain is stale and
	// never vouches for anything.
	PinSeq   int         `json:"pin_seq"`
	PinHead  string      `json:"pin_head"`
	Private  bool        `json:"private,omitempty"`
	Verified time.Time   `json:"verified"`
	Entries  []SnapEntry `json:"entries"`
}

// ParseSnapshot strictly parses a snapshot file.
func ParseSnapshot(data []byte) (*Snapshot, error) {
	var s Snapshot
	if err := format.DecodeStrict(data, maxSnapshotSize, &s); err != nil {
		return nil, err
	}
	bad := fmt.Errorf("%w: bad index snapshot", format.ErrMalformed)
	if s.Version != snapshotVersion || format.ValidateVaultID(s.VaultID) != nil || format.ValidateKeyID(s.KeyID) != nil ||
		s.PinSeq < 0 || s.PinSeq >= format.MaxLogEntries || len(s.PinHead) != 64 || len(s.Entries) > format.MaxIndexEntries {
		return nil, bad
	}
	seen := map[string]bool{}
	for i := range s.Entries {
		e := &s.Entries[i]
		id := e.Name
		if s.Private {
			id = e.NameTag
			if e.Name != "" || e.Description != "" || len(e.Tags) != 0 || e.UpdatedBy != "" || !e.Updated.IsZero() || len(e.NameTag) != 64 {
				return nil, bad
			}
		} else {
			if e.NameTag != "" || format.ValidateKeyName(e.Name) != nil {
				return nil, bad
			}
			ie := e.entry()
			ie.Version, ie.Rev = max(e.Version, 1), max(e.Rev, 1)
			if ie.Updated.IsZero() {
				ie.Updated = time.Unix(1, 0)
			}
			if ie.MAC == "" {
				ie.MAC = strings.Repeat("0", 64)
			}
			if err := ie.Validate(); err != nil {
				return nil, bad
			}
		}
		if seen[id] || e.Version < 1 || e.Version > format.MaxCounter || e.Rev < 1 || e.Rev > format.MaxCounter || len(e.MAC) != 64 {
			return nil, bad
		}
		seen[id] = true
	}
	return &s, nil
}

func (e SnapEntry) entry() format.IndexEntry {
	return format.IndexEntry{Name: e.Name, Description: e.Description, Tags: e.Tags, Updated: e.Updated, UpdatedBy: e.UpdatedBy,
		Version: e.Version, Rev: e.Rev, Deleted: e.Deleted, MAC: e.MAC}
}

// Anchored reports whether this snapshot belongs to the verified chain: its
// pin head is the record at PinSeq (headAt) and its key was one of the
// vault's keys (knowsKey). A snapshot that is not anchored (an accepted
// rollback, a different vault generation) must be treated as absent.
func (s *Snapshot) Anchored(headAt func(seq int) (string, bool), knowsKey func(keyID string) bool) bool {
	if s == nil {
		return false
	}
	h, ok := headAt(s.PinSeq)
	return ok && h == s.PinHead && knowsKey(s.KeyID)
}

// Get returns the snapshot entry for name (in a private snapshot, looked up
// by tag, which needs the key).
func (s *Snapshot) Get(name string, key *crypto.VaultKey) (SnapEntry, bool) {
	if s == nil {
		return SnapEntry{}, false
	}
	for _, e := range s.Entries {
		if s.Private {
			if key != nil && e.NameTag == crypto.NameTag(key, name) {
				return e, true
			}
			continue
		}
		if e.Name == name {
			return e, true
		}
	}
	return SnapEntry{}, false
}

// Store keeps snapshots in a per-user directory (~/.config/vault/index).
type Store struct{ dir string }

// NewStore returns the store in dir.
func NewStore(dir string) *Store { return &Store{dir: dir} }

func (t *Store) path(vaultID string) (string, error) {
	if err := format.ValidateVaultID(vaultID); err != nil {
		return "", err
	}
	return filepath.Join(t.dir, vaultID+".json"), nil
}

// Load returns the snapshot for vaultID, or nil if there is none.
func (t *Store) Load(vaultID string) (*Snapshot, error) {
	p, err := t.path(vaultID)
	if err != nil {
		return nil, err
	}
	data, err := format.ReadRegularFile(p, maxSnapshotSize)
	if err != nil {
		if os.IsNotExist(err) || isNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	s, err := ParseSnapshot(data)
	if err != nil {
		return nil, err
	}
	if s.VaultID != vaultID {
		return nil, fmt.Errorf("%w: index snapshot for another vault", format.ErrMalformed)
	}
	return s, nil
}

// Save writes s (0600, directory 0700).
func (t *Store) Save(s *Snapshot) error {
	p, err := t.path(s.VaultID)
	if err != nil {
		return err
	}
	slices.SortFunc(s.Entries, func(a, b SnapEntry) int { return strings.Compare(a.Name+a.NameTag, b.Name+b.NameTag) })
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(t.dir, format.DirMode); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(t.dir, format.DirMode); err != nil { // #nosec G302 -- a directory needs the execute bit; 0700 is owner-only
			return err
		}
	}
	return format.WriteFileAtomic(p, append(data, '\n'), format.FileMode)
}

// Delete removes the snapshot for vaultID (detach, accepted rollback).
func (t *Store) Delete(vaultID string) error {
	p, err := t.path(vaultID)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !isNotExist(err) {
		return err
	}
	return nil
}
