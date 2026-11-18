package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Arntek/secrets-vault/internal/format"
)

// Index entry authentication (docs/design/index-auth.md). Every entry of
// index.json carries a MAC under a key derived from the vault key, bound to
// the vault ID and the vault key's ID, so only a key holder can create or
// change an entry, and entries from before a rotation fail afterwards.
const (
	infoIndexKey  = "secrets-vault/v3 index mac key"
	entryDomain   = "secrets-vault/v3 index entry\x00"
	nameTagDomain = "secrets-vault/v3 snapshot name\x00"
)

func (k *VaultKey) macKey() []byte {
	b, err := hkdf.Key(sha256.New, k.b[:], nil, infoIndexKey, 32)
	if err != nil {
		panic("crypto: hkdf: " + err.Error())
	}
	return b
}

// lp appends a length-prefixed field (our own encoding, as for the
// membership digests, so the MAC input is deterministic and unambiguous).
func lp(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) // #nosec G115 -- every field is bounded far below 4 GiB
	return append(b, s...)
}

func entryInput(vaultID, keyID string, e *format.IndexEntry) []byte {
	b := []byte(entryDomain)
	b = lp(b, vaultID)
	b = lp(b, keyID)
	b = lp(b, e.Name)
	b = lp(b, strconv.FormatUint(uint64(e.Version), 10))
	b = lp(b, strconv.FormatUint(uint64(e.Rev), 10))
	b = lp(b, strconv.FormatBool(e.Deleted))
	b = lp(b, e.Description)
	b = lp(b, strconv.Itoa(len(e.Tags)))
	for _, t := range e.Tags {
		b = lp(b, t)
	}
	b = lp(b, e.Updated.UTC().Format(time.RFC3339Nano))
	b = lp(b, e.UpdatedBy)
	return b
}

// EntryMAC returns the hex MAC of e under key for the vault vaultID.
func EntryMAC(key *VaultKey, vaultID string, e *format.IndexEntry) string {
	mk := key.macKey()
	defer clear(mk)
	m := hmac.New(sha256.New, mk)
	m.Write(entryInput(vaultID, key.ID(), e))
	return hex.EncodeToString(m.Sum(nil))
}

// SealEntry sets e.MAC.
func SealEntry(key *VaultKey, vaultID string, e *format.IndexEntry) {
	e.MAC = EntryMAC(key, vaultID, e)
}

// VerifyEntry reports whether e.MAC is the MAC of e under key (constant
// time).
func VerifyEntry(key *VaultKey, vaultID string, e *format.IndexEntry) bool {
	want, err := hex.DecodeString(EntryMAC(key, vaultID, e))
	if err != nil {
		return false
	}
	got, err := hex.DecodeString(e.MAC)
	if err != nil {
		return false
	}
	return hmac.Equal(got, want)
}

// NameTag returns a keyed tag of a key name, for the label-free snapshot
// of a private index.
func NameTag(key *VaultKey, name string) string {
	mk := key.macKey()
	defer clear(mk)
	m := hmac.New(sha256.New, mk)
	m.Write([]byte(nameTagDomain))
	m.Write([]byte(name))
	return hex.EncodeToString(m.Sum(nil))
}

// VerifiedEntries parses index data and returns the entries that verify
// under key, one per name (a verified duplicate keeps the higher rev), and
// how many entries were dropped (malformed, bad MAC, or other vault). A
// file that is not a version-2 index returns ok false.
func VerifiedEntries(data []byte, vaultID string, key *VaultKey) (idx *format.Index, entries []format.IndexEntry, dropped int, ok bool) {
	idx, bad, err := format.ParseIndexTolerant(data)
	if err != nil || idx.Version != format.IndexVersion || (idx.VaultID != "" && idx.VaultID != vaultID) {
		return nil, nil, 0, false
	}
	dropped = bad
	byName := map[string]format.IndexEntry{}
	for i := range idx.Entries {
		e := idx.Entries[i]
		if !VerifyEntry(key, vaultID, &e) {
			dropped++
			continue
		}
		if old, dup := byName[e.Name]; dup && old.Rev >= e.Rev {
			continue
		}
		byName[e.Name] = e
	}
	for _, e := range byName {
		entries = append(entries, e)
	}
	slices.SortFunc(entries, func(a, b format.IndexEntry) int { return strings.Compare(a.Name, b.Name) })
	return idx, entries, dropped, true
}

// stageIndex builds the re-MAC'd index.json of a rotation: only entries
// that verify under oldKey (the verified head's current key, IM2) plus the
// caller's trusted entries, re-sealed under newKey. Tombstones are kept
// unless no file under any key, live or trashed, exists for the name (IS1).
//
// oldID and newID differ for a rebuild (a new vault ID); legacy is true for
// a format-2 vault being rotated into format 3, whose unauthenticated index
// is trusted once, like `vault upgrade` does.
func stageIndex(vaultDir, oldID, newID string, legacy bool, oldKey, newKey *VaultKey, trusted []format.IndexEntry, live, present map[string]bool) ([]byte, int, error) {
	out := &format.Index{Version: format.IndexVersion, VaultID: newID, Entries: []format.IndexEntry{}}
	dropped := 0
	raw, err := format.ReadIndexRaw(vaultDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// An unreadable index must not block a membership change.
		raw = nil
	}
	byName := map[string]format.IndexEntry{}
	if legacy {
		if old, err := format.ReadIndex(vaultDir); err == nil {
			out.Private = old.Private
			for _, e := range old.Entries {
				if live[e.Name] {
					e.Version, e.Rev, e.Deleted = 1, 1, false
					byName[e.Name] = e
				}
			}
		}
	} else if raw != nil {
		if idx, entries, d, ok := VerifiedEntries(raw, oldID, oldKey); ok {
			out.Private = idx.Private
			dropped = d
			for _, e := range entries {
				byName[e.Name] = e
			}
		}
	}
	// The caller's trusted entries (its anchored snapshot) fill every name
	// the folder's index doesn't carry at an equal or higher rev: live ones
	// only if their file is there and not older than the entry, tombstones
	// as tombstones (ue1.14).
	for _, e := range trusted {
		if old, ok := byName[e.Name]; ok && e.Rev <= old.Rev {
			continue
		}
		if !e.Deleted {
			if !live[e.Name] {
				continue
			}
			if ct, err := format.ReadSecretFile(vaultDir, e.Name); err != nil {
				continue
			} else if v, err := VersionOf(ct); err != nil || v < e.Version {
				continue
			}
		}
		byName[e.Name] = e
	}
	for _, e := range byName {
		if e.Deleted && !present[e.Name] {
			continue
		}
		SealEntry(newKey, newID, &e)
		out.Entries = append(out.Entries, e)
	}
	data, err := format.MarshalIndex(out)
	return data, dropped, err
}
