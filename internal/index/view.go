package index

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// Status says what Load and Verdict decided about one key.
type Status int

// Statuses. Readable ones come first.
const (
	// StatusOK: a verified entry whose file matches it.
	StatusOK Status = iota
	// StatusIndexBehind: the file is newer than its entry (the index is
	// stale or still syncing). The file is authentic; the value is readable.
	StatusIndexBehind
	// StatusReconstructed: no entry in the folder, but this machine's
	// snapshot vouches for the file (a lost update); readable, repaired by
	// the next write.
	StatusReconstructed
	// StatusFileOlder: the file is older than its entry or than the
	// snapshot: rolled back, or the file has not synced yet. Refused.
	StatusFileOlder
	// StatusEntryOlder: the entry is older than the snapshot. Refused.
	StatusEntryOlder
	// StatusFileMissing: an entry with no file. Refused.
	StatusFileMissing
	// StatusUnlisted: a file with no usable entry. Refused (doctor --adopt).
	StatusUnlisted
	// StatusResurrected: a deleted key's file is back. Refused.
	StatusResurrected
	// StatusDeleted: a tombstone with no file: the normal deleted state.
	StatusDeleted
	// StatusDamaged: the index is missing or damaged and the snapshot does
	// not vouch for this key. Refused.
	StatusDamaged

	statusPending // internal: verified live entry, file not yet compared
)

// Errors a refused key maps to. Every one is a verification failure
// (the CLI exits 5). Messages never quote input.
var (
	ErrFileOlder    = errors.New("that key's file is older than the index says; it may still be syncing, and if it persists someone restored an old copy")
	ErrEntryOlder   = errors.New("that key's index entry is older than what this machine has verified; the index was rolled back or is still syncing")
	ErrFileMissing  = errors.New("that key is listed but its file is missing; it may have been deleted outside secrets-vault, or is still syncing")
	ErrUnlisted     = errors.New("that key's file has no signed entry in the index, so it is not trusted; check it with the doctor command")
	ErrResurrected  = errors.New("that key was deleted and its file has reappeared; it is not trusted")
	ErrIndexDamaged = errors.New("the index of this vault is missing or damaged, so the keys it lists can't be trusted")
	// ErrCounterLimit is returned when a version or rev would pass format.MaxCounter.
	ErrCounterLimit = errors.New("this key has reached its change limit; save it under a new name and delete this one")
)

// KeyInfo is the verdict about one key name.
type KeyInfo struct {
	Name   string
	Entry  format.IndexEntry
	Status Status
	// FileVersion and HasFile are filled by Verdict.
	FileVersion uint32
	HasFile     bool
}

// Readable reports whether the value may be read.
func (k KeyInfo) Readable() bool {
	return k.Status == StatusOK || k.Status == StatusIndexBehind || k.Status == StatusReconstructed
}

// Err returns why the key is refused, or nil when it is readable (or is a
// plain tombstone, which callers report as not found).
func (k KeyInfo) Err() error {
	switch k.Status {
	case StatusFileOlder:
		return ErrFileOlder
	case StatusEntryOlder:
		return ErrEntryOlder
	case StatusFileMissing:
		return ErrFileMissing
	case StatusUnlisted:
		return ErrUnlisted
	case StatusResurrected:
		return ErrResurrected
	case StatusDamaged:
		return ErrIndexDamaged
	}
	return nil
}

// Session is what Load and Commit need to know about one vault.
type Session struct {
	Dir     string
	VaultID string
	Key     *crypto.VaultKey
	// Legacy is true only when the verified chain says the vault is at
	// format 2 (never decided by the index file, IM1).
	Legacy bool
	// Snap is this machine's snapshot, already checked with Anchored (nil
	// if none or not anchored).
	Snap *Snapshot
	// PinSeq and PinHead are the verified trust pin, recorded in the
	// snapshots this session produces.
	PinSeq  int
	PinHead string
	// Now is the clock (tests).
	Now func() time.Time
}

func (s *Session) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// View is the verified state of one vault's index.
type View struct {
	// Legacy: a format-2 vault; entries are unauthenticated and nothing is
	// cross-checked.
	Legacy bool
	// Damaged: a format-3 index that is missing, not version 2, not
	// parseable or for another vault (IM1).
	Damaged   bool
	DamageWhy string
	// Dropped counts folder entries that failed parsing or verification.
	Dropped int
	Private bool
	// Keys holds every name known: verified entries (live and tombstones),
	// reconstructed ones, unlisted files and refused entries.
	Keys map[string]*KeyInfo
	// Raw is the exact index.json read (nil if it was absent), for the CAS.
	Raw []byte

	s *Session
	// carry are the entries a commit keeps: verified (not older than the
	// snapshot) and reconstructed ones.
	carry         map[string]format.IndexEntry
	reconstructed map[string]bool
	older         []string // entries older than the snapshot
	present       map[string]bool
}

// Names returns the readable live key names, sorted.
func (v *View) Names() []string {
	var out []string
	for n, k := range v.Keys {
		if k.Status != StatusDeleted && k.Status != StatusUnlisted && k.Status != StatusResurrected && !k.Entry.Deleted {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// Key returns the verdict for name (a zero KeyInfo with StatusUnlisted-free
// "unknown" is reported by ok false).
func (v *View) Key(name string) (*KeyInfo, bool) {
	k, ok := v.Keys[name]
	return k, ok
}

// Load reads and verifies the index (design "Verification").
func (s *Session) Load() (*View, error) {
	v := &View{Keys: map[string]*KeyInfo{}, s: s, carry: map[string]format.IndexEntry{}, reconstructed: map[string]bool{}, present: map[string]bool{}, Legacy: s.Legacy}
	files, err := format.ListSecrets(s.Dir)
	if err != nil && !isNotExist(err) {
		return nil, err
	}
	for _, f := range files {
		v.present[f.Name] = true
	}
	raw, rerr := format.ReadIndexRaw(s.Dir)
	if rerr == nil {
		v.Raw = raw
	}
	if s.Legacy {
		return v, s.loadLegacy(v, files)
	}
	var verified []format.IndexEntry
	switch {
	case rerr != nil:
		v.Damaged, v.DamageWhy = true, "missing or unreadable"
	default:
		idx, entries, dropped, ok := crypto.VerifiedEntries(raw, s.VaultID, s.Key)
		if !ok {
			v.Damaged, v.DamageWhy = true, "not a current index for this vault"
		} else {
			v.Private = idx.Private
			v.Dropped = dropped
			verified = entries
		}
	}
	byName := map[string]format.IndexEntry{}
	for _, e := range verified {
		byName[e.Name] = e
	}
	// Entries verified under the key: compare with the snapshot.
	for name, e := range byName {
		if sn, ok := s.Snap.Get(name, s.Key); ok && (e.Rev < sn.Rev || e.Version < sn.Version) {
			v.Keys[name] = &KeyInfo{Name: name, Entry: e, Status: StatusEntryOlder}
			v.older = append(v.older, name)
			continue
		}
		v.carry[name] = e
		switch {
		case e.Deleted && v.present[name]:
			v.Keys[name] = &KeyInfo{Name: name, Entry: e, Status: StatusResurrected}
		case e.Deleted:
			v.Keys[name] = &KeyInfo{Name: name, Entry: e, Status: StatusDeleted}
		case !v.present[name]:
			v.Keys[name] = &KeyInfo{Name: name, Entry: e, Status: StatusFileMissing}
		default:
			v.Keys[name] = &KeyInfo{Name: name, Entry: e, Status: statusPending}
		}
	}
	// Files without a (usable) entry: the snapshot may vouch for them (a
	// lost update); otherwise they are unlisted, or the index is damaged.
	for _, f := range files {
		if _, ok := v.Keys[f.Name]; ok {
			continue
		}
		sn, ok := s.Snap.Get(f.Name, s.Key)
		if !ok || sn.Deleted {
			st := StatusUnlisted
			switch {
			case ok && sn.Deleted:
				st = StatusResurrected
			case v.Damaged:
				st = StatusDamaged
			}
			v.Keys[f.Name] = &KeyInfo{Name: f.Name, Status: st}
			continue
		}
		v.setReconstructed(f.Name, sn)
	}
	return v, nil
}

// setReconstructed makes the entry for name from the snapshot, if the file
// is not older than it.
func (v *View) setReconstructed(name string, sn SnapEntry) {
	fv := v.fileVersion(name)
	e := sn.entry()
	e.Name = name
	if e.Updated.IsZero() {
		e.Updated = v.s.Snap.Verified
	}
	if fv < sn.Version {
		v.Keys[name] = &KeyInfo{Name: name, Entry: e, Status: StatusFileOlder, FileVersion: fv, HasFile: true}
		return
	}
	e.Version = max(sn.Version, fv)
	e.MAC = ""
	v.carry[name] = e
	v.reconstructed[name] = true
	v.Keys[name] = &KeyInfo{Name: name, Entry: e, Status: StatusReconstructed, FileVersion: fv, HasFile: true}
}

// fileVersion reads the version stamped in secrets/NAME.age's header (0 if
// unreadable or unversioned).
func (v *View) fileVersion(name string) uint32 {
	ct, err := format.ReadSecretFile(v.s.Dir, name)
	if err != nil {
		return 0
	}
	n, err := crypto.VersionOf(ct)
	if err != nil {
		return 0
	}
	return n
}

func (s *Session) loadLegacy(v *View, files []format.SecretInfo) error {
	old, rerr := format.ReadIndex(s.Dir)
	if rerr != nil {
		old = nil
	}
	idx, _, err := format.RebuildIndex(s.Dir, old)
	if err != nil {
		return err
	}
	v.Private = idx.Private
	for _, e := range idx.Entries {
		v.Keys[e.Name] = &KeyInfo{Name: e.Name, Entry: e, Status: StatusOK}
	}
	return nil
}

// Verdict decides whether name may be read, given the version stamped in
// the file that was just opened (the caller reads the file once, with
// crypto.ReadSecretVersion, and passes what that returned). hasFile is
// false if the file does not exist.
func (v *View) Verdict(name string, fileVersion uint32, hasFile bool) KeyInfo {
	k, ok := v.Keys[name]
	if !ok {
		if hasFile {
			return KeyInfo{Name: name, Status: StatusUnlisted, FileVersion: fileVersion, HasFile: true}
		}
		return KeyInfo{Name: name, Status: StatusDeleted}
	}
	out := *k
	out.FileVersion, out.HasFile = fileVersion, hasFile
	if v.Legacy {
		return out
	}
	switch k.Status {
	case statusPending:
		switch {
		case !hasFile:
			out.Status = StatusFileMissing
		case fileVersion < k.Entry.Version:
			out.Status = StatusFileOlder
		case fileVersion > k.Entry.Version:
			out.Status = StatusIndexBehind
		default:
			out.Status = StatusOK
		}
	case StatusReconstructed:
		if !hasFile || fileVersion < k.Entry.Version {
			out.Status = StatusFileOlder
		}
	}
	return out
}

// Floor returns the highest version known for name: its file, its entry
// and this machine's snapshot.
func (v *View) Floor(name string) uint32 {
	n := v.fileVersion(name)
	if k, ok := v.Keys[name]; ok {
		n = max(n, k.Entry.Version)
	}
	if sn, ok := v.s.Snap.Get(name, v.s.Key); ok {
		n = max(n, sn.Version)
	}
	return n
}

// NextVersion returns the version a new write of name should carry: one
// above everything known about it.
func (v *View) NextVersion(name string) (uint32, error) {
	n := v.Floor(name)
	if n >= format.MaxCounter {
		return 0, ErrCounterLimit
	}
	return n + 1, nil
}

// Unlisted returns the names of files with no usable entry, sorted.
func (v *View) Unlisted() []string {
	var out []string
	for n, k := range v.Keys {
		if k.Status == StatusUnlisted {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// Problems returns every key that is refused, sorted by name, for doctor.
func (v *View) Problems() []KeyInfo {
	var out []KeyInfo
	for _, n := range sortedKeys(v.Keys) {
		k := *v.Keys[n]
		if k.Status == statusPending {
			ver := v.fileVersion(n)
			k = v.Verdict(n, ver, v.present[n])
		}
		if k.Err() != nil {
			out = append(out, k)
		}
	}
	return out
}

func sortedKeys(m map[string]*KeyInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Describe is a one-line, human reason for a refused status (doctor).
func (k KeyInfo) Describe() string {
	switch k.Status {
	case StatusFileOlder:
		return fmt.Sprintf("file version %d is older than the index's %d", k.FileVersion, k.Entry.Version)
	case StatusEntryOlder:
		return "index entry is older than this machine has verified"
	case StatusFileMissing:
		return "listed, but the file is missing"
	case StatusUnlisted:
		return "a file with no signed entry"
	case StatusResurrected:
		return "deleted, but its file is back"
	case StatusDamaged:
		return "the index is damaged"
	}
	return ""
}
