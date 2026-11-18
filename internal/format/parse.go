package format

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// ParseVaultFile strictly decodes and validates vault.json. A file written
// by a newer format version returns ErrUnsupportedVersion; anything else
// that is not exactly a valid version-1 or version-2 file returns an error
// wrapping ErrMalformed (or ErrTooLarge). It never returns a partly filled
// value. It checks structure only: the membership log's signatures are
// verified by package members, and callers must refuse version 1 except
// for migration.
func ParseVaultFile(data []byte) (*VaultFile, error) {
	if len(data) > MaxVaultFileSize {
		return nil, fmt.Errorf("vault.json: %w", ErrTooLarge)
	}
	if err := checkVersion(data, MaxVaultFileSize, VaultVersion); err != nil {
		return nil, fmt.Errorf("vault.json: %w", err)
	}
	var vf VaultFile
	if err := decodeStrictMax(data, MaxVaultFileSize, &vf); err != nil {
		return nil, fmt.Errorf("vault.json: %w", err)
	}
	if err := vf.Validate(); err != nil {
		return nil, fmt.Errorf("vault.json: %w", err)
	}
	return &vf, nil
}

// ParseIndex strictly decodes and validates index.json (version 1 or 2),
// with the same guarantees as ParseVaultFile: any bad entry fails the whole
// file. Verification code uses ParseIndexTolerant instead.
func ParseIndex(data []byte) (*Index, error) {
	if err := checkVersion(data, MaxFileSize, IndexVersion); err != nil {
		return nil, fmt.Errorf("index.json: %w", err)
	}
	var idx Index
	if err := decodeStrict(data, &idx); err != nil {
		return nil, fmt.Errorf("index.json: %w", err)
	}
	if err := idx.Validate(); err != nil {
		return nil, fmt.Errorf("index.json: %w", err)
	}
	return &idx, nil
}

// ParseIndexTolerant parses index.json for verification (docs/design/
// index-auth.md, IS4). The file must be well-formed JSON of the right
// shape, but entries are decoded one by one: an entry that is malformed
// is dropped and counted instead of failing the file, and duplicate names
// are kept (a duplicate has no valid MAC; the caller drops it after
// verifying MACs). The result has the file's own version, so callers can
// tell a version-1 index. It never returns a partly filled Index with an
// error.
func ParseIndexTolerant(data []byte) (idx *Index, dropped int, err error) {
	if err := checkVersion(data, MaxFileSize, IndexVersion); err != nil {
		return nil, 0, fmt.Errorf("index.json: %w", err)
	}
	var raw struct {
		Version int               `json:"version"`
		VaultID string            `json:"vault_id"`
		Private bool              `json:"private"`
		Entries []json.RawMessage `json:"entries"`
	}
	if err := decodeStrict(data, &raw); err != nil {
		return nil, 0, fmt.Errorf("index.json: %w", err)
	}
	if len(raw.Entries) > MaxIndexEntries {
		return nil, 0, fmt.Errorf("index.json: %w: more than %d entries", ErrMalformed, MaxIndexEntries)
	}
	if raw.VaultID != "" && ValidateVaultID(raw.VaultID) != nil {
		return nil, 0, fmt.Errorf("index.json: %w: bad vault id", ErrMalformed)
	}
	if raw.Version == LegacyIndexVersion && raw.VaultID != "" {
		return nil, 0, fmt.Errorf("index.json: %w: version 1 has no vault id", ErrMalformed)
	}
	idx = &Index{Version: raw.Version, VaultID: raw.VaultID, Private: raw.Private, Entries: []IndexEntry{}}
	for _, r := range raw.Entries {
		var e IndexEntry
		if err := decodeStrict(r, &e); err != nil || e.validate(raw.Version) != nil {
			dropped++
			continue
		}
		idx.Entries = append(idx.Entries, e)
	}
	return idx, dropped, nil
}

// checkVersion reads only the version field, so a file from a newer build
// (which may add fields) reports "upgrade" instead of "malformed".
func checkVersion(data []byte, maxSize, newest int) error {
	if err := checkJSONShapeMax(data, maxSize); err != nil {
		return err
	}
	var v struct {
		Version json.RawMessage `json:"version"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return describeJSONError(err)
	}
	var n int
	if err := json.Unmarshal(v.Version, &n); err != nil {
		return fmt.Errorf("%w: missing or non-integer version", ErrMalformed)
	}
	if n > newest {
		return ErrUnsupportedVersion
	}
	if n < 1 {
		return fmt.Errorf("%w: version must be at least 1", ErrMalformed)
	}
	return nil
}

// Validate checks every field of vf. Marshal calls it, so an invalid vault
// file is never written. Version 1 (pre-membership-log, read only for
// migration) and version 2 have different rules.
func (vf *VaultFile) Validate() error {
	switch vf.Version {
	case 1:
		return vf.validateV1()
	case LegacyVaultVersion, VaultVersion:
		return vf.validateV2()
	}
	return fmt.Errorf("%w: unsupported version", ErrMalformed)
}

func (vf *VaultFile) validateHeader() error {
	if err := ValidateVaultID(vf.ID); err != nil {
		return err
	}
	if err := ValidateVaultName(vf.Name); err != nil {
		return err
	}
	if err := ValidateKeyID(vf.KeyID); err != nil {
		return err
	}
	if len(vf.Unlockers) == 0 {
		return fmt.Errorf("%w: no unlockers", ErrMalformed)
	}
	if len(vf.Unlockers) > MaxUnlockers {
		return fmt.Errorf("%w: more than %d unlockers", ErrMalformed, MaxUnlockers)
	}
	return nil
}

func (vf *VaultFile) validateV1() error {
	if err := vf.validateHeader(); err != nil {
		return err
	}
	if len(vf.Members) != 0 || len(vf.Log) != 0 {
		return fmt.Errorf("%w: version 1 has no members or log", ErrMalformed)
	}
	passphrases := 0
	seen := map[string]bool{}
	for i, u := range vf.Unlockers {
		if err := u.Validate(); err != nil {
			return fmt.Errorf("unlocker %d: %w", i+1, err)
		}
		if u.Type == UnlockerPassphrase {
			passphrases++
			if passphrases > 1 {
				return fmt.Errorf("%w: more than one passphrase unlocker", ErrMalformed)
			}
		}
		if u.Recipient != "" {
			k := string(u.Type) + " " + u.Recipient
			if seen[k] {
				return fmt.Errorf("unlocker %d: %w: duplicate recipient", i+1, ErrMalformed)
			}
			seen[k] = true
		}
	}
	return nil
}

// validateV2 checks the structure of a version-2 file: a non-empty member
// set sorted by name with unique names, recipients and signing keys;
// exactly one member unlocker per member (same label and recipient) and at
// most one passphrase unlocker, nothing else; and 1-MaxLogEntries log
// entries. Signatures and the hashes in the log are package members' job.
func (vf *VaultFile) validateV2() error {
	if err := vf.validateHeader(); err != nil {
		return err
	}
	if err := ValidateMembers(vf.Members); err != nil {
		return err
	}
	byName := make(map[string]Member, len(vf.Members))
	for _, m := range vf.Members {
		byName[m.Name] = m
	}
	passphrases := 0
	unlocked := map[string]bool{}
	for i, u := range vf.Unlockers {
		if err := u.Validate(); err != nil {
			return fmt.Errorf("unlocker %d: %w", i+1, err)
		}
		switch u.Type {
		case UnlockerPassphrase:
			passphrases++
			if passphrases > 1 {
				return fmt.Errorf("%w: more than one passphrase unlocker", ErrMalformed)
			}
			if u.Label != "" || u.Recipient != "" {
				return fmt.Errorf("unlocker %d: %w: passphrase unlocker has a label or recipient", i+1, ErrMalformed)
			}
		case UnlockerMember:
			m, ok := byName[u.Label]
			if !ok || m.Recipient != u.Recipient {
				return fmt.Errorf("unlocker %d: %w: member unlocker does not match a member", i+1, ErrMalformed)
			}
			if unlocked[u.Label] {
				return fmt.Errorf("unlocker %d: %w: two unlockers for one member", i+1, ErrMalformed)
			}
			unlocked[u.Label] = true
		default:
			return fmt.Errorf("unlocker %d: %w: unlocker type not allowed in this format version", i+1, ErrMalformed)
		}
	}
	if len(unlocked) != len(vf.Members) {
		return fmt.Errorf("%w: a member has no unlocker", ErrMalformed)
	}
	if len(vf.Log) == 0 || len(vf.Log) > MaxLogEntries {
		return fmt.Errorf("%w: membership log must have 1-%d records", ErrMalformed, MaxLogEntries)
	}
	for i, e := range vf.Log {
		if err := e.Validate(); err != nil {
			return fmt.Errorf("log record %d: %w", i, err)
		}
	}
	return nil
}

// Validate checks one log entry's structure.
func (e *LogEntry) Validate() error {
	if len(e.Body) == 0 || len(e.Body) > MaxRecordSize {
		return fmt.Errorf("%w: record body must be 1-%d bytes", ErrMalformed, MaxRecordSize)
	}
	if err := ValidateMemberName(e.By); err != nil {
		return fmt.Errorf("%w: bad signer name", ErrMalformed)
	}
	if len(e.Sig) != SignatureSize {
		return fmt.Errorf("%w: bad signature length", ErrMalformed)
	}
	return nil
}

// Validate checks one unlocker record.
func (u *Unlocker) Validate() error {
	switch u.Type {
	case UnlockerPassphrase:
	case UnlockerTouchID, UnlockerMember:
		if u.Label == "" {
			return fmt.Errorf("%w: %s unlocker needs a label", ErrMalformed, u.Type)
		}
	default:
		return fmt.Errorf("%w: unknown unlocker type", ErrMalformed)
	}
	if u.Type == UnlockerMember && u.Recipient == "" {
		return fmt.Errorf("%w: member unlocker needs a recipient", ErrMalformed)
	}
	if err := validateText("unlocker label", u.Label, MaxLabelLen); err != nil {
		return err
	}
	if err := validateRecipient(u.Recipient); err != nil {
		return err
	}
	if len(u.WrappedKey) == 0 || len(u.WrappedKey) > MaxWrappedKeyLen {
		return fmt.Errorf("%w: wrapped key must be 1-%d bytes", ErrMalformed, MaxWrappedKeyLen)
	}
	if u.Created.IsZero() {
		return fmt.Errorf("%w: unlocker has no created time", ErrMalformed)
	}
	return nil
}

// MarshalVaultFile validates vf and encodes it as indented JSON. Only the
// current version is ever written.
func MarshalVaultFile(vf *VaultFile) ([]byte, error) {
	if vf.Version != VaultVersion && vf.Version != LegacyVaultVersion {
		return nil, fmt.Errorf("%w: only versions %d and %d are written", ErrMalformed, LegacyVaultVersion, VaultVersion)
	}
	if err := vf.Validate(); err != nil {
		return nil, err
	}
	return marshal(vf)
}

// UnlockersOf returns the unlockers of type t, in file order.
func (vf *VaultFile) UnlockersOf(t UnlockerType) []Unlocker {
	var out []Unlocker
	for _, u := range vf.Unlockers {
		if u.Type == t {
			out = append(out, u)
		}
	}
	return out
}

// SetUnlocker adds u, replacing an existing unlocker it supersedes: the
// passphrase unlocker for a passphrase, or the unlocker of the same type
// and recipient otherwise (or same type and label when the recipient is
// empty). It reports whether one was replaced.
func (vf *VaultFile) SetUnlocker(u Unlocker) bool {
	for i, old := range vf.Unlockers {
		if old.Type != u.Type {
			continue
		}
		same := u.Type == UnlockerPassphrase ||
			(u.Recipient != "" && old.Recipient == u.Recipient) ||
			(u.Recipient == "" && old.Recipient == "" && old.Label == u.Label)
		if same {
			vf.Unlockers[i] = u
			return true
		}
	}
	vf.Unlockers = append(vf.Unlockers, u)
	return false
}

// RemoveUnlockers deletes every unlocker for which drop returns true and
// returns how many were removed. Validate fails if none are left.
func (vf *VaultFile) RemoveUnlockers(drop func(Unlocker) bool) int {
	before := len(vf.Unlockers)
	vf.Unlockers = slices.DeleteFunc(vf.Unlockers, drop)
	return before - len(vf.Unlockers)
}

// Validate checks every field of idx (version 1 or 2).
func (idx *Index) Validate() error {
	if idx.Version != IndexVersion && idx.Version != LegacyIndexVersion {
		return fmt.Errorf("%w: unsupported version", ErrMalformed)
	}
	if idx.Version == LegacyIndexVersion && idx.VaultID != "" {
		return fmt.Errorf("%w: version 1 has no vault id", ErrMalformed)
	}
	if idx.VaultID != "" {
		if err := ValidateVaultID(idx.VaultID); err != nil {
			return err
		}
	}
	if len(idx.Entries) > MaxIndexEntries {
		return fmt.Errorf("%w: more than %d entries", ErrMalformed, MaxIndexEntries)
	}
	seen := make(map[string]bool, len(idx.Entries))
	for i := range idx.Entries {
		e := &idx.Entries[i]
		if err := e.validate(idx.Version); err != nil {
			return fmt.Errorf("entry %d: %w", i+1, err)
		}
		if seen[e.Name] {
			return fmt.Errorf("entry %d: %w: duplicate key name", i+1, ErrMalformed)
		}
		seen[e.Name] = true
	}
	return nil
}

// Validate checks one index entry as a version-2 entry.
func (e *IndexEntry) Validate() error { return e.validate(IndexVersion) }

func (e *IndexEntry) validate(indexVersion int) error {
	if err := ValidateKeyName(e.Name); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if err := validateText("description", e.Description, MaxDescriptionLen); err != nil {
		return err
	}
	if len(e.Tags) > MaxTags {
		return fmt.Errorf("%w: more than %d tags", ErrMalformed, MaxTags)
	}
	for j, t := range e.Tags {
		if err := ValidateTag(t); err != nil {
			return err
		}
		if slices.Contains(e.Tags[:j], t) {
			return fmt.Errorf("%w: duplicate tag", ErrMalformed)
		}
	}
	if err := validateText("updated_by", e.UpdatedBy, MaxUpdatedByLen); err != nil {
		return err
	}
	if e.Updated.IsZero() {
		return fmt.Errorf("%w: entry has no updated time", ErrMalformed)
	}
	if indexVersion == LegacyIndexVersion {
		if e.Version != 0 || e.Rev != 0 || e.Deleted || e.MAC != "" {
			return fmt.Errorf("%w: version 1 entry has version 2 fields", ErrMalformed)
		}
		return nil
	}
	if e.Version < 1 || e.Version > MaxCounter || e.Rev < 1 || e.Rev > MaxCounter {
		return fmt.Errorf("%w: entry version or rev out of range", ErrMalformed)
	}
	if !isHex(e.MAC, 64) {
		return fmt.Errorf("%w: entry mac must be 64 lower-case hex characters", ErrMalformed)
	}
	return nil
}

// MarshalIndex validates idx and encodes it as indented JSON with entries
// sorted by name. idx itself is not modified.
func MarshalIndex(idx *Index) ([]byte, error) {
	if idx.Version != IndexVersion {
		return nil, fmt.Errorf("%w: only index version %d is written", ErrMalformed, IndexVersion)
	}
	if err := idx.Validate(); err != nil {
		return nil, err
	}
	out := *idx
	out.Entries = slices.Clone(idx.Entries)
	if out.Entries == nil {
		out.Entries = []IndexEntry{}
	}
	slices.SortFunc(out.Entries, func(a, b IndexEntry) int { return strings.Compare(a.Name, b.Name) })
	return marshal(&out)
}

func marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
