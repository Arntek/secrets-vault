package format

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// ParseVaultFile strictly decodes and validates vault.json. A file written
// by a newer format version returns ErrUnsupportedVersion; anything else
// that is not exactly a valid version-1 file returns an error wrapping
// ErrMalformed (or ErrTooLarge). It never returns a partly filled value.
func ParseVaultFile(data []byte) (*VaultFile, error) {
	if err := checkVersion(data); err != nil {
		return nil, fmt.Errorf("vault.json: %w", err)
	}
	var vf VaultFile
	if err := decodeStrict(data, &vf); err != nil {
		return nil, fmt.Errorf("vault.json: %w", err)
	}
	if err := vf.Validate(); err != nil {
		return nil, fmt.Errorf("vault.json: %w", err)
	}
	return &vf, nil
}

// ParseIndex strictly decodes and validates index.json, with the same
// guarantees as ParseVaultFile.
func ParseIndex(data []byte) (*Index, error) {
	if err := checkVersion(data); err != nil {
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

// checkVersion reads only the version field, so a file from a newer build
// (which may add fields) reports "upgrade" instead of "malformed".
func checkVersion(data []byte) error {
	if err := checkJSONShape(data); err != nil {
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
	if n > CurrentVersion {
		return ErrUnsupportedVersion
	}
	if n < 1 {
		return fmt.Errorf("%w: version must be at least 1", ErrMalformed)
	}
	return nil
}

// Validate checks every field of vf. Marshal calls it, so an invalid vault
// file is never written.
func (vf *VaultFile) Validate() error {
	if vf.Version != CurrentVersion {
		return fmt.Errorf("%w: unsupported version", ErrMalformed)
	}
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

// MarshalVaultFile validates vf and encodes it as indented JSON.
func MarshalVaultFile(vf *VaultFile) ([]byte, error) {
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

// Validate checks every field of idx. Marshal calls it.
func (idx *Index) Validate() error {
	if idx.Version != CurrentVersion {
		return fmt.Errorf("%w: unsupported version", ErrMalformed)
	}
	if len(idx.Entries) > MaxIndexEntries {
		return fmt.Errorf("%w: more than %d entries", ErrMalformed, MaxIndexEntries)
	}
	seen := make(map[string]bool, len(idx.Entries))
	for i := range idx.Entries {
		e := &idx.Entries[i]
		if err := e.Validate(); err != nil {
			return fmt.Errorf("entry %d: %w", i+1, err)
		}
		if seen[e.Name] {
			return fmt.Errorf("entry %d: %w: duplicate key name", i+1, ErrMalformed)
		}
		seen[e.Name] = true
	}
	return nil
}

// Validate checks one index entry.
func (e *IndexEntry) Validate() error {
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
	return nil
}

// MarshalIndex validates idx and encodes it as indented JSON with entries
// sorted by name. idx itself is not modified.
func MarshalIndex(idx *Index) ([]byte, error) {
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
