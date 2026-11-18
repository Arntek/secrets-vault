package members

import (
	"errors"
	"slices"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// The write guard (design Threat 4): before any write, look for evidence
// that the folder has seen a newer state than the verified vault.json (a
// removed member's rollback leaves some behind unless they scrub it), and
// for secrets sealed under keys the chain has retired.

// ErrNewerState refuses a write when the folder shows signs of a newer
// state than the verified vault.json.
var ErrNewerState = errors.New("this vault shows signs of a newer state than the one this machine verified (a secret or vault.json copy from a later key). Nothing was written. Check with the other members")

// Exposed is a secret sealed under a key the chain has retired.
type Exposed struct {
	Name  string
	KeyID string
	// RetiredAt is the seq of the record that replaced the key; Removed
	// names whoever that record removed (empty for a plain rotation).
	RetiredAt int
	Removed   string
}

// FolderReport is the write guard's finding.
type FolderReport struct {
	// Unknown lists secrets (and trash entries) sealed under keys this
	// chain never had: evidence of a newer state.
	Unknown []string
	// UnknownStaging lists rotation staging folders for keys the chain
	// never had.
	UnknownStaging []string
	// NewerCopy is set when a sync-conflict copy of vault.json verifies and
	// is ahead of this one.
	NewerCopy bool
	// Retired lists secrets under keys the chain has replaced.
	Retired []Exposed
}

// Blocking reports whether writes must be refused.
func (r *FolderReport) Blocking() bool {
	return len(r.Unknown) > 0 || len(r.UnknownStaging) > 0 || r.NewerCopy
}

// CheckFolder runs the write guard over vaultDir for the verified chain c.
// ignore lists key IDs to treat as known (this machine's own pending keys
// while it repairs a lost race).
func CheckFolder(vaultDir string, c *Chain, ignore ...string) (*FolderReport, error) {
	r := &FolderReport{}
	head := c.Head().KeyID
	check := func(name string, ct []byte) {
		id, err := crypto.KeyIDOf(ct)
		if err != nil || id == head || slices.Contains(ignore, id) {
			return // damaged files are reported when read
		}
		seq, _, ok := c.KeyIntroducedAt(id)
		if !ok {
			r.Unknown = append(r.Unknown, name)
			return
		}
		e := Exposed{Name: name, KeyID: id}
		for i := seq + 1; i < len(c.Records); i++ {
			if c.Records[i].KeyID != id {
				e.RetiredAt = i
				if c.Records[i].Op == format.OpRemoveMember {
					e.Removed = c.Records[i].Member.Name
				}
				break
			}
		}
		r.Retired = append(r.Retired, e)
	}
	secrets, err := format.ListSecrets(vaultDir)
	if err != nil {
		return nil, err
	}
	for _, s := range secrets {
		ct, err := format.ReadSecretFile(vaultDir, s.Name)
		if err != nil {
			continue
		}
		check(s.Name, ct)
	}
	trash, err := format.ListTrash(vaultDir)
	if err != nil {
		return nil, err
	}
	for _, t := range trash {
		ct, err := format.ReadTrashedFile(vaultDir, t)
		if err != nil {
			continue
		}
		check(t.Name+" (in the trash)", ct)
	}
	staging, err := format.PendingRotations(vaultDir)
	if err != nil {
		return nil, err
	}
	for _, id := range staging {
		if !c.KnowsKey(id) && !slices.Contains(ignore, id) {
			r.UnknownStaging = append(r.UnknownStaging, id)
		}
	}
	conflicts, err := format.FindConflicts(vaultDir)
	if err != nil {
		return nil, err
	}
	for _, cf := range conflicts {
		if cf.Kind != format.ConflictSyncCopy || cf.Original != format.VaultFileName {
			continue
		}
		vf, raw, err := format.ReadVaultFileCopy(vaultDir, cf.Path)
		if err != nil {
			continue
		}
		if cc, err := Verify(vf, raw, c.File.ID); err == nil && cc.Head().Seq > c.Head().Seq {
			r.NewerCopy = true
		}
	}
	return r, nil
}
