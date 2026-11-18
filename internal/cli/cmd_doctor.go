package cli

import (
	"fmt"
	"sort"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/index"
	"github.com/Arntek/secrets-vault/internal/members"
)

// cmdDoctor: doctor VAULT [--quarantine-staging] [--adopt NAME] [--yes]
//
// Reports what can block a vault: sync-conflict copies, key-rotation
// staging folders and, when the vault is unlocked (or --adopt is given),
// keys the authenticated index refuses (docs/design/index-auth.md). With
// --quarantine-staging it deals with staging folders after verifying the
// vault: the one for a verified interrupted rotation is finished if every
// staged file opens under the vault key; any other (a planted folder, or
// one this vault's history never had) is moved to quarantine/ in the vault
// folder. Nothing is deleted (ue1.10). With --adopt NAME it gives a file
// that has no signed entry one, after showing it and asking.
func cmdDoctor(a *app, p *parsed) error {
	if err := p.wantArgs(1, 1, a.prog+" doctor VAULT [--quarantine-staging] [--adopt NAME] [--yes]"); err != nil {
		return err
	}
	v, err := a.vault(p.args[0])
	if err != nil {
		return err
	}
	if _, err := a.open(v); err != nil {
		return err
	}
	if v.v1 != nil {
		return failf("vault '%s' was made by a pre-release version; open it once (%s unlock %s) to upgrade it", v.name, a.prog, v.name)
	}
	conflicts, err := format.FindConflicts(v.dir)
	if err != nil {
		return failf("cannot check vault '%s': %v", v.name, vaultErr(err))
	}
	staging, err := format.PendingRotations(v.dir)
	if err != nil {
		return failf("cannot check vault '%s': %v", v.name, vaultErr(err))
	}
	type stagingRow struct {
		KeyID  string `json:"key_id"`
		Status string `json:"status"`
		Moved  string `json:"moved_to,omitempty"`
	}
	rows := []stagingRow{}
	var key *crypto.VaultKey
	switch {
	case p.has("adopt"):
		k, err := a.openKey(v, nil, openOpts{purpose: purposeWrite})
		if err != nil {
			return err
		}
		key = k
	case p.has("quarantine-staging") && len(staging) > 0:
		k, err := a.openKey(v, nil, openOpts{purpose: purposeRead})
		if err != nil {
			return err
		}
		key = k
	default:
		key = a.agentKey(v) // only if already unlocked; doctor never asks
	}
	if key != nil {
		defer key.Destroy()
	}
	head := v.chain.Head().KeyID
	_, rotation, _ := v.chain.KeyIntroducedAt(head)
	for _, id := range staging {
		r := stagingRow{KeyID: id}
		current := id == head && rotation
		switch {
		case key == nil && current:
			r.Status = "an interrupted rotation of this vault. If its files are intact the next change finishes it; if not, it can't be finished and --quarantine-staging moves it aside. Unlock the vault and run doctor again to find out which"
		case key == nil:
			r.Status = "not part of this vault's history (planted, or another member's rotation still syncing)"
		case current && !p.has("quarantine-staging"):
			if err := crypto.VerifyStaged(v.dir, key); err != nil {
				r.Status = "cannot be finished: a staged file does not open under the vault key. If no member is changing the vault key right now, move it aside with --quarantine-staging"
			} else {
				r.Status = "an interrupted rotation of this vault; the next change finishes it"
			}
		case !p.has("quarantine-staging"):
			r.Status = "not part of this vault's history (planted, or another member's rotation still syncing)"
		case current:
			if _, err := crypto.RecoverRotation(v.dir, key); err == nil {
				r.Status = "finished the interrupted rotation"
				break
			}
			fallthrough
		default:
			moved, err := format.QuarantineStaging(v.dir, id, a.now())
			if err != nil {
				return failf("could not move a staging folder of '%s' aside: %v", v.name, vaultErr(err))
			}
			r.Status, r.Moved = "moved aside", moved
		}
		rows = append(rows, r)
	}

	// The authenticated index (needs the key).
	type problemRow struct {
		Key     string `json:"key"`
		Problem string `json:"problem"`
	}
	problems := []problemRow{}
	unlisted := []string{}
	indexCopies := map[string]bool{} // conflict copy of index.json -> already merged
	dropped := 0
	var vi *vindex
	if key != nil && !legacyChain(v.chain) {
		if vi, err = a.openIndex(v, key); err != nil {
			return err
		}
		dropped = vi.view.Dropped
		for _, k := range vi.view.Problems() {
			if k.Status == index.StatusUnlisted {
				unlisted = append(unlisted, k.Name)
				continue
			}
			problems = append(problems, problemRow{k.Name, k.Describe()})
		}
		for _, c := range conflicts {
			if c.Kind != format.ConflictSyncCopy || c.Original != format.IndexFileName {
				continue
			}
			indexCopies[c.Path] = indexCopyMerged(v, vi, key, c.Path)
		}
	}
	if p.has("adopt") {
		return a.adopt(v, vi, key, p.str("adopt"), p.has("yes"))
	}

	if a.asJSON {
		cs := []string{}
		for _, c := range conflicts {
			cs = append(cs, c.Path)
		}
		sort.Strings(unlisted)
		return a.printJSON(map[string]any{
			"vault": v.name, "conflicts": cs, "staging": rows, "state_code": members.StateCode(v.chain, v.chain.Head().Seq),
			"index_checked": vi != nil, "index_problems": problems, "unlisted": unlisted, "index_entries_failed": dropped,
		})
	}
	healthy := len(conflicts) == 0 && len(rows) == 0 && len(problems) == 0 && len(unlisted) == 0 && dropped == 0
	if healthy {
		extra := ""
		if vi == nil && !legacyChain(v.chain) {
			extra = fmt.Sprintf("; its index was not checked (unlock it first: %s unlock %s)", a.prog, v.name)
		}
		a.printf("'%s' looks healthy (%s)%s.\n", v.name, members.StateCode(v.chain, v.chain.Head().Seq), extra)
		return nil
	}
	for _, c := range conflicts {
		if merged, ok := indexCopies[c.Path]; ok && merged {
			a.printf("Sync conflict copy: %s (its entries are already in the index; safe to delete)\n", c.Path)
			continue
		}
		a.printf("Sync conflict copy: %s (resolve it by hand, keeping the right version)\n", c.Path)
	}
	for _, r := range rows {
		if r.Moved != "" {
			a.printf("Key-rotation folder %s: moved aside to %s (nothing deleted)\n", r.KeyID, r.Moved)
		} else {
			a.printf("Key-rotation folder %s: %s\n", r.KeyID, r.Status)
		}
	}
	for _, pr := range problems {
		a.printf("Key %s: %s\n", pr.Key, pr.Problem)
	}
	for _, n := range unlisted {
		a.printf("File %s has no signed entry in the index, so it is not trusted. If it is yours: %s doctor %s --adopt %s\n", n, a.prog, v.name, n)
	}
	if dropped > 0 {
		a.printf("%s in the index failed verification and are ignored.\n", plural(dropped, "entry"))
	}
	if !p.has("quarantine-staging") && len(rows) > 0 {
		a.printf("If no member is changing the vault key right now: %s doctor %s --quarantine-staging\n", a.prog, v.name)
	}
	return nil
}

// indexCopyMerged reports whether every verified entry of a conflict copy
// of index.json is already in the verified index at the same or a higher rev.
func indexCopyMerged(v *vaultRef, vi *vindex, key *crypto.VaultKey, rel string) bool {
	raw, err := format.ReadIndexCopy(v.dir, rel)
	if err != nil {
		return false
	}
	_, entries, _, ok := crypto.VerifiedEntries(raw, v.chain.File.ID, key)
	if !ok {
		return false
	}
	for _, e := range entries {
		k, have := vi.view.Key(e.Name)
		if !have || k.Entry.Rev < e.Rev {
			return false
		}
	}
	return true
}

// adopt gives a file that has no signed entry one (doctor --adopt). The
// file must open under the vault key with its own name, so only a member
// can have written it; a key that was deleted, or that this machine has
// verified at a higher version, is never adopted.
func (a *app) adopt(v *vaultRef, vi *vindex, key *crypto.VaultKey, name string, yes bool) error {
	if err := format.ValidateKeyName(name); err != nil {
		return usageErrf("%v", err)
	}
	if vi == nil {
		return failf("vault '%s' must be upgraded first: %s upgrade %s", v.name, a.prog, v.name)
	}
	if k, ok := vi.view.Key(name); !ok || k.Status != index.StatusUnlisted {
		return failf("%s is not an unlisted file in '%s'", name, v.name)
	}
	val, ver, err := crypto.ReadSecretVersion(v.dir, name, key)
	if err != nil {
		return failf("that file does not open under this vault's key with its own name, so it is not adopted")
	}
	clear(val)
	if !yes {
		if !a.term.StdinTTY() {
			return failf("adopting needs confirmation: run it in a terminal, or pass --yes")
		}
		ok, _ := a.confirm(fmt.Sprintf("Give %s (file version %d) a signed entry in '%s'? It opens under this vault's key, so a member wrote it.", name, ver, v.name))
		if !ok {
			return failf("cancelled")
		}
	}
	nv, err := vi.view.NextVersion(name)
	if err != nil {
		return failf("%v", err)
	}
	// A file from a build before this format has no version: seal it at the
	// next one so it can't be told from a rolled-back copy.
	if ver == 0 {
		val, _, err := crypto.ReadSecretVersion(v.dir, name, key)
		if err != nil {
			return failf("cannot read %s: %v", name, vaultErr(err))
		}
		err = crypto.WriteSecretVersion(v.dir, name, key, val, nv)
		clear(val)
		if err != nil {
			return failf("cannot re-seal %s: %v", name, vaultErr(err))
		}
		ver = nv
	}
	if err := vi.commit(index.Edit{Name: name, Apply: func(cur *format.IndexEntry) (format.IndexEntry, error) {
		return format.IndexEntry{Version: max(ver, nv-1), Updated: a.now().UTC(), UpdatedBy: a.myName()}, nil
	}}); err != nil {
		return err
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": v.name, "name": name, "adopted": true})
	}
	a.printf("Adopted %s in '%s'. Add a description with: %s describe %s TEXT\n", name, v.name, a.prog, name)
	return nil
}
