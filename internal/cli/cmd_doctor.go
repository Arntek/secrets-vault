package cli

import (
	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/members"
)

// cmdDoctor: doctor VAULT [--quarantine-staging]
//
// Reports what can block a vault: sync-conflict copies and key-rotation
// staging folders. With --quarantine-staging it deals with staging folders
// after verifying the vault: the one for a verified interrupted rotation
// is finished if every staged file opens under the vault key; any other
// (a planted folder, or one this vault's history never had) is moved to
// quarantine/ in the vault folder. Nothing is deleted (ue1.10).
func cmdDoctor(a *app, p *parsed) error {
	if err := p.wantArgs(1, 1, a.prog+" doctor VAULT [--quarantine-staging]"); err != nil {
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
	if p.has("quarantine-staging") && len(staging) > 0 {
		k, err := a.openKey(v, nil, openOpts{purpose: purposeRead})
		if err != nil {
			return err
		}
		key = k
		defer key.Destroy()
	}
	head := v.chain.Head().KeyID
	_, rotation, _ := v.chain.KeyIntroducedAt(head)
	for _, id := range staging {
		r := stagingRow{KeyID: id}
		current := id == head && rotation
		switch {
		case key == nil && current:
			r.Status = "interrupted rotation of this vault; the next change finishes it"
		case key == nil:
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
	if a.asJSON {
		cs := []string{}
		for _, c := range conflicts {
			cs = append(cs, c.Path)
		}
		return a.printJSON(map[string]any{"vault": v.name, "conflicts": cs, "staging": rows, "state_code": members.StateCode(v.chain, v.chain.Head().Seq)})
	}
	if len(conflicts) == 0 && len(rows) == 0 {
		a.printf("'%s' looks healthy (%s).\n", v.name, members.StateCode(v.chain, v.chain.Head().Seq))
		return nil
	}
	for _, c := range conflicts {
		a.printf("Sync conflict copy: %s (resolve it by hand, keeping the right version)\n", c.Path)
	}
	for _, r := range rows {
		if r.Moved != "" {
			a.printf("Key-rotation folder %s: moved aside to %s (nothing deleted)\n", r.KeyID, r.Moved)
		} else {
			a.printf("Key-rotation folder %s: %s\n", r.KeyID, r.Status)
		}
	}
	if !p.has("quarantine-staging") && len(rows) > 0 {
		a.printf("If no member is changing the vault key right now: %s doctor %s --quarantine-staging\n", a.prog, v.name)
	}
	return nil
}
