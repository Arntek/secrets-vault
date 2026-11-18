package cli

import (
	"errors"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/members"
)

// cmdUpgrade: upgrade VAULT [--yes]
//
// Moves a format-2 vault to format 3 (docs/design/index-auth.md): secret
// files are stamped with versions, the index gets per-entry MACs, and a
// signed upgrade-format record makes the format part of the vault's signed
// history. Any member can do it (a personal vault needs only the identity
// unlock). Order: files, index, then vault.json with compare-and-swap as the
// commit; it can be run again after an interruption.
func cmdUpgrade(a *app, p *parsed) error {
	if err := p.wantArgs(1, 1, a.prog+" upgrade VAULT [--yes]"); err != nil {
		return err
	}
	v, err := a.vault(p.args[0])
	if err != nil {
		return err
	}
	vf, err := a.open(v)
	if err != nil {
		return err
	}
	if v.v1 != nil {
		return failf("vault '%s' was made by a pre-release version; open it once (%s unlock %s) to upgrade it first", v.name, a.prog, v.name)
	}
	if !legacyChain(v.chain) {
		if a.asJSON {
			return a.printJSON(map[string]any{"vault": v.name, "upgraded": false, "already": true})
		}
		a.printf("'%s' already uses the current format.\n", v.name)
		return nil
	}
	if !p.has("yes") {
		if !a.term.StdinTTY() {
			return failf("upgrading needs confirmation: run it in a terminal, or pass --yes")
		}
		ok, _ := a.confirm("Upgrade '" + v.name + "' to the new format? Older builds can no longer open it: " + upgradeHint + ".")
		if !ok {
			return failf("cancelled")
		}
	}
	v.allowLegacy = true
	key, err := a.openKey(v, vf, openOpts{purpose: purposeWrite})
	if err != nil {
		return err
	}
	defer key.Destroy()
	un, err := a.signer(v)
	if err != nil {
		return err
	}
	c := v.chain
	n, err := crypto.UpgradeToV3(v.dir, key)
	if err != nil {
		return failf("cannot re-seal the secrets of '%s': %v (run the command again to finish)", v.name, vaultErr(err))
	}
	if err := writeUpgradedIndex(v.dir, c.File.ID, key); err != nil {
		return failf("cannot write the index of '%s': %v (run the command again to finish)", v.name, vaultErr(err))
	}
	next, err := c.UpgradeFormat(un, a.now())
	if err != nil {
		return failf("cannot upgrade '%s': %v", v.name, vaultErr(err))
	}
	nc, err := members.WriteUpgrade(v.dir, c, next)
	if err != nil {
		if errors.Is(err, format.ErrChanged) {
			return failf("vault.json of '%s' changed while upgrading; run the command again", v.name)
		}
		return failf("cannot upgrade '%s': %v", v.name, vaultErr(err))
	}
	if err := a.afterWrite(v, nc, nc.LastEntry()); err != nil {
		return err
	}
	v.allowLegacy = false
	// First snapshot of the authenticated index.
	_, _ = a.openIndex(v, key)
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": v.name, "upgraded": true, "files_resealed": n, "state_code": members.StateCode(nc, nc.Head().Seq)})
	}
	a.printf("Upgraded '%s' (%s). Its index now carries signed entries; look over '%s list --vault %s' once, since the labels were taken as they were. Every member must upgrade secrets-vault to keep using it.\n",
		v.name, plural(n, "secret file")+" re-sealed", a.prog, v.name)
	return nil
}

// writeUpgradedIndex builds the authenticated index of a vault being
// upgraded from its old, unauthenticated one: every existing secret file
// gets an entry at rev 1, version 1 (UpgradeToV3 stamped the files so), with
// the labels as they were: the one time they are taken on trust.
func writeUpgradedIndex(dir, vaultID string, key *crypto.VaultKey) error {
	raw, rerr := format.ReadIndexRaw(dir)
	if rerr != nil {
		raw = nil
	}
	old, err := format.ReadIndex(dir)
	if err != nil {
		old = nil
	}
	idx, _, err := format.RebuildIndex(dir, old)
	if err != nil {
		return err
	}
	out := &format.Index{Version: format.IndexVersion, VaultID: vaultID, Private: idx.Private, Entries: make([]format.IndexEntry, 0, len(idx.Entries))}
	for _, e := range idx.Entries {
		e.Version, e.Rev, e.Deleted = 1, 1, false
		crypto.SealEntry(key, vaultID, &e)
		out.Entries = append(out.Entries, e)
	}
	return format.WriteIndexCAS(dir, out, raw)
}
