package cli

import (
	"errors"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/members"
)

// cmdTrust: trust VAULT [--expect CODE] [--accept-rollback]
//
// Without flags it verifies the vault, pins it on first use, and repairs a
// change of this machine's that raced another member's. With --expect it
// checks the vault against a state code another member gave out of band
// (for example after a removal) and refuses a folder that is behind it.
// --accept-rollback is the deliberate way past a hard refusal: it shows
// what the folder holds and needs the fingerprint of whoever signed it.
func cmdTrust(a *app, p *parsed) error {
	if err := p.wantArgs(1, 1, a.prog+" trust VAULT [--expect CODE] [--accept-rollback]"); err != nil {
		return err
	}
	v, err := a.vault(p.args[0])
	if err != nil {
		return err
	}
	if p.has("accept-rollback") {
		return a.acceptRollback(v)
	}
	if _, err := a.open(v); err != nil {
		return err
	}
	if v.v1 != nil {
		return failf("vault '%s' was made by a pre-release version; open it once (%s unlock %s) to upgrade it", v.name, a.prog, v.name)
	}
	if v.class.Outcome == members.LostRace {
		key, err := a.openKey(v, nil, openOpts{purpose: purposeWrite})
		if err != nil {
			return err
		}
		key.Destroy()
	}
	if a.expectCode != "" {
		// open() has already checked the code (and remembered it if the
		// folder is behind). Here it is met: pin the head.
		if v.pin == nil {
			if _, err := a.applyExpect(v, a.expectCode); err != nil {
				return err
			}
		}
		if v.pin == nil || v.pin.Head != v.chain.Head().Head {
			if err := a.savePin(v, nil); err != nil {
				return err
			}
		}
	}
	code := members.StateCode(v.chain, v.chain.Head().Seq)
	trusted := v.pin != nil
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": v.name, "trusted": trusted, "state_code": code, "head": v.chain.Head().Head})
	}
	if !trusted {
		a.printf("'%s' verifies, but this machine doesn't trust a state of it yet (you are not a member, or haven't unlocked it). State: %s\n", v.name, code)
		return nil
	}
	a.printf("'%s' is at %s. State code: %s\n", v.name, headLine(v.chain), code)
	return nil
}

// acceptRollback re-pins a vault whose folder doesn't extend this
// machine's pin, after the person types the fingerprint of the member who
// signed the folder's latest change.
func (a *app) acceptRollback(v *vaultRef) error {
	c, _, err := a.loadVault(v)
	if errors.Is(err, members.ErrOldFormat) {
		return failf("vault '%s' holds a pre-release format; that is not a state this machine can accept", v.name)
	}
	if err != nil {
		return err
	}
	ts, err := a.trustStore()
	if err != nil {
		return err
	}
	pin, err := ts.Load(c.File.ID)
	if err != nil {
		return err
	}
	behind := pin != nil && pin.Expect != nil && !pin.Expect.Met(c)
	if cl := members.Classify(c, pin); cl.Outcome != members.Rollback && !behind {
		return failf("'%s' is not refused on this machine; there is nothing to accept", v.name)
	}
	if behind {
		a.infof("You were given the state code %s%s for '%s', and the folder is behind it.", c.File.Name, pin.Expect, v.name)
	}
	h := c.Head()
	var signer format.Member
	if h.Seq == 0 {
		signer = *c.Records[0].Member
	} else {
		signer, _ = c.States[h.Seq-1].Member(h.By)
	}
	fp, err := members.Fingerprint(signer.Recipient, signer.SignKey)
	if err != nil {
		return err
	}
	if !a.asJSON {
		a.infof("This machine last verified '%s' at %s@%d.", v.name, c.File.Name, pin.Seq)
		a.infof("The folder now holds %s. Its members:", headLine(c))
		a.printMembers(c)
		for i, r := range c.Records {
			if r.Op == format.OpRemoveMember && i > 0 {
				a.infof("  (%s was removed at %s@%d by %s)", r.Member.Name, c.File.Name, i, c.States[i].By)
			}
		}
		a.infof("This also forgets what this machine verified of the index; keys are checked afresh from the folder's state.")
		a.infof("Accept this only if every member agrees it is the right state.")
	}
	typed := a.signerFP
	if typed == "" {
		if !a.term.StdinTTY() {
			return failf("accepting another state needs %s's fingerprint: run it in a terminal, or pass --signer-fingerprint FP", h.By)
		}
		line, err := a.ask("Type " + h.By + "'s fingerprint as " + h.By + " reads it to you: ")
		if err != nil {
			return failf("cancelled")
		}
		typed = line
	}
	if !members.FingerprintsEqual(members.NormalizeFingerprint(typed), fp) {
		return failf("that is not %s's fingerprint; nothing was changed", h.By)
	}
	v.chain, v.pin = c, nil
	if err := a.savePin(v, nil); err != nil {
		return err
	}
	if ps, err := a.pendingStore(); err == nil {
		_ = ps.DeleteAll(c.File.ID)
	}
	// What this machine verified of the index belonged to the state it just
	// gave up: every key reads as first use from here (IS3).
	if st, err := a.indexStore(); err == nil {
		_ = st.Delete(c.File.ID)
	}
	if rep, err := members.CheckFolder(v.dir, c); err == nil {
		for _, n := range rep.Unknown {
			a.warnf("warning: %s is sealed with a key this state doesn't know; it may have been exposed", n)
		}
		a.warnExposed(v, rep)
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": v.name, "accepted": members.StateCode(c, h.Seq)})
	}
	a.printf("This machine now trusts '%s' at %s.\n", v.name, members.StateCode(c, h.Seq))
	return nil
}

// cmdRebuild: rebuild VAULT [--yes]
//
// Creates the vault again in the same folder, with a new vault ID and key,
// owned by this person's identity, and moves every secret into it. It is
// the recovery route when the only member's identity is lost (open it with
// the vault passphrase) and when the membership history is full. Every
// other member has to attach and be approved again.
func cmdRebuild(a *app, p *parsed) error {
	if err := p.wantArgs(1, 1, a.prog+" rebuild VAULT [--yes]"); err != nil {
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
		return failf("vault '%s' was made by a pre-release version; open it once (%s unlock %s) to upgrade it instead", v.name, a.prog, v.name)
	}
	if !p.has("yes") {
		if !a.term.StdinTTY() {
			return failf("rebuilding needs confirmation: run it in a terminal, or pass --yes")
		}
		ok, _ := a.confirm("Rebuild '" + v.name + "' with you as its only member? Everyone else must attach and be approved again.")
		if !ok {
			return failf("cancelled")
		}
	}
	key, err := a.openKey(v, nil, openOpts{purpose: purposeRead, forceAuth: true})
	if err != nil {
		return err
	}
	defer key.Destroy()
	if _, ok := a.myIdentity(); !ok && !a.identityNeedsUpgrade() {
		if _, err := a.createIdentity(""); err != nil {
			return err
		}
	}
	un, err := a.unlockIdentity()
	if err != nil {
		return err
	}
	np, err := a.askNewPassphrase("Choose a recovery passphrase for the rebuilt '" + v.name + "'")
	if err != nil {
		return err
	}
	pw, err := a.passphraseWrapper(np)
	clear(np)
	if err != nil {
		return failf("that passphrase cannot be used")
	}
	defer destroyWrapper(pw)
	mw, err := un.MemberWrapper()
	if err != nil {
		return err
	}
	oldID := v.chain.File.ID
	newKey, err := crypto.Rotate(v.dir, key, crypto.RotateOptions{
		Expect:         v.chain.Raw,
		NewVaultID:     true,
		TrustedEntries: a.trustedEntries(v),
		Next: func(nk *crypto.VaultKey) (*format.VaultFile, error) {
			vf, err := crypto.NewVaultFile(v.chain.File.Name, nk, []crypto.KeyWrapper{mw, pw})
			if err != nil {
				return nil, err
			}
			return vf, members.Genesis(vf, un, a.now())
		},
	})
	if newKey == nil {
		return failf("could not rebuild '%s': %v", v.name, vaultErr(err))
	}
	defer newKey.Destroy()
	cfg, cerr := a.loadConfig()
	if cerr != nil {
		return cerr
	}
	c, _, lerr := members.Load(v.dir, "")
	if lerr != nil {
		return failf("rebuilt '%s', but it does not verify: %v", v.name, lerr)
	}
	cfg.Vaults[v.name].ID, cfg.Vaults[v.name].KeyID = c.File.ID, ""
	if err := a.saveConfig(cfg); err != nil {
		return err
	}
	v.entry, v.chain, v.pin = cfg.Vaults[v.name], c, nil
	if err := a.savePin(v, []format.LogEntry{c.LastEntry()}); err != nil {
		return err
	}
	if ts, err := a.trustStore(); err == nil {
		_ = ts.Delete(oldID)
	}
	if cl := a.client(false); cl != nil {
		_ = cl.Lock(oldID)
	}
	a.switchKey(v, newKey)
	if err != nil {
		a.warnf("%v", vaultErr(err))
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": v.name, "rebuilt": true, "state_code": members.StateCode(c, 0)})
	}
	a.printf("Rebuilt '%s' with you as its only member. Other members must detach, attach and be approved again.\n", v.name)
	return nil
}
