package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/members"
)

// Trust: every vault.json is verified (members.Load) against the vault ID
// registered on this machine and this machine's trust pin before anything
// in it is used (docs/design/membership-auth.md, sections 4-8).

func (a *app) trustStore() (*members.TrustStore, error) {
	d, err := a.configDir()
	if err != nil {
		return nil, err
	}
	return members.NewTrustStore(filepath.Join(d, "trust")), nil
}

func (a *app) pendingStore() (*members.PendingStore, error) {
	d, err := a.configDir()
	if err != nil {
		return nil, err
	}
	return members.NewPendingStore(filepath.Join(d, "pending")), nil
}

// loadVault verifies v's vault.json against its registered ID. It never
// prompts and never writes. A version-1 file returns members.ErrOldFormat
// with the parsed file.
func (a *app) loadVault(v *vaultRef) (*members.Chain, *format.VaultFile, error) {
	c, vf, err := members.Load(v.dir, v.entry.ID)
	switch {
	case err == nil, errors.Is(err, members.ErrOldFormat):
		return c, vf, err
	case errors.Is(err, members.ErrOtherVault):
		return nil, nil, failf("the folder of '%s' now holds a different vault than the one registered here. "+
			"If you rebuilt it on purpose, run: %s detach %s, then %s attach %s DIR", v.name, a.prog, v.name, a.prog, v.name)
	case errors.Is(err, members.ErrTampered):
		return nil, nil, failf("vault '%s': %v", v.name, members.ErrTampered)
	case errors.Is(err, format.ErrUnsupportedVersion):
		return nil, nil, failf("vault '%s' was saved by a newer secrets-vault. Upgrade to open it: brew upgrade secrets-vault (Homebrew) or npm update -g secrets-vault (npm)", v.name)
	case errors.Is(err, format.ErrUnsafeDir):
		return nil, nil, failf("vault '%s': a folder inside it is a symlink or is not owned by you; refusing to use it", v.name)
	}
	return nil, nil, failf("cannot open vault '%s': %v", v.name, vaultErr(err))
}

// open verifies the vault (once per command) and classifies it against
// this machine's pin: an extension advances the pin silently, a first use
// by a member asks the person to confirm (trustOnFirstUse), a lost race is
// remembered for openKey to repair on a write, and anything else is a hard
// refusal. It returns the verified vault.json (or a version-1 file, which
// openKey migrates).
func (a *app) open(v *vaultRef) (*format.VaultFile, error) {
	if v.chain != nil {
		return v.chain.File, nil
	}
	if v.v1 != nil {
		return v.v1, nil
	}
	c, vf, err := a.loadVault(v)
	if errors.Is(err, members.ErrOldFormat) {
		v.v1 = vf
		return vf, nil
	}
	if err != nil {
		return nil, err
	}
	ts, err := a.trustStore()
	if err != nil {
		return nil, err
	}
	if v.entry.ID == "" {
		// No registered ID (an older build may have rewritten the
		// registry, ue1.8 A). If this machine already trusts a vault in this
		// folder, never fall back to first-use trust.
		if old, err := ts.FindByPath(v.dir); err != nil || old != nil {
			return nil, failf("this machine has lost its record of which vault '%s' is (an older secrets-vault may have rewritten its settings). "+
				"Nothing was read or written. To register it again, run: %s detach %s, then %s attach %s DIR", v.name, a.prog, v.name, a.prog, v.name)
		}
	}
	pin, err := ts.Load(c.File.ID)
	if err != nil {
		return nil, failf("this machine's trust record for '%s' is damaged: %v", v.name, err)
	}
	// A registry entry from before trust pins: its key must be in the
	// chain, or the folder was replaced (M3's twin for version-2 files).
	if pin == nil && v.entry.KeyID != "" && !c.KnowsKey(v.entry.KeyID) {
		return nil, failf("vault '%s': %v", v.name, members.ErrRollback)
	}
	cl := members.Classify(c, pin)
	v.chain, v.pin, v.class = c, pin, cl
	switch cl.Outcome {
	case members.Same:
	case members.Extension:
		// Someone extended the state this machine pinned: what this
		// machine wrote is confirmed, and its pending rotation keys can go.
		if err := a.savePin(v, nil); err != nil {
			return nil, err
		}
		if ps, err := a.pendingStore(); err == nil {
			_ = ps.DeleteAll(c.File.ID)
		}
	case members.FirstUse:
		if err := a.trustOnFirstUse(v); err != nil {
			v.chain = nil
			return nil, err
		}
	case members.LostRace:
		a.warnf("Your last change to '%s' and another member's change happened at the same time. "+
			"It will be applied again on your next change, or run: %s trust %s", v.name, a.prog, v.name)
	default:
		v.chain = nil
		return nil, failf("vault '%s': %v", v.name, members.ErrRollback)
	}
	if err := a.registerID(v, c.File.ID); err != nil {
		return nil, err
	}
	return c.File, nil
}

// registerID records the vault ID in the registry entry (M1) and drops the
// legacy key pin once a trust pin exists.
func (a *app) registerID(v *vaultRef, id string) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	e, ok := cfg.Vaults[v.name]
	if !ok {
		return nil
	}
	changed := false
	if e.ID == "" {
		e.ID, changed = id, true
	}
	if e.KeyID != "" && v.pin != nil {
		e.KeyID, changed = "", true
	}
	if changed {
		v.entry = e
		return a.saveConfig(cfg)
	}
	return nil
}

// savePin pins v's current chain head. own are the records this machine
// just wrote on top of the previous pin (nil when the head is someone
// else's).
func (a *app) savePin(v *vaultRef, written []format.LogEntry) error {
	ts, err := a.trustStore()
	if err != nil {
		return err
	}
	var own []format.LogEntry
	if len(written) > 0 {
		if v.pin != nil && len(v.pin.Own) > 0 && v.class.Outcome == members.Same {
			own = append(own, v.pin.Own...)
		}
		own = append(own, written...)
	}
	pin := members.PinFor(v.chain, own)
	pin.Path = v.dir
	if err := ts.Save(pin); err != nil {
		return failf("cannot save this machine's trust record for '%s': %v", v.name, pathless(err))
	}
	v.pin = pin
	v.class = members.Classification{Outcome: members.Same}
	return nil
}

// afterWrite switches v to the chain a membership change produced and pins
// it, remembering the record as this machine's own.
func (a *app) afterWrite(v *vaultRef, c *members.Chain, written ...format.LogEntry) error {
	v.chain = c
	return a.savePin(v, written)
}

// headLine describes a chain head for people: "team@5, 2026-11-20 10:02,
// signed by alice".
func headLine(c *members.Chain) string {
	h := c.Head()
	return fmt.Sprintf("%s@%d, %s, signed by %s", c.File.Name, h.Seq, h.Time.Local().Format("2006-01-02 15:04"), h.By)
}

// printMembers lists the head's members with fingerprints on stderr.
func (a *app) printMembers(c *members.Chain) {
	for _, m := range c.Head().Members {
		fp, _ := members.Fingerprint(m.Recipient, m.SignKey)
		a.infof("  %-20s %s  %s", m.Name, fp, m.Role)
	}
}

// trustOnFirstUse decides the first pin for a vault (design section 7, S2).
// Only members pin here; a person who is not a member yet pins nothing
// until they are added (and are then asked who added them), and a
// passphrase-only user pins on their first successful unlock (openKey).
func (a *app) trustOnFirstUse(v *vaultRef) error {
	c := v.chain
	me, ok := a.myIdentity()
	if !ok {
		return nil
	}
	m, isMember := c.Head().Member(me.Name)
	if !isMember || m.Recipient != me.Recipient || m.SignKey != me.SignKey {
		return nil
	}
	by, _, _ := c.WhoAdded(me.Recipient, me.SignKey)
	if by == me.Name {
		// Nobody else holds my signing key, but a removed member could show
		// me a chain cut off before their removal: show the head and ask
		// for the state code from another machine (S2).
		if err := a.checkStateCode(v, true); err != nil {
			return err
		}
		return a.savePin(v, nil)
	}
	adder, ok := adderOf(c, me)
	if !ok {
		return failf("vault '%s': %v", v.name, members.ErrTampered)
	}
	fp, err := members.Fingerprint(adder.Recipient, adder.SignKey)
	if err != nil {
		return err
	}
	typed := a.signerFP
	if typed == "" {
		if !a.term.StdinTTY() {
			return failf("you were added to '%s' by %s. Check their fingerprint once: run this in a terminal, or pass --signer-fingerprint FP after %s reads it to you", v.name, by, by)
		}
		a.infof("You were added to '%s' by %s (%s).", v.name, by, headLine(c))
		line, err := a.ask("Type " + by + "'s fingerprint as " + by + " reads it to you: ")
		if err != nil {
			return failf("cancelled")
		}
		typed = line
	}
	if !members.FingerprintsEqual(members.NormalizeFingerprint(typed), fp) {
		return failf("that is not %s's fingerprint. Do not use '%s' until you have checked with %s; someone may have replaced the vault", by, v.name, by)
	}
	if a.expectCode != "" {
		if err := members.MatchStateCode(c, a.expectCode); err != nil {
			return failf("vault '%s': %v", v.name, err)
		}
	}
	return a.savePin(v, nil)
}

// adderOf returns the member (as of just before) who signed the record
// that added me.
func adderOf(c *members.Chain, me members.Identity) (format.Member, bool) {
	for i := len(c.Records) - 1; i > 0; i-- {
		r := c.Records[i]
		if r.Op == format.OpAddMember && r.Member.Recipient == me.Recipient && r.Member.SignKey == me.SignKey {
			return c.States[i-1].Member(c.States[i].By)
		}
	}
	return format.Member{}, false
}

// checkStateCode shows the head and checks the state code: --expect if
// given, otherwise (when ask and on a terminal) one typed by the person;
// Enter skips.
func (a *app) checkStateCode(v *vaultRef, ask bool) error {
	c := v.chain
	code := a.expectCode
	if code == "" && ask && a.term.StdinTTY() && !a.asJSON {
		a.infof("Vault '%s' is at %s. Members:", v.name, headLine(c))
		a.printMembers(c)
		line, err := a.ask("Type the state code from '" + a.prog + " status' on another member's machine (or press Enter to trust what's shown): ")
		if err == nil {
			code = strings.TrimSpace(line)
		}
	} else if code == "" {
		// Always on stderr, --json included, so a script or AI agent can't
		// hide from the user that a vault was pinned unchecked.
		a.infof("Trusting vault '%s' at %s without a state code (state_code_checked: false). Compare with '%s status' on another member's machine.", v.name, headLine(c), a.prog)
	}
	if code == "" {
		return nil
	}
	if !strings.Contains(code, "@") {
		code = c.File.Name + "@" + code
	}
	if err := members.MatchStateCode(c, code); err != nil {
		return failf("vault '%s': %v", v.name, err)
	}
	return nil
}

// repairLostRace re-applies this machine's lost records on top of the
// winning chain (design 8b/10, N1), returning the vault key to use.
func (a *app) repairLostRace(v *vaultRef, key *crypto.VaultKey) (*crypto.VaultKey, error) {
	un, err := a.unlockIdentity()
	if err != nil {
		return nil, err
	}
	ps, err := a.pendingStore()
	if err != nil {
		return nil, err
	}
	pending, _ := ps.Load(v.chain.File.ID, un)
	ask := func(policy string) (crypto.KeyWrapper, error) {
		if policy == format.PassKept {
			p, err := a.askHidden("Re-applying your change needs the current vault passphrase for '" + v.name + "': ")
			if err != nil {
				return nil, err
			}
			defer clear(p)
			return a.passphraseWrapper(p)
		}
		p, err := a.askNewPassphrase("Re-applying your change: the new passphrase for '" + v.name + "'")
		if err != nil {
			return nil, err
		}
		defer clear(p)
		return a.passphraseWrapper(p)
	}
	res, err := members.Rebase(v.dir, v.chain, key, un, v.class.Lost, pending, ask, ps, a.now())
	if res != nil && len(res.Written) > 0 {
		if serr := a.afterWrite(v, res.Chain, res.Written...); serr != nil && err == nil {
			err = serr
		}
	}
	if err != nil {
		return nil, failf("could not re-apply your change to '%s': %v", v.name, vaultErr(err))
	}
	for _, n := range res.Notes {
		a.infof("%s", n)
	}
	if len(res.Written) == 0 {
		// Nothing left to re-apply: trust the winning head.
		v.chain = res.Chain
		if err := a.savePin(v, nil); err != nil {
			return nil, err
		}
	}
	a.infof("Applied your earlier change to '%s' again on top of the other member's.", v.name)
	_ = ps.DeleteAll(v.chain.File.ID)
	if res.Key != key {
		key.Destroy()
	}
	return res.Key, nil
}

// prepareWrite runs before every write to a vault (design section 6):
// finish a verified interrupted rotation, then the write guard.
func (a *app) prepareWrite(v *vaultRef, key *crypto.VaultKey) error {
	c := v.chain
	if _, rotation, ok := c.KeyIntroducedAt(c.Head().KeyID); ok && rotation {
		if _, err := crypto.RecoverRotation(v.dir, key); err != nil {
			return failf("vault '%s' has an unfinished key rotation that could not be completed: %v", v.name, vaultErr(err))
		}
	}
	// Files a migration left in the version-1 format (if it was
	// interrupted) are re-sealed so no older build can use them (ue1.8).
	if _, err := crypto.UpgradeSecrets(v.dir, key); err != nil {
		return failf("cannot upgrade the secret files of '%s': %v", v.name, vaultErr(err))
	}
	rep, err := members.CheckFolder(v.dir, c)
	if err != nil {
		return failf("cannot check vault '%s': %v", v.name, vaultErr(err))
	}
	if rep.Blocking() {
		return failf("vault '%s': %v", v.name, members.ErrNewerState)
	}
	a.warnExposed(v, rep)
	return nil
}

func (a *app) warnExposed(v *vaultRef, rep *members.FolderReport) {
	for _, e := range rep.Retired {
		why := "a key rotation"
		if e.Removed != "" {
			why = e.Removed + "'s removal"
		}
		a.warnf("warning: %s in '%s' is still sealed with the key replaced at %s; it may have been exposed. Set a new value and rotate it at the provider.", e.Name, v.name, why)
	}
}
