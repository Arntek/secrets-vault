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
		return nil, nil, verifyErrf("the folder of '%s' now holds a different vault than the one registered here. "+
			"If you rebuilt it on purpose, run: %s detach %s, then %s attach %s DIR", v.name, a.prog, v.name, a.prog, v.name)
	case errors.Is(err, members.ErrTampered):
		return nil, nil, verifyErrf("vault '%s': %v", v.name, members.ErrTampered)
	case errors.Is(err, format.ErrUnsupportedVersion):
		return nil, nil, failf("vault '%s' was saved by a newer secrets-vault. Upgrade to open it: brew upgrade secrets-vault (Homebrew) or npm update -g secrets-vault (npm)", v.name)
	case errors.Is(err, format.ErrUnsafeDir):
		if format.CheckStructuralDirs(v.dir) == nil {
			// The trash, requests/ or a staging folder: a key change sets it aside.
			return nil, nil, verifyErrf("vault '%s': a folder inside it is a symlink or is not owned by you; refusing to use it. Nothing was read or written. A key change (%s passwd %s, or %s member rm) renames it aside; or replace it with a real folder", v.name, a.prog, v.name, a.prog)
		}
		return nil, nil, verifyErrf("vault '%s': a folder inside it is a symlink or is not owned by you; refusing to use it. Nothing is read or written (not even by key changes) until it is fixed: replace the link with the real folder, or restore it from the provider's version history", v.name)
	case errors.Is(err, format.ErrMalformed), errors.Is(err, format.ErrTooLarge):
		// A vault.json that exists but doesn't parse is as much "the folder
		// was tampered with" as a bad signature (ue1.12): exit 5, with the
		// innocent explanation (a half-synced file) named too.
		return nil, nil, verifyErrf("vault '%s': vault.json is damaged or was altered (%v). If a sync is still running, wait and try again; otherwise restore it from the provider's version history. Nothing was read or written", v.name, pathless(err))
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
			return nil, verifyErrf("this machine has lost its record of which vault '%s' is (an older secrets-vault may have rewritten its settings). "+
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
		return nil, verifyErrf("vault '%s': %v", v.name, members.ErrRollback)
	}
	// A state code this machine was given and the folder hasn't reached:
	// refuse until it has (ue1.9).
	expectMet := false
	if pin != nil && pin.Expect != nil {
		switch {
		case pin.Expect.Met(c):
			expectMet = true
		case a.expectCode != "" && a.codeMet(v, c, a.expectCode):
			// A new, correct code replaces one that was mistyped or that the
			// folder had not reached: the person just gave it, out of band.
			cleared := *pin
			cleared.Expect = nil
			if err := ts.Save(&cleared); err != nil {
				return nil, err
			}
			pin = &cleared
		default:
			return nil, a.expectRefusal(v, c, pin.Expect)
		}
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
		return nil, verifyErrf("vault '%s': %v", v.name, members.ErrRollback)
	}
	if expectMet && v.pin != nil && v.pin.Expect != nil {
		cleared := *v.pin
		cleared.Expect = nil
		if err := ts.Save(&cleared); err != nil {
			return nil, err
		}
		v.pin = &cleared
	}
	// --expect on any command (TOFU checks it itself).
	if a.expectCode != "" && cl.Outcome != members.FirstUse && v.pin != nil {
		if _, err := a.applyExpect(v, a.expectCode); err != nil {
			v.chain = nil
			return nil, err
		}
	}
	if err := a.registerID(v, c.File.ID); err != nil {
		return nil, err
	}
	return c.File, nil
}

// applyExpect checks a state code against v's verified chain. If the folder
// is behind it, the expectation is saved in the pin, so every later
// command refuses the vault until the folder reaches it (ue1.9).
func (a *app) applyExpect(v *vaultRef, code string) (bool, error) {
	c := v.chain
	exp, err := a.parseCodeFor(v, c, code)
	if err != nil {
		return false, err
	}
	if exp.Met(c) {
		return true, nil
	}
	if v.pin != nil {
		pending := *v.pin
		pending.Expect = exp
		if ts, err := a.trustStore(); err == nil {
			if err := ts.Save(&pending); err != nil {
				return false, err
			}
		}
		v.pin = &pending
	}
	return false, a.expectRefusal(v, c, exp)
}

// expectRefusal is the refusal for a state code the folder does not meet.
// A code whose entry exists in this folder with a different hash does not
// match this vault's history (a typo, or a folder whose history differs from
// the code's author's): "behind" would mislead. A code beyond the folder's
// last entry is a folder that is behind.
func (a *app) expectRefusal(v *vaultRef, c *members.Chain, exp *members.Expectation) error {
	if exp.Seq < len(c.File.Log) {
		return verifyErrf("vault '%s' (expected %s%s): that code doesn't match this vault's history at entry %d. It may have been mistyped, or this folder's history differs from the one the code came from. Nothing was read or written. "+
			"Run '%s trust %s --expect CODE' again with the exact code from the member (it replaces this one), or, if you are sure this folder is right, '%s trust %s --accept-rollback --signer-fingerprint FINGERPRINT'",
			v.name, c.File.Name, exp, exp.Seq, a.prog, v.name, a.prog, v.name)
	}
	return verifyErrf("vault '%s' (expected %s%s): %v", v.name, c.File.Name, exp, members.ErrBehindCode)
}

// parseCodeFor parses a state code for v: the vault name in it (or none) must
// be this vault's, so a code meant for another vault never gets pinned.
func (a *app) parseCodeFor(v *vaultRef, c *members.Chain, code string) (*members.Expectation, error) {
	if i := strings.IndexByte(code, '@'); i < 0 {
		code = c.File.Name + "@" + code
	} else if name := strings.TrimSpace(code[:i]); name != c.File.Name && name != v.name {
		return nil, usageErrf("that state code is for a different vault than '%s'", v.name)
	} else {
		code = c.File.Name + code[i:]
	}
	exp, err := members.ParseStateCode(code)
	if err != nil {
		return nil, usageErrf("%v", err)
	}
	return exp, nil
}

// codeMet reports whether code is valid for v and the folder meets it.
func (a *app) codeMet(v *vaultRef, c *members.Chain, code string) bool {
	exp, err := a.parseCodeFor(v, c, code)
	return err == nil && exp.Met(c)
}

// firstPinInfo is the --json record of a first-use pin.
type firstPinInfo struct {
	Vault    string       `json:"vault"`
	State    string       `json:"state"`
	SignedBy string       `json:"signed_by"`
	Checked  bool         `json:"state_code_checked"`
	Members  []memberInfo `json:"members"`
}

type memberInfo struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
}

func (a *app) noteFirstPin(v *vaultRef, checked bool) {
	c := v.chain
	info := &firstPinInfo{Vault: v.name, State: members.StateCode(c, c.Head().Seq), SignedBy: c.Head().By, Checked: checked, Members: []memberInfo{}}
	for _, m := range c.Head().Members {
		fp, _ := members.Fingerprint(m.Recipient, m.SignKey)
		info.Members = append(info.Members, memberInfo{m.Name, fp})
	}
	a.firstPin = info
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
	s := fmt.Sprintf("%s@%d, %s, signed by %s", c.File.Name, h.Seq, h.Time.Local().Format("2006-01-02 15:04"), h.By)
	if h.Format == format.LegacyVaultVersion {
		s += ", format 2 (not upgraded)" // so a state-code comparison catches a cut-off chain
	}
	return s
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
		checked, err := a.checkStateCode(v, true)
		if err != nil {
			return err
		}
		a.noteFirstPin(v, checked)
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
	checked := false
	if a.expectCode != "" {
		if ok, err := a.applyExpect(v, a.expectCode); err != nil || !ok {
			return err
		}
		checked = true
	}
	a.noteFirstPin(v, checked)
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
func (a *app) checkStateCode(v *vaultRef, ask bool) (bool, error) {
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
		a.infof("Trusting vault '%s' at %s without a state code (state_code_checked: false). Compare with '%s status' on another member's machine. Members:", v.name, headLine(c), a.prog)
		a.printMembers(c)
	}
	if code == "" {
		return false, nil
	}
	return a.applyExpect(v, code)
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
	if err := a.setAsideConflicts(v, key); err != nil {
		return nil, err
	}
	res, err := members.Rebase(v.dir, v.chain, key, un, v.class.Lost, pending, a.trustedEntries(v), ask, ps, a.now())
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
	if legacyChain(c) && !v.allowLegacy {
		return failf("vault '%s' uses the older format and must be upgraded before it can be changed. Run: %s upgrade %s (%s)", v.name, a.prog, v.name, upgradeHint)
	}
	if _, rotation, ok := c.KeyIntroducedAt(c.Head().KeyID); ok && rotation {
		if _, err := crypto.RecoverRotation(v.dir, key); err != nil {
			return failf("vault '%s' has an unfinished key rotation that could not be completed: %v. "+
				"If no member is changing the vault key right now, move the leftover folder aside with: %s doctor %s --quarantine-staging", v.name, vaultErr(err), a.prog, v.name)
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
		if len(rep.Unknown) == 0 && !rep.NewerCopy {
			return verifyErrf("vault '%s': %v. If no member is changing the vault key right now, move the leftover folder aside with: %s doctor %s --quarantine-staging", v.name, members.ErrNewerState, a.prog, v.name)
		}
		return verifyErrf("vault '%s': %v", v.name, members.ErrNewerState)
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
