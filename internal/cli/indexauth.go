package cli

import (
	"errors"
	"io/fs"
	"path/filepath"
	"slices"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/index"
	"github.com/Arntek/secrets-vault/internal/members"
)

// The authenticated index in the CLI (docs/design/index-auth.md). Package
// index decides; this file turns its answers into exit codes, messages and
// the local snapshot. Kept apart from unlock.go and trust.go on purpose.

func (a *app) indexStore() (*index.Store, error) {
	d, err := a.configDir()
	if err != nil {
		return nil, err
	}
	return index.NewStore(filepath.Join(d, "index")), nil
}

const upgradeHint = "every member must first upgrade secrets-vault (brew upgrade secrets-vault, or npm update -g secrets-vault)"

// legacyChain reports whether the verified chain says format 2 (or the
// vault is a version-1 file, c nil).
func legacyChain(c *members.Chain) bool {
	return c == nil || c.Head().Format == format.LegacyVaultVersion
}

// noteLegacy prints, once per vault and command, that the vault has not
// been upgraded.
func (a *app) noteLegacy(v *vaultRef) {
	if v.legacyNoted {
		return
	}
	v.legacyNoted = true
	a.infof("Vault '%s' uses the older format, whose index is not authenticated. Run: %s upgrade %s (%s)", v.name, a.prog, v.name, upgradeHint)
}

// vaultSnapshot loads this machine's index snapshot for the verified chain.
// A snapshot that is not anchored in the chain (an accepted rollback, a
// different vault generation) is treated as absent, and a snapshot for a
// vault whose chain says format 2 is a downgrade (IS3, design).
func (a *app) vaultSnapshot(c *members.Chain) (*index.Snapshot, error) {
	if c == nil {
		return nil, nil
	}
	st, err := a.indexStore()
	if err != nil {
		return nil, err
	}
	snap, err := st.Load(c.File.ID)
	if err != nil {
		a.warnf("warning: this machine's record of what it verified in '%s' is damaged and was ignored: %v", c.File.Name, pathless(err))
		return nil, nil
	}
	if snap == nil {
		return nil, nil
	}
	if legacyChain(c) {
		return nil, verifyErrf("vault '%s' presents an older format than this machine has seen: possible downgrade. Nothing was read or written", c.File.Name)
	}
	headAt := func(seq int) (string, bool) {
		if seq < 0 || seq >= len(c.States) {
			return "", false
		}
		return c.States[seq].Head, true
	}
	if !snap.Anchored(headAt, c.KnowsKey) {
		return nil, nil
	}
	return snap, nil
}

// lockedView is what a command that can't unlock may show of v's index.
func (a *app) lockedView(v *vaultRef, c *members.Chain) (*index.LockedView, error) {
	snap, err := a.vaultSnapshot(c)
	if err != nil {
		return nil, err
	}
	return index.Locked(v.dir, legacyChain(c), snap)
}

// vindex is the authenticated index of one verified, unlocked vault for the
// length of one operation. It holds the key only for that operation: build
// it with openIndex after openKey and drop it before the key is destroyed.
type vindex struct {
	a    *app
	v    *vaultRef
	key  *crypto.VaultKey
	s    *index.Session
	view *index.View
}

// openIndex verifies the vault's index with key, notes what it dropped and
// refreshes the local snapshot (reads never write the folder; the snapshot
// lives on this machine).
func (a *app) openIndex(v *vaultRef, key *crypto.VaultKey) (*vindex, error) {
	c := v.chain
	snap, err := a.vaultSnapshot(c)
	if err != nil {
		return nil, err
	}
	h := c.Head()
	s := &index.Session{Dir: v.dir, VaultID: c.File.ID, Key: key, Legacy: legacyChain(c), Snap: snap, PinSeq: h.Seq, PinHead: h.Head, Now: a.now}
	view, err := s.Load()
	if err != nil {
		return nil, failf("cannot read the index of vault '%s': %v", v.name, vaultErr(err))
	}
	vi := &vindex{a: a, v: v, key: key, s: s, view: view}
	if s.Legacy {
		a.noteLegacy(v)
		return vi, nil
	}
	if view.Damaged {
		a.warnf("warning: the index of '%s' is %s; keys are readable only where this machine's own record vouches for them", v.name, view.DamageWhy)
	}
	if view.Dropped > 0 {
		a.warnf("warning: %s in the index of '%s' failed verification and was ignored", plural(view.Dropped, "entry"), v.name)
	}
	if !view.Damaged {
		vi.saveSnapshot(s.Observe(view), snap)
	}
	return vi, nil
}

// saveSnapshot stores sn unless it says nothing new.
func (vi *vindex) saveSnapshot(sn, old *index.Snapshot) {
	if old != nil && snapshotsSame(old, sn) {
		return
	}
	st, err := vi.a.indexStore()
	if err != nil {
		return
	}
	if err := st.Save(sn); err != nil {
		vi.a.warnf("warning: could not save what this machine verified in '%s': %v", vi.v.name, pathless(err))
	}
}

func snapshotsSame(a, b *index.Snapshot) bool {
	return a.KeyID == b.KeyID && a.PinSeq == b.PinSeq && a.PinHead == b.PinHead && a.Private == b.Private &&
		slices.EqualFunc(a.Entries, b.Entries, func(x, y index.SnapEntry) bool {
			return x.Name == y.Name && x.NameTag == y.NameTag && x.Rev == y.Rev && x.Version == y.Version && x.Deleted == y.Deleted && x.MAC == y.MAC
		})
}

// refused turns a refused key into the exit-5 error it deserves.
func (a *app) refused(v *vaultRef, k index.KeyInfo) error {
	if err := k.Err(); err != nil {
		return verifyErrf("vault '%s': %v", v.name, err)
	}
	return nil
}

// read decrypts one key and checks it against the verified index. The
// caller zeroes the result.
func (vi *vindex) read(name string) ([]byte, index.KeyInfo, error) {
	a := vi.a
	val, ver, err := crypto.ReadSecretVersion(vi.v.dir, name, vi.key)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		k := vi.view.Verdict(name, 0, false)
		if e := a.refused(vi.v, k); e != nil {
			return nil, k, e
		}
		return nil, k, notFoundErr("key not found. Try: %s search WORDS", a.prog)
	case errors.Is(err, crypto.ErrOtherKey):
		return nil, index.KeyInfo{}, failf("that key was sealed with a different vault key (a rotation on another machine?)")
	case err != nil:
		return nil, index.KeyInfo{}, failf("cannot decrypt that key; the file may be damaged")
	}
	k := vi.view.Verdict(name, ver, true)
	if e := a.refused(vi.v, k); e != nil {
		clear(val)
		return nil, k, e
	}
	if k.Status == index.StatusDeleted {
		clear(val)
		return nil, k, notFoundErr("key not found. Try: %s search WORDS", a.prog)
	}
	if k.Status == index.StatusIndexBehind {
		a.warnf("warning: the index of '%s' is behind its files for %s (still syncing, or out of date); the value is authentic. The next change repairs the index.", vi.v.name, name)
		vi.saveSnapshot(vi.s.RaiseFloor(vi.view, name, ver), vi.s.Snap)
	}
	return val, k, nil
}

// commit applies edits and stores the new snapshot, telling the person about
// anything unusual.
func (vi *vindex) commit(edits ...index.Edit) error {
	a := vi.a
	res, err := vi.s.Commit(vi.view, edits...)
	switch {
	case errors.Is(err, index.ErrCounterLimit), errors.Is(err, index.ErrBusy):
		return failf("%v", err)
	case err != nil:
		var ee *exitErr
		if errors.As(err, &ee) {
			return err
		}
		return failf("cannot write the index of vault '%s': %v", vi.v.name, vaultErr(err))
	}
	vi.view = res.View
	vi.saveSnapshot(res.Snapshot, vi.s.Snap)
	for _, n := range res.Concurrent {
		a.warnf("warning: %s was changed by someone else at the same moment as your change; the value saved last is the one in '%s' now. Check it.", n, vi.v.name)
	}
	if res.Merged > 0 {
		a.infof("Merged %s from a sync-conflict copy of the index of '%s'.", plural(res.Merged, "change"), vi.v.name)
	}
	if len(res.Healed) > 0 {
		a.infof("Repaired %s in the index of '%s' from what this machine had verified.", plural(len(res.Healed), "entry"), vi.v.name)
	}
	return nil
}

// agentKey returns the vault key if the unlock agent already holds it, and
// never asks for anything (doctor, status).
func (a *app) agentKey(v *vaultRef) *crypto.VaultKey {
	cl := a.client(false)
	if cl == nil || v.chain == nil {
		return nil
	}
	k, err := cl.Key(v.chain.File.ID)
	if err != nil {
		return nil
	}
	if crypto.CheckKey(v.chain.File, k) != nil {
		k.Destroy()
		return nil
	}
	return k
}

// openQuiet verifies v and classifies it against this machine's trust pin
// without prompting and without writing anything: index-only commands use
// it so that an unmet --expect or a rollback is reported as exit 5 instead
// of answering from a quarantined folder (ue1.12). A first use is allowed:
// its index is simply unverified.
func (a *app) openQuiet(v *vaultRef) (*members.Chain, *format.VaultFile, error) {
	c, vf, err := a.loadVault(v)
	if err != nil {
		return c, vf, err
	}
	ts, err := a.trustStore()
	if err != nil {
		return nil, nil, err
	}
	pin, err := ts.Load(c.File.ID)
	if err != nil {
		return nil, nil, failf("this machine's trust record for '%s' is damaged: %v", v.name, err)
	}
	if pin == nil && v.entry.KeyID != "" && !c.KnowsKey(v.entry.KeyID) {
		return nil, nil, verifyErrf("vault '%s': %v", v.name, members.ErrRollback)
	}
	if pin != nil && pin.Expect != nil && !pin.Expect.Met(c) {
		return nil, nil, verifyErrf("vault '%s' (expected %s%s): %v", v.name, c.File.Name, pin.Expect, members.ErrBehindCode)
	}
	if members.Classify(c, pin).Outcome == members.Rollback {
		return nil, nil, verifyErrf("vault '%s': %v", v.name, members.ErrRollback)
	}
	return c, vf, nil
}

// trustedEntries are this machine's own verified entries for files that
// exist, for a lost-race repair (crypto.RotateOptions.TrustedEntries): the
// loser re-seals its files under a new key, so their entries must come from
// what this machine verified, never from the folder (IM2). A private
// snapshot has no labels to rebuild from and contributes nothing.
func (a *app) trustedEntries(v *vaultRef) []format.IndexEntry {
	snap, err := a.vaultSnapshot(v.chain)
	if err != nil || snap == nil || snap.Private {
		return nil
	}
	files, err := format.ListSecrets(v.dir)
	if err != nil {
		return nil
	}
	have := map[string]bool{}
	for _, f := range files {
		have[f.Name] = true
	}
	var out []format.IndexEntry
	for _, e := range snap.Entries {
		if e.Deleted || !have[e.Name] {
			continue
		}
		ie := format.IndexEntry{Name: e.Name, Description: e.Description, Tags: e.Tags, Updated: e.Updated, UpdatedBy: e.UpdatedBy,
			Version: e.Version, Rev: e.Rev}
		if ie.Updated.IsZero() {
			ie.Updated = snap.Verified
		}
		out = append(out, ie)
	}
	return out
}

// exists reports whether a live key (or any file) of that name is already
// in the vault.
func (vi *vindex) exists(name string) (bool, error) {
	if k, ok := vi.view.Key(name); ok && k.Status != index.StatusDeleted {
		return true, nil
	}
	if _, err := format.ReadSecretFile(vi.v.dir, name); err == nil {
		return true, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, failf("cannot check vault '%s': %v", vi.v.name, vaultErr(err))
	}
	return false, nil
}

// newEntryEdit creates the entry for name at version ver, with the
// description and tags of ent (a move or rename).
func (vi *vindex) newEntryEdit(name string, ent format.IndexEntry, ver uint32) index.Edit {
	a := vi.a
	return index.Edit{Name: name, Apply: func(cur *format.IndexEntry) (format.IndexEntry, error) {
		e := format.IndexEntry{Description: ent.Description, Tags: ent.Tags, Version: ver}
		if cur != nil {
			e.Version = max(ver, cur.Version)
		}
		e.Updated = a.now().UTC()
		e.UpdatedBy = a.myName()
		return e, nil
	}}
}

// tombstoneEdit marks name deleted at the highest version known for it.
func (vi *vindex) tombstoneEdit(name string) index.Edit {
	a := vi.a
	floor := max(vi.view.Floor(name), 1)
	return index.Edit{Name: name, Apply: func(cur *format.IndexEntry) (format.IndexEntry, error) {
		e := format.IndexEntry{Version: floor}
		if cur != nil {
			e.Version = max(floor, cur.Version)
		}
		e.Deleted = true
		e.Updated = a.now().UTC()
		e.UpdatedBy = a.myName()
		return e, nil
	}}
}

// changeEntry opens the vault for writing and changes one live entry's
// metadata (describe, tag): the entry gets a new rev and MAC, its value
// version is unchanged.
func (a *app) changeEntry(k *keyRef, change func(e *format.IndexEntry)) error {
	key, err := a.openKey(k.v, k.vf, openOpts{purpose: purposeWrite})
	if err != nil {
		return err
	}
	defer key.Destroy()
	vi, err := a.openIndex(k.v, key)
	if err != nil {
		return err
	}
	return vi.commit(index.Edit{Name: k.entry.Name, Apply: func(cur *format.IndexEntry) (format.IndexEntry, error) {
		if cur == nil || cur.Deleted {
			return format.IndexEntry{}, notFoundErr("key not found")
		}
		e := *cur
		change(&e)
		e.Updated = a.now().UTC()
		e.UpdatedBy = a.myName()
		return e, nil
	}})
}

// noteIndexState says, once per vault, how far a locked listing can be
// trusted.
func (a *app) noteIndexState(v *vaultRef, lv *index.LockedView) {
	switch lv.State {
	case index.StateLegacy:
		a.noteLegacy(v)
	case index.StatePending:
		when := "when last unlocked"
		if !lv.LastVerified.IsZero() {
			when = "at " + lv.LastVerified.Local().Format("2006-01-02 15:04")
		}
		why := plural(lv.PendingChanges, "change") + " in the folder " + map[bool]string{true: "is", false: "are"}[lv.PendingChanges == 1] + " not verified yet"
		if lv.Damaged {
			why = "the folder's index is missing or damaged"
		}
		a.infof("Vault '%s': the index was verified %s; %s. Unlock to check: %s unlock %s", v.name, when, why, a.prog, v.name)
	case index.StateNever:
		if len(lv.Rows) > 0 || lv.Damaged {
			a.infof("Vault '%s': its index has not been verified on this Mac yet, so what is listed is only what the folder claims. Unlock to verify it: %s unlock %s", v.name, a.prog, v.name)
		}
	case index.StatePrivate:
		a.infof("Vault '%s' has a private index: nothing is listed without unlocking it.", v.name)
	}
}
