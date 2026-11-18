package cli

import (
	"slices"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/members"
)

// migrate upgrades a version-1 vault (made by a pre-release build) to the
// signed format on its first unlock, with the checks of design M3:
//
//   - only a personal vault (no member unlockers): a shared one is refused,
//     because its unlocker list is exactly what can't be trusted;
//   - only if this machine has no trust pin for the vault, and the file's
//     key ID matches the legacy key pin in the registry if there is one
//     (otherwise a folder writer could downgrade a pinned vault);
//   - only with a fresh unwrap of the vault passphrase in this command,
//     never Touch ID or a key held by the agent (a folder writer can wrap
//     a key to this Mac's public Secure Enclave key, but can't make a
//     passphrase unlocker the user opens).
//
// The genesis record is signed by this person's identity (created first if
// needed); Touch ID moves to the identity.
func (a *app) migrate(v *vaultRef, o openOpts) (*crypto.VaultKey, error) {
	old := v.v1
	if len(old.UnlockersOf(format.UnlockerMember)) > 0 {
		return nil, failf("vault '%s' was shared by a pre-release version and can't be upgraded safely. Create a new vault and share it again", v.name)
	}
	ts, err := a.trustStore()
	if err != nil {
		return nil, err
	}
	if pin, err := ts.Load(old.ID); err != nil || pin != nil || (v.entry.KeyID != "" && v.entry.KeyID != old.KeyID) {
		return nil, failf("the folder of '%s' holds an older vault format than this machine has seen: possible downgrade. Nothing was read or written", v.name)
	}
	if len(old.UnlockersOf(format.UnlockerPassphrase)) == 0 {
		return nil, failf("vault '%s' needs its passphrase to be upgraded, and has none", v.name)
	}
	if !a.interactive() {
		return nil, failf("vault '%s' needs a one-time upgrade with its passphrase: run %s unlock %s in a terminal", v.name, a.prog, v.name)
	}
	_, raw, err := format.ReadVaultFileBytes(v.dir)
	if err != nil {
		return nil, failf("cannot open vault '%s': %v", v.name, vaultErr(err))
	}
	a.infof("Vault '%s' was made by a pre-release version and will be upgraded once.", v.name)
	key, err := a.promptVaultPassphrase(v, old)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, a.lockedErr(v.name)
	}
	fail := func(err error) (*crypto.VaultKey, error) { key.Destroy(); return nil, err }
	if _, ok := a.myIdentity(); !ok && !a.identityNeedsUpgrade() {
		if _, err := a.createIdentity(""); err != nil {
			return fail(err)
		}
	}
	un, err := a.unlockIdentity()
	if err != nil {
		return fail(err)
	}
	mw, err := un.MemberWrapper()
	if err != nil {
		return fail(err)
	}
	mu, err := mw.Wrap(key)
	if err != nil {
		return fail(err)
	}
	next := &format.VaultFile{
		Version: format.VaultVersion, ID: old.ID, Name: old.Name, KeyID: old.KeyID,
		Unlockers: append(slices.Clone(old.UnlockersOf(format.UnlockerPassphrase)), mu),
	}
	if err := members.Genesis(next, un, a.now()); err != nil {
		return fail(err)
	}
	if err := format.WriteVaultFileCAS(v.dir, next, raw); err != nil {
		return fail(failf("could not upgrade vault '%s': %v", v.name, vaultErr(err)))
	}
	v.v1 = nil
	c, _, err := a.loadVault(v)
	if err != nil {
		return fail(err)
	}
	v.chain, v.class = c, members.Classification{Outcome: members.FirstUse}
	if err := a.savePin(v, []format.LogEntry{c.LastEntry()}); err != nil {
		return fail(err)
	}
	if err := a.registerID(v, c.File.ID); err != nil {
		return fail(err)
	}
	if len(old.UnlockersOf(format.UnlockerTouchID)) > 0 {
		a.infof("Touch ID now unlocks your identity instead of each vault. If it isn't on yet: %s touchid on", a.prog)
	}
	a.infof("Upgraded '%s'. You are its owner.", v.name)
	if o.purpose == purposeWrite {
		if err := a.prepareWrite(v, key); err != nil {
			return fail(err)
		}
	}
	if cl := a.client(true); cl != nil {
		if dup, err := crypto.VaultKeyFromBytes(key.Bytes()); err == nil {
			_ = cl.Unlock(c.File.ID, dup, a.ttlFor(v))
		}
	}
	return key, nil
}
