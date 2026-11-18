package crypto

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/Arntek/secrets-vault/internal/format"
)

// ErrConflicts is returned by Rotate when the vault folder holds sync
// conflict copies or unknown files; resolve them first (vault doctor).
var ErrConflicts = errors.New("crypto: vault folder has sync conflicts; resolve them before rotating the key")

// WrapAll wraps key once for each wrapper. It needs at least one wrapper.
func WrapAll(key *VaultKey, wrappers []KeyWrapper) ([]format.Unlocker, error) {
	if len(wrappers) == 0 {
		return nil, errors.New("crypto: at least one unlocker is required")
	}
	out := make([]format.Unlocker, 0, len(wrappers))
	for _, w := range wrappers {
		u, err := w.Wrap(key)
		if err != nil {
			return nil, fmt.Errorf("crypto: wrapping for %s unlocker: %w", w.Type(), err)
		}
		out = append(out, u)
	}
	return out, nil
}

// NewVaultFile builds the vault.json content for a new vault: a fresh vault
// ID, key's ID and one unlocker per wrapper. Write it with
// format.CreateVault.
func NewVaultFile(name string, key *VaultKey, wrappers []KeyWrapper) (*format.VaultFile, error) {
	id, err := format.NewVaultID()
	if err != nil {
		return nil, err
	}
	unlockers, err := WrapAll(key, wrappers)
	if err != nil {
		return nil, err
	}
	vf := &format.VaultFile{
		Version:   format.CurrentVersion,
		ID:        id,
		Name:      name,
		KeyID:     key.ID(),
		Unlockers: unlockers,
	}
	if err := vf.Validate(); err != nil {
		return nil, err
	}
	return vf, nil
}

// CheckKey reports whether key is the vault's current key (its ID matches
// vf.KeyID). It returns ErrWrongKey if not.
func CheckKey(vf *format.VaultFile, key *VaultKey) error {
	if key == nil || subtle.ConstantTimeCompare([]byte(key.ID()), []byte(vf.KeyID)) != 1 {
		return ErrWrongKey
	}
	return nil
}

// Unlock tries w on every unlocker of its type in vf and returns the first
// vault key that unwraps and matches vf.KeyID. Any failure is ErrWrongKey.
//
// The key ID check stops a copied-in unlocker from another vault; it cannot
// stop someone with write access to the folder from replacing vault.json
// wholesale with a key they chose. The CLI should remember each vault's
// KeyID and warn when it changes outside a rotation it performed.
func Unlock(vf *format.VaultFile, w KeyWrapper) (*VaultKey, error) {
	for _, u := range vf.Unlockers {
		if u.Type != w.Type() {
			continue
		}
		k, err := w.Unwrap(u)
		if err != nil {
			continue
		}
		if CheckKey(vf, k) == nil {
			return k, nil
		}
		k.Destroy()
	}
	return nil, ErrWrongKey
}

// ReadSecret reads and decrypts secrets/NAME.age. A missing key returns an
// error wrapping fs.ErrNotExist; a file that will not open, ErrDecrypt.
// The caller owns (and should zero) the returned value.
func ReadSecret(vaultDir, name string, key *VaultKey) ([]byte, error) {
	s, err := NewSealer(name)
	if err != nil {
		return nil, err
	}
	ct, err := format.ReadSecretFile(vaultDir, name)
	if err != nil {
		return nil, err
	}
	return s.Open(key, ct)
}

// WriteSecret encrypts value and writes secrets/NAME.age atomically. The
// index entry is the caller's to update.
func WriteSecret(vaultDir, name string, key *VaultKey, value []byte) error {
	s, err := NewSealer(name)
	if err != nil {
		return err
	}
	ct, err := s.Seal(key, value)
	if err != nil {
		return err
	}
	return format.WriteSecretFile(vaultDir, name, ct)
}

// Rotate replaces the vault key: it creates a new key, re-encrypts every
// secret and every trashed secret with it, and rewrites vault.json with the
// new key wrapped for exactly the given wrappers (old unlockers are
// dropped). oldKey must be the current key. It returns the new key; the
// caller should Destroy oldKey and hand the new key to the agent.
//
// The re-encrypted files are staged first and vault.json is the commit
// point (see format.BeginStaging). If Rotate fails before vault.json is
// written, nothing changes. If it fails after, format.RecoverRotation
// finishes the job the next time the vault is opened.
//
// Rotate refuses to run while the folder has sync conflicts, and cannot
// protect against another machine writing a secret with the old key while
// it runs: rotate when other members are not editing.
func Rotate(vaultDir string, oldKey *VaultKey, wrappers []KeyWrapper) (*VaultKey, error) {
	vf, err := format.ReadVaultFile(vaultDir)
	if err != nil {
		return nil, err
	}
	if err := CheckKey(vf, oldKey); err != nil {
		return nil, err
	}
	conflicts, err := format.FindConflicts(vaultDir)
	if err != nil {
		return nil, err
	}
	for _, c := range conflicts {
		if c.Kind != format.ConflictTempFile {
			return nil, ErrConflicts
		}
	}
	secrets, err := format.ListSecrets(vaultDir)
	if err != nil {
		return nil, err
	}
	trash, err := format.ListTrash(vaultDir)
	if err != nil {
		return nil, err
	}

	newKey, err := NewVaultKey()
	if err != nil {
		return nil, err
	}
	unlockers, err := WrapAll(newKey, wrappers)
	if err != nil {
		newKey.Destroy()
		return nil, err
	}
	next := *vf
	next.KeyID = newKey.ID()
	next.Unlockers = unlockers
	if err := next.Validate(); err != nil {
		newKey.Destroy()
		return nil, err
	}

	staging, err := format.BeginStaging(vaultDir, next.KeyID)
	if err != nil {
		newKey.Destroy()
		return nil, err
	}
	fail := func(err error) (*VaultKey, error) {
		_ = staging.Abandon()
		newKey.Destroy()
		return nil, err
	}
	for _, s := range secrets {
		ct, err := format.ReadSecretFile(vaultDir, s.Name)
		if err != nil {
			return fail(err)
		}
		nct, err := reseal(s.Name, oldKey, newKey, ct)
		if err != nil {
			return fail(fmt.Errorf("crypto: re-encrypting a secret: %w", err))
		}
		if err := staging.AddSecret(s.Name, nct); err != nil {
			return fail(err)
		}
	}
	for _, t := range trash {
		ct, err := format.ReadTrashedFile(vaultDir, t)
		if err != nil {
			return fail(err)
		}
		nct, err := reseal(t.Name, oldKey, newKey, ct)
		if err != nil {
			return fail(fmt.Errorf("crypto: re-encrypting a trashed secret: %w", err))
		}
		if err := staging.AddTrashed(t, nct); err != nil {
			return fail(err)
		}
	}
	if err := staging.Finish(); err != nil {
		return fail(err)
	}
	if err := format.WriteVaultFile(vaultDir, &next); err != nil {
		return fail(err)
	}
	// Committed: the new key is live even if moving the files fails now.
	if err := format.CommitStaged(vaultDir, next.KeyID); err != nil {
		return newKey, fmt.Errorf("crypto: key rotated but finishing the file moves failed (run the command again to finish): %w", err)
	}
	return newKey, nil
}

// reseal opens ct with oldKey and seals the plaintext with newKey, zeroing
// the plaintext before returning.
func reseal(name string, oldKey, newKey *VaultKey, ct []byte) ([]byte, error) {
	s, err := NewSealer(name)
	if err != nil {
		return nil, err
	}
	pt, err := s.Open(oldKey, ct)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	return s.Seal(newKey, pt)
}
