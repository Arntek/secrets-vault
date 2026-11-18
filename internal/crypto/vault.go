package crypto

import (
	"bytes"
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

// NewVaultFile builds the start of a new vault's vault.json: a fresh vault
// ID, key's ID and one unlocker per wrapper. It is not complete: package
// members adds the member set and the signed genesis record before it is
// written with format.CreateVault.
func NewVaultFile(name string, key *VaultKey, wrappers []KeyWrapper) (*format.VaultFile, error) {
	id, err := format.NewVaultID()
	if err != nil {
		return nil, err
	}
	unlockers, err := WrapAll(key, wrappers)
	if err != nil {
		return nil, err
	}
	if err := format.ValidateVaultName(name); err != nil {
		return nil, err
	}
	return &format.VaultFile{
		Version:   format.VaultVersion,
		ID:        id,
		Name:      name,
		KeyID:     key.ID(),
		Unlockers: unlockers,
	}, nil
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
// The key ID check stops a copied-in unlocker from another vault. Whether
// vf itself is genuine is decided before this by package members, which
// verifies the signed membership log against this machine's trust pin.
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

// ErrRotationRace means another machine replaced vault.json right after
// this rotation wrote it, so the staged files were not moved. The new key
// is still returned; the caller resolves the race (package members).
var ErrRotationRace = errors.New("crypto: another change to the vault landed at the same time as this key rotation")

// RotateOptions configures Rotate.
type RotateOptions struct {
	// Expect is the exact vault.json content the caller read and verified.
	// Rotate refuses (format.ErrChanged) if the file holds anything else,
	// before and at the moment of writing.
	Expect []byte
	// Next builds the new vault.json for newKey: the new unlockers and the
	// signed record (package members). It is called once, before any file
	// is written, and must keep the vault ID and use newKey's ID.
	Next func(newKey *VaultKey) (*format.VaultFile, error)
	// ExtraKeys are other keys secret files may be sealed under, such as
	// this machine's key from a rotation that lost a race. Files under them
	// are re-sealed to the new key as well.
	ExtraKeys []*VaultKey
	// NewVaultID lets Next give the vault a new ID (vault rebuild).
	NewVaultID bool
}

// Rotate replaces the vault key: it creates a new key, re-encrypts every
// secret and every trashed secret with it, and writes the vault.json that
// opt.Next builds for it. oldKey must be the current key. It returns the
// new key; the caller should Destroy oldKey and hand the new key to the
// agent.
//
// The re-encrypted files are staged first and vault.json is the commit
// point (see format.BeginStaging). If Rotate fails before vault.json is
// written, nothing changes. If it fails after, RecoverRotation finishes
// the job the next time the vault is verified and unlocked.
//
// Rotate refuses to run while the folder has sync conflicts. A secret
// another machine writes with the old key while it runs is not re-sealed.
func Rotate(vaultDir string, oldKey *VaultKey, opt RotateOptions) (*VaultKey, error) {
	if opt.Next == nil {
		return nil, errors.New("crypto: rotate needs the new vault file")
	}
	vf, raw, err := format.ReadVaultFileBytes(vaultDir)
	if err != nil {
		return nil, err
	}
	if opt.Expect != nil && !bytes.Equal(raw, opt.Expect) {
		return nil, format.ErrChanged
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
	next, err := opt.Next(newKey)
	if err != nil {
		newKey.Destroy()
		return nil, err
	}
	if next.KeyID != newKey.ID() || (next.ID != vf.ID && !opt.NewVaultID) {
		newKey.Destroy()
		return nil, errors.New("crypto: rotated vault file does not match the new key")
	}
	if err := next.Validate(); err != nil {
		newKey.Destroy()
		return nil, err
	}
	keys := append([]*VaultKey{oldKey}, opt.ExtraKeys...)

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
		nct, err := reseal(s.Name, keys, newKey, ct)
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
		nct, err := reseal(t.Name, keys, newKey, ct)
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
	if err := format.WriteVaultFileCAS(vaultDir, next, raw); err != nil {
		return fail(err)
	}
	// Committed. Re-check before moving files: if another machine's change
	// replaced ours in the meantime, leave the staging for the race to be
	// resolved rather than mixing keys in secrets/.
	written, err := format.MarshalVaultFile(next)
	if err != nil {
		return newKey, err
	}
	if _, now, err := format.ReadVaultFileBytes(vaultDir); err != nil || !bytes.Equal(now, written) {
		return newKey, ErrRotationRace
	}
	if err := format.CommitStaged(vaultDir, next.KeyID); err != nil {
		return newKey, fmt.Errorf("crypto: key rotated but finishing the file moves failed (run the command again to finish): %w", err)
	}
	return newKey, nil
}

// RecoverRotation finishes an interrupted rotation to key, which must be
// the verified, unlocked current key: it moves the staged files of
// secrets/.sv-rotate-<key id>/ into place, but only after every staged
// file has opened under key with its own name. Staging folders for other
// keys are left alone. The caller must have verified vault.json first
// (package members) and checked that a verified rotation introduced key.
func RecoverRotation(vaultDir string, key *VaultKey) (bool, error) {
	ids, err := format.PendingRotations(vaultDir)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		if id != key.ID() {
			continue
		}
		files, err := format.StagedFiles(vaultDir, id)
		if err != nil {
			return false, err
		}
		for _, f := range files {
			ct, err := format.ReadStagedFile(vaultDir, id, f.Rel)
			if err != nil {
				return false, err
			}
			s, err := NewSealer(f.Name)
			if err != nil {
				return false, err
			}
			pt, err := s.Open(key, ct)
			clear(pt)
			if err != nil {
				return false, fmt.Errorf("crypto: a staged file does not open under the vault key: %w", err)
			}
		}
		if err := format.CommitStaged(vaultDir, id); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// KeyIDOf returns the vault key ID a secret file is sealed under, read from
// its age header without decrypting anything.
func KeyIDOf(ciphertext []byte) (string, error) {
	const intro = "age-encryption.org/v1\n-> " + stanzaType + " "
	if !bytes.HasPrefix(ciphertext, []byte(intro)) {
		return "", errBadStanza
	}
	rest := ciphertext[len(intro):]
	end := bytes.IndexAny(rest, " \n")
	if end < 0 {
		return "", errBadStanza
	}
	id := string(rest[:end])
	if format.ValidateKeyID(id) != nil {
		return "", errBadStanza
	}
	return id, nil
}

// reseal opens ct with whichever of keys it is sealed under and seals the
// plaintext with newKey, zeroing the plaintext before returning.
func reseal(name string, keys []*VaultKey, newKey *VaultKey, ct []byte) ([]byte, error) {
	s, err := NewSealer(name)
	if err != nil {
		return nil, err
	}
	id, err := KeyIDOf(ct)
	if err != nil {
		return nil, ErrDecrypt
	}
	var key *VaultKey
	for _, k := range keys {
		if k != nil && k.ID() == id {
			key = k
		}
	}
	if key == nil {
		return nil, ErrOtherKey
	}
	pt, err := s.Open(key, ct)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	return s.Seal(newKey, pt)
}
