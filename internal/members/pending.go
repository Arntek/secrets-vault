package members

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// PendingStore keeps the new key of each rotation this machine made until
// the rotation is confirmed (someone extended it), so a rotation that lost
// a race can still re-seal the files it moved (design section 10). Each key
// is age-encrypted to the rotator's own identity recipient: the same
// protection as the identity itself. Files: <dir>/<vault id>-<key id>.age.
type PendingStore struct{ dir string }

// NewPendingStore returns the store in dir (~/.config/vault/pending).
func NewPendingStore(dir string) *PendingStore { return &PendingStore{dir: dir} }

const maxPendingFile = 4096

func (p *PendingStore) path(vaultID, keyID string) (string, error) {
	if err := format.ValidateVaultID(vaultID); err != nil {
		return "", err
	}
	if err := format.ValidateKeyID(keyID); err != nil {
		return "", err
	}
	return filepath.Join(p.dir, vaultID+"-"+keyID+".age"), nil
}

// Save stores key for vaultID, encrypted to recipient.
func (p *PendingStore) Save(vaultID string, key *crypto.VaultKey, recipient string) error {
	path, err := p.path(vaultID, key.ID())
	if err != nil {
		return err
	}
	w, err := crypto.NewMemberWrapper("pending", recipient)
	if err != nil {
		return err
	}
	u, err := w.Wrap(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(p.dir, format.DirMode); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(p.dir, format.DirMode); err != nil { // #nosec G302 -- a directory needs the execute bit; 0700 is owner-only
			return err
		}
	}
	return format.WriteFileAtomic(path, u.WrappedKey, format.FileMode)
}

// Load returns every pending key for vaultID that me can open. Files that
// don't open (another identity, damage) are skipped.
func (p *PendingStore) Load(vaultID string, me *Unlocked) ([]*crypto.VaultKey, error) {
	ids, err := p.keyIDs(vaultID)
	if err != nil {
		return nil, err
	}
	w, err := me.MemberWrapper()
	if err != nil {
		return nil, err
	}
	var out []*crypto.VaultKey
	for _, id := range ids {
		path, _ := p.path(vaultID, id)
		data, err := readSmallFile(path, maxPendingFile)
		if err != nil {
			continue
		}
		k, err := w.Unwrap(format.Unlocker{Type: format.UnlockerMember, Label: me.Name, Recipient: me.Recipient, WrappedKey: data, Created: time.Now()})
		if err != nil || k.ID() != id {
			continue
		}
		out = append(out, k)
	}
	return out, nil
}

// Has reports whether any pending key exists for vaultID.
func (p *PendingStore) Has(vaultID string) bool {
	ids, _ := p.keyIDs(vaultID)
	return len(ids) > 0
}

func (p *PendingStore) keyIDs(vaultID string) ([]string, error) {
	if err := format.ValidateVaultID(vaultID); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.Name(), vaultID+"-")
		if !ok {
			continue
		}
		id, ok := strings.CutSuffix(rest, ".age")
		if ok && format.ValidateKeyID(id) == nil && e.Type().IsRegular() {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// DeleteAll removes every pending key for vaultID (the rotation was
// confirmed, the vault was detached, or a rollback was accepted).
func (p *PendingStore) DeleteAll(vaultID string) error {
	ids, err := p.keyIDs(vaultID)
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range ids {
		path, _ := p.path(vaultID, id)
		if err := os.Remove(path); err != nil && !isNotExist(err) {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("members: removing pending keys: %w", errors.Join(errs...))
	}
	return nil
}
