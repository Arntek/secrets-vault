package format

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Key rotation re-encrypts every secret, which cannot be one atomic step on
// a synced folder. It is staged instead:
//
//  1. BeginStaging creates secrets/.sv-rotate-<newKeyID>/ and the caller
//     adds every re-encrypted secret (and trashed secret) to it.
//  2. Finish writes MANIFEST, listing every staged file, last.
//  3. The caller writes vault.json with the new key ID. This is the commit
//     point: before it the old key and live files are untouched.
//  4. CommitStaged moves the staged files over the live ones and removes
//     the staging folder.
//
// If the process dies between 3 and 4, RecoverRotation (called whenever a
// vault is opened) finishes step 4. Staging folders for other key IDs are
// left alone, since on a second machine vault.json may simply not have
// synced yet; AbandonStaging removes one explicitly.
const (
	stagingPrefix    = ".sv-rotate-"
	manifestName     = "MANIFEST"
	committingName   = "COMMITTING"
	manifestHeader   = "secrets-vault rotation v1"
	maxManifestFiles = 2 * MaxIndexEntries
)

// ErrRotationIncomplete means a staging folder's MANIFEST lists files that
// are not present (still syncing, or the folder was damaged).
var ErrRotationIncomplete = errors.New("key rotation staging is incomplete")

// Staging collects re-encrypted files for one key rotation.
type Staging struct {
	vaultDir string
	keyID    string
	dir      string
	files    []string
	seen     map[string]bool
}

func stagingDir(vaultDir, keyID string) string {
	return filepath.Join(SecretsPath(vaultDir), stagingPrefix+keyID)
}

// BeginStaging creates the staging folder for a rotation to keyID.
func BeginStaging(vaultDir, keyID string) (*Staging, error) {
	if err := ValidateKeyID(keyID); err != nil {
		return nil, err
	}
	dir := stagingDir(vaultDir, keyID)
	if err := os.MkdirAll(SecretsPath(vaultDir), DirMode); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, DirMode); err != nil {
		return nil, err
	}
	return &Staging{vaultDir: vaultDir, keyID: keyID, dir: dir, seen: map[string]bool{}}, nil
}

func (s *Staging) add(rel string, data []byte) error {
	if err := validateManifestEntry(rel); err != nil {
		return err
	}
	if s.seen[rel] {
		return fmt.Errorf("%w: file staged twice", ErrMalformed)
	}
	if len(data) > MaxSecretFileSize {
		return ErrTooLarge
	}
	p := filepath.Join(s.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), DirMode); err != nil {
		return err
	}
	if err := WriteFileAtomic(p, data, FileMode); err != nil {
		return err
	}
	s.seen[rel] = true
	s.files = append(s.files, rel)
	return nil
}

// AddSecret stages the new ciphertext for live key name.
func (s *Staging) AddSecret(name string, ciphertext []byte) error {
	if err := ValidateKeyName(name); err != nil {
		return err
	}
	return s.add(name+SecretExt, ciphertext)
}

// AddTrashed stages the new ciphertext for a trashed key.
func (s *Staging) AddTrashed(t TrashedSecret, ciphertext []byte) error {
	if _, err := ParseTrashName(t.File); err != nil {
		return err
	}
	return s.add(TrashDir+"/"+t.File, ciphertext)
}

// Finish writes the MANIFEST. After it, writing vault.json commits.
func (s *Staging) Finish() error {
	var b strings.Builder
	b.WriteString(manifestHeader + "\nkey " + s.keyID + "\n")
	for _, f := range s.files {
		b.WriteString(f + "\n")
	}
	return WriteFileAtomic(filepath.Join(s.dir, manifestName), []byte(b.String()), FileMode)
}

// Abandon deletes the staging folder. Use it when the rotation fails before
// vault.json is written.
func (s *Staging) Abandon() error { return AbandonStaging(s.vaultDir, s.keyID) }

// AbandonStaging deletes the staging folder for keyID.
func AbandonStaging(vaultDir, keyID string) error {
	if err := ValidateKeyID(keyID); err != nil {
		return err
	}
	return os.RemoveAll(stagingDir(vaultDir, keyID))
}

// ParseManifest strictly parses a staging MANIFEST for keyID and returns
// the staged files, relative to the staging folder with "/" separators.
func ParseManifest(data []byte, keyID string) ([]string, error) {
	bad := func(why string) error { return fmt.Errorf("%w: rotation manifest %s", ErrMalformed, why) }
	if len(data) > MaxFileSize*8 {
		return nil, ErrTooLarge
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, bad("does not end with a newline")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) < 2 || lines[0] != manifestHeader {
		return nil, bad("has a bad header")
	}
	if lines[1] != "key "+keyID {
		return nil, bad("is for a different key")
	}
	files := lines[2:]
	if len(files) > maxManifestFiles {
		return nil, bad("lists too many files")
	}
	seen := make(map[string]bool, len(files))
	for _, f := range files {
		if err := validateManifestEntry(f); err != nil {
			return nil, err
		}
		if seen[f] {
			return nil, bad("lists a file twice")
		}
		seen[f] = true
	}
	return files, nil
}

// validateManifestEntry allows "NAME.age" and ".trash/<trash file name>".
func validateManifestEntry(rel string) error {
	if t, ok := strings.CutPrefix(rel, TrashDir+"/"); ok {
		_, err := ParseTrashName(t)
		return err
	}
	if _, ok := secretNameFromFile(rel); !ok {
		return fmt.Errorf("%w: bad staged file name", ErrMalformed)
	}
	return nil
}

// PendingRotations returns the key IDs of staging folders in secrets/.
func PendingRotations(vaultDir string) ([]string, error) {
	entries, err := os.ReadDir(SecretsPath(vaultDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		id, ok := strings.CutPrefix(e.Name(), stagingPrefix)
		if ok && e.IsDir() && ValidateKeyID(id) == nil {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// CommitStaged moves the staged files for keyID over the live ones and
// removes the staging folder. Call it only after vault.json carries keyID.
// It refuses with ErrRotationIncomplete if MANIFEST lists a missing file,
// unless a previous commit already started (then missing files were moved).
func CommitStaged(vaultDir, keyID string) error {
	if err := ValidateKeyID(keyID); err != nil {
		return err
	}
	dir := stagingDir(vaultDir, keyID)
	data, err := readRegular(filepath.Join(dir, manifestName), MaxFileSize*8)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrRotationIncomplete
		}
		return err
	}
	files, err := ParseManifest(data, keyID)
	if err != nil {
		return err
	}
	marker := filepath.Join(dir, committingName)
	_, statErr := os.Lstat(marker)
	resuming := statErr == nil
	if !resuming {
		for _, f := range files {
			if _, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(f))); err != nil {
				return ErrRotationIncomplete
			}
		}
		if err := WriteFileAtomic(marker, []byte("1\n"), FileMode); err != nil {
			return err
		}
	}
	for _, f := range files {
		src := filepath.Join(dir, filepath.FromSlash(f))
		dst := filepath.Join(SecretsPath(vaultDir), filepath.FromSlash(f))
		if path.Dir(f) == TrashDir {
			if err := os.MkdirAll(TrashPath(vaultDir), DirMode); err != nil {
				return err
			}
		}
		if err := os.Rename(src, dst); err != nil {
			if errors.Is(err, fs.ErrNotExist) && resuming {
				continue
			}
			return err
		}
	}
	if err := syncDir(SecretsPath(vaultDir)); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// RecoverRotation finishes an interrupted rotation whose new key is already
// in vault.json (currentKeyID). It reports whether it committed anything.
// Staging folders for other key IDs are left in place.
func RecoverRotation(vaultDir, currentKeyID string) (bool, error) {
	ids, err := PendingRotations(vaultDir)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		if id == currentKeyID {
			if err := CommitStaged(vaultDir, id); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}
