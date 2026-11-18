package format

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
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
// If the process dies between 3 and 4, crypto.RecoverRotation (called
// after a vault is verified and unlocked) finishes step 4. Staging folders for other key IDs are
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
	if err := CheckVaultDirs(vaultDir); err != nil {
		return nil, err
	}
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

// AddIndex stages the new index.json. It is moved to the vault root, not
// into secrets/, when the rotation is committed.
func (s *Staging) AddIndex(data []byte) error {
	if len(data) > MaxFileSize {
		return ErrTooLarge
	}
	return s.add(IndexFileName, data)
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
	if err := CheckVaultDirs(vaultDir); err != nil {
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

// validateManifestEntry allows "NAME.age", ".trash/<trash file name>" and
// "index.json".
func validateManifestEntry(rel string) error {
	if rel == IndexFileName {
		return nil
	}
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
	if err := CheckVaultDirs(vaultDir); err != nil {
		return err
	}
	dir := stagingDir(vaultDir, keyID)
	if err := checkDir(filepath.Join(dir, TrashDir), true); err != nil {
		return err
	}
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
			fi, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(f)))
			if err != nil {
				return ErrRotationIncomplete
			}
			if !fi.Mode().IsRegular() {
				return fmt.Errorf("staged %s: %w", path.Base(f), ErrNotRegular)
			}
		}
		if err := WriteFileAtomic(marker, []byte("1\n"), FileMode); err != nil {
			return err
		}
	}
	for _, f := range files {
		src := filepath.Join(dir, filepath.FromSlash(f))
		dst := filepath.Join(SecretsPath(vaultDir), filepath.FromSlash(f))
		if f == IndexFileName {
			dst = IndexPath(vaultDir)
		}
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

// StagedFile is one file listed in a rotation's MANIFEST.
type StagedFile struct {
	// Rel is the path inside the staging folder ("NAME.age" or
	// ".trash/<trash file>").
	Rel string
	// Name is the key name the file belongs to (empty for index.json).
	Name string
}

// StagedFiles parses the MANIFEST of the staging folder for keyID.
func StagedFiles(vaultDir, keyID string) ([]StagedFile, error) {
	if err := ValidateKeyID(keyID); err != nil {
		return nil, err
	}
	if err := CheckVaultDirs(vaultDir); err != nil {
		return nil, err
	}
	dir := stagingDir(vaultDir, keyID)
	if err := checkDir(filepath.Join(dir, TrashDir), true); err != nil {
		return nil, err
	}
	data, err := readRegular(filepath.Join(dir, manifestName), MaxFileSize*8)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrRotationIncomplete
		}
		return nil, err
	}
	rels, err := ParseManifest(data, keyID)
	if err != nil {
		return nil, err
	}
	out := make([]StagedFile, 0, len(rels))
	for _, rel := range rels {
		if rel == IndexFileName {
			out = append(out, StagedFile{Rel: rel})
			continue
		}
		if t, ok := strings.CutPrefix(rel, TrashDir+"/"); ok {
			ts, err := ParseTrashName(t)
			if err != nil {
				return nil, err
			}
			out = append(out, StagedFile{Rel: rel, Name: ts.Name})
			continue
		}
		name, _ := secretNameFromFile(rel)
		out = append(out, StagedFile{Rel: rel, Name: name})
	}
	return out, nil
}

// ReadStagedFile reads one staged file (a regular file, not a symlink).
func ReadStagedFile(vaultDir, keyID, rel string) ([]byte, error) {
	if err := ValidateKeyID(keyID); err != nil {
		return nil, err
	}
	if err := validateManifestEntry(rel); err != nil {
		return nil, err
	}
	limit := int64(MaxSecretFileSize)
	if rel == IndexFileName {
		limit = MaxFileSize
	}
	return readRegular(filepath.Join(stagingDir(vaultDir, keyID), filepath.FromSlash(rel)), limit)
}

// QuarantineDir is where `vault doctor --quarantine-staging` moves rotation
// staging folders it can't use: at the vault root, outside secrets/, so the
// write guard no longer sees them. Nothing is deleted.
const QuarantineDir = "quarantine"

// QuarantineStaging moves secrets/.sv-rotate-<keyID>/ to
// quarantine/sv-rotate-<keyID>-<UTC time>/ and returns the new path
// relative to the vault folder.
func QuarantineStaging(vaultDir, keyID string, now time.Time) (string, error) {
	if err := ValidateKeyID(keyID); err != nil {
		return "", err
	}
	if err := CheckVaultDirs(vaultDir); err != nil {
		return "", err
	}
	q := filepath.Join(vaultDir, QuarantineDir)
	if err := checkDir(q, true); err != nil {
		return "", err
	}
	if err := os.MkdirAll(q, DirMode); err != nil {
		return "", err
	}
	if err := checkDir(q, false); err != nil {
		return "", err
	}
	name := "sv-rotate-" + keyID + "-" + now.UTC().Format("20060102T150405Z")
	if err := os.Rename(stagingDir(vaultDir, keyID), filepath.Join(q, name)); err != nil {
		return "", err
	}
	if err := syncDir(SecretsPath(vaultDir)); err != nil {
		return "", err
	}
	return path.Join(QuarantineDir, name), nil
}

// QuarantineSecret moves secrets/NAME.age to
// quarantine/secrets/NAME.<UTC time>.age and returns the new path relative
// to the vault folder. Nothing is deleted. A rotation uses it for files it
// cannot re-seal (sealed under a retired key), so they stop being reported
// on every write.
func QuarantineSecret(vaultDir, name string, now time.Time) (string, error) {
	src, err := SecretPath(vaultDir, name)
	if err != nil {
		return "", err
	}
	if err := CheckVaultDirs(vaultDir); err != nil {
		return "", err
	}
	if fi, err := os.Lstat(src); err != nil {
		return "", err
	} else if !fi.Mode().IsRegular() {
		return "", ErrNotRegular
	}
	q := filepath.Join(vaultDir, QuarantineDir)
	if err := checkDir(q, true); err != nil {
		return "", err
	}
	// Both levels must be real directories of ours before and after they
	// are made: a folder writer can plant a symlink at quarantine/ or
	// quarantine/secrets to send the file anywhere.
	qs := filepath.Join(q, SecretsDir)
	if err := checkDir(qs, true); err != nil {
		return "", err
	}
	if err := os.MkdirAll(qs, DirMode); err != nil {
		return "", err
	}
	if err := checkDir(q, false); err != nil {
		return "", err
	}
	if err := checkDir(qs, false); err != nil {
		return "", err
	}
	file := name + "." + now.UTC().Format("20060102T150405.000000000Z") + SecretExt
	if err := os.Rename(src, filepath.Join(qs, file)); err != nil {
		return "", err
	}
	if err := syncDir(SecretsPath(vaultDir)); err != nil {
		return "", err
	}
	return path.Join(QuarantineDir, SecretsDir, file), nil
}
