package format

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// File modes for everything written into a vault folder. Sync services
// ignore them, but on the local disk only the owner can read vault files.
const (
	FileMode fs.FileMode = 0o600
	DirMode  fs.FileMode = 0o700
)

// tempPrefix starts every temporary file WriteFileAtomic creates. Such
// files are leftovers of an interrupted write and FindConflicts reports them.
const tempPrefix = ".sv-tmp-"

// WriteFileAtomic writes data to path so that readers (and sync clients such
// as Dropbox and Box) only ever see the old file or the complete new one:
// it writes a temporary file in the same directory, fsyncs it, renames it
// over path, then fsyncs the directory. On error the temporary file is
// removed and path is unchanged.
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, tempPrefix+"*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(perm); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir fsyncs a directory so a rename in it is durable. File systems
// that cannot fsync a directory are tolerated.
func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- vault directory chosen by the user
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) && !errors.Is(err, errors.ErrUnsupported) {
		return err
	}
	return nil
}

// readRegular reads a regular file of at most max bytes. Symlinks,
// directories and devices are refused, so a tampered vault cannot point a
// vault file at something else on the machine.
func readRegular(path string, max int64) ([]byte, error) {
	f, err := openNoFollow(path)
	if err != nil {
		if isSymlinkErr(err) {
			return nil, fmt.Errorf("%s: %w", filepath.Base(path), ErrNotRegular)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), ErrNotRegular)
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), ErrTooLarge)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), ErrTooLarge)
	}
	return data, nil
}

// VaultFilePath returns the path of vault.json in vaultDir.
func VaultFilePath(vaultDir string) string { return filepath.Join(vaultDir, VaultFileName) }

// IndexPath returns the path of index.json in vaultDir.
func IndexPath(vaultDir string) string { return filepath.Join(vaultDir, IndexFileName) }

// SecretsPath returns the secrets directory of vaultDir.
func SecretsPath(vaultDir string) string { return filepath.Join(vaultDir, SecretsDir) }

// TrashPath returns the trash directory of vaultDir.
func TrashPath(vaultDir string) string { return filepath.Join(vaultDir, SecretsDir, TrashDir) }

// ReadVaultFile reads and parses vaultDir/vault.json.
func ReadVaultFile(vaultDir string) (*VaultFile, error) {
	vf, _, err := ReadVaultFileBytes(vaultDir)
	return vf, err
}

// ReadVaultFileBytes reads and parses vaultDir/vault.json and also returns
// the exact bytes read, for WriteVaultFileCAS.
func ReadVaultFileBytes(vaultDir string) (*VaultFile, []byte, error) {
	if err := CheckVaultDirs(vaultDir); err != nil {
		return nil, nil, err
	}
	data, err := readRegular(VaultFilePath(vaultDir), MaxVaultFileSize)
	if err != nil {
		return nil, nil, err
	}
	vf, err := ParseVaultFile(data)
	if err != nil {
		return nil, nil, err
	}
	return vf, data, nil
}

// WriteVaultFileCAS validates vf and writes vaultDir/vault.json atomically,
// but only if the file still holds exactly expect (the bytes the caller
// read and verified). Otherwise it returns ErrChanged and writes nothing.
// A nil expect means the file must not exist yet.
func WriteVaultFileCAS(vaultDir string, vf *VaultFile, expect []byte) error {
	data, err := MarshalVaultFile(vf)
	if err != nil {
		return err
	}
	if err := CheckVaultDirs(vaultDir); err != nil {
		return err
	}
	cur, err := readRegular(VaultFilePath(vaultDir), MaxVaultFileSize)
	switch {
	case expect == nil && errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	case expect == nil || !bytes.Equal(cur, expect):
		return ErrChanged
	}
	return WriteFileAtomic(VaultFilePath(vaultDir), data, FileMode)
}

// CheckVaultDirs refuses a vault folder whose own directory, secrets/,
// secrets/.trash/, requests/ or any rotation staging folder is a symlink,
// is not a directory or (on Unix) is not owned by the current user.
// Folders that do not exist are fine (except the vault folder itself).
// Every function here that writes, renames or deletes under a vault calls
// it first, so a folder writer cannot redirect those operations elsewhere
// on the machine.
func CheckVaultDirs(vaultDir string) error {
	if err := checkDir(vaultDir, false); err != nil {
		return err
	}
	for _, rel := range []string{SecretsDir, filepath.Join(SecretsDir, TrashDir), RequestsDir} {
		if err := checkDir(filepath.Join(vaultDir, rel), true); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(SecretsPath(vaultDir))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			if err := checkDir(filepath.Join(SecretsPath(vaultDir), e.Name()), true); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkDir requires path to be a real directory owned by the current user.
func checkDir(path string, missingOK bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if missingOK && errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() || !ownedByMe(fi) {
		return fmt.Errorf("%s: %w", filepath.Base(path), ErrUnsafeDir)
	}
	return nil
}

// WriteVaultFile validates vf and writes vaultDir/vault.json atomically.
// Prefer WriteVaultFileCAS for any update of an existing vault.
func WriteVaultFile(vaultDir string, vf *VaultFile) error {
	data, err := MarshalVaultFile(vf)
	if err != nil {
		return err
	}
	if err := CheckVaultDirs(vaultDir); err != nil {
		return err
	}
	return WriteFileAtomic(VaultFilePath(vaultDir), data, FileMode)
}

// ReadIndex reads and parses vaultDir/index.json. A missing index returns
// an error wrapping fs.ErrNotExist; callers rebuild it with RebuildIndex.
func ReadIndex(vaultDir string) (*Index, error) {
	data, err := readRegular(IndexPath(vaultDir), MaxFileSize)
	if err != nil {
		return nil, err
	}
	return ParseIndex(data)
}

// ReadIndexRaw returns the exact bytes of index.json, for WriteIndexCAS and
// for parsing with ParseIndexTolerant. A missing file wraps fs.ErrNotExist.
func ReadIndexRaw(vaultDir string) ([]byte, error) {
	if err := CheckVaultDirs(vaultDir); err != nil {
		return nil, err
	}
	return readRegular(IndexPath(vaultDir), MaxFileSize)
}

// WriteIndex validates idx and writes vaultDir/index.json atomically.
func WriteIndex(vaultDir string, idx *Index) error {
	data, err := MarshalIndex(idx)
	if err != nil {
		return err
	}
	if err := CheckVaultDirs(vaultDir); err != nil {
		return err
	}
	return WriteFileAtomic(IndexPath(vaultDir), data, FileMode)
}

var indexCASMu sync.Mutex

// ErrIndexChanged means index.json changed between reading and writing it.
var ErrIndexChanged = errors.New("index.json changed while this command was running")

// WriteIndexCAS validates idx and writes vaultDir/index.json atomically,
// but only if the file still holds exactly expect (the bytes the caller
// read and verified). Otherwise it returns ErrIndexChanged and writes
// nothing. A nil expect means the file must not exist.
func WriteIndexCAS(vaultDir string, idx *Index, expect []byte) error {
	data, err := MarshalIndex(idx)
	if err != nil {
		return err
	}
	if err := CheckVaultDirs(vaultDir); err != nil {
		return err
	}
	// The check and the write are one step among writers in this process;
	// across machines (a sync service) the compare-and-swap is best effort,
	// like vault.json's, and conflict copies are merged by package index.
	indexCASMu.Lock()
	defer indexCASMu.Unlock()
	cur, err := readRegular(IndexPath(vaultDir), MaxFileSize)
	switch {
	case expect == nil && errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	case expect == nil || !bytes.Equal(cur, expect):
		return ErrIndexChanged
	}
	return WriteFileAtomic(IndexPath(vaultDir), data, FileMode)
}

// CreateVault lays out a new vault in vaultDir (created if missing):
// secrets/, an empty index.json and vault.json, written last so a
// half-created folder is never mistaken for a vault. It returns
// ErrVaultExists if vault.json is already there.
func CreateVault(vaultDir string, vf *VaultFile) error {
	if err := vf.Validate(); err != nil {
		return err
	}
	if _, err := os.Lstat(VaultFilePath(vaultDir)); err == nil {
		return ErrVaultExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(SecretsPath(vaultDir), DirMode); err != nil {
		return err
	}
	if err := CheckVaultDirs(vaultDir); err != nil {
		return err
	}
	if vf.Version == LegacyVaultVersion {
		// Tests only: a format-2 vault starts with a version-1 index.
		if err := WriteFileAtomic(IndexPath(vaultDir), []byte("{\n  \"version\": 1,\n  \"entries\": []\n}\n"), FileMode); err != nil {
			return err
		}
	} else {
		idx := NewIndex()
		idx.VaultID = vf.ID
		if err := WriteIndex(vaultDir, idx); err != nil {
			return err
		}
	}
	return WriteVaultFile(vaultDir, vf)
}

// ReadSecretFile reads the encrypted file for key name. A missing key
// returns an error wrapping fs.ErrNotExist.
func ReadSecretFile(vaultDir, name string) ([]byte, error) {
	p, err := SecretPath(vaultDir, name)
	if err != nil {
		return nil, err
	}
	return readRegular(p, MaxSecretFileSize)
}

// WriteSecretFile atomically writes the encrypted file for key name.
func WriteSecretFile(vaultDir, name string, ciphertext []byte) error {
	p, err := SecretPath(vaultDir, name)
	if err != nil {
		return err
	}
	if len(ciphertext) > MaxSecretFileSize {
		return ErrTooLarge
	}
	if err := CheckVaultDirs(vaultDir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), DirMode); err != nil {
		return err
	}
	return WriteFileAtomic(p, ciphertext, FileMode)
}

// SecretExists reports whether secrets/NAME.age exists.
func SecretExists(vaultDir, name string) (bool, error) {
	p, err := SecretPath(vaultDir, name)
	if err != nil {
		return false, err
	}
	_, err = os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// SecretInfo describes one secrets/NAME.age file.
type SecretInfo struct {
	Name     string
	Modified time.Time
}

// ListSecrets returns the valid secret files in secrets/, sorted by name.
// Anything else in the directory (conflict copies, temp files, unknown
// files) is skipped here and reported by FindConflicts.
func ListSecrets(vaultDir string) ([]SecretInfo, error) {
	entries, err := os.ReadDir(SecretsPath(vaultDir))
	if err != nil {
		return nil, err
	}
	var out []SecretInfo
	for _, e := range entries {
		name, ok := secretNameFromFile(e.Name())
		if !ok || !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // removed while listing
			}
			return nil, err
		}
		out = append(out, SecretInfo{Name: name, Modified: fi.ModTime().UTC()})
	}
	slices.SortFunc(out, func(a, b SecretInfo) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// secretNameFromFile maps "NAME.age" to NAME if NAME is a valid key name.
func secretNameFromFile(file string) (string, bool) {
	name, ok := strings.CutSuffix(file, SecretExt)
	if !ok || ValidateKeyName(name) != nil {
		return "", false
	}
	return name, true
}

// LeaseFileName is the rotation lease at the vault root (package members
// writes and checks it).
const LeaseFileName = "rotation.lease"

// maxLeaseSize bounds the lease file.
const maxLeaseSize = 8 << 10

// ReadLease returns the raw rotation lease, or an error wrapping
// fs.ErrNotExist if there is none.
func ReadLease(vaultDir string) ([]byte, error) {
	return readRegular(filepath.Join(vaultDir, LeaseFileName), maxLeaseSize)
}

// WriteLease writes the rotation lease atomically.
func WriteLease(vaultDir string, data []byte) error {
	if len(data) > maxLeaseSize {
		return ErrTooLarge
	}
	if err := CheckVaultDirs(vaultDir); err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(vaultDir, LeaseFileName), data, FileMode)
}

// RemoveLease deletes the rotation lease if present.
func RemoveLease(vaultDir string) error {
	if err := CheckVaultDirs(vaultDir); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(vaultDir, LeaseFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// ReadVaultFileCopy reads and parses a sync-conflict copy of vault.json
// (rel as reported by FindConflicts), and returns its bytes too.
func ReadVaultFileCopy(vaultDir, rel string) (*VaultFile, []byte, error) {
	if strings.Contains(rel, "/") || strings.Contains(rel, `\`) || rel == "" || rel == "." || rel == ".." {
		return nil, nil, fmt.Errorf("%w: not a file in the vault root", ErrMalformed)
	}
	data, err := readRegular(filepath.Join(vaultDir, rel), MaxVaultFileSize)
	if err != nil {
		return nil, nil, err
	}
	vf, err := ParseVaultFile(data)
	if err != nil {
		return nil, nil, err
	}
	return vf, data, nil
}

// ReadIndexCopy reads the raw bytes of a sync-conflict copy of index.json
// (rel as reported by FindConflicts).
func ReadIndexCopy(vaultDir, rel string) ([]byte, error) {
	if strings.Contains(rel, "/") || strings.Contains(rel, `\`) || rel == "" || rel == "." || rel == ".." {
		return nil, fmt.Errorf("%w: not a file in the vault root", ErrMalformed)
	}
	return readRegular(filepath.Join(vaultDir, rel), MaxFileSize)
}

// ReadRegularFile reads a regular file of at most max bytes, refusing
// symlinks. For other packages' small local files (snapshots).
func ReadRegularFile(path string, max int64) ([]byte, error) { return readRegular(path, max) }

// DecodeStrict decodes exactly one JSON value with the strict rules of
// this package (no duplicate or unknown keys, bounded depth, no trailing
// data), for other packages' file formats.
func DecodeStrict(data []byte, maxSize int, v any) error { return decodeStrictMax(data, maxSize, v) }
