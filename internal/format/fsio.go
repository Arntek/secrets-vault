package format

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	data, err := readRegular(VaultFilePath(vaultDir), MaxFileSize)
	if err != nil {
		return nil, err
	}
	return ParseVaultFile(data)
}

// WriteVaultFile validates vf and writes vaultDir/vault.json atomically.
func WriteVaultFile(vaultDir string, vf *VaultFile) error {
	data, err := MarshalVaultFile(vf)
	if err != nil {
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

// WriteIndex validates idx and writes vaultDir/index.json atomically.
func WriteIndex(vaultDir string, idx *Index) error {
	data, err := MarshalIndex(idx)
	if err != nil {
		return err
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
	if err := WriteIndex(vaultDir, NewIndex()); err != nil {
		return err
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
