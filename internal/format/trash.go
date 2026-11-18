package format

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// TrashRetention is how long deleted keys stay in secrets/.trash.
const TrashRetention = 30 * 24 * time.Hour

// trashTimeLayout is the deletion time in a trashed file's name:
// NAME.20261117T153045.123456789Z.age. Key names contain no ".", so the
// name ends at the first one.
const trashTimeLayout = "20060102T150405.000000000Z"

// ErrTrashedExists is returned when a file being moved would replace one
// that is already there.
var ErrTrashedExists = errors.New("target already exists")

// TrashedSecret is one deleted key in secrets/.trash.
type TrashedSecret struct {
	Name    string    // key name
	Deleted time.Time // when it was moved to the trash (UTC)
	File    string    // file name inside secrets/.trash
}

// TrashFileName returns the trash file name for key name deleted at t.
func TrashFileName(name string, t time.Time) (string, error) {
	if err := ValidateKeyName(name); err != nil {
		return "", err
	}
	return name + "." + t.UTC().Format(trashTimeLayout) + SecretExt, nil
}

// ParseTrashName parses a file name inside secrets/.trash.
func ParseTrashName(file string) (TrashedSecret, error) {
	bad := fmt.Errorf("%w: not a trash file name", ErrMalformed)
	rest, ok := strings.CutSuffix(file, SecretExt)
	if !ok {
		return TrashedSecret{}, bad
	}
	name, stamp, ok := strings.Cut(rest, ".")
	if !ok || ValidateKeyName(name) != nil || len(stamp) != len(trashTimeLayout) {
		return TrashedSecret{}, bad
	}
	t, err := time.Parse(trashTimeLayout, stamp)
	if err != nil || t.UTC().Format(trashTimeLayout) != stamp {
		return TrashedSecret{}, bad
	}
	return TrashedSecret{Name: name, Deleted: t.UTC(), File: file}, nil
}

// TrashSecret moves secrets/NAME.age into secrets/.trash, stamped with now.
// The index entry is the caller's to remove.
func TrashSecret(vaultDir, name string, now time.Time) (TrashedSecret, error) {
	if err := CheckVaultDirs(vaultDir); err != nil {
		return TrashedSecret{}, err
	}
	src, err := SecretPath(vaultDir, name)
	if err != nil {
		return TrashedSecret{}, err
	}
	file, err := TrashFileName(name, now)
	if err != nil {
		return TrashedSecret{}, err
	}
	if fi, err := os.Lstat(src); err != nil {
		return TrashedSecret{}, err
	} else if !fi.Mode().IsRegular() {
		return TrashedSecret{}, fmt.Errorf("%s: %w", filepath.Base(src), ErrNotRegular)
	}
	trash := TrashPath(vaultDir)
	if err := os.MkdirAll(trash, DirMode); err != nil {
		return TrashedSecret{}, err
	}
	dst := filepath.Join(trash, file)
	if _, err := os.Lstat(dst); err == nil {
		return TrashedSecret{}, ErrTrashedExists
	}
	if err := os.Rename(src, dst); err != nil {
		return TrashedSecret{}, err
	}
	if err := syncDir(trash); err != nil {
		return TrashedSecret{}, err
	}
	if err := syncDir(filepath.Dir(src)); err != nil {
		return TrashedSecret{}, err
	}
	return ParseTrashName(file)
}

// ListTrash returns the trashed keys, oldest first. Files in the trash
// that do not follow the naming scheme are ignored.
func ListTrash(vaultDir string) ([]TrashedSecret, error) {
	entries, err := os.ReadDir(TrashPath(vaultDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []TrashedSecret
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		t, err := ParseTrashName(e.Name())
		if err != nil {
			continue
		}
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b TrashedSecret) int {
		if c := a.Deleted.Compare(b.Deleted); c != 0 {
			return c
		}
		return strings.Compare(a.File, b.File)
	})
	return out, nil
}

// ReadTrashedFile reads the encrypted content of a trashed key.
func ReadTrashedFile(vaultDir string, t TrashedSecret) ([]byte, error) {
	if _, err := ParseTrashName(t.File); err != nil {
		return nil, err
	}
	return readRegular(filepath.Join(TrashPath(vaultDir), t.File), MaxSecretFileSize)
}

// PurgeTrash permanently removes trashed keys deleted more than
// TrashRetention before now and returns them.
func PurgeTrash(vaultDir string, now time.Time) ([]TrashedSecret, error) {
	if err := CheckVaultDirs(vaultDir); err != nil {
		return nil, err
	}
	all, err := ListTrash(vaultDir)
	if err != nil {
		return nil, err
	}
	cutoff := now.Add(-TrashRetention)
	var purged []TrashedSecret
	for _, t := range all {
		if !t.Deleted.Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(TrashPath(vaultDir), t.File)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return purged, err
		}
		purged = append(purged, t)
	}
	return purged, nil
}

// RestoreSecret moves a trashed key back to secrets/NAME.age. It refuses
// (ErrTrashedExists) if a live key of that name exists.
func RestoreSecret(vaultDir string, t TrashedSecret) error {
	if err := CheckVaultDirs(vaultDir); err != nil {
		return err
	}
	parsed, err := ParseTrashName(t.File)
	if err != nil {
		return err
	}
	dst, err := SecretPath(vaultDir, parsed.Name)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dst); err == nil {
		return ErrTrashedExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(filepath.Join(TrashPath(vaultDir), parsed.File), dst); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dst))
}
