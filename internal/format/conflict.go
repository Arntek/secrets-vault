package format

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// ConflictKind classifies an unexpected file in a vault folder.
type ConflictKind string

const (
	// ConflictSyncCopy is a copy made by a sync service when two machines
	// changed the same file, e.g. Dropbox's
	// "index (Dan's conflicted copy 2026-11-20).json".
	ConflictSyncCopy ConflictKind = "sync-conflict"
	// ConflictTempFile is a temporary file left by an interrupted write.
	ConflictTempFile ConflictKind = "temp-file"
	// ConflictUnknown is any other file in secrets/ that is not NAME.age.
	ConflictUnknown ConflictKind = "unknown"
)

// Conflict is one unexpected file found by FindConflicts.
type Conflict struct {
	// Path is relative to the vault folder, with "/" separators.
	Path string
	Kind ConflictKind
	// Original is the vault file this one is a copy of (relative path), if
	// it could be worked out from the name; otherwise empty.
	Original string
}

// Patterns sync services use for conflict copies:
//
//	Dropbox:   NAME (Dan's conflicted copy 2026-11-20).ext, NAME (conflicted copy).ext
//	Box Drive: NAME (Dan Smith's conflicted copy).ext, NAME (1).ext
//	Syncthing: NAME.sync-conflict-20261120-101500-ABCDEFG.ext
//	OneDrive:  NAME-HOSTNAME.ext (not detectable by name; caught as unknown in secrets/)
var (
	parenConflictRe = regexp.MustCompile(`^(.+?)((?: \((?:[^()]*conflict[^()]*|\d{1,4})\))+)(\.[A-Za-z0-9]+)?$`)
	syncthingRe     = regexp.MustCompile(`^(.+?)\.sync-conflict-\d{8}-\d{6}-[A-Z0-9]{7}(\.[A-Za-z0-9]+)?$`)
)

// conflictOriginal returns the file name a conflict copy was made from, or
// "" if file does not look like a conflict copy.
func conflictOriginal(file string) string {
	if len(file) > 1024 {
		return ""
	}
	if m := syncthingRe.FindStringSubmatch(file); m != nil {
		return m[1] + m[2]
	}
	m := parenConflictRe.FindStringSubmatch(file)
	if m == nil {
		return ""
	}
	// A bare "(n)" suffix is only a conflict marker when it follows a name we
	// recognise; "(conflicted copy)" always is.
	if !strings.Contains(strings.ToLower(m[2]), "conflict") && !isKnownVaultFile(m[1]+m[3]) {
		return ""
	}
	return m[1] + m[3]
}

// isKnownVaultFile reports whether a bare file name is one a vault folder
// is expected to contain at the root or in secrets/.
func isKnownVaultFile(file string) bool {
	if file == VaultFileName || file == IndexFileName {
		return true
	}
	_, ok := secretNameFromFile(file)
	return ok
}

// FindConflicts lists sync-conflict copies, leftover temporary files and
// unknown files in the vault root and secrets/. Ordinary extra files in the
// root (a README, .DS_Store) are not reported; anything in secrets/ that is
// not NAME.age, the trash or a rotation staging folder is.
func FindConflicts(vaultDir string) ([]Conflict, error) {
	var out []Conflict
	scan := func(rel string, strict bool) error {
		entries, err := os.ReadDir(filepath.Join(vaultDir, filepath.FromSlash(rel)))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, e := range entries {
			name := e.Name()
			p := path.Join(rel, name)
			switch {
			case strings.HasPrefix(name, tempPrefix):
				out = append(out, Conflict{Path: p, Kind: ConflictTempFile})
				continue
			case rel == "" && (name == VaultFileName || name == IndexFileName || name == SecretsDir || name == RequestsDir):
				continue
			case rel == SecretsDir && (name == TrashDir || strings.HasPrefix(name, stagingPrefix)):
				continue
			}
			if rel == SecretsDir {
				if _, ok := secretNameFromFile(name); ok && e.Type().IsRegular() {
					continue
				}
			}
			if orig := conflictOriginal(name); orig != "" {
				c := Conflict{Path: p, Kind: ConflictSyncCopy}
				if isKnownVaultFile(orig) {
					c.Original = path.Join(rel, orig)
				}
				out = append(out, c)
				continue
			}
			if strict && !isIgnorableHidden(name) {
				out = append(out, Conflict{Path: p, Kind: ConflictUnknown})
			}
		}
		return nil
	}
	if err := scan("", false); err != nil {
		return nil, err
	}
	if err := scan(SecretsDir, true); err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b Conflict) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

// isIgnorableHidden reports operating-system and sync-client litter.
func isIgnorableHidden(name string) bool {
	switch name {
	case ".DS_Store", ".dropbox", ".dropbox.attr", "desktop.ini", "Thumbs.db", "Icon\r":
		return true
	}
	return strings.HasPrefix(name, "._")
}
