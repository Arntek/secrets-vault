package members

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Arntek/secrets-vault/internal/format"
)

// Join request files: <vault>/requests/<name>.json, written by someone who
// is not yet a member. They hold public information only.
const (
	requestVersion = 1
	// MaxRequestSize bounds a request file.
	MaxRequestSize = 4 << 10
	maxRequests    = 1000
	requestExt     = ".json"
)

type requestFile struct {
	Version     int       `json:"version"`
	Name        string    `json:"name"`
	Recipient   string    `json:"recipient"`
	Fingerprint string    `json:"fingerprint"`
	Created     time.Time `json:"created"`
}

// ParseRequest strictly parses a request file. Beyond the usual strictness
// it checks that the name is valid, the key is a canonical age X25519
// recipient, and the stated fingerprint is the one derived from that key,
// so a request edited in the shared folder is rejected.
func ParseRequest(data []byte) (JoinRequest, error) {
	var rf requestFile
	if err := decodeStrict(data, MaxRequestSize, &rf); err != nil {
		return JoinRequest{}, err
	}
	if rf.Version != requestVersion {
		return JoinRequest{}, fmt.Errorf("%w: unsupported request version", ErrMalformed)
	}
	if err := ValidateMemberName(rf.Name); err != nil {
		return JoinRequest{}, fmt.Errorf("%w: bad name", ErrMalformed)
	}
	if rf.Created.IsZero() {
		return JoinRequest{}, fmt.Errorf("%w: no created time", ErrMalformed)
	}
	fp, err := Fingerprint(rf.Recipient)
	if err != nil {
		return JoinRequest{}, fmt.Errorf("%w: bad public key", ErrMalformed)
	}
	if err := CheckFingerprintFormat(rf.Fingerprint); err != nil {
		return JoinRequest{}, fmt.Errorf("%w: fingerprint is not in the current three-word format (file from an older version?)", ErrMalformed)
	}
	if !FingerprintsEqual(fp, rf.Fingerprint) {
		return JoinRequest{}, fmt.Errorf("%w: fingerprint does not match the public key", ErrMalformed)
	}
	return JoinRequest{
		Identity: Identity{Name: rf.Name, Recipient: rf.Recipient, Fingerprint: fp},
		Created:  rf.Created.UTC(),
	}, nil
}

// RequestPath returns requests/NAME.json inside vaultDir.
func RequestPath(vaultDir, name string) (string, error) {
	if err := ValidateMemberName(name); err != nil {
		return "", err
	}
	return filepath.Join(vaultDir, format.RequestsDir, name+requestExt), nil
}

// BadRequest is a file in requests/ that could not be used. File is
// sanitised for display; Err never quotes the file.
type BadRequest struct {
	File string
	Err  error
}

// WriteRequest files a join request for id in the vault folder. The folder
// must hold a vault. It refuses a name already used by a member or a
// pending request (ErrDuplicateName), a key that is already a member
// (ErrAlreadyMember) and a key that already has a request (ErrRequestPending).
// The write is atomic, so Dropbox and Box only ever see a whole file.
//
// The duplicate check and the write are not atomic across machines: two
// people filing the same name at the same moment can overwrite each other;
// the approver sees whichever file is there and checks its fingerprint.
func WriteRequest(vaultDir string, id Identity, created time.Time) error {
	if err := ValidateMemberName(id.Name); err != nil {
		return err
	}
	fp, err := Fingerprint(id.Recipient)
	if err != nil {
		return err
	}
	if !FingerprintsEqual(fp, id.Fingerprint) {
		return ErrFingerprintMismatch
	}
	if created.IsZero() {
		created = time.Now()
	}
	vf, err := format.ReadVaultFile(vaultDir)
	if err != nil {
		return err
	}
	for _, u := range vf.UnlockersOf(format.UnlockerMember) {
		if u.Recipient == id.Recipient {
			return ErrAlreadyMember
		}
		if u.Label == id.Name {
			return ErrDuplicateName
		}
	}
	dir := filepath.Join(vaultDir, format.RequestsDir)
	if fi, err := os.Lstat(dir); err == nil && !fi.IsDir() {
		return fmt.Errorf("%w: requests is not a folder", ErrMalformed)
	}
	pending, _, err := ListRequests(vaultDir)
	if err != nil {
		return err
	}
	for _, p := range pending {
		if p.Identity.Name == id.Name {
			return ErrDuplicateName
		}
		if p.Identity.Recipient == id.Recipient {
			return ErrRequestPending
		}
	}
	path, err := RequestPath(vaultDir, id.Name)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return ErrDuplicateName // an unreadable file already holds the name
	}
	data, err := json.MarshalIndent(requestFile{
		Version:     requestVersion,
		Name:        id.Name,
		Recipient:   id.Recipient,
		Fingerprint: fp,
		Created:     created.UTC().Round(0),
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, format.DirMode); err != nil {
		return err
	}
	return format.WriteFileAtomic(path, append(data, '\n'), format.FileMode)
}

// ReadRequest reads and parses requests/NAME.json. A missing request returns
// ErrNoRequest.
func ReadRequest(vaultDir, name string) (JoinRequest, error) {
	path, err := RequestPath(vaultDir, name)
	if err != nil {
		return JoinRequest{}, err
	}
	data, err := readSmallFile(path, MaxRequestSize)
	if err != nil {
		if isNotExist(err) {
			return JoinRequest{}, ErrNoRequest
		}
		return JoinRequest{}, err
	}
	req, err := ParseRequest(data)
	if err != nil {
		return JoinRequest{}, err
	}
	if req.Identity.Name != name {
		return JoinRequest{}, fmt.Errorf("%w: request name does not match its file name", ErrMalformed)
	}
	return req, nil
}

// ListRequests returns the pending join requests, oldest first, and the
// files in requests/ that were rejected. Sync-conflict copies, temp files
// and OS litter are skipped silently.
func ListRequests(vaultDir string) ([]JoinRequest, []BadRequest, error) {
	dir := filepath.Join(vaultDir, format.RequestsDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if isNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var good []JoinRequest
	var bad []BadRequest
	for i, e := range entries {
		if i >= maxRequests {
			bad = append(bad, BadRequest{File: "(more files)", Err: ErrTooLarge})
			break
		}
		file := e.Name()
		if strings.HasPrefix(file, ".sv-tmp-") || strings.HasPrefix(file, ".") || file == "desktop.ini" || file == "Thumbs.db" {
			continue
		}
		name, ok := strings.CutSuffix(file, requestExt)
		if !ok || ValidateMemberName(name) != nil {
			if !looksLikeConflictCopy(file) {
				bad = append(bad, BadRequest{File: displayName(file), Err: fmt.Errorf("%w: unexpected file name", ErrMalformed)})
			}
			continue
		}
		req, err := ReadRequest(vaultDir, name)
		if err != nil {
			bad = append(bad, BadRequest{File: displayName(file), Err: err})
			continue
		}
		good = append(good, req)
	}
	slices.SortFunc(good, func(a, b JoinRequest) int {
		if c := a.Created.Compare(b.Created); c != 0 {
			return c
		}
		return strings.Compare(a.Identity.Name, b.Identity.Name)
	})
	return good, bad, nil
}

// looksLikeConflictCopy spots sync-service copies such as
// "dan (conflicted copy).json", which are not errors worth reporting.
func looksLikeConflictCopy(file string) bool {
	l := strings.ToLower(file)
	return strings.Contains(l, "conflict")
}

// DeleteRequest removes a pending request (after approval, or to refuse it).
func DeleteRequest(vaultDir, name string) error {
	path, err := RequestPath(vaultDir, name)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		if isNotExist(err) {
			return ErrNoRequest
		}
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: not a regular file", ErrMalformed)
	}
	return os.Remove(path)
}

// displayName makes a file name safe to print: printable ASCII only, at
// most 64 characters.
func displayName(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i >= 64 {
			b.WriteString("...")
			break
		}
		if r < ' ' || r > '~' {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}
