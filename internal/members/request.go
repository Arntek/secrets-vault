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
// is not yet a member. They hold public information only, and are signed
// by the requester's own signing key over a body that names the vault, so
// a request can't be edited, moved to another vault, or pair someone else's
// keys with a name (design Threat 5, G7).
const (
	requestVersion = 2
	// MaxRequestSize bounds a request file.
	MaxRequestSize = 4 << 10
	maxRequests    = 1000
	requestExt     = ".json"
)

type requestFile struct {
	Version int    `json:"version"`
	Body    []byte `json:"body"`
	Sig     []byte `json:"sig"`
}

type requestBody struct {
	VaultID   string    `json:"vault_id"`
	Name      string    `json:"name"`
	Recipient string    `json:"recipient"`
	SignKey   string    `json:"sign_key"`
	Created   time.Time `json:"created"`
}

// ParseRequest strictly parses a request file for the vault vaultID.
// Beyond the usual strictness it checks the name, both public keys and the
// requester's signature, and that the request names this vault.
func ParseRequest(data []byte, vaultID string) (JoinRequest, error) {
	var rf requestFile
	if err := decodeStrict(data, MaxRequestSize, &rf); err != nil {
		return JoinRequest{}, err
	}
	if rf.Version != requestVersion {
		return JoinRequest{}, fmt.Errorf("%w: request from an older version; ask the person to run attach again", ErrMalformed)
	}
	var b requestBody
	if err := decodeStrict(rf.Body, MaxRequestSize, &b); err != nil {
		return JoinRequest{}, err
	}
	if b.VaultID != vaultID {
		return JoinRequest{}, fmt.Errorf("%w: request is for another vault", ErrMalformed)
	}
	if err := ValidateMemberName(b.Name); err != nil {
		return JoinRequest{}, fmt.Errorf("%w: bad name", ErrMalformed)
	}
	if b.Created.IsZero() {
		return JoinRequest{}, fmt.Errorf("%w: no created time", ErrMalformed)
	}
	fp, err := Fingerprint(b.Recipient, b.SignKey)
	if err != nil {
		return JoinRequest{}, fmt.Errorf("%w: bad public key", ErrMalformed)
	}
	if !verifySig(b.SignKey, requestDomain, rf.Body, rf.Sig) {
		return JoinRequest{}, fmt.Errorf("%w: request signature does not match", ErrMalformed)
	}
	return JoinRequest{
		Identity: Identity{Name: b.Name, Recipient: b.Recipient, SignKey: b.SignKey, Fingerprint: fp},
		Created:  b.Created.UTC(),
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

// WriteRequest files a join request for me in the vault folder, signed by
// me. The folder must hold a vault. It refuses a name already used by a
// member or a pending request (ErrDuplicateName), a key that is already a
// member (ErrAlreadyMember) and a key that already has a request
// (ErrRequestPending). The write is atomic, so Dropbox and Box only ever
// see a whole file. The member check reads vault.json's member list without
// verifying it: it only saves a pointless request, and approval verifies.
//
// The duplicate check and the write are not atomic across machines: two
// people filing the same name at the same moment can overwrite each other;
// the approver sees whichever file is there and checks its fingerprint.
func WriteRequest(vaultDir string, me *Unlocked, created time.Time) error {
	if err := ValidateMemberName(me.Name); err != nil {
		return err
	}
	if created.IsZero() {
		created = time.Now()
	}
	vf, err := format.ReadVaultFile(vaultDir)
	if err != nil {
		return err
	}
	for _, m := range vf.Members {
		if m.Recipient == me.Recipient || m.SignKey == me.SignKey {
			return ErrAlreadyMember
		}
		if m.Name == me.Name {
			return ErrDuplicateName
		}
	}
	dir := filepath.Join(vaultDir, format.RequestsDir)
	if err := format.CheckVaultDirs(vaultDir); err != nil {
		return err
	}
	pending, _, err := ListRequests(vaultDir, vf.ID)
	if err != nil {
		return err
	}
	for _, p := range pending {
		if p.Identity.Name == me.Name {
			return ErrDuplicateName
		}
		if p.Identity.Recipient == me.Recipient {
			return ErrRequestPending
		}
	}
	path, err := RequestPath(vaultDir, me.Name)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return ErrDuplicateName // an unreadable file already holds the name
	}
	body, err := json.Marshal(requestBody{VaultID: vf.ID, Name: me.Name, Recipient: me.Recipient, SignKey: me.SignKey, Created: created.UTC().Round(0)})
	if err != nil {
		return err
	}
	sig, err := me.Sign(requestDomain, body)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(requestFile{Version: requestVersion, Body: body, Sig: sig}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, format.DirMode); err != nil {
		return err
	}
	if err := format.CheckVaultDirs(vaultDir); err != nil {
		return err
	}
	return format.WriteFileAtomic(path, append(data, '\n'), format.FileMode)
}

// ReadRequest reads and parses requests/NAME.json for the vault vaultID. A
// missing request returns ErrNoRequest.
func ReadRequest(vaultDir, vaultID, name string) (JoinRequest, error) {
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
	req, err := ParseRequest(data, vaultID)
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
func ListRequests(vaultDir, vaultID string) ([]JoinRequest, []BadRequest, error) {
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
		req, err := ReadRequest(vaultDir, vaultID, name)
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
	if err := format.CheckVaultDirs(vaultDir); err != nil {
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
