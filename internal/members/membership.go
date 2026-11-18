package members

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// MembersFileName is the display-metadata file next to vault.json. It
// records who added whom and roles. vault.json decides who is a member;
// anyone who can write the folder can edit this file, so never trust it for
// a decision.
const (
	MembersFileName = "members.json"
	metaVersion     = 1
)

type metaFile struct {
	Version int         `json:"version"`
	Members []metaEntry `json:"members"`
}

type metaEntry struct {
	Name      string    `json:"name"`
	Recipient string    `json:"recipient"`
	Role      Role      `json:"role"`
	AddedBy   string    `json:"added_by,omitempty"`
	Added     time.Time `json:"added"`
}

// ParseMembersFile strictly parses members.json. Exposed for fuzzing.
func ParseMembersFile(data []byte) error {
	_, err := parseMeta(data)
	return err
}

func parseMeta(data []byte) (*metaFile, error) {
	var m metaFile
	if err := decodeStrict(data, format.MaxFileSize, &m); err != nil {
		return nil, err
	}
	if m.Version != metaVersion {
		return nil, fmt.Errorf("%w: unsupported version", ErrMalformed)
	}
	if len(m.Members) > format.MaxUnlockers {
		return nil, fmt.Errorf("%w: too many members", ErrMalformed)
	}
	seen := map[string]bool{}
	for _, e := range m.Members {
		if ValidateMemberName(e.Name) != nil || checkRecipient(e.Recipient) != nil {
			return nil, fmt.Errorf("%w: bad member entry", ErrMalformed)
		}
		if e.Role != RoleOwner && e.Role != RoleMember {
			return nil, fmt.Errorf("%w: bad role", ErrMalformed)
		}
		if e.AddedBy != "" && ValidateMemberName(e.AddedBy) != nil {
			return nil, fmt.Errorf("%w: bad added_by", ErrMalformed)
		}
		if seen[e.Recipient] {
			return nil, fmt.Errorf("%w: duplicate member", ErrMalformed)
		}
		seen[e.Recipient] = true
	}
	return &m, nil
}

func readMeta(vaultDir string) (*metaFile, error) {
	data, err := readSmallFile(metaPath(vaultDir), format.MaxFileSize)
	if err != nil {
		if isNotExist(err) {
			return &metaFile{Version: metaVersion}, nil
		}
		return nil, err
	}
	return parseMeta(data)
}

func metaPath(vaultDir string) string { return filepath.Join(vaultDir, MembersFileName) }

func writeMeta(vaultDir string, m *metaFile) error {
	m.Version = metaVersion
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return format.WriteFileAtomic(metaPath(vaultDir), append(data, '\n'), format.FileMode)
}

// upsertMeta records e, replacing an entry for the same recipient. A
// missing or unreadable members.json starts afresh.
func upsertMeta(vaultDir string, e metaEntry) error {
	m, err := readMeta(vaultDir)
	if err != nil {
		m = &metaFile{Version: metaVersion}
	}
	m.Members = slices.DeleteFunc(m.Members, func(x metaEntry) bool { return x.Recipient == e.Recipient })
	m.Members = append(m.Members, e)
	return writeMeta(vaultDir, m)
}

// openVault reads vault.json and checks key is its current key.
func openVault(vaultDir string, key *crypto.VaultKey) (*format.VaultFile, error) {
	vf, err := format.ReadVaultFile(vaultDir)
	if err != nil {
		return nil, err
	}
	if err := crypto.CheckKey(vf, key); err != nil {
		return nil, err
	}
	return vf, nil
}

// AddSelf adds the owner's own member unlocker, used when a shared vault is
// created or an existing vault becomes shared. key must be the vault key.
func AddSelf(vaultDir string, key *crypto.VaultKey, me Identity) (Member, error) {
	return addMember(vaultDir, key, me, RoleOwner, "")
}

// addMember wraps key for id and records it in vault.json then members.json.
func addMember(vaultDir string, key *crypto.VaultKey, id Identity, role Role, addedBy string) (Member, error) {
	vf, err := openVault(vaultDir, key)
	if err != nil {
		return Member{}, err
	}
	for _, u := range vf.UnlockersOf(format.UnlockerMember) {
		if u.Recipient == id.Recipient {
			return Member{}, ErrAlreadyMember
		}
		if u.Label == id.Name {
			return Member{}, ErrDuplicateName
		}
	}
	u, err := Approve(key, JoinRequest{Identity: id})
	if err != nil {
		return Member{}, err
	}
	vf.SetUnlocker(u)
	if err := format.WriteVaultFile(vaultDir, vf); err != nil { // the commit point
		return Member{}, err
	}
	m := Member{Identity: id, Role: role, Added: u.Created, AddedBy: addedBy}
	// members.json is display metadata: a failure here must not undo the
	// approval, and List falls back to defaults.
	_ = upsertMeta(vaultDir, metaEntry{Name: id.Name, Recipient: id.Recipient, Role: role, AddedBy: addedBy, Added: u.Created})
	return m, nil
}

// ApproveRequest adds the requester called name to the vault.
//
// key is the vault key of an unlocked member (approver is that member's
// name, recorded as added_by). confirmedFingerprint is what the user read
// out and compared with the requester; it must equal the fingerprint
// derived from the request's own key, character for character (use
// NormalizeFingerprint on typed input first), otherwise nothing changes and
// ErrFingerprintMismatch is returned. On success the vault key is wrapped
// for the requester in vault.json and the request file is deleted.
func ApproveRequest(vaultDir string, key *crypto.VaultKey, name, confirmedFingerprint, approver string) (Member, error) {
	if approver != "" {
		if err := ValidateMemberName(approver); err != nil {
			return Member{}, err
		}
	}
	req, err := ReadRequest(vaultDir, name)
	if err != nil {
		return Member{}, err
	}
	if err := CheckFingerprintFormat(confirmedFingerprint); err != nil {
		return Member{}, fmt.Errorf("%w (%w)", ErrFingerprintMismatch, err)
	}
	if !FingerprintsEqual(confirmedFingerprint, req.Identity.Fingerprint) {
		return Member{}, ErrFingerprintMismatch
	}
	m, err := addMember(vaultDir, key, req.Identity, RoleMember, approver)
	if err != nil {
		if errors.Is(err, ErrAlreadyMember) {
			_ = DeleteRequest(vaultDir, name) // stale request for someone already in
		}
		return Member{}, err
	}
	if err := DeleteRequest(vaultDir, name); err != nil {
		return m, fmt.Errorf("members: approved, but the request file could not be removed: %w", err)
	}
	return m, nil
}

// Warning is a problem with a vault's membership worth showing the user.
type Warning struct {
	Code    string
	Message string
}

// Warning codes.
const (
	WarnSoleMemberNoRecovery  = "sole-member-no-recovery"
	WarnMemberNotesUnreadable = "member-notes-unreadable"
)

// Overview is everything `vault member list` and `vault member requests`
// show.
type Overview struct {
	Members       []Member
	HasPassphrase bool
	Requests      []JoinRequest
	BadRequests   []BadRequest
	Warnings      []Warning
}

// List returns the vault's members, in vault.json order. Membership comes
// from vault.json; role and added_by come from members.json when it has a
// matching entry for the same key, and default to "member" and empty.
func List(vaultDir string) ([]Member, error) {
	ov, err := Inspect(vaultDir)
	if err != nil {
		return nil, err
	}
	return ov.Members, nil
}

// Inspect reads the vault's members, pending requests and warnings. It
// warns when the vault has at most one member and no passphrase unlocker:
// losing that one key (or Mac) would lock everyone out for good.
func Inspect(vaultDir string) (*Overview, error) {
	vf, err := format.ReadVaultFile(vaultDir)
	if err != nil {
		return nil, err
	}
	ov := &Overview{HasPassphrase: len(vf.UnlockersOf(format.UnlockerPassphrase)) > 0}
	meta, merr := readMeta(vaultDir)
	if merr != nil {
		meta = &metaFile{}
		ov.Warnings = append(ov.Warnings, Warning{WarnMemberNotesUnreadable,
			"members.json could not be read; who added whom and roles are not shown"})
	}
	for _, u := range vf.UnlockersOf(format.UnlockerMember) {
		fp, err := Fingerprint(u.Recipient)
		if err != nil {
			return nil, fmt.Errorf("members: vault.json holds a member with an invalid public key: %w", ErrMalformed)
		}
		m := Member{
			Identity: Identity{Name: u.Label, Recipient: u.Recipient, Fingerprint: fp},
			Role:     RoleMember,
			Added:    u.Created,
		}
		for _, e := range meta.Members {
			if e.Recipient == u.Recipient {
				m.Role, m.AddedBy = e.Role, e.AddedBy
				break
			}
		}
		ov.Members = append(ov.Members, m)
	}
	if len(ov.Members) <= 1 && !ov.HasPassphrase {
		ov.Warnings = append(ov.Warnings, Warning{WarnSoleMemberNoRecovery,
			"this vault has only one member and no passphrase unlocker; if that key is lost the vault cannot be opened"})
	}
	if ov.Requests, ov.BadRequests, err = ListRequests(vaultDir); err != nil {
		return nil, err
	}
	return ov, nil
}

// RemoveResult describes a completed removal.
type RemoveResult struct {
	// Removed is the member that lost access.
	Removed Member
	// NewKey is the rotated vault key. The caller destroys the old key and
	// hands NewKey to the agent. It is set even when Remove also returns an
	// error from finishing the file moves (re-run to finish).
	NewKey *crypto.VaultKey
	// ExposedKeys are the names of the secrets the removed member could have
	// read, sorted: every secret in the vault (including trashed ones), since
	// a member holds the vault key that opens all of them. The user should
	// rotate these at their providers. Secrets deleted and purged earlier are
	// unknowable here.
	ExposedKeys []string
	// Dropped lists unlockers (other Macs' Touch ID) that could not be
	// re-wrapped because no wrapper for them was supplied; those devices
	// must enrol again.
	Dropped []format.Unlocker
	// Notes are non-fatal follow-ups, such as a members.json that could not
	// be updated.
	Notes []string
}

// Remove takes name out of the vault and rotates the vault key so their
// copy of the old key opens nothing new: every secret (and trashed secret)
// is re-encrypted, and vault.json is rewritten with the new key wrapped for
// every remaining member and for each wrapper in rewrap.
//
// key is the current vault key of an unlocked member. rewrap must hold a
// wrapper for the vault's passphrase unlocker if it has one (otherwise
// ErrPassphraseRequired, because dropping the recovery route silently would
// be worse than refusing), and may hold wrappers for Touch ID on this Mac.
// Member wrappers are not accepted here; remaining members are re-wrapped
// from the public keys in vault.json.
//
// Removing a member does not recall what they already saw: the old key and
// any secrets they read or synced remain theirs. Hence ExposedKeys.
func Remove(vaultDir string, key *crypto.VaultKey, name string, rewrap ...crypto.KeyWrapper) (*RemoveResult, error) {
	vf, err := openVault(vaultDir, key)
	if err != nil {
		return nil, err
	}
	var gone, stay []format.Unlocker
	for _, u := range vf.UnlockersOf(format.UnlockerMember) {
		if u.Label == name {
			gone = append(gone, u)
		} else {
			stay = append(stay, u)
		}
	}
	if len(gone) == 0 {
		return nil, ErrNotMember
	}
	hasPass := false
	for _, w := range rewrap {
		switch w.Type() {
		case format.UnlockerMember:
			return nil, errors.New("members: member unlockers are re-wrapped automatically; do not pass them")
		case format.UnlockerPassphrase:
			hasPass = true
		}
	}
	if len(vf.UnlockersOf(format.UnlockerPassphrase)) > 0 && !hasPass {
		return nil, ErrPassphraseRequired
	}
	wrappers := make([]crypto.KeyWrapper, 0, len(stay)+len(rewrap))
	for _, u := range stay {
		w, err := crypto.NewMemberWrapper(u.Label, u.Recipient)
		if err != nil {
			return nil, fmt.Errorf("members: vault.json holds a member with an invalid public key: %w", ErrMalformed)
		}
		wrappers = append(wrappers, w)
	}
	wrappers = append(wrappers, rewrap...)
	if len(wrappers) == 0 {
		return nil, ErrLastUnlocker
	}

	exposed, err := secretNames(vaultDir)
	if err != nil {
		return nil, err
	}
	removed, err := memberFromUnlocker(vaultDir, gone[0])
	if err != nil {
		return nil, err
	}

	newKey, rotErr := crypto.Rotate(vaultDir, key, wrappers)
	if newKey == nil {
		return nil, rotErr // nothing changed
	}
	res := &RemoveResult{Removed: removed, NewKey: newKey, ExposedKeys: exposed}
	res.Dropped = droppedUnlockers(vaultDir, vf)
	if m, err := readMeta(vaultDir); err == nil {
		m.Members = slices.DeleteFunc(m.Members, func(e metaEntry) bool {
			return slices.ContainsFunc(gone, func(u format.Unlocker) bool { return u.Recipient == e.Recipient })
		})
		if err := writeMeta(vaultDir, m); err != nil {
			res.Notes = append(res.Notes, "members.json could not be updated")
		}
	}
	return res, rotErr
}

// secretNames returns every secret name in the vault, trash included.
func secretNames(vaultDir string) ([]string, error) {
	live, err := format.ListSecrets(vaultDir)
	if err != nil {
		return nil, err
	}
	trash, err := format.ListTrash(vaultDir)
	if err != nil {
		return nil, err
	}
	set := map[string]struct{}{}
	for _, s := range live {
		set[s.Name] = struct{}{}
	}
	for _, t := range trash {
		set[t.Name] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	slices.Sort(out)
	return out, nil
}

func memberFromUnlocker(vaultDir string, u format.Unlocker) (Member, error) {
	fp, err := Fingerprint(u.Recipient)
	if err != nil {
		return Member{}, fmt.Errorf("members: vault.json holds a member with an invalid public key: %w", ErrMalformed)
	}
	m := Member{Identity: Identity{Name: u.Label, Recipient: u.Recipient, Fingerprint: fp}, Role: RoleMember, Added: u.Created}
	if meta, err := readMeta(vaultDir); err == nil {
		for _, e := range meta.Members {
			if e.Recipient == u.Recipient {
				m.Role, m.AddedBy = e.Role, e.AddedBy
			}
		}
	}
	return m, nil
}

// droppedUnlockers compares the old vault.json with the rotated one and
// returns old non-member unlockers that did not survive.
func droppedUnlockers(vaultDir string, old *format.VaultFile) []format.Unlocker {
	cur, err := format.ReadVaultFile(vaultDir)
	if err != nil {
		return nil
	}
	var out []format.Unlocker
	for _, o := range old.Unlockers {
		if o.Type == format.UnlockerMember {
			continue
		}
		kept := slices.ContainsFunc(cur.Unlockers, func(n format.Unlocker) bool {
			if n.Type != o.Type {
				return false
			}
			switch {
			case o.Type == format.UnlockerPassphrase:
				return true
			case o.Recipient != "":
				return n.Recipient == o.Recipient
			default:
				return strings.EqualFold(n.Label, o.Label)
			}
		})
		if !kept {
			o.WrappedKey = nil // never hand wrapped keys back
			out = append(out, o)
		}
	}
	return out
}
