package members

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// Load reads vault.json from vaultDir and verifies it (Verify). Version-1
// files return ErrOldFormat with the parsed file, for the migration path.
func Load(vaultDir, registeredID string) (*Chain, *format.VaultFile, error) {
	vf, raw, err := format.ReadVaultFileBytes(vaultDir)
	if err != nil {
		return nil, nil, err
	}
	if vf.Version == 1 {
		if registeredID != "" && vf.ID != registeredID {
			return nil, nil, ErrOtherVault
		}
		return nil, vf, ErrOldFormat
	}
	c, err := Verify(vf, raw, registeredID)
	if err != nil {
		return nil, nil, err
	}
	return c, vf, nil
}

// NewVault creates a vault in vaultDir owned by owner: the vault key is
// wrapped for owner (and passphrase, if not nil) and the genesis record is
// signed by owner. It returns the verified chain.
func NewVault(vaultDir, name string, key *crypto.VaultKey, owner *Unlocked, passphrase crypto.KeyWrapper, now time.Time) (*Chain, error) {
	mw, err := owner.MemberWrapper()
	if err != nil {
		return nil, err
	}
	wrappers := []crypto.KeyWrapper{mw}
	if passphrase != nil {
		wrappers = append(wrappers, passphrase)
	}
	vf, err := crypto.NewVaultFile(name, key, wrappers)
	if err != nil {
		return nil, err
	}
	if err := Genesis(vf, owner, now); err != nil {
		return nil, err
	}
	if err := format.CreateVault(vaultDir, vf); err != nil {
		return nil, err
	}
	c, _, err := Load(vaultDir, vf.ID)
	return c, err
}

// write stores next over c's file (compare-and-swap on c.Raw) and returns
// the re-read, verified chain and the record just written.
func write(vaultDir string, c *Chain, next *format.VaultFile) (*Chain, error) {
	if err := format.WriteVaultFileCAS(vaultDir, next, c.Raw); err != nil {
		return nil, err
	}
	nc, _, err := Load(vaultDir, c.File.ID)
	return nc, err
}

// LastEntry returns the newest log entry of c (what a writer adds to its
// pin's Own list).
func (c *Chain) LastEntry() format.LogEntry { return c.File.Log[len(c.File.Log)-1] }

// ApproveRequest adds the requester called name to the vault.
//
// c is the verified chain, key its unlocked vault key and signer the
// approving member. confirmedFingerprint is what the approver typed after
// the requester read theirs out; it must equal the fingerprint derived
// from the request's own keys (NormalizeFingerprint is applied), otherwise
// nothing changes and ErrFingerprintMismatch is returned. The request is
// re-read here, after the check, so a request swapped in between fails. A
// key that an earlier record removed needs readd (G7). On success the
// signed add-member record is written and the request file deleted.
func ApproveRequest(vaultDir string, c *Chain, key *crypto.VaultKey, signer *Unlocked, name, confirmedFingerprint string, readd bool, now time.Time) (*Chain, Member, error) {
	if err := crypto.CheckKey(c.File, key); err != nil {
		return nil, Member{}, err
	}
	req, err := ReadRequest(vaultDir, c.File.ID, name)
	if err != nil {
		return nil, Member{}, err
	}
	typed := NormalizeFingerprint(confirmedFingerprint)
	if err := CheckFingerprintFormat(typed); err != nil {
		return nil, Member{}, fmt.Errorf("%w (%w)", ErrFingerprintMismatch, err)
	}
	if !FingerprintsEqual(typed, req.Identity.Fingerprint) {
		return nil, Member{}, ErrFingerprintMismatch
	}
	for _, m := range c.Head().Members {
		if m.Recipient == req.Identity.Recipient || m.SignKey == req.Identity.SignKey {
			_ = DeleteRequest(vaultDir, name) // stale request for someone already in
			return nil, Member{}, ErrAlreadyMember
		}
		if m.Name == req.Identity.Name {
			return nil, Member{}, ErrDuplicateName
		}
	}
	if len(c.RemovedAt(req.Identity.Recipient, req.Identity.SignKey)) > 0 && !readd {
		return nil, Member{}, ErrPreviouslyRemoved
	}
	mw, err := crypto.NewMemberWrapper(req.Identity.Name, req.Identity.Recipient)
	if err != nil {
		return nil, Member{}, ErrInvalidRecipient
	}
	u, err := mw.Wrap(key)
	if err != nil {
		return nil, Member{}, err
	}
	m := format.Member{Name: req.Identity.Name, Recipient: req.Identity.Recipient, SignKey: req.Identity.SignKey, Role: format.RoleMember}
	next, err := c.Append(signer, Change{
		Op: format.OpAddMember, Member: &m, KeyID: c.File.KeyID,
		Unlockers: append(slices.Clone(c.File.Unlockers), u), Time: now,
	})
	if err != nil {
		return nil, Member{}, err
	}
	nc, err := write(vaultDir, c, next)
	if err != nil {
		return nil, Member{}, err
	}
	out := Member{Identity: req.Identity, Role: format.RoleMember, Added: now.UTC(), AddedBy: signer.Name}
	if err := DeleteRequest(vaultDir, name); err != nil {
		return nc, out, fmt.Errorf("members: approved, but the request file could not be removed: %w", err)
	}
	return nc, out, nil
}

// RotateOptions are the choices for a key rotation (Remove, Passwd).
type RotateOptions struct {
	// Passphrase is the passphrase policy: format.PassDropped (default),
	// PassKept (Keep must wrap under the current passphrase) or
	// PassReplaced (New wraps under the new one).
	Passphrase string
	Keep       crypto.KeyWrapper
	New        crypto.KeyWrapper
	// ExtraKeys are keys some files may still be sealed under (a lost
	// rotation's key, design section 10); those files are re-sealed too.
	ExtraKeys []*crypto.VaultKey
	// Pending, if set, keeps the new key (encrypted to signer) until the
	// rotation is confirmed, so a lost race can be repaired.
	Pending *PendingStore
	Now     time.Time
}

// RotateResult describes a completed rotation.
type RotateResult struct {
	Chain  *Chain
	NewKey *crypto.VaultKey
	// Removed is the member who lost access (Remove only).
	Removed Member
	// ExposedKeys are the names of every secret the removed member could
	// have read (Remove only): all of them, trash included.
	ExposedKeys []string
	// Passphrase is the policy applied.
	Passphrase string
}

// Remove takes name out of the vault and rotates the vault key, so their
// copy of the old key opens nothing new. Every secret (and trashed secret)
// is re-encrypted, and the new key is wrapped only for the remaining
// members of the verified state, plus the passphrase per opt (default:
// dropped, ue1.6). The signed remove-member record is written in the same
// vault.json write as the new key.
//
// Removing a member does not recall what they already saw: the old key and
// any secrets they read or synced remain theirs. Hence ExposedKeys. Their
// access to the shared folder must also be removed, or they can roll the
// folder back for members who are offline (design Threat 4).
func Remove(vaultDir string, c *Chain, key *crypto.VaultKey, signer *Unlocked, name string, opt RotateOptions) (*RotateResult, error) {
	gone, ok := c.Head().Member(name)
	if !ok {
		return nil, ErrNotMember
	}
	exposed, err := secretNames(vaultDir)
	if err != nil {
		return nil, err
	}
	fp, err := Fingerprint(gone.Recipient, gone.SignKey)
	if err != nil {
		return nil, err
	}
	by, at := c.AddedBy(name)
	res, err := rotate(vaultDir, c, key, signer, format.OpRemoveMember, &gone, opt)
	if res != nil {
		res.Removed = Member{Identity: Identity{Name: gone.Name, Recipient: gone.Recipient, SignKey: gone.SignKey, Fingerprint: fp}, Role: gone.Role, Added: at, AddedBy: by}
		res.ExposedKeys = exposed
	}
	return res, err
}

// Passwd sets a new vault passphrase. With rotate (the default for the
// CLI, and required in a shared vault by policy of the CLI) it rotates the
// vault key, so old copies of vault.json opened with the old passphrase
// give nothing new (ue1.6); without, it only re-wraps the current key
// under newPass (a signed set-unlocker record) and returns NewKey nil.
func Passwd(vaultDir string, c *Chain, key *crypto.VaultKey, signer *Unlocked, newPass crypto.KeyWrapper, rotateKey bool, opt RotateOptions) (*RotateResult, error) {
	if newPass == nil || newPass.Type() != format.UnlockerPassphrase {
		return nil, errors.New("members: passwd needs a passphrase wrapper")
	}
	if rotateKey {
		opt.Passphrase, opt.New = format.PassReplaced, newPass
		return rotate(vaultDir, c, key, signer, format.OpRotate, nil, opt)
	}
	if err := crypto.CheckKey(c.File, key); err != nil {
		return nil, err
	}
	u, err := newPass.Wrap(key)
	if err != nil {
		return nil, err
	}
	us := slices.Clone(c.File.Unlockers)
	us = slices.DeleteFunc(us, func(x format.Unlocker) bool { return x.Type == format.UnlockerPassphrase })
	us = append(us, u)
	next, err := c.Append(signer, Change{Op: format.OpSetUnlocker, KeyID: c.File.KeyID, Unlockers: us, Time: opt.Now})
	if err != nil {
		return nil, err
	}
	nc, err := write(vaultDir, c, next)
	if err != nil {
		return nil, err
	}
	return &RotateResult{Chain: nc, Passphrase: format.PassReplaced}, nil
}

// rotate is the shared body of Remove and Passwd: lease, then
// crypto.Rotate with a Next that wraps the new key for the verified
// members (minus a removed one) and appends the signed record.
func rotate(vaultDir string, c *Chain, key *crypto.VaultKey, signer *Unlocked, op format.RecordOp, gone *format.Member, opt RotateOptions) (*RotateResult, error) {
	if err := crypto.CheckKey(c.File, key); err != nil {
		return nil, err
	}
	if opt.Passphrase == "" {
		opt.Passphrase = format.PassDropped
	}
	var passW crypto.KeyWrapper
	switch opt.Passphrase {
	case format.PassDropped:
	case format.PassKept:
		if opt.Keep == nil {
			return nil, ErrPassphraseRequired
		}
		k, err := crypto.Unlock(c.File, opt.Keep)
		if err != nil {
			return nil, err // prove it is the current passphrase first
		}
		k.Destroy()
		passW = opt.Keep
	case format.PassReplaced:
		if opt.New == nil {
			return nil, ErrPassphraseRequired
		}
		passW = opt.New
	default:
		return nil, errors.New("members: unknown passphrase policy")
	}
	var stay []format.Member
	for _, m := range c.Head().Members {
		if gone == nil || m.Name != gone.Name {
			stay = append(stay, m)
		}
	}
	if len(stay) == 0 {
		return nil, ErrLastUnlocker
	}
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	if err := CheckLease(vaultDir, c, signer.Name, now); err != nil {
		return nil, err
	}
	if err := WriteLease(vaultDir, c, signer, now); err != nil {
		return nil, err
	}
	defer func() { _ = format.RemoveLease(vaultDir) }()

	newKey, err := crypto.Rotate(vaultDir, key, crypto.RotateOptions{
		Expect:    c.Raw,
		ExtraKeys: opt.ExtraKeys,
		Next: func(nk *crypto.VaultKey) (*format.VaultFile, error) {
			ws := make([]crypto.KeyWrapper, 0, len(stay)+1)
			for _, m := range stay {
				w, err := crypto.NewMemberWrapper(m.Name, m.Recipient)
				if err != nil {
					return nil, ErrInvalidRecipient
				}
				ws = append(ws, w)
			}
			if passW != nil {
				ws = append(ws, passW)
			}
			us, err := crypto.WrapAll(nk, ws)
			if err != nil {
				return nil, err
			}
			next, err := c.Append(signer, Change{Op: op, Member: gone, Passphrase: opt.Passphrase, KeyID: nk.ID(), Unlockers: us, Time: now})
			if err != nil {
				return nil, err
			}
			if opt.Pending != nil {
				if err := opt.Pending.Save(c.File.ID, nk, signer.Recipient); err != nil {
					return nil, err
				}
			}
			return next, nil
		},
	})
	if newKey == nil {
		return nil, err
	}
	res := &RotateResult{NewKey: newKey, Passphrase: opt.Passphrase}
	if errors.Is(err, crypto.ErrRotationRace) {
		return res, err
	}
	nc, _, lerr := Load(vaultDir, c.File.ID)
	if lerr != nil && err == nil {
		err = lerr
	}
	res.Chain = nc
	return res, err
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

// Warning is a problem with a vault's membership worth showing the user.
type Warning struct {
	Code    string
	Message string
}

// Warning codes.
const (
	WarnSoleMember = "sole-member"
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

// Inspect returns the verified chain's members (with who added them and
// when, from the signed records), pending requests and warnings.
func Inspect(vaultDir string, c *Chain) (*Overview, error) {
	ov := &Overview{HasPassphrase: c.HasPassphrase()}
	for _, m := range c.Head().Members {
		fp, err := Fingerprint(m.Recipient, m.SignKey)
		if err != nil {
			return nil, err
		}
		by, at := c.AddedBy(m.Name)
		ov.Members = append(ov.Members, Member{
			Identity: Identity{Name: m.Name, Recipient: m.Recipient, SignKey: m.SignKey, Fingerprint: fp},
			Role:     m.Role, Added: at, AddedBy: by,
		})
	}
	if len(ov.Members) == 1 {
		msg := "this vault has only one member; if that identity is lost, only the vault passphrase can open it. Add a second trusted member as the recovery route (they attach, you run member approve)"
		if !ov.HasPassphrase {
			msg = "this vault has only one member and no passphrase; if that identity is lost the vault cannot be opened. Add a second trusted member as the recovery route (they attach, you run member approve)"
		}
		ov.Warnings = append(ov.Warnings, Warning{WarnSoleMember, msg})
	}
	var err error
	if ov.Requests, ov.BadRequests, err = ListRequests(vaultDir, c.File.ID); err != nil {
		return nil, err
	}
	return ov, nil
}
