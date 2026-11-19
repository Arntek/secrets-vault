package members

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Arntek/secrets-vault/internal/format"
)

// The membership log (docs/design/membership-auth.md): every change to who
// can open a vault is a record signed by a member of the state before it,
// the records are hash-chained, and the state of the vault is what replaying
// them from genesis gives. Nothing in a vault.json is trusted until Verify
// has replayed it.

// Signature domains. Each kind of signed thing has its own, so a signature
// made for one can never be replayed as another.
const (
	recordDomain  = "secrets-vault/v2 membership record\x00"
	requestDomain = "secrets-vault/v2 join request\x00"
	leaseDomain   = "secrets-vault/v2 rotation lease\x00"
)

// Errors from verifying and changing the log. Messages never quote input.
var (
	// ErrTampered means vault.json fails verification: a bad signature, a
	// broken chain, or unlockers/members that don't match the signed state.
	ErrTampered = errors.New("vault.json was changed outside secrets-vault (it does not match its signed history); nothing was read or written")
	// ErrNotAuthorised means a change was signed by someone who was not a
	// member at that point, or breaks the membership rules.
	ErrNotAuthorised = errors.New("members: that change is not allowed")
	// ErrOtherVault means vault.json holds a different vault than the one
	// registered on this machine (M1).
	ErrOtherVault = errors.New("this folder now holds a different vault than the one registered here")
	// ErrLogFull means the membership log reached format.MaxLogEntries.
	ErrLogFull = errors.New("this vault's history is full; create a new vault and move the secrets (vault rebuild)")
	// ErrOldFormat means vault.json is version 1 (made by a pre-release build).
	ErrOldFormat = errors.New("this vault was made by an older pre-release version")
)

// State is a vault's membership after one record.
type State struct {
	Seq           int
	Head          string // format.RecordHash of record Seq
	KeyID         string
	Members       []format.Member // sorted by name
	MembersHash   string
	UnlockersHash string
	Time          time.Time
	By            string
	Op            format.RecordOp
	// Format is the vault format after this record: 2 until genesis or an
	// upgrade-format record says 3. It never decreases.
	Format int
}

// Member returns the member called name.
func (s *State) Member(name string) (format.Member, bool) {
	for _, m := range s.Members {
		if m.Name == name {
			return m, true
		}
	}
	return format.Member{}, false
}

// Chain is a verified vault.json: the file, its exact bytes, the parsed
// records and the state after each.
type Chain struct {
	File    *format.VaultFile
	Raw     []byte
	Records []*format.Record
	States  []State
}

// Head is the current state.
func (c *Chain) Head() *State { return &c.States[len(c.States)-1] }

// KeyIntroducedAt returns the seq of the record that made keyID the vault
// key, and whether it was a rotation (rather than genesis).
func (c *Chain) KeyIntroducedAt(keyID string) (seq int, rotation, ok bool) {
	for i := len(c.Records) - 1; i >= 0; i-- {
		if c.Records[i].KeyID != keyID {
			continue
		}
		if i == 0 || c.Records[i-1].KeyID != keyID {
			return i, i > 0, true
		}
	}
	return 0, false, false
}

// KnowsKey reports whether keyID was ever this vault's key.
func (c *Chain) KnowsKey(keyID string) bool {
	_, _, ok := c.KeyIntroducedAt(keyID)
	return ok
}

// AddedBy returns who added member name and when (the signer and time of
// the latest record that added them), so `member list` never shows a value
// the signatures don't support.
func (c *Chain) AddedBy(name string) (by string, at time.Time) {
	for i := len(c.Records) - 1; i >= 0; i-- {
		r := c.Records[i]
		if (r.Op == format.OpAddMember || r.Op == format.OpGenesis) && r.Member.Name == name {
			return c.States[i].By, r.Time
		}
	}
	return "", time.Time{}
}

// RemovedAt returns the records (seq) that removed a member with this
// recipient or signing key, for re-add warnings (G7).
func (c *Chain) RemovedAt(recipient, signKey string) []int {
	var out []int
	for i, r := range c.Records {
		if r.Op == format.OpRemoveMember && (r.Member.Recipient == recipient || r.Member.SignKey == signKey) {
			out = append(out, i)
		}
	}
	return out
}

// HasPassphrase reports whether the head has a passphrase unlocker.
func (c *Chain) HasPassphrase() bool {
	return len(c.File.UnlockersOf(format.UnlockerPassphrase)) > 0
}

// Verify replays a version-2 vault.json from genesis and returns the
// verified chain. registeredID, if not empty, is the vault ID this machine
// registered; a file for any other ID is refused (ErrOtherVault). It needs
// no key: every record is signed by a member of the state before it.
func Verify(vf *format.VaultFile, raw []byte, registeredID string) (*Chain, error) {
	if vf.Version != format.VaultVersion && vf.Version != format.LegacyVaultVersion {
		return nil, ErrOldFormat
	}
	if registeredID != "" && vf.ID != registeredID {
		return nil, ErrOtherVault
	}
	if err := vf.Validate(); err != nil {
		return nil, fmt.Errorf("%w (%w)", ErrTampered, err)
	}
	c := &Chain{File: vf, Raw: raw}
	for i, e := range vf.Log {
		rec, err := format.ParseRecordBody(e.Body)
		if err != nil {
			return nil, fmt.Errorf("%w (record %d: %w)", ErrTampered, i, err)
		}
		if rec.Seq != i || rec.VaultID != vf.ID {
			return nil, fmt.Errorf("%w (record %d is out of place)", ErrTampered, i)
		}
		var prev *State
		if i > 0 {
			prev = &c.States[i-1]
			if rec.Prev != prev.Head {
				return nil, fmt.Errorf("%w (record %d does not follow record %d)", ErrTampered, i, i-1)
			}
		}
		next, err := applyRecord(prev, rec, e.By)
		if err != nil {
			return nil, fmt.Errorf("%w (record %d: %w)", ErrTampered, i, err)
		}
		var signer format.Member
		if prev == nil {
			signer = *rec.Member // genesis: self-signed by the owner it creates
		} else {
			signer, _ = prev.Member(e.By)
		}
		if !verifySig(signer.SignKey, recordDomain, e.Body, e.Sig) {
			return nil, fmt.Errorf("%w (record %d has a bad signature)", ErrTampered, i)
		}
		next.Head = format.RecordHash(e.Body)
		c.Records = append(c.Records, rec)
		c.States = append(c.States, next)
	}
	head := c.Head()
	// The format is part of the signed history: a vault.json whose version
	// differs from what the chain says (a downgrade or an upgrade nobody
	// signed) is refused.
	if vf.Version != head.Format {
		return nil, fmt.Errorf("%w (the file's format differs from the signed history)", ErrTampered)
	}
	if vf.KeyID != head.KeyID ||
		format.MembersDigest(vf.Members) != head.MembersHash ||
		format.UnlockersDigest(vf.Unlockers) != head.UnlockersHash {
		return nil, fmt.Errorf("%w (the members or unlockers differ from the signed state)", ErrTampered)
	}
	if last := c.Records[len(c.Records)-1]; last.Passphrase == format.PassDropped && c.HasPassphrase() {
		return nil, fmt.Errorf("%w (a passphrase unlocker the last change dropped)", ErrTampered)
	}
	return c, nil
}

// applyRecord checks that rec, signed by by, is allowed after prev (nil
// for genesis) and returns the state after it, without Head.
func applyRecord(prev *State, rec *format.Record, by string) (State, error) {
	next := State{Seq: rec.Seq, KeyID: rec.KeyID, UnlockersHash: rec.UnlockersHash, MembersHash: rec.MembersHash, Time: rec.Time, By: by, Op: rec.Op}
	if prev == nil {
		if rec.Op != format.OpGenesis || rec.Member.Role != format.RoleOwner || by != rec.Member.Name {
			return State{}, ErrNotAuthorised
		}
		next.Members = []format.Member{*rec.Member}
		next.Format = format.LegacyVaultVersion
		if rec.Format != 0 {
			next.Format = rec.Format
		}
	} else {
		signer, ok := prev.Member(by)
		if !ok {
			return State{}, ErrNotAuthorised
		}
		if err := authorise(prev, rec, signer); err != nil {
			return State{}, err
		}
		next.Members = slices.Clone(prev.Members)
		next.Format = prev.Format
		if rec.Op == format.OpUpgradeFormat {
			next.Format = rec.Format
		}
		switch rec.Op {
		case format.OpAddMember:
			next.Members = append(next.Members, *rec.Member)
			format.SortMembers(next.Members)
		case format.OpRemoveMember:
			next.Members = slices.DeleteFunc(next.Members, func(m format.Member) bool { return m.Name == rec.Member.Name })
		}
	}
	if err := format.ValidateMembers(next.Members); err != nil {
		return State{}, err
	}
	if format.MembersDigest(next.Members) != rec.MembersHash {
		return State{}, errors.New("member set does not match its hash")
	}
	return next, nil
}

// authorise is the one place the membership policy lives (decided: any
// current member may sign any change; the product is for high-trust
// teams). Writers and the verifier both call it, so a stricter policy
// later (for example owner-only removal) is a change here only.
func authorise(prev *State, rec *format.Record, signer format.Member) error {
	if m, ok := prev.Member(signer.Name); !ok || m != signer {
		return ErrNotAuthorised
	}
	switch rec.Op {
	case format.OpGenesis:
		return ErrNotAuthorised
	case format.OpAddMember:
		if rec.Member.Role != format.RoleMember {
			return ErrNotAuthorised
		}
		for _, m := range prev.Members {
			if m.Name == rec.Member.Name || m.Recipient == rec.Member.Recipient || m.SignKey == rec.Member.SignKey {
				return ErrNotAuthorised
			}
		}
	case format.OpRemoveMember:
		m, ok := prev.Member(rec.Member.Name)
		if !ok || m != *rec.Member || len(prev.Members) < 2 {
			return ErrNotAuthorised
		}
	}
	if rec.Op == format.OpUpgradeFormat && (prev.Format != format.LegacyVaultVersion || rec.Format != format.VaultVersion) {
		return ErrNotAuthorised
	}
	// The vault key changes exactly on rotations (removal always rotates).
	rotates := rec.Op == format.OpRotate || rec.Op == format.OpRemoveMember
	if rotates == (rec.KeyID == prev.KeyID) {
		return ErrNotAuthorised
	}
	return nil
}

// Change describes one new record for Append.
type Change struct {
	Op         format.RecordOp
	Member     *format.Member
	Format     int // only for OpUpgradeFormat
	Passphrase string
	// KeyID is the vault key ID after the change (new for a rotation).
	KeyID string
	// Unlockers is the complete unlocker list after the change.
	Unlockers []format.Unlocker
	Time      time.Time
}

// Append returns the vault.json that results from adding ch to c, signed
// by signer, who must be a member of the head state. The result is
// verified before it is returned.
func (c *Chain) Append(signer *Unlocked, ch Change) (*format.VaultFile, error) {
	if len(c.File.Log) >= format.MaxLogEntries {
		return nil, ErrLogFull
	}
	head := c.Head()
	me, ok := head.Member(signer.Name)
	if !ok || me.SignKey != signer.SignKey || me.Recipient != signer.Recipient {
		return nil, ErrNotMember
	}
	if ch.Time.IsZero() {
		ch.Time = time.Now()
	}
	rec := &format.Record{
		Seq: len(c.Records), Prev: head.Head, VaultID: c.File.ID, Time: ch.Time.UTC().Round(0),
		Op: ch.Op, Member: ch.Member, Passphrase: ch.Passphrase, Format: ch.Format, KeyID: ch.KeyID,
		UnlockersHash: format.UnlockersDigest(ch.Unlockers),
	}
	members := slices.Clone(head.Members)
	switch ch.Op {
	case format.OpAddMember:
		members = append(members, *ch.Member)
		format.SortMembers(members)
	case format.OpRemoveMember:
		members = slices.DeleteFunc(members, func(m format.Member) bool { return m.Name == ch.Member.Name })
	}
	rec.MembersHash = format.MembersDigest(members)
	ns, err := applyRecord(head, rec, signer.Name)
	if err != nil {
		return nil, err
	}
	next := *c.File
	next.Version = ns.Format
	next.KeyID = ch.KeyID
	next.Members = members
	next.Unlockers = slices.Clone(ch.Unlockers)
	entry, err := signRecord(signer, rec)
	if err != nil {
		return nil, err
	}
	next.Log = append(slices.Clone(c.File.Log), entry)
	if _, err := Verify(&next, nil, c.File.ID); err != nil {
		return nil, err
	}
	return &next, nil
}

func signRecord(signer *Unlocked, rec *format.Record) (format.LogEntry, error) {
	body, err := format.MarshalRecordBody(rec)
	if err != nil {
		return format.LogEntry{}, err
	}
	sig, err := signer.Sign(recordDomain, body)
	if err != nil {
		return format.LogEntry{}, err
	}
	return format.LogEntry{Body: body, By: signer.Name, Sig: sig}, nil
}

// Genesis completes a new vault file (from crypto.NewVaultFile, whose
// unlockers must include owner's member unlocker) with the owner as the
// only member and the genesis record, signed by the owner.
func Genesis(vf *format.VaultFile, owner *Unlocked, now time.Time) error {
	return GenesisFormat(vf, owner, now, format.VaultVersion)
}

// GenesisFormat is Genesis for a given vault format: 3 for every real vault.
// Format 2 exists for tests and for building a legacy vault to upgrade.
func GenesisFormat(vf *format.VaultFile, owner *Unlocked, now time.Time, formatVersion int) error {
	m := owner.Member(format.RoleOwner)
	vf.Version = formatVersion
	vf.Members = []format.Member{m}
	rec := &format.Record{
		Seq: 0, VaultID: vf.ID, Time: now.UTC().Round(0), Op: format.OpGenesis, Member: &m,
		KeyID: vf.KeyID, MembersHash: format.MembersDigest(vf.Members), UnlockersHash: format.UnlockersDigest(vf.Unlockers),
	}
	if formatVersion == format.VaultVersion {
		rec.Format = format.VaultVersion
	}
	entry, err := signRecord(owner, rec)
	if err != nil {
		return err
	}
	vf.Log = []format.LogEntry{entry}
	_, err = Verify(vf, nil, "")
	return err
}

// WhoAdded returns the signer of the latest record that added the member
// with these keys (genesis included). TOFU (design section 7) uses it:
// "added by me" needs no fingerprint check, anyone else does.
func (c *Chain) WhoAdded(recipient, signKey string) (by string, at time.Time, ok bool) {
	for i := len(c.Records) - 1; i >= 0; i-- {
		r := c.Records[i]
		if (r.Op == format.OpAddMember || r.Op == format.OpGenesis) && r.Member.Recipient == recipient && r.Member.SignKey == signKey {
			return c.States[i].By, r.Time, true
		}
	}
	return "", time.Time{}, false
}
