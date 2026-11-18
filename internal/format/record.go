package format

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Membership log limits (docs/design/membership-auth.md).
const (
	// MaxLogEntries caps the membership log. At the cap, membership changes
	// are refused and the vault must be rebuilt.
	MaxLogEntries = 4096
	// MaxRecordSize bounds one record body.
	MaxRecordSize = 4096
	// SignatureSize is the length of an Ed25519 signature.
	SignatureSize = 64
	// SignKeyHexLen is the length of an Ed25519 public key in hex.
	SignKeyHexLen = 64
	// MaxMemberNameLen is the longest member name.
	MaxMemberNameLen = 64
)

// RecordOp names what one membership record does.
type RecordOp string

// Record operations.
const (
	OpGenesis        RecordOp = "genesis"
	OpAddMember      RecordOp = "add-member"
	OpRemoveMember   RecordOp = "remove-member"
	OpRotate         RecordOp = "rotate"
	OpSetUnlocker    RecordOp = "set-unlocker"
	OpRemoveUnlocker RecordOp = "remove-unlocker"
)

// Passphrase policies recorded by remove-member and rotate records.
const (
	PassDropped  = "dropped"
	PassReplaced = "replaced"
	PassKept     = "kept"
)

// Record is the body of one membership log entry: a delta from the
// previous state plus hashes of the state after it. Package members signs,
// replays and verifies records; this package only parses them.
type Record struct {
	Seq           int       `json:"seq"`
	Prev          string    `json:"prev"`
	VaultID       string    `json:"vault_id"`
	Time          time.Time `json:"time"`
	Op            RecordOp  `json:"op"`
	Member        *Member   `json:"member,omitempty"`
	Passphrase    string    `json:"passphrase,omitempty"`
	KeyID         string    `json:"key_id"`
	MembersHash   string    `json:"members_hash"`
	UnlockersHash string    `json:"unlockers_hash"`
}

// ParseRecordBody strictly parses and validates a record body.
func ParseRecordBody(data []byte) (*Record, error) {
	if len(data) > MaxRecordSize {
		return nil, fmt.Errorf("record: %w", ErrTooLarge)
	}
	var r Record
	if err := decodeStrictMax(data, MaxRecordSize, &r); err != nil {
		return nil, fmt.Errorf("record: %w", err)
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("record: %w", err)
	}
	return &r, nil
}

// MarshalRecordBody validates r and encodes it compactly. The result is
// the exact byte string that is signed and stored.
func MarshalRecordBody(r *Record) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	out := *r
	out.Time = r.Time.UTC()
	b, err := json.Marshal(&out)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxRecordSize {
		return nil, ErrTooLarge
	}
	return b, nil
}

// Validate checks one record's fields (not its signature or hashes).
func (r *Record) Validate() error {
	bad := func(why string) error { return fmt.Errorf("%w: record %s", ErrMalformed, why) }
	if r.Seq < 0 || r.Seq >= MaxLogEntries {
		return bad("has a bad sequence number")
	}
	if (r.Seq == 0) != (r.Prev == "") {
		return bad("has a bad previous-record hash")
	}
	if r.Prev != "" && !isHex(r.Prev, 64) {
		return bad("has a bad previous-record hash")
	}
	if err := ValidateVaultID(r.VaultID); err != nil {
		return err
	}
	if r.Time.IsZero() {
		return bad("has no time")
	}
	if (r.Seq == 0) != (r.Op == OpGenesis) {
		return bad("genesis must be record 0 and only record 0")
	}
	switch r.Op {
	case OpGenesis, OpAddMember, OpRemoveMember:
		if r.Member == nil {
			return bad("needs a member")
		}
		if err := r.Member.Validate(); err != nil {
			return err
		}
		if r.Op == OpGenesis && r.Member.Role != RoleOwner {
			return bad("genesis member must be the owner")
		}
	case OpRotate, OpSetUnlocker, OpRemoveUnlocker:
		if r.Member != nil {
			return bad("must not name a member")
		}
	default:
		return bad("has an unknown operation")
	}
	switch r.Op {
	case OpRemoveMember, OpRotate:
		if r.Passphrase != PassDropped && r.Passphrase != PassReplaced && r.Passphrase != PassKept {
			return bad("needs a passphrase policy")
		}
	default:
		if r.Passphrase != "" {
			return bad("must not have a passphrase policy")
		}
	}
	if err := ValidateKeyID(r.KeyID); err != nil {
		return err
	}
	if !isHex(r.MembersHash, 64) || !isHex(r.UnlockersHash, 64) {
		return bad("has a bad state hash")
	}
	return nil
}

// Validate checks one member entry.
func (m *Member) Validate() error {
	if err := ValidateMemberName(m.Name); err != nil {
		return err
	}
	if m.Recipient == "" {
		return fmt.Errorf("%w: member has no public key", ErrMalformed)
	}
	if err := validateRecipient(m.Recipient); err != nil {
		return err
	}
	if !isHex(m.SignKey, SignKeyHexLen) {
		return fmt.Errorf("%w: member signing key must be %d lower-case hex characters", ErrMalformed, SignKeyHexLen)
	}
	if m.Role != RoleOwner && m.Role != RoleMember {
		return fmt.Errorf("%w: unknown member role", ErrMalformed)
	}
	return nil
}

// ValidateMembers checks a member set: 1-MaxUnlockers valid entries sorted
// by name, with unique names, recipients and signing keys.
func ValidateMembers(ms []Member) error {
	if len(ms) == 0 || len(ms) > MaxUnlockers {
		return fmt.Errorf("%w: a vault needs 1-%d members", ErrMalformed, MaxUnlockers)
	}
	recips := map[string]bool{}
	signs := map[string]bool{}
	for i := range ms {
		m := &ms[i]
		if err := m.Validate(); err != nil {
			return fmt.Errorf("member %d: %w", i+1, err)
		}
		if i > 0 && ms[i-1].Name >= m.Name {
			return fmt.Errorf("member %d: %w: members must be sorted by name, without duplicates", i+1, ErrMalformed)
		}
		if recips[m.Recipient] || signs[m.SignKey] {
			return fmt.Errorf("member %d: %w: duplicate member key", i+1, ErrMalformed)
		}
		recips[m.Recipient] = true
		signs[m.SignKey] = true
	}
	return nil
}

// SortMembers sorts ms by name in place.
func SortMembers(ms []Member) {
	slices.SortFunc(ms, func(a, b Member) int { return strings.Compare(a.Name, b.Name) })
}

// ValidateMemberName checks a member name: 1-64 characters of a-z, 0-9,
// "-" and "_", starting with a letter or digit.
func ValidateMemberName(name string) error {
	if name == "" || len(name) > MaxMemberNameLen {
		return fmt.Errorf("%w: member name must be 1-%d characters", ErrMalformed, MaxMemberNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '-' || c == '_') && i > 0:
		default:
			return fmt.Errorf("%w: member name may use only a-z, 0-9, - and _", ErrMalformed)
		}
	}
	return nil
}

// RecordHash is the hex SHA-256 of a record body: what the next record's
// Prev and a trust pin's head hold.
func RecordHash(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

// MembersDigest hashes a member set (in the given order; vault files keep
// it sorted by name) with an unambiguous length-prefixed encoding.
func MembersDigest(ms []Member) string {
	h := sha256.New()
	h.Write([]byte("secrets-vault/v2 members\x00"))
	writeLP(h, fmt.Sprint(len(ms)))
	for _, m := range ms {
		writeLP(h, m.Name)
		writeLP(h, m.Recipient)
		writeLP(h, m.SignKey)
		writeLP(h, m.Role)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// UnlockersDigest hashes an unlocker list, in file order: type, label,
// recipient, SHA-256 of the wrapped key and created time of each.
func UnlockersDigest(us []Unlocker) string {
	h := sha256.New()
	h.Write([]byte("secrets-vault/v2 unlockers\x00"))
	writeLP(h, fmt.Sprint(len(us)))
	for _, u := range us {
		wk := sha256.Sum256(u.WrappedKey)
		writeLP(h, string(u.Type))
		writeLP(h, u.Label)
		writeLP(h, u.Recipient)
		writeLP(h, string(wk[:]))
		writeLP(h, u.Created.UTC().Format(time.RFC3339Nano))
	}
	return hex.EncodeToString(h.Sum(nil))
}

type byteWriter interface{ Write([]byte) (int, error) }

func writeLP(w byteWriter, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s))) // #nosec G115 -- every field is bounded far below 4 GiB
	_, _ = w.Write(n[:])
	_, _ = w.Write([]byte(s))
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
