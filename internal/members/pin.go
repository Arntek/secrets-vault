package members

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Arntek/secrets-vault/internal/format"
)

// A trust pin records, on this machine and outside any synced folder, the
// last head of a vault's membership log this machine verified (design
// section 5). A vault.json that doesn't extend the pin is refused.

const (
	pinVersion = 1
	maxPinSize = 256 << 10
	// MaxOwn bounds the records a pin remembers as written by this machine.
	MaxOwn = 16
)

// Pin is one vault's trust pin.
type Pin struct {
	Version int    `json:"version"`
	VaultID string `json:"vault_id"`
	Seq     int    `json:"seq"`
	Head    string `json:"head"`
	KeyID   string `json:"key_id"`
	// Path is the vault folder this machine registered, so a registry that
	// lost its vault ID can be noticed (ue1.8). Informational otherwise.
	Path string `json:"path,omitempty"`
	// Own holds the records this machine wrote that nobody has extended
	// yet, oldest first, ending at Seq. They let a lost race be told apart
	// from a rollback and re-applied (design section 8b).
	Own []format.LogEntry `json:"own,omitempty"`
}

// ParsePin strictly parses a pin file.
func ParsePin(data []byte) (*Pin, error) {
	var p Pin
	if err := decodeStrict(data, maxPinSize, &p); err != nil {
		return nil, err
	}
	if p.Version != pinVersion || format.ValidateVaultID(p.VaultID) != nil || p.Seq < 0 || p.Seq >= format.MaxLogEntries ||
		len(p.Head) != 64 || format.ValidateKeyID(p.KeyID) != nil || len(p.Own) > MaxOwn {
		return nil, fmt.Errorf("%w: bad trust pin", ErrMalformed)
	}
	if _, err := hex.DecodeString(p.Head); err != nil || strings.ToLower(p.Head) != p.Head {
		return nil, fmt.Errorf("%w: bad trust pin", ErrMalformed)
	}
	if len(p.Path) > 4096 || strings.ContainsFunc(p.Path, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return nil, fmt.Errorf("%w: bad trust pin", ErrMalformed)
	}
	for i, e := range p.Own {
		if e.Validate() != nil {
			return nil, fmt.Errorf("%w: bad trust pin", ErrMalformed)
		}
		r, err := format.ParseRecordBody(e.Body)
		if err != nil || r.VaultID != p.VaultID || r.Seq != p.Seq-len(p.Own)+1+i {
			return nil, fmt.Errorf("%w: bad trust pin", ErrMalformed)
		}
	}
	if n := len(p.Own); n > 0 && format.RecordHash(p.Own[n-1].Body) != p.Head {
		return nil, fmt.Errorf("%w: bad trust pin", ErrMalformed)
	}
	return &p, nil
}

// PinFor returns the pin for the head of c. own is the list of records
// this machine wrote that are still unextended (see Pin.Own).
func PinFor(c *Chain, own []format.LogEntry) *Pin {
	h := c.Head()
	if len(own) > MaxOwn {
		own = own[len(own)-MaxOwn:]
	}
	return &Pin{Version: pinVersion, VaultID: c.File.ID, Seq: h.Seq, Head: h.Head, KeyID: h.KeyID, Own: own}
}

// TrustStore keeps pins in a per-user directory (~/.config/vault/trust).
type TrustStore struct{ dir string }

// NewTrustStore returns the store in dir.
func NewTrustStore(dir string) *TrustStore { return &TrustStore{dir: dir} }

func (t *TrustStore) path(vaultID string) (string, error) {
	if err := format.ValidateVaultID(vaultID); err != nil {
		return "", err
	}
	return filepath.Join(t.dir, vaultID+".json"), nil
}

// Load returns the pin for vaultID, or nil if there is none.
func (t *TrustStore) Load(vaultID string) (*Pin, error) {
	p, err := t.path(vaultID)
	if err != nil {
		return nil, err
	}
	data, err := readSmallFile(p, maxPinSize)
	if err != nil {
		if isNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	pin, err := ParsePin(data)
	if err != nil {
		return nil, err
	}
	if pin.VaultID != vaultID {
		return nil, fmt.Errorf("%w: trust pin for another vault", ErrMalformed)
	}
	return pin, nil
}

// Save writes pin (0600, directory 0700).
func (t *TrustStore) Save(pin *Pin) error {
	p, err := t.path(pin.VaultID)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(pin, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(t.dir, format.DirMode); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(t.dir, format.DirMode); err != nil { // #nosec G302 -- a directory needs the execute bit; 0700 is owner-only
			return err
		}
	}
	return format.WriteFileAtomic(p, append(data, '\n'), format.FileMode)
}

// FindByPath returns a pin recorded for the vault folder path, or nil.
func (t *TrustStore) FindByPath(path string) (*Pin, error) {
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		if isNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || format.ValidateVaultID(id) != nil {
			continue
		}
		p, err := t.Load(id)
		if err != nil {
			continue
		}
		if p != nil && p.Path != "" && filepath.Clean(p.Path) == filepath.Clean(path) {
			return p, nil
		}
	}
	return nil, nil
}

// Delete removes the pin for vaultID.
func (t *TrustStore) Delete(vaultID string) error {
	p, err := t.path(vaultID)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !isNotExist(err) {
		return err
	}
	return nil
}

// Outcome is how a verified vault.json relates to this machine's pin.
type Outcome int

// Outcomes of Classify.
const (
	// FirstUse: no pin yet (trust on first use, design section 7).
	FirstUse Outcome = iota
	// Same: the folder holds exactly the pinned head.
	Same
	// Extension: the folder extends the pinned head; advance silently.
	Extension
	// LostRace: this machine's own latest records were overtaken by a
	// concurrent, harmless change; they are to be re-applied on top.
	LostRace
	// Rollback: anything else. Hard refusal.
	Rollback
)

// Classification is the result of Classify.
type Classification struct {
	Outcome Outcome
	// For LostRace: the seq both branches share, and this machine's
	// records after it, which the folder lost.
	Diverge int
	Lost    []*format.Record
	// For Rollback: why (for the error message; never quotes input).
	Reason string
}

// ErrRollback is the hard refusal of design section 8c.
var ErrRollback = errors.New("vault.json is older than, or different from, what this machine has already verified. Nothing was read or written. Someone may have restored an old copy of the folder; check with the other members")

// Classify compares a verified chain with this machine's pin (design
// section 8, including Security's N1 rule for lost races).
func Classify(c *Chain, pin *Pin) Classification {
	if pin == nil {
		return Classification{Outcome: FirstUse}
	}
	n := len(c.File.Log)
	if pin.Seq < n && format.RecordHash(c.File.Log[pin.Seq].Body) == pin.Head {
		if pin.Seq == n-1 {
			return Classification{Outcome: Same}
		}
		return Classification{Outcome: Extension}
	}
	if len(pin.Own) == 0 {
		return Classification{Outcome: Rollback, Reason: "the pinned state is missing"}
	}
	var own []*format.Record
	for _, e := range pin.Own {
		r, err := format.ParseRecordBody(e.Body)
		if err != nil {
			return Classification{Outcome: Rollback, Reason: "bad pin"}
		}
		own = append(own, r)
	}
	d := own[0].Seq - 1
	if d < 0 || d >= n || format.RecordHash(c.File.Log[d].Body) != own[0].Prev {
		return Classification{Outcome: Rollback, Reason: "the history before this machine's last change is different"}
	}
	// N1: the winning branch must not be able to weaken our ops. Every
	// winning record must be signed by someone our ops don't remove, add
	// no member, and add or replace no passphrase.
	removed := map[string]bool{}
	for _, r := range own {
		if r.Op == format.OpRemoveMember {
			removed[r.Member.Name] = true
		}
	}
	for i := d + 1; i < n; i++ {
		r := c.Records[i]
		switch {
		case removed[c.States[i].By]:
			return Classification{Outcome: Rollback, Reason: "a concurrent change was signed by someone this machine removed"}
		case r.Op == format.OpAddMember:
			return Classification{Outcome: Rollback, Reason: "a concurrent change added a member"}
		case r.Op == format.OpSetUnlocker, r.Passphrase == format.PassReplaced:
			return Classification{Outcome: Rollback, Reason: "a concurrent change set a passphrase"}
		}
	}
	return Classification{Outcome: LostRace, Diverge: d, Lost: own}
}

// StateCode is the short out-of-band code for the state at seq (design
// section 8): "NAME@SEQ" plus six words from its hash (66 bits).
func StateCode(c *Chain, seq int) string {
	return c.File.Name + "@" + strconv.Itoa(seq) + " " + hashWords(format.RecordHash(c.File.Log[seq].Body))
}

func hashWords(hexHash string) string {
	b, _ := hex.DecodeString(hexHash)
	var acc uint64
	var bits uint
	var out []string
	for _, x := range b {
		acc = acc<<8 | uint64(x)
		bits += 8
		for bits >= 11 && len(out) < 6 {
			bits -= 11
			out = append(out, strings.ToUpper(words[(acc>>bits)&0x7ff]))
		}
		if len(out) == 6 {
			break
		}
	}
	return strings.Join(out, "-")
}

// ErrBadCode means a state code can't be parsed.
var ErrBadCode = errors.New("members: a state code looks like team@5 CANDLE-ORBIT-SWIFT-MAPLE-RIVER-OTTER, or the 64-character head hash")

// MatchStateCode checks code (a StateCode, or "SEQ HEXHASH"/"HEXHASH@SEQ"
// forms are not needed: the full form is "NAME@SEQ <64 hex>") against c. It
// returns nil if the state named by the code is in c's history, so the
// folder is that state or extends it, and ErrRollback if the folder is
// behind it or doesn't contain it.
func MatchStateCode(c *Chain, code string) error {
	code = strings.TrimSpace(code)
	at := strings.IndexByte(code, '@')
	sp := strings.IndexAny(code, " \t")
	if at < 0 || sp < at {
		return ErrBadCode
	}
	seq, err := strconv.Atoi(code[at+1 : sp])
	if err != nil || seq < 0 || seq >= format.MaxLogEntries {
		return ErrBadCode
	}
	rest := strings.TrimSpace(code[sp+1:])
	if seq >= len(c.File.Log) {
		return ErrRollback
	}
	h := format.RecordHash(c.File.Log[seq].Body)
	if len(rest) == 64 {
		if strings.ToLower(rest) != h {
			return ErrRollback
		}
		return nil
	}
	if NormalizeFingerprint(rest) != hashWords(h) {
		return ErrRollback
	}
	return nil
}
