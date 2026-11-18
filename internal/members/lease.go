package members

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Arntek/secrets-vault/internal/format"
)

// The rotation lease (design section 10, G6): before rotating, a member
// writes rotation.lease at the vault root, signed, naming the head it
// starts from. Another member who finds a fresh, valid lease by someone
// else for the same head waits. It is advisory: it narrows the race between
// two rotations but can't close it (lost races are repaired instead).

// LeaseTTL is how long a lease holds off other rotations.
const LeaseTTL = 15 * time.Minute

type leaseFile struct {
	Version int    `json:"version"`
	Body    []byte `json:"body"`
	By      string `json:"by"`
	Sig     []byte `json:"sig"`
}

type leaseBody struct {
	VaultID string    `json:"vault_id"`
	BaseSeq int       `json:"base_seq"`
	Time    time.Time `json:"time"`
}

// LeaseHeldError means another member is rotating the vault key now.
type LeaseHeldError struct {
	By   string
	Time time.Time
}

func (e *LeaseHeldError) Error() string {
	return fmt.Sprintf("%s started changing the vault key at %s; try again in a few minutes", e.By, e.Time.Local().Format("15:04"))
}

// WriteLease writes a lease for c's head, signed by signer.
func WriteLease(vaultDir string, c *Chain, signer *Unlocked, now time.Time) error {
	body, err := json.Marshal(leaseBody{VaultID: c.File.ID, BaseSeq: c.Head().Seq, Time: now.UTC().Round(0)})
	if err != nil {
		return err
	}
	sig, err := signer.Sign(leaseDomain, body)
	if err != nil {
		return err
	}
	data, err := json.Marshal(leaseFile{Version: 1, Body: body, By: signer.Name, Sig: sig})
	if err != nil {
		return err
	}
	return format.WriteLease(vaultDir, data)
}

// CheckLease returns a *LeaseHeldError if a valid lease by someone other
// than me exists for c's head and is less than LeaseTTL old. Anything else
// (no lease, a stale, damaged or forged one, our own) is no obstacle.
func CheckLease(vaultDir string, c *Chain, me string, now time.Time) error {
	data, err := format.ReadLease(vaultDir)
	if err != nil {
		return nil
	}
	by, at, ok := parseLease(data, c)
	if !ok || by == me {
		return nil
	}
	if now.Sub(at) > LeaseTTL || at.Sub(now) > 2*time.Minute {
		return nil
	}
	return &LeaseHeldError{By: by, Time: at}
}

// parseLease parses and verifies a lease against c's head.
func parseLease(data []byte, c *Chain) (string, time.Time, bool) {
	var lf leaseFile
	if decodeStrict(data, 8<<10, &lf) != nil || lf.Version != 1 {
		return "", time.Time{}, false
	}
	var b leaseBody
	if decodeStrict(lf.Body, 4<<10, &b) != nil {
		return "", time.Time{}, false
	}
	m, ok := c.Head().Member(lf.By)
	if !ok || b.VaultID != c.File.ID || b.BaseSeq != c.Head().Seq || !verifySig(m.SignKey, leaseDomain, lf.Body, lf.Sig) {
		return "", time.Time{}, false
	}
	return lf.By, b.Time, true
}

// ParseLeaseFile strictly parses a lease file's structure. Exposed for
// fuzzing.
func ParseLeaseFile(data []byte) error {
	var lf leaseFile
	if err := decodeStrict(data, 8<<10, &lf); err != nil {
		return err
	}
	var b leaseBody
	return decodeStrict(lf.Body, 4<<10, &b)
}
