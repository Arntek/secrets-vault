package members

import (
	"errors"
	"fmt"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// Rebasing a lost race (design section 8b and 10, Security N1). Classify
// has already checked that the winning branch can't weaken this machine's
// ops; Rebase re-applies them, re-signed, on top of the winner.

// AskPassphrase supplies a passphrase wrapper when re-applying an op needs
// one: policy format.PassKept asks for the current vault passphrase,
// format.PassReplaced for the new one. Returning an error stops the rebase.
type AskPassphrase func(policy string) (crypto.KeyWrapper, error)

// RebaseResult reports what Rebase did.
type RebaseResult struct {
	Chain *Chain
	// Key is the vault key after the rebase (the winner's key, or a new one
	// if an op rotated). The caller destroys the key it passed in only if
	// Key differs.
	Key *crypto.VaultKey
	// Written are the records this machine wrote, for the pin's Own list.
	Written []format.LogEntry
	// Notes describe ops that no longer applied and were dropped.
	Notes []string
}

// Rebase re-applies lost (this machine's records the folder lost) on top
// of the verified winning chain c, whose key is key. pending are this
// machine's keys from lost rotations: files sealed under them are re-sealed
// to the key of the re-applied rotation, never to the winner's key (N1). If
// no lost op rotates any more but such files exist, a plain rotation is
// made for them.
func Rebase(vaultDir string, c *Chain, key *crypto.VaultKey, signer *Unlocked, lost []*format.Record, pending []*crypto.VaultKey, ask AskPassphrase, store *PendingStore, now time.Time) (*RebaseResult, error) {
	res := &RebaseResult{Chain: c, Key: key}
	extra := pending
	advance := func(nc *Chain, nk *crypto.VaultKey) {
		res.Chain = nc
		if nk != nil {
			res.Key = nk
			extra = nil // re-sealed by this rotation
		}
		res.Written = append(res.Written, nc.LastEntry())
	}
	askFor := func(policy string) (RotateOptions, error) {
		opt := RotateOptions{Passphrase: policy, ExtraKeys: extra, Pending: store, Now: now}
		if policy == format.PassDropped {
			return opt, nil
		}
		if ask == nil {
			return opt, errors.New("members: re-applying this change needs the vault passphrase; run the command again in a terminal")
		}
		w, err := ask(policy)
		if err != nil {
			return opt, err
		}
		if policy == format.PassKept {
			opt.Keep = w
		} else {
			opt.New = w
		}
		return opt, nil
	}
	for _, r := range lost {
		c := res.Chain
		switch r.Op {
		case format.OpAddMember:
			clash := false
			for _, m := range c.Head().Members {
				if m.Name == r.Member.Name || m.Recipient == r.Member.Recipient || m.SignKey == r.Member.SignKey {
					clash = true
				}
			}
			if clash {
				res.Notes = append(res.Notes, fmt.Sprintf("%s is already in the vault (or the name is taken); not added again", r.Member.Name))
				continue
			}
			mw, err := crypto.NewMemberWrapper(r.Member.Name, r.Member.Recipient)
			if err != nil {
				return res, err
			}
			u, err := mw.Wrap(res.Key)
			if err != nil {
				return res, err
			}
			m := *r.Member
			next, err := c.Append(signer, Change{Op: format.OpAddMember, Member: &m, KeyID: c.File.KeyID, Unlockers: append(append([]format.Unlocker{}, c.File.Unlockers...), u), Time: now})
			if err != nil {
				return res, err
			}
			nc, err := write(vaultDir, c, next)
			if err != nil {
				return res, err
			}
			advance(nc, nil)
		case format.OpRemoveMember:
			if _, ok := c.Head().Member(r.Member.Name); !ok {
				res.Notes = append(res.Notes, fmt.Sprintf("%s was already removed", r.Member.Name))
				continue
			}
			opt, err := askFor(r.Passphrase)
			if err != nil {
				return res, err
			}
			rr, err := Remove(vaultDir, c, res.Key, signer, r.Member.Name, opt)
			if err != nil {
				return res, err
			}
			advance(rr.Chain, rr.NewKey)
		case format.OpRotate, format.OpSetUnlocker:
			policy := r.Passphrase
			if r.Op == format.OpSetUnlocker {
				policy = format.PassReplaced
			}
			opt, err := askFor(policy)
			if err != nil {
				return res, err
			}
			var rr *RotateResult
			if r.Op == format.OpRotate {
				rr, err = rotate(vaultDir, c, res.Key, signer, format.OpRotate, nil, opt)
			} else {
				rr, err = Passwd(vaultDir, c, res.Key, signer, opt.New, false, opt)
			}
			if err != nil {
				return res, err
			}
			advance(rr.Chain, rr.NewKey)
		default:
			res.Notes = append(res.Notes, fmt.Sprintf("a %s change could not be re-applied", r.Op))
		}
	}
	if len(extra) > 0 {
		// Files may still be sealed under a lost rotation's key. Re-seal
		// them with a fresh rotation, never to the winner's key (N1).
		if needsReseal(vaultDir, extra) {
			policy := format.PassDropped
			if res.Chain.HasPassphrase() {
				policy = format.PassKept
			}
			opt, err := askFor(policy)
			if err != nil {
				return res, err
			}
			rr, err := rotate(vaultDir, res.Chain, res.Key, signer, format.OpRotate, nil, opt)
			if err != nil {
				return res, err
			}
			advance(rr.Chain, rr.NewKey)
		}
	}
	// Staging folders of lost rotations whose files never moved are this
	// machine's own leftovers.
	for _, k := range pending {
		if k.ID() != res.Chain.Head().KeyID {
			_ = format.AbandonStaging(vaultDir, k.ID())
		}
	}
	return res, nil
}

func keyIDs(keys []*crypto.VaultKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.ID())
	}
	return out
}

// needsReseal reports whether any live or trashed secret is sealed under
// one of keys.
func needsReseal(vaultDir string, keys []*crypto.VaultKey) bool {
	ids := keyIDs(keys)
	match := func(ct []byte) bool {
		id, err := crypto.KeyIDOf(ct)
		if err != nil {
			return false
		}
		for _, x := range ids {
			if x == id {
				return true
			}
		}
		return false
	}
	secrets, _ := format.ListSecrets(vaultDir)
	for _, s := range secrets {
		if ct, err := format.ReadSecretFile(vaultDir, s.Name); err == nil && match(ct) {
			return true
		}
	}
	trash, _ := format.ListTrash(vaultDir)
	for _, t := range trash {
		if ct, err := format.ReadTrashedFile(vaultDir, t); err == nil && match(ct) {
			return true
		}
	}
	return false
}
