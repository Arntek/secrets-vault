package cli

import (
	"runtime"
	"time"

	"github.com/Arntek/secrets-vault/internal/agent"
	"github.com/Arntek/secrets-vault/internal/audit"
	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/members"
)

// cmdUnlock: unlock [VAULT] [--for DUR] [--expect CODE]
func cmdUnlock(a *app, p *parsed) error {
	if err := p.wantArgs(0, 1, a.prog+" unlock [VAULT] [--for DURATION]"); err != nil {
		return err
	}
	arg := ""
	if len(p.args) == 1 {
		arg = p.args[0]
	}
	v, err := a.defaultVault(arg)
	if err != nil {
		return err
	}
	var ttl time.Duration
	if p.has("for") {
		d, err := time.ParseDuration(p.str("for"))
		if err != nil {
			return usageErrf("--for needs a duration such as 30m or 2h")
		}
		if err := agent.ValidateTTL(d); err != nil {
			return usageErrf("%v", err)
		}
		ttl = d
	}
	until, err := a.unlockVault(v, ttl)
	if err != nil {
		return err
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": v.name, "unlocked": true, "until": until.UTC().Format(time.RFC3339)})
	}
	a.printf("Unlocked '%s' until %s\n", v.name, until.Local().Format("15:04"))
	return nil
}

// unlockVault unlocks v in the agent (asking for Touch ID or a passphrase as
// needed) and returns when it locks again. Shared by `unlock` and the UI.
func (a *app) unlockVault(v *vaultRef, ttl time.Duration) (time.Time, error) {
	if _, err := a.open(v); err != nil {
		return time.Time{}, err
	}
	// An explicit unlock always asks, so --for can reset the window; an
	// already-unlocked vault with no --for is left alone.
	key, err := a.openKey(v, nil, openOpts{forceAuth: false, ttl: ttl, requireAgent: true})
	if err != nil {
		return time.Time{}, err
	}
	defer key.Destroy()
	// Unlocking is when a vault's index gets verified, and what a locked
	// `list` shows afterwards is exactly what was verified here.
	if _, err := a.openIndex(v, key); err != nil {
		return time.Time{}, err
	}
	vf := v.chain.File
	if ttl != 0 {
		// Re-store with the requested window.
		cl := a.client(true)
		if cl != nil {
			if dup, derr := keyCopy(key); derr == nil {
				_ = cl.Unlock(vf.ID, dup, ttl)
			}
		}
	}
	until := a.now().Add(a.ttlFor(v))
	if ttl != 0 {
		until = a.now().Add(ttl)
	} else if cl := a.client(false); cl != nil {
		if list, err := cl.Status(); err == nil {
			for _, s := range list {
				if s.VaultID == vf.ID && s.Unlocked {
					until = s.ExpiresAt
				}
			}
		}
	}
	a.record(v.name, "", audit.ActionUnlock)
	return until, nil
}

// cmdLock: lock [VAULT | --all]
func cmdLock(a *app, p *parsed) error {
	if err := p.wantArgs(0, 1, a.prog+" lock [VAULT | --all]"); err != nil {
		return err
	}
	if len(p.args) == 1 && p.has("all") {
		return usageErrf("give a vault name or --all, not both")
	}
	if len(p.args) == 0 {
		if err := a.lockAll(); err != nil {
			return err
		}
		if a.asJSON {
			return a.printJSON(map[string]any{"locked": "all"})
		}
		if a.client(false) == nil && runtime.GOOS == "windows" {
			a.printf("Nothing to lock: on Windows no vault stays unlocked between commands.\n")
			return nil
		}
		a.printf("Locked every vault.\n")
		return nil
	}
	name, err := a.lockVault(p.args[0])
	if err != nil {
		return err
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"locked": name})
	}
	a.printf("Locked '%s'.\n", name)
	return nil
}

// lockAll makes the agent forget every key. Shared by `lock` and the UI.
func (a *app) lockAll() error {
	if cl := a.client(false); cl != nil {
		if err := cl.LockAll(); err != nil {
			return failf("could not lock: %v", err)
		}
	}
	a.record("", "", audit.ActionLock)
	return nil
}

// lockVault makes the agent forget one vault's key.
func (a *app) lockVault(name string) (string, error) {
	v, err := a.vault(name)
	if err != nil {
		return "", err
	}
	vf, err := format.ReadVaultFile(v.dir)
	if err != nil {
		return "", failf("cannot open vault '%s': %v", v.name, vaultErr(err))
	}
	if cl := a.client(false); cl != nil {
		if err := cl.Lock(vf.ID); err != nil {
			return "", failf("could not lock: %v", err)
		}
	}
	a.record(v.name, "", audit.ActionLock)
	return v.name, nil
}

// cmdStatus: status
func cmdStatus(a *app, p *parsed) error {
	if err := p.wantArgs(0, 0, a.prog+" status"); err != nil {
		return err
	}
	names, err := a.vaultNames()
	if err != nil {
		return err
	}
	states := a.lockStates()
	type req struct {
		Name        string `json:"name"`
		Fingerprint string `json:"fingerprint"`
	}
	type head struct {
		Seq       int    `json:"seq"`
		Time      string `json:"time"`
		By        string `json:"by"`
		Hash      string `json:"hash"`
		StateCode string `json:"state_code"`
		Trusted   bool   `json:"trusted"`
	}
	type row struct {
		Vault       string `json:"vault"`
		Unlocked    bool   `json:"unlocked"`
		SecondsLeft int    `json:"seconds_left"`
		Expires     string `json:"expires,omitempty"`
		Requests    []req  `json:"join_requests"`
		Head        *head  `json:"head,omitempty"`
		Error       string `json:"error,omitempty"`
		// Removed: this identity was a member and no longer is.
		Removed bool `json:"removed,omitempty"`
		// Expecting is a state code this machine was given that the folder
		// has not met; every command refuses the vault until it does.
		Expecting string `json:"expecting,omitempty"`
		left      time.Duration
	}
	rows := []row{}
	for _, n := range names {
		v, err := a.vault(n)
		if err != nil {
			return err
		}
		r := row{Vault: n, Requests: []req{}}
		vf, err := format.ReadVaultFile(v.dir)
		if err != nil {
			r.Error = "unavailable"
			rows = append(rows, r)
			continue
		}
		if st := states[vf.ID]; st.Unlocked && a.heldKeyCurrent(vf) {
			r.Unlocked = true
			r.left = time.Until(st.Expires)
			r.SecondsLeft = int(r.left.Seconds())
			r.Expires = st.Expires.UTC().Format(time.RFC3339)
		}
		if c, _, err := members.Load(v.dir, v.entry.ID); err == nil {
			h := c.Head()
			r.Head = &head{Seq: h.Seq, Time: h.Time.UTC().Format(time.RFC3339), By: h.By, Hash: h.Head, StateCode: members.StateCode(c, h.Seq)}
			if ts, err := a.trustStore(); err == nil {
				pin, _ := ts.Load(c.File.ID)
				cl := members.Classify(c, pin)
				r.Head.Trusted = cl.Outcome == members.Same || cl.Outcome == members.Extension
				if pin != nil && pin.Expect != nil && !pin.Expect.Met(c) {
					r.Expecting = c.File.Name + pin.Expect.String()
					r.Unlocked = false // blocked until the code is met
				}
			}
			if a.removedFrom(c) {
				r.Removed, r.Unlocked = true, false
			}
		} else if vf.Version >= format.LegacyVaultVersion {
			r.Error = "does not verify"
		}
		reqs, _, err := members.ListRequests(v.dir, vf.ID)
		if err == nil {
			for _, q := range reqs {
				r.Requests = append(r.Requests, req{q.Identity.Name, q.Identity.Fingerprint})
			}
		}
		rows = append(rows, r)
	}
	if a.asJSON {
		return a.printJSON(rows)
	}
	if len(rows) == 0 {
		a.printf("No vaults yet. Create one with: %s init NAME --path DIR\n", a.prog)
		return nil
	}
	t := newTable(a.out, "VAULT", "STATE", "TIME LEFT", "STATE CODE", "")
	for _, r := range rows {
		state, left, note, code := "locked", "", "", ""
		switch {
		case r.Error != "":
			state = r.Error
			if r.Error == "unavailable" {
				state = "unavailable"
			}
		case r.Removed:
			state = "removed"
		case r.Expecting != "":
			state = "blocked"
		case r.Unlocked:
			state, left = "unlocked", timeLeft(r.left)+" left"
		}
		if r.Head != nil {
			code = r.Head.StateCode
			if !r.Head.Trusted {
				code += " (not yet trusted here)"
			}
		}
		if len(r.Requests) > 0 {
			note = plural(len(r.Requests), "join request") + ":"
			for _, q := range r.Requests {
				note += " " + q.Name + " (" + q.Fingerprint + ")"
			}
		}
		switch {
		case r.Removed:
			note = "you are no longer a member; ask a member to add you again" + sep(note)
		case r.Expecting != "":
			note = "waiting for state " + r.Expecting + " (the folder doesn't match it): run 'trust " + r.Vault + " --expect CODE' with the right code" + sep(note)
		}
		t.row(r.Vault, state, left, code, note)
	}
	t.flush()
	return nil
}

func sep(note string) string {
	if note == "" {
		return ""
	}
	return "; " + note
}

// heldKeyCurrent reports whether the key the agent holds for this vault still
// opens it: after another member rotated the key, the held one is stale and
// the vault is effectively locked, whatever the agent's timer says.
func (a *app) heldKeyCurrent(vf *format.VaultFile) bool {
	cl := a.client(false)
	if cl == nil {
		return false
	}
	k, err := cl.Key(vf.ID)
	if err != nil {
		return false
	}
	defer k.Destroy()
	return crypto.CheckKey(vf, k) == nil
}
