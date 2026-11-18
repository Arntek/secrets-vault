package cli

import (
	"time"

	"github.com/Arntek/secrets-vault/internal/agent"
	"github.com/Arntek/secrets-vault/internal/audit"
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
	if _, err := a.open(v); err != nil {
		return err
	}
	// An explicit unlock always asks, so --for can reset the window; an
	// already-unlocked vault with no --for is left alone.
	key, err := a.openKey(v, nil, openOpts{forceAuth: false, ttl: ttl, requireAgent: true})
	if err != nil {
		return err
	}
	defer key.Destroy()
	// Unlocking is when a vault's index gets verified, and what a locked
	// `list` shows afterwards is exactly what was verified here.
	if _, err := a.openIndex(v, key); err != nil {
		return err
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
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": v.name, "unlocked": true, "until": until.UTC().Format(time.RFC3339)})
	}
	a.printf("Unlocked '%s' until %s\n", v.name, until.Local().Format("15:04"))
	return nil
}

// cmdLock: lock [VAULT | --all]
func cmdLock(a *app, p *parsed) error {
	if err := p.wantArgs(0, 1, a.prog+" lock [VAULT | --all]"); err != nil {
		return err
	}
	if len(p.args) == 1 && p.has("all") {
		return usageErrf("give a vault name or --all, not both")
	}
	cl := a.client(false)
	if len(p.args) == 0 {
		if cl != nil {
			if err := cl.LockAll(); err != nil {
				return failf("could not lock: %v", err)
			}
		}
		a.record("", "", audit.ActionLock)
		if a.asJSON {
			return a.printJSON(map[string]any{"locked": "all"})
		}
		a.printf("Locked every vault.\n")
		return nil
	}
	v, err := a.vault(p.args[0])
	if err != nil {
		return err
	}
	vf, err := format.ReadVaultFile(v.dir)
	if err != nil {
		return failf("cannot open vault '%s': %v", v.name, vaultErr(err))
	}
	if cl != nil {
		if err := cl.Lock(vf.ID); err != nil {
			return failf("could not lock: %v", err)
		}
	}
	a.record(v.name, "", audit.ActionLock)
	if a.asJSON {
		return a.printJSON(map[string]any{"locked": v.name})
	}
	a.printf("Locked '%s'.\n", v.name)
	return nil
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
		left        time.Duration
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
		if st := states[vf.ID]; st.Unlocked {
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
			}
		} else if vf.Version == format.VaultVersion {
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
		t.row(r.Vault, state, left, code, note)
	}
	t.flush()
	return nil
}
