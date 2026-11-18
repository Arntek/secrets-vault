package cli

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/Arntek/secrets-vault/internal/audit"
	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/members"
)

func memberErr(err error) error {
	switch {
	case errors.Is(err, members.ErrFingerprintMismatch):
		return failf("the fingerprint does not match the request. Do not approve")
	case errors.Is(err, members.ErrNoRequest):
		return failf("no such join request. See: requests")
	case errors.Is(err, members.ErrNotMember):
		return failf("that person is not a member of this vault")
	case errors.Is(err, members.ErrAlreadyMember):
		return failf("that person is already a member")
	}
	return failf("%v", err)
}

// cmdMember: member approve|rm|list|requests VAULT [NAME]
func cmdMember(a *app, p *parsed) error {
	usage := a.prog + " member approve|rm|list|requests VAULT [NAME]"
	if len(p.args) < 2 {
		return usageErrf("usage: %s", usage)
	}
	sub := p.args[0]
	v, err := a.vault(p.args[1])
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		if err := p.wantArgs(2, 2, usage); err != nil {
			return err
		}
		ov, err := members.Inspect(v.dir)
		if err != nil {
			return failf("cannot read the members of '%s': %v", v.name, vaultErr(err))
		}
		type row struct {
			Name        string `json:"name"`
			Fingerprint string `json:"fingerprint"`
			Role        string `json:"role"`
			Added       string `json:"added"`
			AddedBy     string `json:"added_by,omitempty"`
		}
		rows := []row{}
		for _, m := range ov.Members {
			rows = append(rows, row{m.Identity.Name, m.Identity.Fingerprint, string(m.Role), m.Added.UTC().Format("2006-01-02"), m.AddedBy})
		}
		if a.asJSON {
			warns := []string{}
			for _, w := range ov.Warnings {
				warns = append(warns, w.Message)
			}
			return a.printJSON(map[string]any{"members": rows, "has_passphrase": ov.HasPassphrase, "warnings": warns})
		}
		if len(rows) == 0 {
			a.printf("No members yet; '%s' opens with its passphrase.\n", v.name)
		} else {
			t := newTable(a.out, "NAME", "FINGERPRINT", "ROLE", "ADDED")
			for _, r := range rows {
				added := r.Added
				if r.AddedBy != "" {
					added += " by " + r.AddedBy
				}
				t.row(r.Name, r.Fingerprint, r.Role, added)
			}
			t.flush()
		}
		for _, w := range ov.Warnings {
			a.warnf("warning: %s", w.Message)
		}
		return nil

	case "requests":
		if err := p.wantArgs(2, 2, usage); err != nil {
			return err
		}
		reqs, bad, err := members.ListRequests(v.dir)
		if err != nil {
			return failf("cannot read the join requests of '%s': %v", v.name, vaultErr(err))
		}
		type row struct {
			Name        string `json:"name"`
			Fingerprint string `json:"fingerprint"`
			Created     string `json:"created"`
		}
		rows := []row{}
		for _, r := range reqs {
			rows = append(rows, row{r.Identity.Name, r.Identity.Fingerprint, r.Created.UTC().Format("2006-01-02 15:04")})
		}
		if a.asJSON {
			return a.printJSON(map[string]any{"requests": rows, "unreadable": len(bad)})
		}
		if len(rows) == 0 {
			a.printf("No join requests for '%s'.\n", v.name)
		} else {
			t := newTable(a.out, "NAME", "FINGERPRINT", "FILED")
			for _, r := range rows {
				t.row(r.Name, r.Fingerprint, r.Created)
			}
			t.flush()
		}
		if len(bad) > 0 {
			a.warnf("%s could not be read and was ignored", plural(len(bad), "request file"))
		}
		return nil

	case "approve":
		if err := p.wantArgs(3, 3, usage); err != nil {
			return err
		}
		name := p.args[2]
		if err := members.ValidateMemberName(name); err != nil {
			return usageErrf("%v", err)
		}
		req, err := members.ReadRequest(v.dir, name)
		if err != nil {
			return memberErr(err)
		}
		fp := req.Identity.Fingerprint
		if p.has("fingerprint") {
			fp = members.NormalizeFingerprint(p.str("fingerprint"))
		} else {
			if !a.term.StdinTTY() {
				return failf("approving needs you to check the fingerprint: run it in a terminal, or pass --fingerprint FP after checking it with the person")
			}
			a.printf("Request from %s. Fingerprint %s.\n", name, req.Identity.Fingerprint)
			ok, _ := a.confirm("Confirm this matches what " + name + " sees?")
			if !ok {
				return failf("cancelled")
			}
		}
		vf, err := v.open()
		if err != nil {
			return err
		}
		key, err := a.openKey(v, vf, openOpts{purpose: purposeWrite})
		if err != nil {
			return err
		}
		defer key.Destroy()
		m, err := members.ApproveRequest(v.dir, key, name, fp, a.myName())
		if err != nil {
			return memberErr(err)
		}
		if a.asJSON {
			return a.printJSON(map[string]any{"vault": v.name, "approved": name, "fingerprint": m.Identity.Fingerprint})
		}
		a.printf("%s added to '%s'.\n", name, v.name)
		return nil

	case "rm":
		if err := p.wantArgs(3, 3, usage); err != nil {
			return err
		}
		return a.memberRemove(v, p.args[2], p.has("yes"))
	}
	return usageErrf("usage: %s", usage)
}

func (a *app) memberRemove(v *vaultRef, name string, yes bool) error {
	if err := members.ValidateMemberName(name); err != nil {
		return usageErrf("%v", err)
	}
	vf, err := v.open()
	if err != nil {
		return err
	}
	found := false
	for _, u := range vf.UnlockersOf(format.UnlockerMember) {
		if u.Label == name {
			found = true
		}
	}
	if !found {
		return failf("that person is not a member of '%s'", v.name)
	}
	if !yes {
		if !a.term.StdinTTY() {
			return failf("removing a member needs confirmation: run it in a terminal, or pass --yes")
		}
		ok, _ := a.confirm("Remove " + name + " from '" + v.name + "'? This replaces the vault key and re-encrypts every secret.")
		if !ok {
			return failf("cancelled")
		}
	}
	key, err := a.openKey(v, vf, openOpts{purpose: purposeWrite})
	if err != nil {
		return err
	}
	defer key.Destroy()
	var rewrap []crypto.KeyWrapper
	if len(vf.UnlockersOf(format.UnlockerPassphrase)) > 0 {
		pass, err := a.askHidden("Vault passphrase for '" + v.name + "' (kept as the recovery route): ")
		if err != nil {
			return err
		}
		pw, err := a.passphraseWrapper(pass)
		clear(pass)
		if err != nil {
			return failf("that passphrase cannot be used")
		}
		defer destroyWrapper(pw)
		// Prove it is the right passphrase before rotating.
		if k, err := crypto.Unlock(vf, pw); err != nil {
			return failf("wrong passphrase")
		} else {
			k.Destroy()
		}
		rewrap = append(rewrap, pw)
	}
	if rec := a.thisMacRecipient(); rec != "" {
		for _, u := range vf.UnlockersOf(format.UnlockerTouchID) {
			if u.Recipient == rec {
				if tw := a.touchWrapper(v.name); tw != nil {
					rewrap = append(rewrap, tw)
				}
			}
		}
	}
	res, err := members.Remove(v.dir, key, name, rewrap...)
	if res != nil && res.NewKey != nil {
		// The rotation happened (even if finishing the file moves needs a
		// re-run): switch this Mac to the new key.
		a.pinKey(v, res.NewKey.ID())
		if cl := a.client(true); cl != nil {
			_ = cl.Unlock(vf.ID, res.NewKey, a.ttlFor(v))
		}
	}
	if err != nil {
		return memberErr(err)
	}
	a.record(v.name, "", audit.ActionUnlock)
	exposed := res.ExposedKeys
	if exposed == nil {
		exposed = []string{}
	}
	dropped := make([]string, 0, len(res.Dropped))
	for _, d := range res.Dropped {
		dropped = append(dropped, d.Label)
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": v.name, "removed": name, "rotate_at_provider": exposed, "touchid_reenrol": dropped, "notes": res.Notes})
	}
	a.printf("Removed %s from '%s' and replaced the vault key.\n", name, v.name)
	if len(exposed) > 0 {
		a.printf("%s could have read these keys. Rotate them at their providers:\n", name)
		for _, k := range exposed {
			a.printf("  %s\n", k)
		}
	}
	if len(dropped) > 0 {
		a.printf("Touch ID must be turned on again on: %s\n", strings.Join(dropped, ", "))
	}
	for _, n := range res.Notes {
		a.warnf("%s", n)
	}
	return nil
}

// cmdIdentity: identity export|import FILE
func cmdIdentity(a *app, p *parsed) error {
	usage := a.prog + " identity export|import FILE"
	if err := p.wantArgs(2, 2, usage); err != nil {
		return err
	}
	file, err := a.expandPath(p.args[1])
	if err != nil {
		return err
	}
	store, err := a.identityStore()
	if err != nil {
		return err
	}
	switch p.args[0] {
	case "export":
		if !store.Exists() {
			return failf("you have no identity yet")
		}
		unlockW, closeW, err := a.identityUnlockWrapper()
		if err != nil {
			return err
		}
		defer closeW()
		pp, err := a.askNewPassphrase("Choose a passphrase to protect the exported file")
		if err != nil {
			return err
		}
		protect, err := a.passphraseWrapper(pp)
		clear(pp)
		if err != nil {
			return failf("that passphrase cannot be used")
		}
		defer destroyWrapper(protect)
		data, err := store.Export(unlockW, protect)
		if err != nil {
			return failf("could not export your identity: %v", err)
		}
		defer clear(data)
		f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path given by the user
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				return failf("that file already exists; choose a new file name")
			}
			return failf("cannot write the file: %v", pathless(err))
		}
		_, werr := f.Write(data)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			_ = os.Remove(file)
			return failf("cannot write the file")
		}
		if a.asJSON {
			return a.printJSON(map[string]any{"exported": true, "file": file})
		}
		a.printf("Exported your identity to %s. Delete the file after importing it on your other Mac.\n", file)
		return nil
	case "import":
		if store.Exists() {
			return failf("this Mac already has an identity")
		}
		f, err := os.Open(file) // #nosec G304 -- path given by the user
		if err != nil {
			return failf("cannot read the file: %v", pathless(err))
		}
		data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
		_ = f.Close()
		if err != nil || len(data) > 1<<20 {
			return failf("cannot read the file")
		}
		pp, err := a.askHidden("Passphrase of the exported file: ")
		if err != nil {
			return err
		}
		from, err := a.passphraseWrapper(pp)
		clear(pp)
		if err != nil {
			return failf("that passphrase cannot be used")
		}
		defer destroyWrapper(from)
		np, err := a.askNewPassphrase("Choose a personal passphrase for this Mac")
		if err != nil {
			return err
		}
		pw, err := a.passphraseWrapper(np)
		clear(np)
		if err != nil {
			return failf("that passphrase cannot be used")
		}
		defer destroyWrapper(pw)
		wrappers := []crypto.KeyWrapper{pw}
		if a.touch.available() && a.term.StdinTTY() && a.confirmDefaultYes("Use Touch ID to unlock your identity on this Mac?") {
			if d, err := a.ensureDevice(); err == nil {
				if tw, err := a.touch.wrapper(d, ""); err == nil {
					wrappers = append(wrappers, tw)
				}
			}
		}
		id, err := store.Import(data, from, wrappers...)
		if err != nil {
			if errors.Is(err, crypto.ErrWrongKey) {
				return failf("wrong passphrase, or the file is damaged")
			}
			return failf("could not import the identity: %v", err)
		}
		if a.asJSON {
			return a.printJSON(map[string]any{"imported": true, "name": id.Name, "fingerprint": id.Fingerprint})
		}
		a.printf("Imported identity '%s'. Fingerprint: %s\n", id.Name, id.Fingerprint)
		return nil
	}
	return usageErrf("usage: %s", usage)
}

// identityUnlockWrapper returns a wrapper that opens the stored identity
// (Touch ID if it works, else the personal passphrase) for Store.Export.
func (a *app) identityUnlockWrapper() (crypto.KeyWrapper, func(), error) {
	store, err := a.identityStore()
	if err != nil {
		return nil, nil, err
	}
	if tw := a.touchWrapper(""); tw != nil {
		if un, err := store.Unlock(tw); err == nil {
			un.Destroy()
			return tw, func() {}, nil
		}
	}
	for try := 0; try < maxPassphraseTry; try++ {
		p, err := a.askHidden("Your personal passphrase: ")
		if err != nil {
			return nil, nil, err
		}
		w, err := a.passphraseWrapper(p)
		clear(p)
		if err != nil {
			return nil, nil, failf("that passphrase cannot be used")
		}
		if un, err := store.Unlock(w); err == nil {
			un.Destroy()
			return w, func() { destroyWrapper(w) }, nil
		}
		destroyWrapper(w)
		if !a.term.StdinTTY() {
			break
		}
		a.infof("Wrong passphrase.")
	}
	return nil, nil, failf("could not unlock your identity: wrong passphrase")
}
