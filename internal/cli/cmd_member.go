package cli

import (
	"errors"
	"io"
	"io/fs"
	"os"

	"github.com/Arntek/secrets-vault/internal/audit"
	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/members"
)

func memberErr(err error) error {
	var held *members.LeaseHeldError
	switch {
	case errors.Is(err, members.ErrFingerprintMismatch):
		return failf("the fingerprint does not match the request. Do not approve")
	case errors.Is(err, members.ErrNoRequest):
		return failf("no such join request. See: requests")
	case errors.Is(err, members.ErrNotMember):
		return failf("that person is not a member of this vault")
	case errors.Is(err, members.ErrAlreadyMember):
		return failf("that person is already a member")
	case errors.Is(err, members.ErrPreviouslyRemoved):
		return failf("this key was removed from the vault before. If re-adding it is intended, run approve again with --readd and type the fingerprint again")
	case errors.Is(err, members.ErrLogFull):
		return failf("%v", members.ErrLogFull)
	case errors.As(err, &held):
		return failf("%v", held)
	case errors.Is(err, format.ErrChanged):
		return failf("%v", format.ErrChanged)
	}
	return failf("%v", vaultErr(err))
}

// cmdMember: member approve|rm|list|requests|log VAULT [NAME]
func cmdMember(a *app, p *parsed) error {
	usage := a.prog + " member approve|rm|list|requests|log VAULT [NAME]"
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
		if _, err := a.open(v); err != nil {
			return err
		}
		if v.v1 != nil {
			return failf("vault '%s' was made by a pre-release version; open it once (%s unlock %s) to upgrade it", v.name, a.prog, v.name)
		}
		ov, err := members.Inspect(v.dir, v.chain)
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
			rows = append(rows, row{m.Identity.Name, m.Identity.Fingerprint, m.Role, m.Added.UTC().Format("2006-01-02"), m.AddedBy})
		}
		if a.asJSON {
			warns := []string{}
			for _, w := range ov.Warnings {
				warns = append(warns, w.Message)
			}
			return a.printJSON(map[string]any{"members": rows, "has_passphrase": ov.HasPassphrase, "warnings": warns, "state_code": members.StateCode(v.chain, v.chain.Head().Seq)})
		}
		t := newTable(a.out, "NAME", "FINGERPRINT", "ROLE", "ADDED")
		for _, r := range rows {
			added := r.Added
			if r.AddedBy != "" {
				added += " by " + r.AddedBy
			}
			t.row(r.Name, r.Fingerprint, r.Role, added)
		}
		t.flush()
		for _, w := range ov.Warnings {
			a.warnf("warning: %s", w.Message)
		}
		return nil

	case "log":
		if err := p.wantArgs(2, 2, usage); err != nil {
			return err
		}
		if _, err := a.open(v); err != nil {
			return err
		}
		if v.v1 != nil {
			return failf("vault '%s' was made by a pre-release version; open it once to upgrade it", v.name)
		}
		type row struct {
			Seq        int    `json:"seq"`
			Time       string `json:"time"`
			By         string `json:"by"`
			Op         string `json:"op"`
			Member     string `json:"member,omitempty"`
			Passphrase string `json:"passphrase,omitempty"`
		}
		rows := []row{}
		for i, r := range v.chain.Records {
			m := ""
			if r.Member != nil {
				m = r.Member.Name
			}
			rows = append(rows, row{i, r.Time.UTC().Format("2006-01-02 15:04"), v.chain.States[i].By, string(r.Op), m, r.Passphrase})
		}
		if a.asJSON {
			return a.printJSON(rows)
		}
		t := newTable(a.out, "SEQ", "WHEN (UTC)", "BY", "CHANGE", "MEMBER", "PASSPHRASE")
		for _, r := range rows {
			t.row(itoa(r.Seq), r.Time, r.By, r.Op, r.Member, r.Passphrase)
		}
		t.flush()
		return nil

	case "requests":
		if err := p.wantArgs(2, 2, usage); err != nil {
			return err
		}
		vf, err := format.ReadVaultFile(v.dir)
		if err != nil {
			return failf("cannot open vault '%s': %v", v.name, vaultErr(err))
		}
		reqs, bad, err := members.ListRequests(v.dir, vf.ID)
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
			t := newTable(a.out, "NAME", "FILED")
			for _, r := range rows {
				t.row(r.Name, r.Created)
			}
			t.flush()
			a.printf("Approve with: %s member approve %s NAME (you will type their fingerprint as they read it to you)\n", a.prog, v.name)
		}
		if len(bad) > 0 {
			a.warnf("%s could not be read and was ignored", plural(len(bad), "request file"))
		}
		return nil

	case "approve":
		if err := p.wantArgs(3, 3, usage); err != nil {
			return err
		}
		return a.memberApprove(v, p.args[2], p)

	case "rm":
		if err := p.wantArgs(3, 3, usage); err != nil {
			return err
		}
		return a.memberRemove(v, p.args[2], p)
	}
	return usageErrf("usage: %s", usage)
}

// memberApprove adds a requester after the approver TYPES the requester's
// fingerprint as the requester reads it out (G4: not a y/N against a value
// on screen). --fingerprint FP is the non-interactive form.
func (a *app) memberApprove(v *vaultRef, name string, p *parsed) error {
	if err := members.ValidateMemberName(name); err != nil {
		return usageErrf("%v", err)
	}
	vf, err := a.open(v)
	if err != nil {
		return err
	}
	if v.v1 != nil {
		return failf("vault '%s' was made by a pre-release version; open it once (%s unlock %s) to upgrade it", v.name, a.prog, v.name)
	}
	if _, err := members.ReadRequest(v.dir, vf.ID, name); err != nil {
		return memberErr(err)
	}
	fp := p.str("fingerprint")
	if !p.has("fingerprint") {
		if !a.term.StdinTTY() {
			return failf("approving needs you to check the fingerprint: run it in a terminal, or pass --fingerprint FP after %s reads it to you", name)
		}
		line, err := a.ask("Ask " + name + " to read out their fingerprint, and type it here: ")
		if err != nil {
			return failf("cancelled")
		}
		fp = line
	}
	key, err := a.openKey(v, vf, openOpts{purpose: purposeWrite})
	if err != nil {
		return err
	}
	defer key.Destroy()
	un, err := a.signer(v)
	if err != nil {
		return err
	}
	c, m, err := members.ApproveRequest(v.dir, v.chain, key, un, name, fp, p.has("readd"), a.now())
	if c != nil {
		if serr := a.afterWrite(v, c, c.LastEntry()); serr != nil && err == nil {
			err = serr
		}
	}
	if err != nil {
		return memberErr(err)
	}
	a.recordEvent(audit.Event{Vault: v.name, Action: audit.ActionMemberAdd, Member: name})
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": v.name, "approved": name, "fingerprint": m.Identity.Fingerprint, "your_fingerprint": un.Fingerprint})
	}
	a.printf("%s added to '%s'.\n", name, v.name)
	a.printf("Now read %s your own fingerprint; they will type it the first time they open '%s': %s\n", name, v.name, un.Fingerprint)
	return nil
}

// memberRemove removes a member and rotates the vault key. It requires
// confirming that the person's access to the shared folder is removed
// (otherwise they can roll the folder back for offline members, ue1.2),
// and drops the vault passphrase unless told otherwise (ue1.6).
func (a *app) memberRemove(v *vaultRef, name string, p *parsed) error {
	if err := members.ValidateMemberName(name); err != nil {
		return usageErrf("%v", err)
	}
	a.setAsideBadFolders(v)
	vf, err := a.open(v)
	if err != nil {
		return err
	}
	if v.v1 != nil {
		return failf("vault '%s' was made by a pre-release version; open it once (%s unlock %s) to upgrade it", v.name, a.prog, v.name)
	}
	if _, ok := v.chain.Head().Member(name); !ok {
		return failf("that person is not a member of '%s'", v.name)
	}
	policy := format.PassDropped
	switch {
	case p.has("keep-passphrase") && (p.has("new-passphrase") || p.has("new-passphrase-stdin")):
		return usageErrf("choose --keep-passphrase or --new-passphrase, not both")
	case p.has("keep-passphrase"):
		policy = format.PassKept
	case p.has("new-passphrase"), p.has("new-passphrase-stdin"):
		policy = format.PassReplaced
	}
	hasPass := len(vf.UnlockersOf(format.UnlockerPassphrase)) > 0
	if !hasPass && policy == format.PassKept {
		return usageErrf("'%s' has no passphrase to keep", v.name)
	}
	tty := a.term.StdinTTY()
	if !p.has("folder-access-removed") {
		if !tty {
			return failf("removing a member needs confirmation that their access to the shared folder (Box, Dropbox) is removed: run it in a terminal, or pass --folder-access-removed")
		}
		ok, _ := a.confirm("Have you removed " + name + "'s access to the shared folder (Box, Dropbox)? Without that they can restore an old copy of the vault for members who are offline.")
		if !ok {
			return failf("cancelled. Remove %s's access to the shared folder first, then run this again", name)
		}
	}
	if !p.has("yes") {
		if !tty {
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
	un, err := a.signer(v)
	if err != nil {
		return err
	}
	ps, err := a.pendingStore()
	if err != nil {
		return err
	}
	var skipped []string
	dropped := 0
	opt := members.RotateOptions{Passphrase: policy, Pending: ps, Now: a.now(), TrustedEntries: a.trustedEntries(v), SkippedFiles: &skipped, IndexDropped: &dropped}
	switch policy {
	case format.PassKept:
		pass, err := a.askHidden("Current vault passphrase for '" + v.name + "' (to keep it): ")
		if err != nil {
			return err
		}
		pw, err := a.passphraseWrapper(pass)
		clear(pass)
		if err != nil {
			return failf("that passphrase cannot be used")
		}
		defer destroyWrapper(pw)
		opt.Keep = pw
	case format.PassReplaced:
		if p.has("new-passphrase-stdin") {
			a.passStdin = true
		}
		np, err := a.askNewPassphrase("New vault passphrase for '" + v.name + "'")
		if err != nil {
			return err
		}
		pw, err := a.passphraseWrapper(np)
		clear(np)
		if err != nil {
			return failf("that passphrase cannot be used")
		}
		defer destroyWrapper(pw)
		opt.New = pw
	}
	if err := a.setAsideConflicts(v, key); err != nil {
		return err
	}
	res, err := members.Remove(v.dir, v.chain, key, un, name, opt)
	a.noteRotation(v, &skipped, &dropped)
	if res != nil && res.NewKey != nil {
		a.switchKey(v, res.NewKey)
	}
	if res != nil && res.Chain != nil {
		if serr := a.afterWrite(v, res.Chain, res.Chain.LastEntry()); serr != nil && err == nil {
			err = serr
		}
	}
	if err != nil {
		if errors.Is(err, crypto.ErrWrongKey) {
			return failf("wrong passphrase")
		}
		return memberErr(err)
	}
	a.recordEvent(audit.Event{Vault: v.name, Action: audit.ActionMemberRemove, Member: name})
	exposed := res.ExposedKeys
	if exposed == nil {
		exposed = []string{}
	}
	code := members.StateCode(v.chain, v.chain.Head().Seq)
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": v.name, "removed": name, "rotate_at_provider": exposed,
			"passphrase": res.Passphrase, "revoke_folder_access": name, "state_code": code, "quarantined": a.quarantinedList()})
	}
	a.printf("Removed %s from '%s' and replaced the vault key.\n", name, v.name)
	switch res.Passphrase {
	case format.PassDropped:
		if hasPass {
			a.printf("The vault passphrase no longer opens '%s'. To set a new one: %s passwd %s\n", v.name, a.prog, v.name)
		}
	case format.PassKept:
		a.printf("The vault passphrase was kept: anyone who knows it still has access.\n")
	case format.PassReplaced:
		a.printf("The vault passphrase was replaced.\n")
	}
	if len(exposed) > 0 {
		a.printf("%s could have read these keys. Rotate them at their providers:\n", name)
		for _, k := range exposed {
			a.printf("  %s\n", k)
		}
	}
	a.printf("Make sure %s can no longer write to the shared folder.\n", name)
	a.printf("State code (give it to the other members; they run '%s trust %s --expect CODE'): %s\n", a.prog, v.name, code)
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
	if tw := a.touchWrapper(""); tw != nil && !a.passStdin {
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
