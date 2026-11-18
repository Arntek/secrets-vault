package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Arntek/secrets-vault/internal/agent"
	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/members"
)

// insideGitRepo reports whether dir (or a parent) is a git working tree.
func insideGitRepo(dir string) bool {
	d := dir
	for {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(d)
		if parent == d {
			return false
		}
		d = parent
	}
}

// cmdInit: init NAME --path DIR [--desc TEXT] [--force]
func cmdInit(a *app, p *parsed) error {
	if err := p.wantArgs(1, 1, a.prog+" init NAME --path DIR [--desc TEXT] [--force]"); err != nil {
		return err
	}
	name := p.args[0]
	if err := format.ValidateVaultName(name); err != nil {
		return usageErrf("%v", err)
	}
	if !p.has("path") {
		return usageErrf("usage: %s init NAME --path DIR [--desc TEXT] [--force]", a.prog)
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if _, ok := cfg.Vaults[name]; ok {
		return failf("a vault with that name is already registered")
	}
	dir, err := a.expandPath(p.str("path"))
	if err != nil {
		return err
	}
	if insideGitRepo(dir) && !p.has("force") {
		return failf("that folder is inside a git repository, and vault files must never be committed. Choose another folder, or pass --force")
	}
	if _, err := os.Lstat(format.VaultFilePath(dir)); err == nil {
		return failf("a vault already exists in that folder. Use '%s attach' to register it", a.prog)
	}
	// Every vault has an owner: this person's identity (design section 1).
	var un *members.Unlocked
	if _, ok := a.myIdentity(); !ok && !a.identityNeedsUpgrade() {
		if _, un, err = a.createIdentityOpts(p.str("as"), !p.has("no-touchid"), p.has("touchid")); err != nil {
			return err
		}
	} else if un, err = a.unlockIdentity(); err != nil {
		return err
	}
	var pw crypto.KeyWrapper
	if !p.has("no-passphrase") {
		pass, err := a.askNewPassphrase("Choose a recovery passphrase for '" + name + "' (keep it somewhere safe)")
		if err != nil {
			return err
		}
		pw, err = a.passphraseWrapper(pass)
		clear(pass)
		if err != nil {
			return failf("that passphrase cannot be used")
		}
		defer destroyWrapper(pw)
	}
	key, err := crypto.NewVaultKey()
	if err != nil {
		return failf("cannot create a vault key")
	}
	defer key.Destroy()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return failf("cannot create the folder: %v", pathless(err))
	}
	c, err := members.NewVault(dir, name, key, un, pw, a.now())
	if err != nil {
		return failf("cannot create the vault: %v", vaultErr(err))
	}
	vf := c.File
	touchOn := a.identityHasTouchID()
	cfg.Vaults[name] = &VaultEntry{Path: dir, Description: p.str("desc"), ID: vf.ID}
	if cfg.DefaultVault == "" {
		cfg.DefaultVault = name
	}
	if err := a.saveConfig(cfg); err != nil {
		return err
	}
	ref := &vaultRef{name: name, entry: cfg.Vaults[name], dir: dir, chain: c, class: members.Classification{Outcome: members.FirstUse}}
	if err := a.savePin(ref, []format.LogEntry{c.LastEntry()}); err != nil {
		return err
	}
	// Leave the new vault unlocked, as 'unlock' would, so the first 'set'
	// does not ask for the passphrase again. Failing to reach the agent
	// never fails the init.
	unlocked := false
	if cl := a.client(true); cl != nil {
		if dup, err := keyCopy(key); err == nil {
			ttl := a.ttlFor(&vaultRef{name: name, entry: cfg.Vaults[name], dir: dir})
			unlocked = cl.Unlock(vf.ID, dup, ttl) == nil
		}
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": name, "path": dir, "touchid": touchOn, "unlocked": unlocked})
	}
	a.printf("Created vault '%s' at %s\n", name, dir)
	if pw == nil {
		a.warnf("warning: '%s' has no recovery passphrase; if your identity is lost it cannot be opened. Add a second trusted member, or set one with: %s passwd %s", name, a.prog, name)
	}
	if !unlocked {
		a.infof("The vault is locked: the unlock agent could not be reached. Run: %s unlock %s", a.prog, name)
	}
	return nil
}

// cmdAttach: attach NAME DIR [--as NAME] [--no-request]
func cmdAttach(a *app, p *parsed) error {
	if err := p.wantArgs(2, 2, a.prog+" attach NAME DIR"); err != nil {
		return err
	}
	name := p.args[0]
	if err := format.ValidateVaultName(name); err != nil {
		return usageErrf("%v", err)
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if _, ok := cfg.Vaults[name]; ok {
		return failf("a vault with that name is already registered")
	}
	dir, err := a.expandPath(p.args[1])
	if err != nil {
		return err
	}
	vf, err := format.ReadVaultFile(dir)
	if err != nil {
		return failf("that folder does not hold a vault: %v", vaultErr(err))
	}
	for _, e := range cfg.Vaults {
		if e.ID == vf.ID {
			return failf("that vault is already registered under another name")
		}
		if d, err := a.expandEntry(e); err == nil && e.ID == "" {
			if other, err := format.ReadVaultFile(d); err == nil && other.ID == vf.ID {
				return failf("that vault is already registered under another name")
			}
		}
	}
	idx, err := (&vaultRef{name: name, dir: dir}).index()
	if err != nil {
		return err
	}
	cfg.Vaults[name] = &VaultEntry{Path: dir, Description: p.str("desc"), ID: vf.ID}
	if cfg.DefaultVault == "" {
		cfg.DefaultVault = name
	}
	if err := a.saveConfig(cfg); err != nil {
		return err
	}

	res := map[string]any{"vault": name, "path": dir, "keys": len(idx.Entries)}
	ref := &vaultRef{name: name, entry: cfg.Vaults[name], dir: dir}
	member := false
	if id, ok := a.myIdentity(); ok {
		for _, m := range vf.Members {
			if m.Recipient == id.Recipient && m.SignKey == id.SignKey {
				member = true
			}
		}
	}
	res["member"] = member
	if member || p.has("no-request") {
		if vf.Version == format.VaultVersion {
			// Verify it and pin it now (trust on first use, with the checks
			// of design section 7).
			if _, err := a.open(ref); err != nil {
				return err
			}
		}
		if a.asJSON {
			return a.printJSON(res)
		}
		a.printf("Registered '%s' (%d keys)\n", name, len(idx.Entries))
		return nil
	}
	if vf.Version != format.VaultVersion {
		return failf("registered '%s', but it was made by a pre-release version: ask its owner to open it once, then attach again", name)
	}

	// Not a member: file a signed join request.
	id, ok := a.myIdentity()
	if !ok && !a.identityNeedsUpgrade() {
		if id, err = a.createIdentity(p.str("as")); err != nil {
			a.warnf("Registered '%s', but no join request was filed: %v", name, err)
			return err
		}
	}
	un, err := a.unlockIdentity()
	if err != nil {
		a.warnf("Registered '%s', but no join request was filed", name)
		return err
	}
	id = un.Identity
	werr := members.WriteRequest(dir, un, a.now())
	pending := errors.Is(werr, members.ErrRequestPending)
	if errors.Is(werr, members.ErrDuplicateName) {
		// The same person re-attaching finds their own request waiting.
		if old, rerr := members.ReadRequest(dir, vf.ID, id.Name); rerr == nil && old.Identity.Recipient == id.Recipient {
			pending, werr = true, nil
		} else {
			return failf("registered '%s', but the name '%s' is already used by another member or request in it", name, id.Name)
		}
	}
	if werr != nil && !pending {
		return failf("registered '%s', but the join request could not be written: %v", name, werr)
	}
	res["fingerprint"] = id.Fingerprint
	res["request"] = "filed"
	if pending {
		res["request"] = "pending"
	}
	if a.asJSON {
		return a.printJSON(res)
	}
	a.printf("Registered '%s' (%d keys)\n", name, len(idx.Entries))
	if pending {
		a.printf("You're not a member of '%s' yet; your join request is already waiting.\n", name)
	} else {
		a.printf("You're not a member of '%s' yet. Request written to the vault folder.\n", name)
	}
	a.printf("Ask a member to approve fingerprint %s.\n", id.Fingerprint)
	a.printf("When they approve, they will read you their own fingerprint: you'll be asked for it the first time you open '%s'.\n", name)
	return nil
}

// cmdDetach: detach NAME
func cmdDetach(a *app, p *parsed) error {
	if err := p.wantArgs(1, 1, a.prog+" detach NAME"); err != nil {
		return err
	}
	v, err := a.vault(p.args[0])
	if err != nil {
		return err
	}
	cfg, _ := a.loadConfig()
	id := v.entry.ID
	if vf, err := format.ReadVaultFile(v.dir); err == nil {
		if id == "" {
			id = vf.ID
		}
		if cl := a.client(false); cl != nil {
			_ = cl.Lock(vf.ID)
		}
	}
	// The trust pin stays (a re-attach is still checked against it); the
	// keys of unconfirmed rotations go (S3).
	if ps, err := a.pendingStore(); err == nil && id != "" {
		_ = ps.DeleteAll(id)
	}
	delete(cfg.Vaults, v.name)
	if cfg.DefaultVault == v.name {
		cfg.DefaultVault = ""
	}
	if err := a.saveConfig(cfg); err != nil {
		return err
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"detached": v.name})
	}
	a.printf("Detached '%s'. The files are untouched.\n", v.name)
	return nil
}

// cmdVaults: vaults
func cmdVaults(a *app, p *parsed) error {
	if err := p.wantArgs(0, 0, a.prog+" vaults"); err != nil {
		return err
	}
	names, err := a.vaultNames()
	if err != nil {
		return err
	}
	states := a.lockStates()
	type row struct {
		Name        string `json:"name"`
		Path        string `json:"path"`
		Description string `json:"description,omitempty"`
		Keys        *int   `json:"keys"`
		Unlocked    bool   `json:"unlocked"`
		Default     bool   `json:"default,omitempty"`
		Error       string `json:"error,omitempty"`
	}
	cfg, _ := a.loadConfig()
	var rows []row
	for _, n := range names {
		v, err := a.vault(n)
		if err != nil {
			return err
		}
		r := row{Name: n, Path: v.dir, Description: v.entry.Description, Default: cfg.DefaultVault == n}
		if vf, err := format.ReadVaultFile(v.dir); err != nil {
			r.Error = "unavailable"
		} else {
			r.Unlocked = states[vf.ID].Unlocked
			if idx, err := v.index(); err == nil {
				k := len(idx.Entries)
				r.Keys = &k
			}
		}
		rows = append(rows, r)
	}
	if a.asJSON {
		if rows == nil {
			rows = []row{}
		}
		return a.printJSON(rows)
	}
	if len(rows) == 0 {
		a.printf("No vaults yet. Create one with: %s init NAME --path DIR\n", a.prog)
		return nil
	}
	t := newTable(a.out, "NAME", "KEYS", "STATE", "PATH", "DESCRIPTION")
	for _, r := range rows {
		keys, state := "?", "unavailable"
		if r.Keys != nil {
			keys = itoa(*r.Keys)
		}
		if r.Error == "" {
			state = "locked"
			if r.Unlocked {
				state = "unlocked"
			}
		}
		n := r.Name
		if r.Default {
			n += " *"
		}
		t.row(n, keys, state, r.Path, r.Description)
	}
	t.flush()
	return nil
}

// cmdPasswd: passwd VAULT [--no-rotate]
//
// Sets a new vault passphrase and rotates the vault key (ue1.6): without
// the rotation, anyone with the old passphrase and an old copy of
// vault.json would still get every future secret. In a shared vault the
// rotation is required. It is a signed change, so only a member can make
// it.
func cmdPasswd(a *app, p *parsed) error {
	if err := p.wantArgs(1, 1, a.prog+" passwd VAULT [--no-rotate]"); err != nil {
		return err
	}
	v, err := a.vault(p.args[0])
	if err != nil {
		return err
	}
	vf, err := a.open(v)
	if err != nil {
		return err
	}
	key, err := a.openKey(v, vf, openOpts{purpose: purposeWrite})
	if err != nil {
		return err
	}
	defer key.Destroy()
	rotate := !p.has("no-rotate")
	if !rotate && len(v.chain.Head().Members) > 1 {
		return usageErrf("--no-rotate is only for a vault with one member: in a shared vault a new passphrase must come with a new key")
	}
	un, err := a.signer(v)
	if err != nil {
		return err
	}
	np, err := a.askNewPassphrase("New passphrase for '" + v.name + "'")
	if err != nil {
		return err
	}
	nw, err := a.passphraseWrapper(np)
	clear(np)
	if err != nil {
		return failf("that passphrase cannot be used")
	}
	defer destroyWrapper(nw)
	ps, err := a.pendingStore()
	if err != nil {
		return err
	}
	res, err := members.Passwd(v.dir, v.chain, key, un, nw, rotate, members.RotateOptions{Pending: ps, Now: a.now()})
	if res != nil && res.NewKey != nil {
		a.switchKey(v, res.NewKey)
	}
	if res != nil && res.Chain != nil {
		if serr := a.afterWrite(v, res.Chain, res.Chain.LastEntry()); serr != nil && err == nil {
			err = serr
		}
	}
	if err != nil {
		return failf("could not change the passphrase of '%s': %v", v.name, vaultErr(err))
	}
	code := members.StateCode(v.chain, v.chain.Head().Seq)
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": v.name, "changed": true, "rotated": rotate, "state_code": code})
	}
	if rotate {
		a.printf("Passphrase changed for '%s', and the vault key replaced: the old passphrase opens nothing new.\n", v.name)
	} else {
		a.printf("Passphrase changed for '%s'. The vault key was not replaced: anyone who knew the old passphrase can still open old copies of this vault.\n", v.name)
	}
	a.printf("State code (give it to the other members): %s\n", code)
	return nil
}

// switchKey hands a rotated key to the agent.
func (a *app) switchKey(v *vaultRef, k *crypto.VaultKey) {
	if cl := a.client(true); cl != nil {
		if dup, err := crypto.VaultKeyFromBytes(k.Bytes()); err == nil {
			_ = cl.Unlock(v.chain.File.ID, dup, a.ttlFor(v))
		}
	}
}

// cmdTouchID: touchid on|off|status
//
// Touch ID protects this person's identity (and so every vault they are a
// member of) on this Mac, not each vault: a key rotation never drops it.
func cmdTouchID(a *app, p *parsed) error {
	usage := a.prog + " touchid on|off|status"
	if err := p.wantArgs(1, 2, usage); err != nil {
		return err
	}
	s, err := a.identityStore()
	if err != nil {
		return err
	}
	switch p.args[0] {
	case "on":
		if !s.Exists() {
			return failf("you have no identity yet. Run: %s init NAME --path DIR, or %s attach NAME DIR", a.prog, a.prog)
		}
		d, err := a.ensureDevice()
		if err != nil {
			return err
		}
		tw, err := a.touch.wrapper(d, "")
		if err != nil {
			return failf("Touch ID could not be set up: %v", err)
		}
		pass, err := a.askHidden("Your personal passphrase: ")
		if err != nil {
			return err
		}
		pw, err := a.passphraseWrapper(pass)
		clear(pass)
		if err != nil {
			return failf("that passphrase cannot be used")
		}
		defer destroyWrapper(pw)
		if err := s.AddUnlocker(pw, tw); err != nil {
			return failf("could not turn on Touch ID: %v", err)
		}
		if a.asJSON {
			return a.printJSON(map[string]any{"touchid": true})
		}
		a.printf("Touch ID now unlocks your identity on this Mac.\n")
		return nil
	case "off":
		if !s.Exists() {
			return failf("you have no identity on this Mac")
		}
		if err := s.RemoveUnlockers(format.UnlockerTouchID); err != nil {
			return failf("could not turn off Touch ID: %v", err)
		}
		if a.asJSON {
			return a.printJSON(map[string]any{"touchid": false})
		}
		a.printf("Touch ID no longer unlocks your identity on this Mac.\n")
		return nil
	case "status", "list":
		on := a.identityHasTouchID()
		if a.asJSON {
			return a.printJSON(map[string]any{"touchid": on, "available": a.touch.available()})
		}
		if on {
			a.printf("Touch ID unlocks your identity on this Mac.\n")
		} else {
			a.printf("Touch ID is off on this Mac. Turn it on with: %s touchid on\n", a.prog)
		}
		return nil
	}
	return usageErrf("usage: %s", usage)
}

// identityHasTouchID reports whether this Mac's Touch ID opens the identity.
func (a *app) identityHasTouchID() bool {
	s, err := a.identityStore()
	if err != nil || !s.Exists() {
		return false
	}
	rec := a.thisMacRecipient()
	if rec == "" {
		return false
	}
	recs, _ := s.UnlockerRecipients(format.UnlockerTouchID)
	for _, r := range recs {
		if r == rec {
			return true
		}
	}
	return false
}

// cmdConfig: config set KEY VALUE [--vault V] | config list
func cmdConfig(a *app, p *parsed) error {
	usage := a.prog + " config set KEY VALUE [--vault VAULT] | config list"
	if len(p.args) == 0 {
		return usageErrf("usage: %s", usage)
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	switch p.args[0] {
	case "list":
		if err := p.wantArgs(1, 1, usage); err != nil {
			return err
		}
		out := map[string]any{
			"default_ttl":      orDefault(cfg.DefaultTTL, agent.DefaultTTL.String()),
			"default_vault":    cfg.DefaultVault,
			"touch_every_read": cfg.TouchEveryRead,
			"dialog":           orDefault(cfg.Dialog, "auto"),
		}
		if a.asJSON {
			return a.printJSON(out)
		}
		a.printf("default-ttl        %v\n", out["default_ttl"])
		a.printf("default-vault      %v\n", out["default_vault"])
		a.printf("touch-every-read   %v\n", out["touch_every_read"])
		a.printf("dialog             %v\n", out["dialog"])
		return nil
	case "set":
		if err := p.wantArgs(3, 3, usage); err != nil {
			return err
		}
		key, val := p.args[1], p.args[2]
		var e *VaultEntry
		if vn := p.str("vault"); vn != "" {
			v, err := a.vault(vn)
			if err != nil {
				return err
			}
			e = v.entry
		}
		if err := setConfig(cfg, e, key, val); err != nil {
			return err
		}
		if err := a.saveConfig(cfg); err != nil {
			return err
		}
		if a.asJSON {
			return a.printJSON(map[string]any{"set": key})
		}
		a.printf("Saved.\n")
		return nil
	}
	return usageErrf("usage: %s", usage)
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func parseBool(s string) (bool, bool) {
	switch strings.ToLower(s) {
	case "true", "on", "yes", "1":
		return true, true
	case "false", "off", "no", "0":
		return false, true
	}
	return false, false
}

func setConfig(cfg *Config, e *VaultEntry, key, val string) error {
	switch key {
	case "default-ttl", "ttl":
		if key == "ttl" && e == nil {
			return usageErrf("'ttl' needs --vault; use default-ttl for the global setting")
		}
		d, err := time.ParseDuration(val)
		if err != nil {
			return usageErrf("not a duration (try 4h or 30m)")
		}
		if err := agent.ValidateTTL(d); err != nil {
			return usageErrf("%v", err)
		}
		if e != nil {
			e.TTL = val
		} else {
			cfg.DefaultTTL = val
		}
	case "touch-every-read":
		b, ok := parseBool(val)
		if !ok {
			return usageErrf("expected true or false")
		}
		if e != nil {
			e.TouchEveryRead = &b
		} else {
			cfg.TouchEveryRead = b
		}
	case "dialog":
		if val != "auto" && val != "off" {
			return usageErrf("dialog must be 'auto' or 'off'")
		}
		if e != nil {
			e.Dialog = val
		} else {
			cfg.Dialog = val
		}
	case "default-vault":
		if e != nil {
			return usageErrf("default-vault is a global setting")
		}
		if _, ok := cfg.Vaults[val]; !ok {
			return failf("no such vault. Register it first")
		}
		cfg.DefaultVault = val
	default:
		return usageErrf("unknown setting. Known: default-ttl, default-vault, touch-every-read, dialog")
	}
	return nil
}

// --- aliases ---

var aliasNameOK = func(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case (c >= '0' && c <= '9' || c == '-' || c == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}

// cmdAlias: alias add|rm|list NAME [--force]
func cmdAlias(a *app, p *parsed) error {
	usage := a.prog + " alias add|rm|list NAME [--force]"
	if len(p.args) == 0 {
		return usageErrf("usage: %s", usage)
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	exe, err := a.exePath()
	if err != nil {
		return failf("cannot find this program")
	}
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return failf("cannot find this program")
	}
	dir := filepath.Dir(exe)
	switch p.args[0] {
	case "list":
		type row struct {
			Name   string `json:"name"`
			Exists bool   `json:"exists"`
			Path   string `json:"path"`
		}
		rows := []row{}
		names := append([]string(nil), cfg.Aliases...)
		sort.Strings(names)
		for _, n := range names {
			path := filepath.Join(dir, n)
			rows = append(rows, row{n, isLinkTo(path, real), path})
		}
		if a.asJSON {
			return a.printJSON(rows)
		}
		if len(rows) == 0 {
			a.printf("No short names added by %s. Add one with: %s alias add NAME\n", a.prog, a.prog)
			return nil
		}
		for _, r := range rows {
			st := "ok"
			if !r.Exists {
				st = "missing"
			}
			a.printf("%-12s %s  (%s)\n", r.Name, r.Path, st)
		}
		return nil
	case "add":
		if err := p.wantArgs(2, 2, usage); err != nil {
			return err
		}
		name := p.args[1]
		if !aliasNameOK(name) {
			return usageErrf("a short name uses a-z, 0-9, - and _ and starts with a letter")
		}
		if name == "secrets-vault" {
			return usageErrf("that name is the program itself")
		}
		if runtimeIsWindows() {
			return failf("short names are not supported on Windows; use secrets-vault")
		}
		link := filepath.Join(dir, name)
		if !p.has("force") {
			if other := a.otherOnPath(name, dir); other != "" {
				return failf("'%s' is already used by another program on your PATH (%s). Skipped. Use a different name, or: %s alias add %s --force", name, other, a.prog, name)
			}
		}
		if _, err := os.Lstat(link); err == nil {
			if isLinkTo(link, real) {
				a.recordAlias(cfg, name)
				return a.aliasDone(name, link, true)
			}
			// Never delete another program's file, even with --force: the
			// only existing file we accept is a link to this program.
			return failf("%s already exists and is not a link to this program. It was not changed, even with --force. Remove or rename it yourself, or choose another name", link)
		}
		target := real
		if rd, err := filepath.EvalSymlinks(dir); err == nil && filepath.Dir(real) == rd {
			target = filepath.Base(real)
		}
		if err := os.Symlink(target, link); err != nil {
			return failf("cannot create the short name: %v", pathless(err))
		}
		a.recordAlias(cfg, name)
		return a.aliasDone(name, link, true)
	case "rm":
		if err := p.wantArgs(2, 2, usage); err != nil {
			return err
		}
		name := p.args[1]
		if !aliasNameOK(name) || name == "secrets-vault" {
			return usageErrf("a short name uses a-z, 0-9, - and _ and starts with a letter")
		}
		link := filepath.Join(dir, name)
		if !isLinkTo(link, real) {
			return failf("'%s' is not a short name for this program in %s", name, dir)
		}
		if err := os.Remove(link); err != nil {
			return failf("cannot remove it: %v", pathless(err))
		}
		cfg.Aliases = removeString(cfg.Aliases, name)
		if err := a.saveConfig(cfg); err != nil {
			return err
		}
		if a.asJSON {
			return a.printJSON(map[string]any{"removed": name})
		}
		a.printf("Removed '%s'.\n", name)
		return nil
	}
	return usageErrf("usage: %s", usage)
}

func (a *app) recordAlias(cfg *Config, name string) {
	cfg.Aliases = removeString(cfg.Aliases, name)
	cfg.Aliases = append(cfg.Aliases, name)
	_ = a.saveConfig(cfg)
}

func (a *app) aliasDone(name, link string, added bool) error {
	if a.asJSON {
		return a.printJSON(map[string]any{"added": name, "path": link})
	}
	a.printf("Added '%s' -> %s\n", name, link)
	return nil
}

func removeString(list []string, s string) []string {
	out := list[:0:0]
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

// isLinkTo reports whether path is a symlink that resolves to real.
func isLinkTo(path, real string) bool {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		return false
	}
	r, err := filepath.EvalSymlinks(path)
	return err == nil && r == real
}

// otherOnPath returns the path of another program called name that comes
// before our own folder on PATH ("" if none).
func (a *app) otherOnPath(name, ourDir string) string {
	for _, d := range filepath.SplitList(a.getenv("PATH")) {
		if d == "" {
			d = "."
		}
		if filepath.Clean(d) == filepath.Clean(ourDir) {
			return ""
		}
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}
