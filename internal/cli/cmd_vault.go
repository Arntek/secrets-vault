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
	pass, err := a.askNewPassphrase("Choose a passphrase for '" + name + "'")
	if err != nil {
		return err
	}
	pw, err := a.passphraseWrapper(pass)
	clear(pass)
	if err != nil {
		return failf("that passphrase cannot be used")
	}
	defer destroyWrapper(pw)
	key, err := crypto.NewVaultKey()
	if err != nil {
		return failf("cannot create a vault key")
	}
	defer key.Destroy()
	wrappers := []crypto.KeyWrapper{pw}
	touchOn := false
	if a.touch.available() && !p.has("no-touchid") && (p.has("touchid") || a.confirmDefaultYes("Use Touch ID to unlock '"+name+"' on this Mac?")) {
		if d, err := a.ensureDevice(); err != nil {
			a.warnf("%v", err)
		} else if tw, err := a.touch.wrapper(d, name); err != nil {
			a.warnf("Touch ID could not be set up: %v", err)
		} else {
			wrappers = append(wrappers, tw)
			touchOn = true
		}
	}
	vf, err := crypto.NewVaultFile(name, key, wrappers)
	if err != nil {
		return failf("cannot create the vault: %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return failf("cannot create the folder: %v", pathless(err))
	}
	if err := format.CreateVault(dir, vf); err != nil {
		return failf("cannot create the vault: %v", vaultErr(err))
	}
	cfg.Vaults[name] = &VaultEntry{Path: dir, Description: p.str("desc"), KeyID: vf.KeyID}
	if cfg.DefaultVault == "" {
		cfg.DefaultVault = name
	}
	if err := a.saveConfig(cfg); err != nil {
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
		if d, err := a.expandEntry(e); err == nil {
			if other, err := format.ReadVaultFile(d); err == nil && other.ID == vf.ID {
				return failf("that vault is already registered under another name")
			}
		}
	}
	idx, err := (&vaultRef{name: name, dir: dir}).index()
	if err != nil {
		return err
	}
	cfg.Vaults[name] = &VaultEntry{Path: dir, Description: p.str("desc"), KeyID: vf.KeyID}
	if cfg.DefaultVault == "" {
		cfg.DefaultVault = name
	}
	if err := a.saveConfig(cfg); err != nil {
		return err
	}

	res := map[string]any{"vault": name, "path": dir, "keys": len(idx.Entries)}
	member := false
	if id, ok := a.myIdentity(); ok {
		for _, u := range vf.UnlockersOf(format.UnlockerMember) {
			if u.Recipient == id.Recipient {
				member = true
			}
		}
	}
	res["member"] = member
	if member || p.has("no-request") {
		if a.asJSON {
			return a.printJSON(res)
		}
		a.printf("Registered '%s' (%d keys)\n", name, len(idx.Entries))
		return nil
	}

	// Not a member: file a join request.
	id, ok := a.myIdentity()
	if !ok {
		if id, err = a.createIdentity(p.str("as")); err != nil {
			a.warnf("Registered '%s', but no join request was filed: %v", name, err)
			return err
		}
	}
	werr := members.WriteRequest(dir, id, a.now())
	pending := errors.Is(werr, members.ErrRequestPending)
	if errors.Is(werr, members.ErrDuplicateName) {
		// The same person re-attaching finds their own request waiting.
		if old, rerr := members.ReadRequest(dir, id.Name); rerr == nil && old.Identity.Recipient == id.Recipient {
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
	if vf, err := format.ReadVaultFile(v.dir); err == nil {
		if cl := a.client(false); cl != nil {
			_ = cl.Lock(vf.ID)
		}
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

// cmdPasswd: passwd VAULT
func cmdPasswd(a *app, p *parsed) error {
	if err := p.wantArgs(1, 1, a.prog+" passwd VAULT"); err != nil {
		return err
	}
	v, err := a.vault(p.args[0])
	if err != nil {
		return err
	}
	vf, err := v.open()
	if err != nil {
		return err
	}
	if len(vf.UnlockersOf(format.UnlockerPassphrase)) == 0 {
		return failf("this vault has no passphrase unlocker")
	}
	old, err := a.askHidden("Current passphrase for '" + v.name + "': ")
	if err != nil {
		return err
	}
	ow, err := a.passphraseWrapper(old)
	clear(old)
	if err != nil {
		return failf("that passphrase cannot be used")
	}
	key, err := crypto.Unlock(vf, ow)
	destroyWrapper(ow)
	if err != nil {
		return failf("wrong passphrase")
	}
	defer key.Destroy()
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
	u, err := nw.Wrap(key)
	if err != nil {
		return failf("cannot wrap the vault key")
	}
	vf.RemoveUnlockers(func(u format.Unlocker) bool { return u.Type == format.UnlockerPassphrase })
	vf.SetUnlocker(u)
	if err := format.WriteVaultFile(v.dir, vf); err != nil {
		return failf("cannot write vault.json: %v", vaultErr(err))
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": v.name, "changed": true})
	}
	a.printf("Passphrase changed for '%s'.\n", v.name)
	return nil
}

// cmdTouchID: touchid on|off|list [VAULT]
func cmdTouchID(a *app, p *parsed) error {
	usage := a.prog + " touchid on|off|list [VAULT]"
	if err := p.wantArgs(1, 2, usage); err != nil {
		return err
	}
	sub := p.args[0]
	arg := ""
	if len(p.args) == 2 {
		arg = p.args[1]
	}
	switch sub {
	case "on":
		v, err := a.defaultVault(arg)
		if err != nil {
			return err
		}
		vf, err := v.open()
		if err != nil {
			return err
		}
		d, err := a.ensureDevice()
		if err != nil {
			return err
		}
		tw, err := a.touch.wrapper(d, v.name)
		if err != nil {
			return failf("Touch ID could not be set up: %v", err)
		}
		key, err := a.openKey(v, vf, openOpts{purpose: purposeWrite})
		if err != nil {
			return err
		}
		defer key.Destroy()
		u, err := tw.Wrap(key)
		if err != nil {
			return failf("Touch ID could not wrap the vault key: %v", err)
		}
		vf.SetUnlocker(u)
		if err := format.WriteVaultFile(v.dir, vf); err != nil {
			return failf("cannot write vault.json: %v", vaultErr(err))
		}
		if a.asJSON {
			return a.printJSON(map[string]any{"vault": v.name, "touchid": true})
		}
		a.printf("Touch ID is on for '%s' on this Mac.\n", v.name)
		return nil
	case "off":
		v, err := a.defaultVault(arg)
		if err != nil {
			return err
		}
		vf, err := v.open()
		if err != nil {
			return err
		}
		rec := a.thisMacRecipient()
		if rec == "" {
			return failf("Touch ID is not set up on this Mac")
		}
		n := vf.RemoveUnlockers(func(u format.Unlocker) bool {
			return u.Type == format.UnlockerTouchID && u.Recipient == rec
		})
		if n == 0 {
			return failf("Touch ID is not on for '%s' on this Mac", v.name)
		}
		if len(vf.Unlockers) == 0 {
			return failf("that would leave the vault with no way to open it")
		}
		if err := format.WriteVaultFile(v.dir, vf); err != nil {
			return failf("cannot write vault.json: %v", vaultErr(err))
		}
		if a.asJSON {
			return a.printJSON(map[string]any{"vault": v.name, "touchid": false})
		}
		a.printf("Touch ID is off for '%s' on this Mac.\n", v.name)
		return nil
	case "list":
		var names []string
		if arg != "" {
			v, err := a.vault(arg)
			if err != nil {
				return err
			}
			names = []string{v.name}
		} else {
			var err error
			if names, err = a.vaultNames(); err != nil {
				return err
			}
		}
		rec := a.thisMacRecipient()
		type row struct {
			Vault   string    `json:"vault"`
			Device  string    `json:"device"`
			Created time.Time `json:"created"`
			ThisMac bool      `json:"this_mac"`
		}
		rows := []row{}
		for _, n := range names {
			v, err := a.vault(n)
			if err != nil {
				return err
			}
			vf, err := format.ReadVaultFile(v.dir)
			if err != nil {
				a.warnf("vault '%s' is unavailable", n)
				continue
			}
			for _, u := range vf.UnlockersOf(format.UnlockerTouchID) {
				rows = append(rows, row{n, u.Label, u.Created, rec != "" && u.Recipient == rec})
			}
		}
		if a.asJSON {
			return a.printJSON(rows)
		}
		if len(rows) == 0 {
			a.printf("No Macs can unlock these vaults with Touch ID yet. Run: %s touchid on VAULT\n", a.prog)
			return nil
		}
		t := newTable(a.out, "VAULT", "MAC", "ADDED", "")
		for _, r := range rows {
			here := ""
			if r.ThisMac {
				here = "(this Mac)"
			}
			t.row(r.Vault, r.Device, r.Created.Local().Format("2006-01-02"), here)
		}
		t.flush()
		return nil
	}
	return usageErrf("usage: %s", usage)
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
		if fi, err := os.Lstat(link); err == nil {
			if isLinkTo(link, real) {
				a.recordAlias(cfg, name)
				return a.aliasDone(name, link, true)
			}
			if !p.has("force") || fi.IsDir() {
				return failf("'%s' already exists in %s and is not a link to this program", name, dir)
			}
			if err := os.Remove(link); err != nil {
				return failf("cannot replace the existing file: %v", pathless(err))
			}
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
