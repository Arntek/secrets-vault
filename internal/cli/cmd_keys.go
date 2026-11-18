package cli

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/Arntek/secrets-vault/internal/audit"
	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/index"
	"github.com/Arntek/secrets-vault/internal/members"
)

// --- listing ---

type keyRow struct {
	Name        string   `json:"name"`
	Vault       string   `json:"vault"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Updated     string   `json:"updated"`
	UpdatedBy   string   `json:"updated_by,omitempty"`
	Locked      bool     `json:"locked"`
	// Verified is true when the row is what this machine last verified
	// with the vault key; false for a name only the folder claims (the
	// index can't be checked without unlocking). PendingChange: the folder
	// holds a different entry than the verified one shown.
	Verified      bool   `json:"verified"`
	PendingChange bool   `json:"pending_change,omitempty"`
	IndexState    string `json:"index_state"`
}

// vaultError is a vault that could not be listed, in --json output.
type vaultError struct {
	Vault string `json:"vault"`
	Error string `json:"error"`
}

type vaultSummary struct {
	Name       string `json:"name"`
	Keys       int    `json:"keys"`
	Unlocked   bool   `json:"unlocked"`
	IndexState string `json:"index_state"`
}

// collectKeys reads every registered vault's index (no unlock needed).
func (a *app) collectKeys(vaultFilter, tag string) ([]keyRow, []vaultSummary, []vaultError, error) {
	names, err := a.vaultNames()
	if err != nil {
		return nil, nil, nil, err
	}
	if vaultFilter != "" {
		if _, err := a.vault(vaultFilter); err != nil {
			return nil, nil, nil, err
		}
		names = []string{vaultFilter}
	}
	if tag != "" {
		if err := format.ValidateTag(tag); err != nil {
			return nil, nil, nil, usageErrf("%v", err)
		}
	}
	states := a.lockStates()
	rows := []keyRow{}
	sums := []vaultSummary{}
	errs := []vaultError{}
	for _, n := range names {
		v, err := a.vault(n)
		if err != nil {
			return nil, nil, nil, err
		}
		// Verified and classified against this machine's pin (no prompts, no
		// writes), so a tampered, substituted or quarantined vault is
		// reported, never silently answered from (ue1.10, ue1.12).
		c, vf, err := a.openQuiet(v)
		if err != nil && !errors.Is(err, members.ErrOldFormat) {
			msg := err.Error()
			var ee *exitErr
			if errors.As(err, &ee) {
				msg = ee.msg
			}
			a.warnf("%s", msg)
			errs = append(errs, vaultError{Vault: n, Error: msg})
			continue
		}
		lv, err := a.lockedView(v, c)
		if err != nil {
			msg := err.Error()
			var ee *exitErr
			if errors.As(err, &ee) {
				msg = ee.msg
			}
			a.warnf("%s", msg)
			errs = append(errs, vaultError{Vault: n, Error: msg})
			continue
		}
		a.noteIndexState(v, lv)
		unlocked := states[vf.ID].Unlocked
		count := 0
		for _, lr := range lv.Rows {
			e := lr.Entry
			if tag != "" && !slices.Contains(e.Tags, tag) {
				continue
			}
			count++
			tags := e.Tags
			if tags == nil {
				tags = []string{}
			}
			rows = append(rows, keyRow{
				Name: e.Name, Vault: n, Description: e.Description, Tags: tags,
				Updated: e.Updated.UTC().Format("2006-01-02T15:04:05Z"), UpdatedBy: e.UpdatedBy,
				Locked: !unlocked, Verified: lr.Verified || lv.State == index.StateLegacy, PendingChange: lr.Pending, IndexState: lv.State,
			})
		}
		sums = append(sums, vaultSummary{Name: n, Keys: count, Unlocked: unlocked, IndexState: lv.State})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].Vault < rows[j].Vault
	})
	return rows, sums, errs, nil
}

func (a *app) printKeyTable(rows []keyRow, sums []vaultSummary) {
	if len(rows) == 0 {
		a.printf("No keys.\n")
	} else {
		t := newTable(a.out, "NAME", "VAULT", "DESCRIPTION")
		for _, r := range rows {
			d := r.Description
			if !r.Verified {
				d = "[unverified] " + d
			}
			t.row(r.Name, r.Vault, d)
		}
		t.flush()
	}
	parts := []string{plural(len(sums), "vault"), plural(len(rows), "key")}
	for _, s := range sums {
		icon := "🔒"
		if s.Unlocked {
			icon = "🔓"
		}
		parts = append(parts, s.Name+" "+icon)
	}
	a.printf("  %s\n", strings.Join(parts, " · "))
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return itoa(n) + " " + word + "s"
}

// withErrors appends vaults that could not be listed to a --json key list
// as {"vault": ..., "error": ...} entries.
func withErrors(rows []keyRow, errs []vaultError) []any {
	out := make([]any, 0, len(rows)+len(errs))
	for _, r := range rows {
		out = append(out, r)
	}
	for _, e := range errs {
		out = append(out, e)
	}
	return out
}

func cmdList(a *app, p *parsed) error {
	if err := p.wantArgs(0, 0, a.prog+" list [--vault V] [--tag T]"); err != nil {
		return err
	}
	rows, sums, errs, err := a.collectKeys(p.str("vault"), p.str("tag"))
	if err != nil {
		return err
	}
	if a.asJSON {
		return a.printJSON(withErrors(rows, errs))
	}
	a.printKeyTable(rows, sums)
	return nil
}

func cmdSearch(a *app, p *parsed) error {
	if err := p.wantArgs(1, -1, a.prog+" search WORDS"); err != nil {
		return err
	}
	rows, sums, errs, err := a.collectKeys(p.str("vault"), p.str("tag"))
	if err != nil {
		return err
	}
	words := make([]string, len(p.args))
	for i, w := range p.args {
		words[i] = strings.ToLower(w)
	}
	out := rows[:0:0]
	for _, r := range rows {
		hay := strings.ToLower(r.Name + " " + r.Description + " " + strings.Join(r.Tags, " "))
		ok := true
		for _, w := range words {
			if !strings.Contains(hay, w) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, r)
		}
	}
	if a.asJSON {
		return a.printJSON(withErrors(out, errs))
	}
	a.printKeyTable(out, sums)
	return nil
}

func cmdInfo(a *app, p *parsed) error {
	if err := p.wantArgs(1, 1, a.prog+" info NAME [--vault V]"); err != nil {
		return err
	}
	k, err := a.findKey(p.args[0], p.str("vault"))
	if err != nil {
		return err
	}
	e := k.entry
	tags := e.Tags
	if tags == nil {
		tags = []string{}
	}
	if a.asJSON {
		return a.printJSON(map[string]any{
			"name": e.Name, "vault": k.v.name, "description": e.Description, "tags": tags,
			"updated": e.Updated.UTC().Format("2006-01-02T15:04:05Z"), "updated_by": e.UpdatedBy,
			"verified": k.verified,
		})
	}
	a.printf("Name         %s\n", e.Name)
	a.printf("Vault        %s\n", k.v.name)
	a.printf("Description  %s\n", e.Description)
	a.printf("Tags         %s\n", strings.Join(tags, ", "))
	a.printf("Updated      %s\n", e.Updated.Local().Format("2006-01-02 15:04"))
	if e.UpdatedBy != "" {
		a.printf("Updated by   %s\n", e.UpdatedBy)
	}
	if !k.verified {
		a.printf("Verified     no (unlock %s to check this entry with the vault key)\n", k.v.name)
	}
	return nil
}

// --- reading values ---

// readValue decrypts one key. The caller zeroes the result.
func (a *app) readValue(k *keyRef, p purpose) ([]byte, error) {
	val, _, err := a.readValueInfo(k, p)
	return val, err
}

// readValueInfo is readValue that also returns the verified index entry of
// the key (its description and tags are what the vault key vouches for,
// unlike the entry a locked listing showed).
func (a *app) readValueInfo(k *keyRef, p purpose) ([]byte, format.IndexEntry, error) {
	key, err := a.openKey(k.v, k.vf, openOpts{purpose: p})
	if err != nil {
		return nil, format.IndexEntry{}, err
	}
	defer key.Destroy()
	return a.decryptInfo(k, key)
}

// decryptInfo opens the vault's authenticated index with key and reads one
// key through it: the value is returned only if the entry and the file
// agree (docs/design/index-auth.md).
func (a *app) decryptInfo(k *keyRef, key *crypto.VaultKey) ([]byte, format.IndexEntry, error) {
	vi, err := a.openIndex(k.v, key)
	if err != nil {
		return nil, format.IndexEntry{}, err
	}
	val, ki, err := vi.read(k.entry.Name)
	if err != nil {
		return nil, format.IndexEntry{}, err
	}
	return val, ki.Entry, nil
}

// record writes one event to the read log (names only, never a value),
// with the command and the calling program. It never fails the command: a
// log that cannot be written produces one warning and the read goes on.
func (a *app) record(vault, key string, act audit.Action) {
	a.recordEvent(audit.Event{Vault: vault, Key: key, Action: act})
}

func (a *app) recordVia(vault string, act audit.Action, via string) {
	a.recordEvent(audit.Event{Vault: vault, Action: act, Via: via})
}

func (a *app) recordEvent(e audit.Event) {
	if a.audit == nil {
		d, err := a.configDir()
		if err != nil {
			a.auditFailed(err)
			return
		}
		a.audit = audit.NewFile(filepath.Join(d, "audit.log"))
	}
	e.Time = a.now()
	e.Command = a.cmdName
	e.Program, e.PID = a.callerInfo()
	if err := a.audit.Record(e); err != nil {
		a.auditFailed(err)
	}
}

// auditFailed warns once per command. The error is the file system's own
// (no path, no event contents).
func (a *app) auditFailed(err error) {
	if a.auditWarned {
		return
	}
	a.auditWarned = true
	var ee *exitErr
	if errors.As(err, &ee) {
		err = errors.New(ee.msg)
	}
	a.warnf("warning: could not write the read log (%v); carrying on", err)
}

func cmdGet(a *app, p *parsed) error {
	if err := p.wantArgs(1, 1, a.prog+" get NAME [--vault V] [--reveal] [-n]"); err != nil {
		return err
	}
	k, err := a.findKey(p.args[0], p.str("vault"))
	if err != nil {
		return err
	}
	val, err := a.readValue(k, purposeRead)
	if err != nil {
		return err
	}
	defer clear(val)
	a.record(k.v.name, k.entry.Name, audit.ActionRead)
	masked := a.term.StdoutTTY() && !p.has("reveal")
	if a.asJSON {
		out := map[string]any{"name": k.entry.Name, "vault": k.v.name}
		if masked {
			out["value"] = nil
			out["masked"] = true
		} else {
			out["value"] = string(val)
		}
		return a.printJSON(out)
	}
	if masked {
		a.printf("••••••••  (hidden; use --reveal to show it, or pipe the output)\n")
		return nil
	}
	if _, err := a.out.Write(val); err != nil {
		return failf("cannot write the value")
	}
	if !p.has("no-newline") {
		a.printf("\n")
	}
	return nil
}

func cmdCopy(a *app, p *parsed) error {
	if err := p.wantArgs(1, 1, a.prog+" copy NAME [--vault V]"); err != nil {
		return err
	}
	k, err := a.findKey(p.args[0], p.str("vault"))
	if err != nil {
		return err
	}
	val, err := a.readValue(k, purposeRead)
	if err != nil {
		return err
	}
	defer clear(val)
	if err := a.clip.Write(val); err != nil {
		return failf("%v", err)
	}
	a.record(k.v.name, k.entry.Name, audit.ActionRead)
	digest := sha256.Sum256(val)
	cleared := true
	if err := a.clip.ScheduleClear(digest, clipClearDelay); err != nil {
		cleared = false
		a.warnf("could not schedule clearing the clipboard; clear it yourself")
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"name": k.entry.Name, "vault": k.v.name, "copied": true, "clears_in_seconds": int(clipClearDelay.Seconds()), "will_clear": cleared})
	}
	a.printf("Copied %s to the clipboard. It will be cleared in %d seconds.\n", k.entry.Name, int(clipClearDelay.Seconds()))
	return nil
}

// cmdRun: run -k A [-k B] -- cmd args
func cmdRun(a *app, p *parsed) error {
	usage := a.prog + " run -k NAME [-k NAME ...] [--vault V] -- COMMAND [ARGS]"
	names := p.all("key")
	if len(names) == 0 || len(p.rest) == 0 || len(p.args) != 0 {
		return usageErrf("usage: %s", usage)
	}
	seen := map[string]bool{}
	var refs []*keyRef
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		k, err := a.findKey(n, p.str("vault"))
		if err != nil {
			return err
		}
		refs = append(refs, k)
	}
	// Resolve and unlock everything before starting the child, so a locked
	// vault stops the run before anything executes.
	vals := make([][]byte, 0, len(refs))
	defer func() {
		for _, v := range vals {
			clear(v)
		}
	}()
	for _, k := range refs {
		val, err := a.readValue(k, purposeRead)
		if err != nil {
			return err
		}
		vals = append(vals, val)
		a.record(k.v.name, k.entry.Name, audit.ActionRead)
	}
	env := make([]string, 0, len(a.environ())+len(refs))
	for _, kv := range a.environ() {
		name, _, _ := strings.Cut(kv, "=")
		if seen[name] {
			continue
		}
		env = append(env, kv)
	}
	for i, k := range refs {
		env = append(env, k.entry.Name+"="+string(vals[i]))
	}
	defer clear(env)

	cmd := exec.Command(p.rest[0], p.rest[1:]...) // #nosec G204 -- running the user's own command is the point
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = a.out, a.errOut
	cmd.Stdin = a.childStdin()
	if err := cmd.Start(); err != nil {
		code := 126
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			code = 127
		}
		return &exitErr{code: code, msg: "could not start the command"}
	}
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return &exitErr{code: exitCodeOf(ee), msg: ""}
		}
		return failf("the command failed to run")
	}
	return nil
}

// --- writing ---

func (a *app) readStdinValue() ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(a.in, maxStdinValueSize+1))
	if err != nil {
		return nil, failf("could not read the value from stdin")
	}
	if len(b) > maxStdinValueSize {
		clear(b)
		return nil, failf("the value is too large")
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	if len(b) == 0 {
		return nil, failf("no value given on stdin")
	}
	return b, nil
}

func (a *app) askValue() ([]byte, error) {
	if a.term.StdinTTY() {
		fmt.Fprint(a.errOut, "Value (hidden): ")
		b, err := a.term.ReadPassword()
		fmt.Fprint(a.errOut, "\n")
		if err != nil || len(b) == 0 {
			return nil, failf("no value given")
		}
		return b, nil
	}
	return a.readStdinValue()
}

// cmdSet: set NAME [--vault V] [--desc TEXT]
func cmdSet(a *app, p *parsed) error {
	usage := a.prog + " set NAME [--vault V] [--desc TEXT]"
	if len(p.args) > 1 {
		return usageErrf("a value must not be given as an argument: it would be saved in your shell history. "+
			"Type it at the prompt, or pipe it in (for example: printf %%s \"$VALUE\" | %s set NAME)", a.prog)
	}
	if err := p.wantArgs(1, 1, usage); err != nil {
		return err
	}
	name := p.args[0]
	if err := format.ValidateKeyName(name); err != nil {
		return usageErrf("%v", err)
	}
	var v *vaultRef
	var vf *format.VaultFile
	if k, err := a.findKey(name, p.str("vault")); err == nil {
		v, vf = k.v, k.vf
	} else {
		var ee *exitErr
		if !errors.As(err, &ee) || (ee.code != ExitNotFound && !ee.indexDamaged) {
			return err
		}
		if v, err = a.defaultVault(p.str("vault")); err != nil {
			return err
		}
		if vf, err = a.open(v); err != nil {
			return err
		}
	}
	key, err := a.openKey(v, vf, openOpts{purpose: purposeWrite})
	if err != nil {
		return err
	}
	defer key.Destroy()
	val, err := a.askValue()
	if err != nil {
		return err
	}
	defer clear(val)
	vi, err := a.openIndex(v, key)
	if err != nil {
		return err
	}
	ver, err := vi.view.NextVersion(name)
	if err != nil {
		return failf("%v", err)
	}
	if err := crypto.WriteSecretVersion(v.dir, name, key, val, ver); err != nil {
		if errors.Is(err, crypto.ErrTooLarge) {
			return failf("the value is too large")
		}
		return failf("cannot save the key: %v", vaultErr(err))
	}
	err = vi.commit(index.Edit{Name: name, Apply: func(cur *format.IndexEntry) (format.IndexEntry, error) {
		e := format.IndexEntry{}
		if cur != nil && !cur.Deleted {
			e = *cur
		}
		if p.has("desc") {
			e.Description = p.str("desc")
		}
		e.Version = max(ver, e.Version)
		e.Deleted = false
		e.Updated = a.now().UTC()
		e.UpdatedBy = a.myName()
		return e, nil
	}})
	if err != nil {
		return err
	}
	_, _ = format.PurgeTrash(v.dir, a.now())
	a.record(v.name, name, audit.ActionSet)
	if a.asJSON {
		return a.printJSON(map[string]any{"name": name, "vault": v.name, "saved": true})
	}
	a.printf("Saved %s to '%s'\n", name, v.name)
	return nil
}

func cmdDescribe(a *app, p *parsed) error {
	usage := a.prog + " describe NAME TEXT"
	if err := p.wantArgs(2, -1, usage); err != nil {
		return err
	}
	k, err := a.findKey(p.args[0], p.str("vault"))
	if err != nil {
		return err
	}
	text := strings.Join(p.args[1:], " ")
	err = a.changeEntry(k, func(e *format.IndexEntry) {
		e.Description = text
	})
	if err != nil {
		return err
	}
	a.record(k.v.name, k.entry.Name, audit.ActionSet)
	if a.asJSON {
		return a.printJSON(map[string]any{"name": k.entry.Name, "vault": k.v.name, "description": text})
	}
	a.printf("Updated the description of %s.\n", k.entry.Name)
	return nil
}

// cmdTag: tag NAME tag1,tag2 [--rm]
func cmdTag(a *app, p *parsed) error {
	usage := a.prog + " tag NAME TAG[,TAG...] [--rm]"
	if err := p.wantArgs(2, 2, usage); err != nil {
		return err
	}
	k, err := a.findKey(p.args[0], p.str("vault"))
	if err != nil {
		return err
	}
	var tags []string
	for _, t := range strings.Split(p.args[1], ",") {
		t = strings.TrimSpace(t)
		if err := format.ValidateTag(t); err != nil {
			return usageErrf("%v", err)
		}
		tags = append(tags, t)
	}
	var final []string
	err = a.changeEntry(k, func(e *format.IndexEntry) {
		cur := slices.Clone(e.Tags)
		if p.has("rm") {
			cur = slices.DeleteFunc(cur, func(t string) bool { return slices.Contains(tags, t) })
		} else {
			for _, t := range tags {
				if !slices.Contains(cur, t) {
					cur = append(cur, t)
				}
			}
		}
		slices.Sort(cur)
		e.Tags, final = cur, cur
	})
	if err != nil {
		return err
	}
	if final == nil {
		final = []string{}
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"name": k.entry.Name, "vault": k.v.name, "tags": final})
	}
	a.printf("%s tags: %s\n", k.entry.Name, strings.Join(final, ", "))
	return nil
}

// cmdMv: mv NAME --to VAULT [--vault SRC]
func cmdMv(a *app, p *parsed) error {
	usage := a.prog + " mv NAME --to VAULT [--vault SRC]"
	if err := p.wantArgs(1, 1, usage); err != nil {
		return err
	}
	if !p.has("to") {
		return usageErrf("usage: %s", usage)
	}
	k, err := a.findKey(p.args[0], p.str("vault"))
	if err != nil {
		return err
	}
	dst, err := a.vault(p.str("to"))
	if err != nil {
		return err
	}
	if dst.name == k.v.name {
		return failf("the key is already in that vault")
	}
	dvf, err := a.open(dst)
	if err != nil {
		return err
	}
	val, ent, err := a.readValueInfo(k, purposeRead)
	if err != nil {
		return err
	}
	defer clear(val)
	dkey, err := a.openKey(dst, dvf, openOpts{purpose: purposeWrite})
	if err != nil {
		return err
	}
	defer dkey.Destroy()
	dvi, err := a.openIndex(dst, dkey)
	if err != nil {
		return err
	}
	if exists, err := dvi.exists(k.entry.Name); err != nil {
		return err
	} else if exists {
		return failf("a key with that name already exists in the destination vault")
	}
	dver, err := dvi.view.NextVersion(k.entry.Name)
	if err != nil {
		return failf("%v", err)
	}
	if err := crypto.WriteSecretVersion(dst.dir, k.entry.Name, dkey, val, dver); err != nil {
		return failf("cannot save the key in the destination vault: %v", vaultErr(err))
	}
	if err := dvi.commit(dvi.newEntryEdit(k.entry.Name, ent, dver)); err != nil {
		return err
	}
	if err := a.trashKey(k); err != nil {
		return failf("copied to the destination, but could not remove it from the source vault: %v", err)
	}
	a.record(k.v.name, k.entry.Name, audit.ActionMove)
	a.record(dst.name, k.entry.Name, audit.ActionMove)
	if a.asJSON {
		return a.printJSON(map[string]any{"name": k.entry.Name, "from": k.v.name, "to": dst.name})
	}
	a.printf("Moved %s from '%s' to '%s'\n", k.entry.Name, k.v.name, dst.name)
	return nil
}

// trashKey deletes a key: its entry becomes a signed tombstone, then the
// file moves to the trash. It opens the vault for writing (an index entry
// can only be sealed with the vault key).
func (a *app) trashKey(k *keyRef) error {
	key, err := a.openKey(k.v, k.vf, openOpts{purpose: purposeWrite})
	if err != nil {
		return err
	}
	defer key.Destroy()
	vi, err := a.openIndex(k.v, key)
	if err != nil {
		return err
	}
	if err := vi.commit(vi.tombstoneEdit(k.entry.Name)); err != nil {
		return err
	}
	return a.trashFile(k)
}

// trashFile moves a key's file to the trash (its tombstone is already
// written) and purges old trash.
func (a *app) trashFile(k *keyRef) error {
	if _, err := format.TrashSecret(k.v.dir, k.entry.Name, a.now()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return vaultErr(err)
	}
	_, _ = format.PurgeTrash(k.v.dir, a.now())
	return nil
}

// cmdRename: rename OLD NEW
func cmdRename(a *app, p *parsed) error {
	if err := p.wantArgs(2, 2, a.prog+" rename OLD NEW [--vault V]"); err != nil {
		return err
	}
	if err := format.ValidateKeyName(p.args[1]); err != nil {
		return usageErrf("%v", err)
	}
	newName := p.args[1]
	k, err := a.findKey(p.args[0], p.str("vault"))
	if err != nil {
		return err
	}
	val, ent, err := a.readValueInfo(k, purposeWrite)
	if err != nil {
		return err
	}
	defer clear(val)
	key, err := a.openKey(k.v, k.vf, openOpts{purpose: purposeWrite})
	if err != nil {
		return err
	}
	defer key.Destroy()
	vi, err := a.openIndex(k.v, key)
	if err != nil {
		return err
	}
	if exists, err := vi.exists(newName); err != nil {
		return err
	} else if exists {
		return failf("a key with the new name already exists in '%s'", k.v.name)
	}
	nver, err := vi.view.NextVersion(newName)
	if err != nil {
		return failf("%v", err)
	}
	// The key name is bound into the encryption, so renaming re-encrypts.
	if err := crypto.WriteSecretVersion(k.v.dir, newName, key, val, nver); err != nil {
		return failf("cannot save the renamed key: %v", vaultErr(err))
	}
	if err := vi.commit(vi.newEntryEdit(newName, ent, nver), vi.tombstoneEdit(k.entry.Name)); err != nil {
		return err
	}
	if err := a.trashFile(k); err != nil {
		return failf("saved under the new name, but could not remove the old one: %v", err)
	}
	a.record(k.v.name, newName, audit.ActionRename)
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": k.v.name, "name": newName, "renamed_from": k.entry.Name})
	}
	a.printf("Renamed %s to %s in '%s'\n", k.entry.Name, newName, k.v.name)
	return nil
}

// cmdRm: rm NAME [--yes]
func cmdRm(a *app, p *parsed) error {
	if err := p.wantArgs(1, 1, a.prog+" rm NAME [--vault V] [--yes]"); err != nil {
		return err
	}
	k, err := a.findKey(p.args[0], p.str("vault"))
	if err != nil {
		return err
	}
	if !p.has("yes") {
		if !a.term.StdinTTY() {
			return failf("deleting needs confirmation: run it in a terminal, or pass --yes")
		}
		ok, _ := a.confirm("Delete " + k.entry.Name + " from '" + k.v.name + "'? It stays in the trash for 30 days.")
		if !ok {
			return failf("cancelled")
		}
	}
	// Deleting needs the vault unlocked, like any other change.
	if err := a.trashKey(k); err != nil {
		return err
	}
	a.record(k.v.name, k.entry.Name, audit.ActionDelete)
	if a.asJSON {
		return a.printJSON(map[string]any{"name": k.entry.Name, "vault": k.v.name, "deleted": true})
	}
	a.printf("Deleted %s from '%s' (kept in the trash for 30 days)\n", k.entry.Name, k.v.name)
	return nil
}

// childStdin gives a child process the real stdin when possible, so it can
// read a terminal directly, and the buffered reader otherwise.
func (a *app) childStdin() io.Reader {
	if f, ok := a.rawStdin.(*os.File); ok && a.in.Buffered() == 0 {
		return f
	}
	return a.in
}
