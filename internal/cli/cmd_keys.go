package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
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
	"time"

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

	updatedAt time.Time // for the terminal UI; not in --json
}

// MarshalJSON: a row that is not verified (a name the folder claims, never
// checked with the vault key) carries the name only. Its description, tags,
// date and author were written by whoever can write the folder, so they are
// null: they must never reach an AI agent that reads this output.
func (r keyRow) MarshalJSON() ([]byte, error) {
	if r.Verified {
		type plain keyRow
		return json.Marshal(plain(r))
	}
	return json.Marshal(struct {
		Name          string  `json:"name"`
		Vault         string  `json:"vault"`
		Description   *string `json:"description"`
		Tags          *string `json:"tags"`
		Updated       *string `json:"updated"`
		UpdatedBy     *string `json:"updated_by"`
		Locked        bool    `json:"locked"`
		Verified      bool    `json:"verified"`
		PendingChange bool    `json:"pending_change,omitempty"`
		IndexState    string  `json:"index_state"`
	}{Name: r.Name, Vault: r.Vault, Locked: r.Locked, PendingChange: r.PendingChange, IndexState: r.IndexState})
}

// vaultError is a vault that could not be listed, in --json output.
type vaultError struct {
	Vault string `json:"vault"`
	Error string `json:"error"`

	verify bool // exit code 5; for the terminal UI, not in --json
}

type vaultSummary struct {
	Name       string `json:"name"`
	Keys       int    `json:"keys"`
	Unlocked   bool   `json:"unlocked"`
	IndexState string `json:"index_state"`

	expires time.Time // for the terminal UI; not in --json
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
			verify := false
			var ee *exitErr
			if errors.As(err, &ee) {
				msg = ee.msg
				verify = ee.code == ExitUnverified
			}
			errs = append(errs, vaultError{Vault: n, Error: msg, verify: verify})
			continue
		}
		lv, err := a.lockedView(v, c)
		if err != nil {
			msg := err.Error()
			verify := false
			var ee *exitErr
			if errors.As(err, &ee) {
				msg = ee.msg
				verify = ee.code == ExitUnverified
			}
			errs = append(errs, vaultError{Vault: n, Error: msg, verify: verify})
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
			verified := lr.Verified || lv.State == index.StateLegacy
			if tag != "" && !verified {
				continue // an unverified entry's tags are not believed
			}
			count++
			tags := cleanTexts(e.Tags)
			if tags == nil {
				tags = []string{}
			}
			row := keyRow{
				Name: e.Name, Vault: n, Description: cleanText(e.Description), Tags: tags,
				Updated: e.Updated.UTC().Format("2006-01-02T15:04:05Z"), UpdatedBy: cleanText(e.UpdatedBy),
				Locked: !unlocked, Verified: verified, PendingChange: lr.Pending, IndexState: lv.State, updatedAt: e.Updated,
			}
			if !verified {
				row.Description, row.Tags, row.Updated, row.UpdatedBy, row.updatedAt = "", []string{}, "", "", time.Time{}
			}
			rows = append(rows, row)
		}
		sums = append(sums, vaultSummary{Name: n, Keys: count, Unlocked: unlocked, IndexState: lv.State, expires: states[vf.ID].Expires})
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
				d = "[unverified]"
			}
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
	if strings.HasSuffix(word, "y") && !strings.HasSuffix(word, "ey") {
		return itoa(n) + " " + word[:len(word)-1] + "ies"
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
	defer a.warnVaultErrors(errs)
	if a.asJSON {
		return a.printJSON(withErrors(rows, errs))
	}
	a.printKeyTable(rows, sums)
	return nil
}

// warnVaultErrors prints the vaults that could not be listed to stderr, after
// the results (so on a terminal they are not buried above the table).
func (a *app) warnVaultErrors(errs []vaultError) {
	for _, e := range errs {
		a.warnf("%s", e.Error)
	}
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
		hay := strings.ToLower(r.Name) // an unverified row has nothing else
		if r.Verified {
			hay = strings.ToLower(r.Name + " " + r.Description + " " + strings.Join(r.Tags, " "))
		}
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
	defer a.warnVaultErrors(errs)
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
	if !k.verified {
		// Only the name: everything else was written by the folder's writer.
		if a.asJSON {
			return a.printJSON(map[string]any{"name": e.Name, "vault": k.v.name, "description": nil, "tags": nil,
				"updated": nil, "updated_by": nil, "verified": false})
		}
		a.printf("Name         %s\nVault        %s\n", e.Name, k.v.name)
		a.printf("Verified     no (unlock %s to check this entry with the vault key; nothing else is shown until then)\n", k.v.name)
		return nil
	}
	e.Description, e.UpdatedBy = cleanText(e.Description), cleanText(e.UpdatedBy)
	tags := cleanTexts(e.Tags)
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
	val, err := a.revealValue(k)
	if err != nil {
		return err
	}
	defer clear(val)
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
	cleared, err := a.copyValue(k)
	if err != nil {
		return err
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
	var desc *string
	if p.has("desc") {
		d := p.str("desc")
		desc = &d
	}
	vault, err := a.setKey(name, p.str("vault"), a.askValue, desc)
	if err != nil {
		return err
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"name": name, "vault": vault, "saved": true})
	}
	a.printf("Saved %s to '%s'\n", name, vault)
	return nil
}

// setKey adds or updates a key. getValue is called once the vault is open
// (so a locked vault fails before anything is asked) and its result is
// zeroed here. desc nil leaves an existing description alone. Shared by
// `set` and the terminal UI.
func (a *app) setKey(name, vaultName string, getValue func() ([]byte, error), desc *string) (string, error) {
	if err := format.ValidateKeyName(name); err != nil {
		return "", usageErrf("%v", err)
	}
	var v *vaultRef
	var vf *format.VaultFile
	if k, err := a.findKey(name, vaultName); err == nil {
		v, vf = k.v, k.vf
	} else {
		var ee *exitErr
		if !errors.As(err, &ee) || (ee.code != ExitNotFound && !ee.indexDamaged) {
			return "", err
		}
		if v, err = a.defaultVault(vaultName); err != nil {
			return "", err
		}
		if vf, err = a.open(v); err != nil {
			return "", err
		}
	}
	key, err := a.openKey(v, vf, openOpts{purpose: purposeWrite})
	if err != nil {
		return "", err
	}
	defer key.Destroy()
	val, err := getValue()
	if err != nil {
		return "", err
	}
	defer clear(val)
	vi, err := a.openIndex(v, key)
	if err != nil {
		return "", err
	}
	ver, err := vi.view.NextVersion(name)
	if err != nil {
		return "", failf("%v", err)
	}
	if err := crypto.WriteSecretVersion(v.dir, name, key, val, ver); err != nil {
		if errors.Is(err, crypto.ErrTooLarge) {
			return "", failf("the value is too large")
		}
		return "", failf("cannot save the key: %v", vaultErr(err))
	}
	err = vi.commit(index.Edit{Name: name, Apply: func(cur *format.IndexEntry) (format.IndexEntry, error) {
		e := format.IndexEntry{}
		if cur != nil && !cur.Deleted {
			e = *cur
		}
		if desc != nil {
			e.Description = *desc
		}
		e.Version = max(ver, e.Version)
		e.Deleted = false
		e.Updated = a.now().UTC()
		e.UpdatedBy = a.myName()
		return e, nil
	}})
	if err != nil {
		return "", err
	}
	_, _ = format.PurgeTrash(v.dir, a.now())
	a.record(v.name, name, audit.ActionSet)
	return v.name, nil
}

func cmdDescribe(a *app, p *parsed) error {
	usage := a.prog + " describe NAME TEXT"
	if err := p.wantArgs(2, -1, usage); err != nil {
		return err
	}
	text := strings.Join(p.args[1:], " ")
	vault, name, err := a.describeKey(p.args[0], p.str("vault"), text)
	if err != nil {
		return err
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"name": name, "vault": vault, "description": text})
	}
	a.printf("Updated the description of %s.\n", name)
	return nil
}

// describeKey changes a key's description (this needs the vault unlocked:
// index entries are sealed). Shared by `describe` and the UI.
func (a *app) describeKey(name, vaultName, text string) (vault, key string, err error) {
	k, err := a.findKey(name, vaultName)
	if err != nil {
		return "", "", err
	}
	err = a.changeEntry(k, func(e *format.IndexEntry) {
		e.Description = text
	})
	if err != nil {
		return "", "", err
	}
	a.record(k.v.name, k.entry.Name, audit.ActionSet)
	return k.v.name, k.entry.Name, nil
}

// cmdTag: tag NAME tag1,tag2 [--rm]
func cmdTag(a *app, p *parsed) error {
	usage := a.prog + " tag NAME TAG[,TAG...] [--rm]"
	if err := p.wantArgs(2, 2, usage); err != nil {
		return err
	}
	tags, err := parseTagList(p.args[1])
	if err != nil {
		return err
	}
	vault, name, final, err := a.tagKey(p.args[0], p.str("vault"), tags, p.has("rm"))
	if err != nil {
		return err
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"name": name, "vault": vault, "tags": final})
	}
	a.printf("%s tags: %s\n", name, strings.Join(final, ", "))
	return nil
}

// parseTagList splits and validates "a,b,c".
func parseTagList(s string) ([]string, error) {
	var tags []string
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if err := format.ValidateTag(t); err != nil {
			return nil, usageErrf("%v", err)
		}
		tags = append(tags, t)
	}
	return tags, nil
}

// tagKey adds (or with rm removes) tags. Shared by `tag` and the UI.
func (a *app) tagKey(name, vaultName string, tags []string, rm bool) (vault, key string, final []string, err error) {
	k, err := a.findKey(name, vaultName)
	if err != nil {
		return "", "", nil, err
	}
	err = a.changeEntry(k, func(e *format.IndexEntry) {
		cur := slices.Clone(e.Tags)
		if rm {
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
		return "", "", nil, err
	}
	if final == nil {
		final = []string{}
	}
	return k.v.name, k.entry.Name, final, nil
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
	from, to, name, err := a.moveKey(p.args[0], p.str("vault"), p.str("to"))
	if err != nil {
		return err
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"name": name, "from": from, "to": to})
	}
	a.printf("Moved %s from '%s' to '%s'\n", name, from, to)
	return nil
}

// moveKey moves a key between vaults. Shared by `mv` and the UI.
func (a *app) moveKey(name, vaultName, toVault string) (from, to, key string, err error) {
	k, err := a.findKey(name, vaultName)
	if err != nil {
		return "", "", "", err
	}
	dst, err := a.vault(toVault)
	if err != nil {
		return "", "", "", err
	}
	if dst.name == k.v.name {
		return "", "", "", failf("the key is already in that vault")
	}
	dvf, err := a.open(dst)
	if err != nil {
		return "", "", "", err
	}
	val, ent, err := a.readValueInfo(k, purposeRead)
	if err != nil {
		return "", "", "", err
	}
	defer clear(val)
	dkey, err := a.openKey(dst, dvf, openOpts{purpose: purposeWrite})
	if err != nil {
		return "", "", "", err
	}
	defer dkey.Destroy()
	dvi, err := a.openIndex(dst, dkey)
	if err != nil {
		return "", "", "", err
	}
	if exists, err := dvi.exists(k.entry.Name); err != nil {
		return "", "", "", err
	} else if exists {
		return "", "", "", failf("a key with that name already exists in the destination vault")
	}
	dver, err := dvi.view.NextVersion(k.entry.Name)
	if err != nil {
		return "", "", "", failf("%v", err)
	}
	if err := crypto.WriteSecretVersion(dst.dir, k.entry.Name, dkey, val, dver); err != nil {
		return "", "", "", failf("cannot save the key in the destination vault: %v", vaultErr(err))
	}
	if err := dvi.commit(dvi.newEntryEdit(k.entry.Name, ent, dver)); err != nil {
		return "", "", "", err
	}
	if err := a.trashKey(k); err != nil {
		return "", "", "", failf("copied to the destination, but could not remove it from the source vault: %v", err)
	}
	a.record(k.v.name, k.entry.Name, audit.ActionMove)
	a.record(dst.name, k.entry.Name, audit.ActionMove)
	return k.v.name, dst.name, k.entry.Name, nil
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
	vault, err := a.renameKey(p.args[0], p.str("vault"), p.args[1])
	if err != nil {
		return err
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"vault": vault, "name": p.args[1], "renamed_from": p.args[0]})
	}
	a.printf("Renamed %s to %s in '%s'\n", p.args[0], p.args[1], vault)
	return nil
}

// renameKey renames a key (re-encrypting it: the name is bound into the
// encryption). Shared by `rename` and the UI.
func (a *app) renameKey(oldName, vaultName, newName string) (string, error) {
	if err := format.ValidateKeyName(newName); err != nil {
		return "", usageErrf("%v", err)
	}
	k, err := a.findKey(oldName, vaultName)
	if err != nil {
		return "", err
	}
	val, ent, err := a.readValueInfo(k, purposeWrite)
	if err != nil {
		return "", err
	}
	defer clear(val)
	key, err := a.openKey(k.v, k.vf, openOpts{purpose: purposeWrite})
	if err != nil {
		return "", err
	}
	defer key.Destroy()
	vi, err := a.openIndex(k.v, key)
	if err != nil {
		return "", err
	}
	if exists, err := vi.exists(newName); err != nil {
		return "", err
	} else if exists {
		return "", failf("a key with the new name already exists in '%s'", k.v.name)
	}
	nver, err := vi.view.NextVersion(newName)
	if err != nil {
		return "", failf("%v", err)
	}
	// The key name is bound into the encryption, so renaming re-encrypts.
	if err := crypto.WriteSecretVersion(k.v.dir, newName, key, val, nver); err != nil {
		return "", failf("cannot save the renamed key: %v", vaultErr(err))
	}
	if err := vi.commit(vi.newEntryEdit(newName, ent, nver), vi.tombstoneEdit(k.entry.Name)); err != nil {
		return "", err
	}
	if err := a.trashFile(k); err != nil {
		return "", failf("saved under the new name, but could not remove the old one: %v", err)
	}
	a.record(k.v.name, newName, audit.ActionRename)
	return k.v.name, nil
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
	if err := a.deleteKey(k); err != nil {
		return err
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"name": k.entry.Name, "vault": k.v.name, "deleted": true})
	}
	a.printf("Deleted %s from '%s' (kept in the trash for 30 days)\n", k.entry.Name, k.v.name)
	return nil
}

// deleteKey moves a key to the trash. It needs the vault unlocked, like any
// other change. The caller has already confirmed. Shared by `rm` and the UI.
func (a *app) deleteKey(k *keyRef) error {
	if err := a.trashKey(k); err != nil {
		return err
	}
	a.record(k.v.name, k.entry.Name, audit.ActionDelete)
	return nil
}

// revealValue decrypts one key for display or copy and records the read.
// This is the single call site for "a value was read on a person's request"
// in get, copy and the terminal UI; the audit hook lives in a.record.
func (a *app) revealValue(k *keyRef) ([]byte, error) {
	val, err := a.readValue(k, purposeRead)
	if err != nil {
		return nil, err
	}
	a.record(k.v.name, k.entry.Name, audit.ActionRead)
	return val, nil
}

// copyValue puts a key's value on the clipboard and schedules clearing it.
// It reports whether the clear was scheduled. Shared by `copy` and the UI.
func (a *app) copyValue(k *keyRef) (bool, error) {
	val, err := a.readValue(k, purposeRead)
	if err != nil {
		return false, err
	}
	defer clear(val)
	if err := a.clip.Write(val); err != nil {
		return false, failf("%v", err)
	}
	a.record(k.v.name, k.entry.Name, audit.ActionRead)
	digest := sha256.Sum256(val)
	if err := a.clip.ScheduleClear(digest, clipClearDelay); err != nil {
		a.warnf("could not schedule clearing the clipboard; clear it yourself")
		return false, nil
	}
	return true, nil
}

// childStdin gives a child process the real stdin when possible, so it can
// read a terminal directly, and the buffered reader otherwise.
func (a *app) childStdin() io.Reader {
	if f, ok := a.rawStdin.(*os.File); ok && a.in.Buffered() == 0 {
		return f
	}
	return a.in
}
