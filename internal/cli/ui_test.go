package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Arntek/secrets-vault/internal/audit"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/tui"
)

// uiDriver runs the real terminal-UI model against the real operations
// (temp HOME, test passphrase), executing commands the way Bubble Tea does.
type uiDriver struct {
	t        *testing.T
	m        *tui.Model
	b        *uiBackend
	msgs     chan tea.Msg
	inflight chan tea.Msg
	frames   []string
	rec      *recAudit
}

type recAudit struct{ events []audit.Event }

func (r *recAudit) Record(e audit.Event) error { r.events = append(r.events, e); return nil }

func (r *recAudit) count(act audit.Action, key string) int {
	n := 0
	for _, e := range r.events {
		if e.Action == act && e.Key == key {
			n++
		}
	}
	return n
}

func newUIDriver(t *testing.T, e *testEnv) *uiDriver {
	t.Helper()
	e.activate()
	a := newApp("sv", strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})

	d := &uiDriver{t: t, msgs: make(chan tea.Msg, 16), rec: &recAudit{}}
	a.audit = d.rec
	d.b = newUIBackend(a)
	t.Cleanup(a.close)
	d.m = tui.New(d.b, tui.Options{NoColor: true})
	d.m.Attach(func(msg tea.Msg) { d.msgs <- msg })
	d.m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	d.press("R")
	return d
}

func (d *uiDriver) run(cmd tea.Cmd) {
	d.t.Helper()
	if cmd == nil {
		return
	}
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	d.inflight = done
	d.pump()
}

func (d *uiDriver) pump() {
	d.t.Helper()
	for d.inflight != nil {
		select {
		case msg := <-d.inflight:
			d.inflight = nil
			d.deliver(msg)
		case msg := <-d.msgs:
			d.deliver(msg)
			if strings.Contains(d.m.View(), "┌─ Unlock") {
				return
			}
		case <-time.After(20 * time.Second):
			d.t.Fatal("command did not finish")
		}
	}
}

func (d *uiDriver) deliver(msg tea.Msg) {
	d.t.Helper()
	if b, ok := msg.(tea.BatchMsg); ok {
		for _, c := range b {
			d.run(c)
		}
		return
	}
	_, cmd := d.m.Update(msg)
	d.frames = append(d.frames, d.m.View())
	if cmd != nil && d.inflight == nil {
		d.run(cmd)
	}
}

func (d *uiDriver) key(k tea.KeyMsg) {
	d.t.Helper()
	_, cmd := d.m.Update(k)
	d.frames = append(d.frames, d.m.View())
	switch {
	case cmd != nil && d.inflight == nil:
		d.run(cmd)
	case d.inflight != nil && (k.Type == tea.KeyEnter || k.Type == tea.KeyEsc):
		d.pump()
	}
}

func (d *uiDriver) press(s string) {
	d.t.Helper()
	for _, r := range s {
		if r == ' ' {
			d.key(tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}})
		} else {
			d.key(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		}
	}
}
func (d *uiDriver) enter()       { d.key(tea.KeyMsg{Type: tea.KeyEnter}) }
func (d *uiDriver) esc()         { d.key(tea.KeyMsg{Type: tea.KeyEsc}) }
func (d *uiDriver) view() string { return d.m.View() }

func (d *uiDriver) want(parts ...string) {
	d.t.Helper()
	v := d.view()
	for _, p := range parts {
		if !strings.Contains(v, p) {
			d.t.Fatalf("screen lacks %q:\n%s", p, v)
		}
	}
}

func (d *uiDriver) goTo(name string) {
	d.t.Helper()
	d.press("g")
	for i := 0; i < 40; i++ {
		if strings.Contains(d.view(), "▸ "+name+" ") || strings.Contains(d.view(), "▸ "+name+"\u00a0") {
			return
		}
		d.press("j")
	}
	d.t.Fatalf("cannot select %s:\n%s", name, d.view())
}

func twoVaults(t *testing.T) (*testEnv, string, string) {
	skipWindows(t)
	e := newEnv(t)
	d1 := e.initVault("personal")
	d2 := e.initVault("work")
	e.unlock("personal")
	e.unlock("work")
	return e, d1, d2
}

func TestUIAddEditDescribeTagRenameMoveDelete(t *testing.T) {
	e, _, _ := twoVaults(t)
	e.set("EXISTING", "personal", "existing-value")
	d := newUIDriver(t, e)
	d.want("2 vaults · 1 key", "EXISTING", "test key existing")

	// Add into a chosen vault: the same code path as `vault set`.
	d.press("a")
	d.press("work")
	d.enter()
	d.press("UI_KEY")
	d.enter()
	d.press("typed-in-the-ui")
	d.enter()
	d.press("made in the UI")
	d.enter()
	d.want("Saved UI_KEY.", "made in the UI")
	if got := e.mustRun("get", "UI_KEY").out; got != "typed-in-the-ui\n" {
		t.Fatalf("saved value %q", got)
	}
	info := decodeJSON[map[string]any](t, e.mustRun("info", "UI_KEY", "--json").out)
	if info["vault"] != "work" || info["description"] != "made in the UI" || info["updated_by"] != testUser {
		t.Fatalf("info %v", info)
	}
	if d.rec.count(audit.ActionSet, "UI_KEY") != 1 {
		t.Fatalf("audit events %v", d.rec.events)
	}

	// Edit the value, keep the description.
	d.press("e")
	d.press("second-value")
	d.enter()
	if got := e.mustRun("get", "UI_KEY").out; got != "second-value\n" {
		t.Fatalf("edited value %q", got)
	}
	d.want("made in the UI")

	// Describe and tag.
	d.press("d")
	d.press(" (v2)")
	d.enter()
	d.press("t")
	d.press(", ci, deploy")
	d.enter()
	info = decodeJSON[map[string]any](t, e.mustRun("info", "UI_KEY", "--json").out)
	if info["description"] != "made in the UI (v2)" || strings.Join(toStrings(info["tags"]), ",") != "ci,deploy" {
		t.Fatalf("info %v", info)
	}
	d.press("t") // drop one tag
	for i := 0; i < len("ci, deploy"); i++ {
		d.key(tea.KeyMsg{Type: tea.KeyBackspace})
	}
	d.press("deploy")
	d.enter()
	info = decodeJSON[map[string]any](t, e.mustRun("info", "UI_KEY", "--json").out)
	if strings.Join(toStrings(info["tags"]), ",") != "deploy" {
		t.Fatalf("tags %v", info["tags"])
	}

	// Rename, then move to the other vault.
	d.press("r")
	d.press("2")
	d.enter()
	d.want("Renamed to UI_KEY2.")
	expectCode(t, e.run("get", "UI_KEY"), ExitNotFound)
	if got := e.mustRun("get", "UI_KEY2").out; got != "second-value\n" {
		t.Fatalf("renamed value %q", got)
	}
	d.press("m")
	d.press("personal")
	d.enter()
	d.want("Moved UI_KEY2 to personal.")
	info = decodeJSON[map[string]any](t, e.mustRun("info", "UI_KEY2", "--json").out)
	if info["vault"] != "personal" {
		t.Fatalf("moved to %v", info["vault"])
	}
	for _, c := range []struct {
		act audit.Action
		key string
	}{{audit.ActionRename, "UI_KEY2"}, {audit.ActionMove, "UI_KEY2"}} {
		if d.rec.count(c.act, c.key) == 0 {
			t.Fatalf("no %s audit event: %v", c.act, d.rec.events)
		}
	}

	// Delete needs a y; any other key cancels.
	d.goTo("UI_KEY2")
	d.press("x")
	d.press("n")
	if got := e.mustRun("get", "UI_KEY2").out; got != "second-value\n" {
		t.Fatalf("deleted without confirmation")
	}
	d.press("x")
	d.press("y")
	d.want("Deleted UI_KEY2")
	expectCode(t, e.run("get", "UI_KEY2"), ExitNotFound)
	if d.rec.count(audit.ActionDelete, "UI_KEY2") != 1 {
		t.Fatalf("audit %v", d.rec.events)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestUIRevealRecordsReadAndRemasks(t *testing.T) {
	e, _, _ := twoVaults(t)
	e.set("API_TOKEN", "personal", "tok-1234-canary")
	d := newUIDriver(t, e)
	d.goTo("API_TOKEN")
	d.want("••••••••••••••••")
	if strings.Contains(d.view(), "tok-1234-canary") {
		t.Fatal("masked value on screen")
	}
	d.press(" ")
	d.want("tok-1234-canary", "hides in")
	if d.rec.count(audit.ActionRead, "API_TOKEN") != 1 {
		t.Fatalf("reveal was not recorded as a read: %v", d.rec.events)
	}
	d.press("j") // focus change re-masks
	if strings.Contains(d.view(), "tok-1234-canary") {
		t.Fatal("value still on screen")
	}
	d.press("c")
	d.want("Copied API_TOKEN")
	if string(e.clip.value) != "tok-1234-canary" || len(e.clip.scheduled) != 1 {
		t.Fatalf("clipboard %q %v", e.clip.value, e.clip.scheduled)
	}
	if strings.Contains(d.view(), "tok-1234-canary") {
		t.Fatal("copy showed the value")
	}
}

func TestUILockedVaultListsKeysThenUnlocksInsideTheUI(t *testing.T) {
	e, _, _ := twoVaults(t)
	e.set("LOCKED_KEY", "work", "locked-canary-value")
	e.mustRun("lock", "--all")
	d := newUIDriver(t, e)
	// Keys still list from the index, with the lock showing.
	d.want("LOCKED_KEY", "work 🔒", "locked: space or u asks to unlock")
	d.goTo("LOCKED_KEY")
	d.press(" ")
	d.want("Unlock", "Your personal passphrase:")
	// A wrong passphrase is answered inside the UI, which asks again.
	d.press("not the passphrase")
	d.enter()
	d.want("Wrong passphrase.", "Your personal passphrase:")
	d.press(testPass)
	for _, f := range d.frames {
		if strings.Contains(f, testPass) || strings.Contains(f, "not the passphrase") {
			t.Fatalf("a typed passphrase was drawn:\n%s", f)
		}
	}
	d.enter()
	d.want("locked-canary-value", "work 🔓")
	if d.rec.count(audit.ActionRead, "LOCKED_KEY") != 1 {
		t.Fatalf("audit %v", d.rec.events)
	}
	// Lock from the UI.
	d.press("l")
	d.want("Locked work.", "work 🔒")
	if strings.Contains(d.view(), "locked-canary-value") {
		t.Fatal("value after lock")
	}
	// Cancel the prompt: nothing unlocks, nothing leaks.
	d.press(" ")
	d.want("Unlock")
	d.esc()
	d.want("! cancelled")
	expectCode(t, e.run("get", "LOCKED_KEY"), ExitLocked)
}

func TestUIWriteToLockedVaultAsksFirst(t *testing.T) {
	e, _, _ := twoVaults(t)
	e.set("A_KEY", "work", "a")
	e.mustRun("lock", "--all")
	d := newUIDriver(t, e)
	d.goTo("A_KEY")
	d.press("e")
	d.press("new-a")
	d.enter()
	d.want("Your personal passphrase:")
	d.press(testPass)
	d.enter()
	d.want("Updated A_KEY.")
	if got := e.mustRun("get", "A_KEY").out; got != "new-a\n" {
		t.Fatalf("value %q", got)
	}
}

func TestUIFailedVaultShowsErrorNotKeys(t *testing.T) {
	e, _, dir2 := twoVaults(t)
	e.set("OK_KEY", "personal", "v")
	e.set("HIDDEN_KEY", "work", "v")
	vf, _ := format.ReadVaultFile(dir2)
	vf.Unlockers[0].WrappedKey[3] ^= 1
	data, _ := json.MarshalIndent(vf, "", "  ")
	_ = os.WriteFile(filepath.Join(dir2, "vault.json"), data, 0o600)
	d := newUIDriver(t, e)
	d.want("OK_KEY", "⚠ work:", "work ⚠", "changed outside secrets-vault")
	if strings.Contains(d.view(), "HIDDEN_KEY") {
		t.Fatalf("keys of a failed vault listed:\n%s", d.view())
	}
	d.want("exit code 5")
	// The CLI agrees.
	expectCode(t, e.run("get", "HIDDEN_KEY"), ExitUnverified)
}

func TestUICommandNeedsATerminal(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	r := e.run("ui")
	expectCode(t, r, ExitError)
	if !strings.Contains(r.err, "needs a terminal") {
		t.Fatal(r)
	}
	expectCode(t, e.run("ui", "--json"), ExitUsage)
	expectCode(t, e.run("ui", "extra"), ExitUsage)
}

func TestUICommandRunsTheUIOnATerminal(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.term.stdinTTY, e.term.stdoutTTY = true, true
	in, _ := os.Open(os.DevNull)
	out, _ := os.Create(filepath.Join(e.home, "out"))
	defer in.Close()
	defer out.Close()
	called := false
	old := uiRun
	uiRun = func(b tui.Backend, o tui.Options, _ io.Reader, _ io.Writer) error {
		called = true
		if _, err := b.Snapshot(); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	defer func() { uiRun = old }()
	e.activate()
	if code := Run([]string{"sv", "ui"}, in, out, &bytes.Buffer{}); code != 0 || !called {
		t.Fatalf("exit %d called %v", code, called)
	}
}

// With index authentication, describe and tag change a sealed index entry,
// so on a locked vault they ask to unlock inside the UI, like any write.
func TestUIDescribeAndTagOnLockedVaultNeedUnlock(t *testing.T) {
	e, _, _ := twoVaults(t)
	e.set("D_KEY", "work", "v")
	e.mustRun("lock", "--all")
	d := newUIDriver(t, e)
	d.goTo("D_KEY")
	d.press("d")
	d.press(" edited")
	d.enter()
	d.want("Your personal passphrase:")
	d.press(testPass)
	d.enter()
	d.want("Updated the description.", "test key d_key edited", "Index     verified")
	d.press("t")
	d.press(", t1")
	d.enter()
	info := decodeJSON[map[string]any](t, e.mustRun("info", "D_KEY", "--json").out)
	if strings.Join(toStrings(info["tags"]), ",") != "t1" {
		t.Fatalf("tags %v", info["tags"])
	}
}
