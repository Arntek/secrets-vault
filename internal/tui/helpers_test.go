package tui

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// fakeBackend is an in-memory vault. Locked vaults ask for a passphrase
// through the prompter, like the real unlock flow.
type fakeBackend struct {
	mu       sync.Mutex
	ask      Prompter
	snap     Snapshot
	values   map[string]string // "vault/name" -> value
	pass     map[string]string // vault -> passphrase; present means it can be locked
	unlocked map[string]bool
	calls    []string
	failWith error
	// unverified marks vaults whose entries this Mac has not verified;
	// pending marks entries the folder changed since.
	unverified map[string]bool
	pending    map[string]bool
}

func newFake() *fakeBackend {
	f := &fakeBackend{unverified: map[string]bool{}, pending: map[string]bool{}, values: map[string]string{}, pass: map[string]string{}, unlocked: map[string]bool{}}
	return f
}

func (f *fakeBackend) addVault(name string, unlocked bool, pass string) {
	f.snap.Vaults = append(f.snap.Vaults, Vault{Name: name})
	f.pass[name] = pass
	f.unlocked[name] = unlocked
}

func (f *fakeBackend) addKey(vault, name, desc, value string, tags ...string) {
	f.snap.Keys = append(f.snap.Keys, Key{Name: name, Vault: vault, Description: desc, Tags: tags,
		Updated: time.Date(2026, 10, 2, 14, 0, 0, 0, time.UTC), UpdatedBy: "arnold"})
	f.values[vault+"/"+name] = value
}

func (f *fakeBackend) call(format string, a ...any) {
	f.calls = append(f.calls, fmt.Sprintf(format, a...))
}

func (f *fakeBackend) SetPrompter(p Prompter) { f.ask = p }
func (f *fakeBackend) ValidateName(n string) error {
	if n == "" || strings.ContainsAny(n, " /") {
		return fmt.Errorf("that name is not allowed")
	}
	return nil
}

func (f *fakeBackend) Snapshot() (Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := Snapshot{Keys: append([]Key(nil), f.snap.Keys...)}
	for i := range s.Keys {
		if !f.unverified[s.Keys[i].Vault] {
			s.Keys[i].Verified = true
		}
		s.Keys[i].Pending = f.pending[s.Keys[i].Name]
	}
	for _, v := range f.snap.Vaults {
		v.Unlocked = f.unlocked[v.Name]
		if v.Unlocked {
			v.Expires = time.Date(2026, 11, 18, 16, 41, 0, 0, time.UTC)
		}
		n := 0
		for _, k := range f.snap.Keys {
			if k.Vault == v.Name {
				n++
			}
		}
		v.Keys = n
		s.Vaults = append(s.Vaults, v)
	}
	return s, nil
}

// need unlocks a vault through the prompter, up to three tries.
func (f *fakeBackend) need(vault string) error {
	if f.unlocked[vault] {
		return nil
	}
	text := "Passphrase for '" + vault + "': "
	for i := 0; i < 3; i++ {
		p, err := f.ask(text, true)
		if err != nil {
			return err
		}
		ok := string(p) == f.pass[vault]
		clear(p)
		if ok {
			f.unlocked[vault] = true
			return nil
		}
		text = "Wrong passphrase.\nPassphrase for '" + vault + "': "
	}
	return fmt.Errorf("could not unlock '%s': wrong passphrase", vault)
}

func (f *fakeBackend) Reveal(vault, name string) ([]byte, error) {
	f.call("reveal %s/%s", vault, name)
	if err := f.need(vault); err != nil {
		return nil, err
	}
	return []byte(f.values[vault+"/"+name]), nil
}
func (f *fakeBackend) Copy(vault, name string) (bool, error) {
	f.call("copy %s/%s", vault, name)
	return true, f.need(vault)
}
func (f *fakeBackend) Set(vault, name string, value []byte, desc *string) error {
	d := "<keep>"
	if desc != nil {
		d = *desc
	}
	f.call("set %s/%s value=%s desc=%s", vault, name, string(value), d)
	if f.failWith != nil {
		return f.failWith
	}
	if err := f.need(vault); err != nil {
		return err
	}
	f.values[vault+"/"+name] = string(value)
	for i, k := range f.snap.Keys {
		if k.Vault == vault && k.Name == name {
			if desc != nil {
				f.snap.Keys[i].Description = *desc
			}
			return nil
		}
	}
	dd := ""
	if desc != nil {
		dd = *desc
	}
	f.snap.Keys = append(f.snap.Keys, Key{Name: name, Vault: vault, Description: dd})
	return nil
}
func (f *fakeBackend) Describe(vault, name, text string) error {
	f.call("describe %s/%s %q", vault, name, text)
	if err := f.need(vault); err != nil { // index entries are sealed: a change needs the key
		return err
	}
	for i, k := range f.snap.Keys {
		if k.Vault == vault && k.Name == name {
			f.snap.Keys[i].Description = text
		}
	}
	return nil
}
func (f *fakeBackend) Tag(vault, name string, add, remove []string) error {
	f.call("tag %s/%s add=%v rm=%v", vault, name, add, remove)
	if err := f.need(vault); err != nil {
		return err
	}
	for i, k := range f.snap.Keys {
		if k.Vault == vault && k.Name == name {
			var out []string
			for _, t := range k.Tags {
				keep := true
				for _, r := range remove {
					if r == t {
						keep = false
					}
				}
				if keep {
					out = append(out, t)
				}
			}
			f.snap.Keys[i].Tags = append(out, add...)
		}
	}
	return nil
}
func (f *fakeBackend) Move(vault, name, to string) error {
	f.call("move %s/%s -> %s", vault, name, to)
	for i, k := range f.snap.Keys {
		if k.Vault == vault && k.Name == name {
			f.snap.Keys[i].Vault = to
			f.values[to+"/"+name] = f.values[vault+"/"+name]
		}
	}
	return nil
}
func (f *fakeBackend) Rename(vault, name, newName string) error {
	f.call("rename %s/%s -> %s", vault, name, newName)
	for i, k := range f.snap.Keys {
		if k.Vault == vault && k.Name == name {
			f.snap.Keys[i].Name = newName
		}
	}
	return nil
}
func (f *fakeBackend) Delete(vault, name string) error {
	f.call("delete %s/%s", vault, name)
	var out []Key
	for _, k := range f.snap.Keys {
		if !(k.Vault == vault && k.Name == name) {
			out = append(out, k)
		}
	}
	f.snap.Keys = out
	return nil
}
func (f *fakeBackend) Unlock(vault string) error {
	f.call("unlock %s", vault)
	return f.need(vault)
}
func (f *fakeBackend) Lock(vault string) error {
	f.call("lock %s", vault)
	f.unlocked[vault] = false
	return nil
}
func (f *fakeBackend) LockAll() error {
	f.call("lockall")
	for v := range f.unlocked {
		f.unlocked[v] = false
	}
	return nil
}

// --- harness ---

type harness struct {
	t        *testing.T
	m        *Model
	f        *fakeBackend
	clock    time.Time
	msgs     chan tea.Msg
	inflight chan tea.Msg
	frames   []string // every rendered frame, for the leak checks
}

func newHarness(t *testing.T, f *fakeBackend) *harness {
	t.Helper()
	h := &harness{t: t, f: f, clock: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC), msgs: make(chan tea.Msg, 16)}
	h.m = New(f, Options{NoColor: true, Now: func() time.Time { return h.clock }})
	h.m.Attach(func(msg tea.Msg) { h.msgs <- msg })
	h.m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	h.run(h.m.loadSnap())
	return h
}

// run executes a command like the Bubble Tea runtime would, feeding results
// (and prompts sent by the backend) back into Update. It returns when the
// command finished or a prompt is waiting for the test to answer.
func (h *harness) run(cmd tea.Cmd) {
	h.t.Helper()
	if cmd == nil {
		return
	}
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	h.inflight = done
	h.pump()
}

func (h *harness) pump() {
	h.t.Helper()
	for h.inflight != nil {
		select {
		case msg := <-h.inflight:
			h.inflight = nil
			h.deliver(msg)
		case msg := <-h.msgs:
			h.deliver(msg)
			if _, ok := msg.(promptMsg); ok {
				return
			}
		case <-time.After(3 * time.Second):
			h.t.Fatal("command did not finish")
		}
	}
}

func (h *harness) deliver(msg tea.Msg) {
	h.t.Helper()
	if b, ok := msg.(tea.BatchMsg); ok {
		for _, c := range b {
			h.run(c)
		}
		return
	}
	_, cmd := h.m.Update(msg)
	h.snap()
	if cmd != nil && h.inflight == nil {
		h.run(cmd)
	}
}

func (h *harness) snap() { h.frames = append(h.frames, h.m.View()) }

func (h *harness) send(msg tea.Msg) {
	h.t.Helper()
	_, cmd := h.m.Update(msg)
	h.snap()
	if cmd != nil {
		if h.inflight != nil {
			h.t.Fatal("a command is already running")
		}
		h.run(cmd)
	} else if h.inflight != nil {
		// Typing changes nothing for the waiting backend; answering does.
		if k, ok := msg.(tea.KeyMsg); ok && (k.Type == tea.KeyEnter || k.Type == tea.KeyEsc || k.Type == tea.KeyCtrlC) {
			h.pump()
		}
	}
}

func (h *harness) typ(s string) {
	for _, r := range s {
		if r == ' ' {
			h.send(tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}})
			continue
		}
		h.send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}
func (h *harness) press(t tea.KeyType) { h.send(tea.KeyMsg{Type: t}) }
func (h *harness) enter()              { h.press(tea.KeyEnter) }
func (h *harness) esc()                { h.press(tea.KeyEsc) }

// tick moves the clock and delivers a tick.
func (h *harness) tick(d time.Duration) {
	h.clock = h.clock.Add(d)
	_, _ = h.m.Update(tickMsg(h.clock))
	h.snap()
}

func (h *harness) resize(w, ht int) {
	h.send(tea.WindowSizeMsg{Width: w, Height: ht})
}

func (h *harness) view() string { return h.m.View() }

func (h *harness) selected() string {
	k, ok := h.m.selectedKey()
	if !ok {
		return ""
	}
	return k.Vault + "/" + k.Name
}

func standard() *fakeBackend {
	f := newFake()
	f.addVault("personal", true, "personal pass")
	f.addVault("ebcfo", false, "ebcfo pass")
	f.addKey("ebcfo", "XERO_CLIENT_ID", `Xero app "EBCFO Reporting"`, "xero-id-value", "xero", "reporting")
	f.addKey("ebcfo", "XERO_CLIENT_SECRET", `Xero app "EBCFO Reporting"`, "xero-secret-value", "xero")
	f.addKey("ebcfo", "XERO_WEBHOOK_KEY", "Webhook signing key", "xero-webhook-value")
	f.addKey("personal", "OPENAI_API_KEY", "Personal OpenAI key", "sk-personal-value", "ai")
	f.addKey("personal", "GITHUB_TOKEN", "GitHub CLI token", "gh-token-value")
	return f
}

func (h *harness) lines() []string { return strings.Split(h.view(), "\n") }
