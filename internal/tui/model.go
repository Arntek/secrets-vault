package tui

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// ErrCancelled is returned to the backend when the person dismisses a prompt.
var ErrCancelled = errors.New("cancelled")

// Options configure a Model.
type Options struct {
	// NoColor turns colours off (NO_COLOR is set).
	NoColor bool
	// Now is the clock; nil means time.Now. Tests inject one.
	Now func() time.Time
}

type pane int

const (
	paneKeys pane = iota
	paneVaults
)

type mode int

const (
	modeBrowse mode = iota
	modeSearch
	modePrompt
	modeConfirm
)

// revealed is the one value currently on screen.
type revealed struct {
	vault, name string
	val         []byte
	until       time.Time
}

func (r *revealed) wipe() {
	if r != nil {
		clear(r.val)
		r.val = nil
	}
}

// prompt is a one-line question at the bottom of the screen.
type prompt struct {
	title  string
	label  string
	note   []string
	hidden bool
	buf    []rune
	submit func(m *Model, text []byte) tea.Cmd
	cancel func(m *Model)
}

type confirmState struct {
	text string
	yes  func(m *Model) tea.Cmd
}

// Messages. Anything holding a secret is wiped when handled.
type (
	tickMsg time.Time
	snapMsg struct {
		snap Snapshot
		err  error
	}
	opDoneMsg struct {
		status                  string
		err                     error
		snap                    Snapshot
		serr                    error
		selectVault, selectName string
	}
	revealMsg struct {
		vault, name string
		val         []byte
		err         error
		snap        Snapshot
		serr        error
	}
	promptMsg struct {
		text   string
		hidden bool
		reply  chan promptReply
	}
)

type promptReply struct {
	val []byte
	err error
}

// Model is the Bubble Tea model.
type Model struct {
	b    Backend
	opts Options
	now  func() time.Time
	// send delivers a message to the running program (from the backend's
	// goroutine, for prompts). Run sets it; tests set their own.
	send func(tea.Msg)

	w, h   int
	snap   Snapshot
	loaded bool

	vaultSel int // 0 = All, i+1 = snap.Vaults[i]
	focus    pane
	keySel   int // index into the visible rows
	query    string
	mode     mode

	pr      *prompt
	conf    *confirmState
	pending []byte // a value typed in the add/edit flow, wiped on cancel or finish
	rev     *revealed

	status    string
	statusErr bool
	busy      string
	quitting  bool

	st styles
}

// New makes a model. It registers itself as the backend's prompter.
func New(b Backend, o Options) *Model {
	m := &Model{b: b, opts: o, now: o.Now, w: 80, h: 24, st: newStyles(!o.NoColor)}
	if m.now == nil {
		m.now = time.Now
	}
	b.SetPrompter(m.ask)
	return m
}

// ask is the Prompter: it runs in the backend's goroutine, hands the
// question to the UI and waits for the answer.
func (m *Model) ask(text string, hidden bool) ([]byte, error) {
	if m.send == nil {
		return nil, ErrCancelled
	}
	reply := make(chan promptReply, 1)
	m.send(promptMsg{text: text, hidden: hidden, reply: reply})
	r := <-reply
	return r.val, r.err
}

// Init loads the first snapshot and starts the clock.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.loadSnap(), m.tick())
}

func (m *Model) tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *Model) loadSnap() tea.Cmd {
	b := m.b
	return func() tea.Msg {
		s, err := b.Snapshot()
		return snapMsg{snap: s, err: err}
	}
}

// wipe clears every secret the model holds.
func (m *Model) wipe() {
	m.rev.wipe()
	m.rev = nil
	clear(m.pending)
	m.pending = nil
	if m.pr != nil {
		clear(m.pr.buf)
		m.pr.buf = nil
	}
}

// Update handles one message. A panic here is turned into a fixed message
// after wiping secrets, so no value can end up in a panic trace.
func (m *Model) Update(msg tea.Msg) (model tea.Model, cmd tea.Cmd) {
	defer func() {
		if r := recover(); r != nil {
			m.wipe()
			panic("vault ui: internal error")
		}
	}()
	return m.update(msg)
}

func (m *Model) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.clampSel()
	case tickMsg:
		return m, m.onTick(time.Time(msg))
	case snapMsg:
		if msg.err != nil {
			m.fail(msg.err)
		} else {
			m.applySnap(msg.snap, "", "")
		}
	case opDoneMsg:
		m.busy = ""
		if msg.serr == nil {
			m.applySnap(msg.snap, msg.selectVault, msg.selectName)
		}
		if msg.err != nil {
			m.fail(msg.err)
		} else {
			m.setStatus(msg.status, false)
		}
	case revealMsg:
		m.busy = ""
		if msg.serr == nil {
			m.applySnap(msg.snap, "", "")
		}
		if msg.err != nil {
			m.fail(msg.err)
			break
		}
		if k, ok := m.selectedKey(); ok && k.Vault == msg.vault && k.Name == msg.name {
			m.rev.wipe()
			m.rev = &revealed{vault: msg.vault, name: msg.name, val: msg.val, until: m.now().Add(RevealFor)}
			m.setStatus("", false)
		} else {
			clear(msg.val) // the selection moved on while it was decrypting
		}
	case promptMsg:
		return m, m.openBackendPrompt(msg)
	case tea.KeyMsg:
		return m.key(msg)
	}
	return m, nil
}

func (m *Model) onTick(t time.Time) tea.Cmd {
	if m.rev != nil && !t.Before(m.rev.until) {
		m.hide()
	}
	if m.rev != nil && m.vaultLockedFor(m.rev.vault) {
		m.hide()
	}
	return m.tick()
}

// vaultLockedFor is true when the vault is known to have locked.
func (m *Model) vaultLockedFor(name string) bool {
	for _, v := range m.snap.Vaults {
		if v.Name == name {
			return !v.Unlocked || (!v.Expires.IsZero() && !m.now().Before(v.Expires))
		}
	}
	return true
}

// hide re-masks the value on screen.
func (m *Model) hide() {
	m.rev.wipe()
	m.rev = nil
}

func (m *Model) setStatus(s string, isErr bool) { m.status, m.statusErr = s, isErr }

func (m *Model) fail(err error) { m.setStatus(clean(err.Error()), true) }

// --- rows and selection ---

// row is one line in the Keys list: a key, or a vault that failed.
type row struct {
	key   Key
	vault *Vault // set for an error row
}

func (m *Model) currentVault() (Vault, bool) {
	if m.vaultSel == 0 || m.vaultSel > len(m.snap.Vaults) {
		return Vault{}, false
	}
	return m.snap.Vaults[m.vaultSel-1], true
}

// rows is what the Keys list shows: failed vaults first (their error
// instead of keys), then the keys that match the vault and the search.
func (m *Model) rows() []row {
	var out []row
	for i := range m.snap.Vaults {
		v := &m.snap.Vaults[i]
		if v.Err == "" {
			continue
		}
		if m.vaultSel == 0 || m.vaultSel == i+1 {
			out = append(out, row{vault: v})
		}
	}
	words := strings.Fields(strings.ToLower(m.query))
	for _, k := range m.snap.Keys {
		if cv, ok := m.currentVault(); ok && k.Vault != cv.Name {
			continue
		}
		if !matches(k, words) {
			continue
		}
		out = append(out, row{key: k})
	}
	return out
}

func matches(k Key, words []string) bool {
	hay := strings.ToLower(k.Name + " " + k.Description + " " + strings.Join(k.Tags, " ") + " " + k.Vault)
	for _, w := range words {
		if !strings.Contains(hay, w) {
			return false
		}
	}
	return true
}

func (m *Model) selectedRow() (row, bool) {
	rs := m.rows()
	if m.keySel < 0 || m.keySel >= len(rs) {
		return row{}, false
	}
	return rs[m.keySel], true
}

func (m *Model) selectedKey() (Key, bool) {
	r, ok := m.selectedRow()
	if !ok || r.vault != nil {
		return Key{}, false
	}
	return r.key, true
}

func (m *Model) clampSel() {
	n := len(m.rows())
	if m.keySel >= n {
		m.keySel = n - 1
	}
	if m.keySel < 0 {
		m.keySel = 0
	}
	if m.vaultSel > len(m.snap.Vaults) {
		m.vaultSel = len(m.snap.Vaults)
	}
}

// applySnap installs a fresh snapshot and keeps the selection on the same
// key (or on selVault/selName when given, after a rename or move).
func (m *Model) applySnap(s Snapshot, selVault, selName string) {
	prev, hadPrev := m.selectedKey()
	prevIdx := m.keySel
	vaultName := ""
	if v, ok := m.currentVault(); ok {
		vaultName = v.Name
	}
	sort.SliceStable(s.Keys, func(i, j int) bool {
		if s.Keys[i].Name != s.Keys[j].Name {
			return s.Keys[i].Name < s.Keys[j].Name
		}
		return s.Keys[i].Vault < s.Keys[j].Vault
	})
	m.snap = s
	m.loaded = true
	m.vaultSel = 0
	if vaultName != "" {
		for i, v := range s.Vaults {
			if v.Name == vaultName {
				m.vaultSel = i + 1
			}
		}
	}
	rs := m.rows()
	idx := -1
	want := func(v, n string) {
		for i, r := range rs {
			if r.vault == nil && r.key.Vault == v && r.key.Name == n {
				idx = i
				return
			}
		}
	}
	switch {
	case selName != "":
		want(selVault, selName)
	case hadPrev:
		want(prev.Vault, prev.Name)
	}
	if idx < 0 {
		idx = prevIdx
	}
	m.keySel = idx
	m.clampSel()
	if m.rev != nil && m.vaultLockedFor(m.rev.vault) {
		m.hide()
	}
}

// --- keys ---

func (m *Model) key(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" {
		return m, m.quit()
	}
	switch m.mode {
	case modePrompt:
		return m, m.promptKey(msg)
	case modeConfirm:
		return m, m.confirmKey(msg)
	case modeSearch:
		return m, m.searchKey(msg)
	}
	if m.busy != "" {
		return m, nil // one operation at a time
	}
	return m, m.browseKey(msg)
}

func (m *Model) quit() tea.Cmd {
	m.wipe()
	m.quitting = true
	if m.pr != nil && m.pr.cancel != nil {
		m.pr.cancel(m)
	}
	return tea.Sequence(tea.ClearScreen, tea.Quit)
}

func (m *Model) move(delta int) {
	switch m.focus {
	case paneVaults:
		n := len(m.snap.Vaults) + 1
		m.vaultSel = min(max(m.vaultSel+delta, 0), n-1)
		m.keySel = 0
	default:
		m.keySel += delta
		m.clampSel()
	}
	m.hide() // focus or selection changed
}

func (m *Model) browseKey(msg tea.KeyMsg) tea.Cmd {
	s := msg.String()
	switch s {
	case "q":
		return m.quit()
	case "esc":
		m.hide()
		if m.query != "" {
			m.query = ""
			m.keySel = 0
		}
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "pgup":
		m.move(-m.listHeight())
	case "pgdown":
		m.move(m.listHeight())
	case "home", "g":
		m.move(-1 << 20)
	case "end", "G":
		m.move(1 << 20)
	case "tab", "shift+tab", "left", "right", "h":
		m.switchFocus(s)
	case "enter":
		if m.focus == paneVaults {
			m.switchFocus("right")
		}
	case "/":
		m.hide()
		m.mode = modeSearch
		m.focus = paneKeys
	case " ":
		return m.doReveal()
	case "R":
		return m.loadSnap() // re-read the vaults (a sync may have changed them)
	case "c":
		return m.doCopy()
	case "a":
		return m.startAdd()
	case "e":
		return m.startEdit()
	case "d":
		return m.startDescribe()
	case "t":
		return m.startTag()
	case "m":
		return m.startMove()
	case "r":
		return m.startRename()
	case "x":
		return m.startDelete()
	case "u":
		return m.doUnlock()
	case "l":
		return m.doLock(false)
	case "L":
		return m.doLock(true)
	}
	return nil
}

func (m *Model) switchFocus(s string) {
	m.hide()
	switch s {
	case "left", "h":
		m.focus = paneVaults
	case "right":
		m.focus = paneKeys
	default:
		if m.focus == paneKeys {
			m.focus = paneVaults
		} else {
			m.focus = paneKeys
		}
	}
}

func (m *Model) searchKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.Type {
	case tea.KeyEnter:
		m.mode = modeBrowse
	case tea.KeyEsc:
		m.query = ""
		m.mode = modeBrowse
		m.keySel = 0
	case tea.KeyBackspace:
		if r := []rune(m.query); len(r) > 0 {
			m.query = string(r[:len(r)-1])
		}
		m.keySel = 0
	case tea.KeyUp:
		m.move(-1)
	case tea.KeyDown:
		m.move(1)
	case tea.KeyRunes, tea.KeySpace:
		m.query += clean(string(msg.Runes))
		if msg.Type == tea.KeySpace {
			m.query += " "
		}
		m.keySel = 0
		m.hide()
	}
	return nil
}

func (m *Model) listHeight() int { return max(m.paneHeight()-3, 1) }

// --- prompts ---

func (m *Model) openPrompt(p *prompt) {
	m.hide()
	m.pr = p
	m.mode = modePrompt
}

func (m *Model) closePrompt() {
	if m.pr != nil {
		clear(m.pr.buf)
		m.pr = nil
	}
	m.mode = modeBrowse
}

func (m *Model) promptKey(msg tea.KeyMsg) tea.Cmd {
	p := m.pr
	if p == nil {
		m.mode = modeBrowse
		return nil
	}
	switch msg.Type {
	case tea.KeyEsc:
		cancel := p.cancel
		m.closePrompt()
		if cancel != nil {
			cancel(m)
		}
	case tea.KeyEnter:
		text := []byte(string(p.buf))
		submit := p.submit
		m.closePrompt()
		cmd := submit(m, text)
		clear(text)
		return cmd
	case tea.KeyBackspace:
		if n := len(p.buf); n > 0 {
			p.buf[n-1] = 0
			p.buf = p.buf[:n-1]
		}
	case tea.KeyCtrlU:
		clear(p.buf)
		p.buf = p.buf[:0]
	case tea.KeySpace:
		p.buf = append(p.buf, ' ')
	case tea.KeyRunes:
		for _, r := range msg.Runes {
			if r >= ' ' && r != 0x7f { // pasted newlines and controls are dropped
				p.buf = append(p.buf, r)
			}
		}
	}
	return nil
}

// openBackendPrompt shows a question from the backend (a passphrase, a
// confirmation) and sends the answer back to its goroutine.
func (m *Model) openBackendPrompt(pm promptMsg) tea.Cmd {
	lines := strings.Split(strings.TrimRight(pm.text, "\n "), "\n")
	label := clean(lines[len(lines)-1])
	var note []string
	for _, l := range lines[:len(lines)-1] {
		if strings.TrimSpace(l) != "" {
			note = append(note, clean(l))
		}
	}
	m.openPrompt(&prompt{
		title: "Unlock", label: label, note: note, hidden: pm.hidden,
		submit: func(_ *Model, text []byte) tea.Cmd {
			pm.reply <- promptReply{val: slices.Clone(text)}
			return nil
		},
		cancel: func(_ *Model) { pm.reply <- promptReply{err: ErrCancelled} },
	})
	return nil
}

func (m *Model) confirmKey(msg tea.KeyMsg) tea.Cmd {
	c := m.conf
	m.conf = nil
	m.mode = modeBrowse
	if c != nil && (msg.String() == "y" || msg.String() == "Y") {
		return c.yes(m)
	}
	m.setStatus("Cancelled.", false)
	return nil
}
