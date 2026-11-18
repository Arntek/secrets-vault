package tui

import (
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// styles draws colour only when asked to. Meaning never depends on colour:
// the selected row has a marker, errors start with "!", locks are glyphs.
type styles struct {
	color                         bool
	dimS, errS, okS, warnS, boldS lipgloss.Style
	selS                          lipgloss.Style
}

func newStyles(color bool) styles {
	s := styles{color: color}
	if color {
		s.dimS = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
		s.errS = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true)
		s.okS = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
		s.warnS = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
		s.boldS = lipgloss.NewStyle().Bold(true)
		s.selS = lipgloss.NewStyle().Reverse(true)
	}
	return s
}

func (s styles) wrap(st lipgloss.Style, t string) string {
	if !s.color || t == "" {
		return t
	}
	return st.Render(t)
}
func (s styles) dim(t string) string  { return s.wrap(s.dimS, t) }
func (s styles) err(t string) string  { return s.wrap(s.errS, t) }
func (s styles) ok(t string) string   { return s.wrap(s.okS, t) }
func (s styles) warn(t string) string { return s.wrap(s.warnS, t) }
func (s styles) bold(t string) string { return s.wrap(s.boldS, t) }
func (s styles) sel(t string) string  { return s.wrap(s.selS, t) }

const footerLines = 2

// layout returns the heights of the panes, bottom box and footer.
func (m *Model) layout() (panes, bottom, footer int) {
	footer = footerLines
	bottom = 5
	if (m.mode == modePrompt && m.pr != nil) || (m.mode == modeConfirm && m.conf != nil) {
		bottom = 3 + len(m.dialogNote())
		if bottom > 9 {
			bottom = 9
		}
	}
	panes = m.h - 1 - bottom - 1 - footer
	if panes < 5 {
		panes = 5
	}
	return
}

func (m *Model) paneHeight() int { p, _, _ := m.layout(); return p }

func (m *Model) dialogNote() []string {
	if m.pr != nil && m.mode == modePrompt {
		if len(m.pr.note) > 5 {
			return m.pr.note[len(m.pr.note)-5:]
		}
		return m.pr.note
	}
	return nil
}

// View draws the screen. It is blank once the person quit, so the last
// frame (which could hold a revealed value) is never left behind.
func (m *Model) View() string {
	if m.quitting {
		return ""
	}
	w, h := max(m.w, 20), max(m.h, 10)
	mm := *m
	mm.w, mm.h = w, h
	ph, bh, _ := mm.layout()
	var lines []string
	lines = append(lines, mm.header(w))
	lines = append(lines, mm.middle(w, ph)...)
	lines = append(lines, mm.bottom(w, bh)...)
	lines = append(lines, mm.statusLine(w))
	for _, l := range wrapWords(mm.hints(), w) {
		lines = append(lines, m.st.dim(pad(l, w)))
	}
	if len(lines) > h {
		lines = lines[:h]
	}
	return strings.Join(lines, "\n")
}

func (m *Model) header(w int) string {
	nk := 0
	for _, v := range m.snap.Vaults {
		nk += v.Keys
	}
	left := m.st.bold("vault") + " ─ " + plural(len(m.snap.Vaults), "vault") + " · " + plural(nk, "key")
	var parts []string
	for _, v := range m.snap.Vaults {
		parts = append(parts, clean(v.Name)+" "+m.lockGlyph(v))
	}
	right := strings.Join(parts, "   ")
	room := w - ansi.StringWidth(left) - 2
	if ansi.StringWidth(right) > room {
		right = fit(right, max(room, 0))
	}
	gap := w - ansi.StringWidth(left) - ansi.StringWidth(right)
	if gap < 1 {
		gap = 1
	}
	return fit(left+strings.Repeat(" ", gap)+right, w)
}

func (m *Model) lockGlyph(v Vault) string {
	switch {
	case v.Err != "":
		return "⚠"
	case m.vaultUnlocked(v):
		return "🔓 " + timeLeft(v.Expires.Sub(m.now()))
	}
	return "🔒"
}

func (m *Model) vaultUnlocked(v Vault) bool {
	return v.Err == "" && v.Unlocked && (v.Expires.IsZero() || m.now().Before(v.Expires))
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return itoa(n) + " " + word + "s"
}

// --- middle: vaults pane and keys pane ---

func (m *Model) middle(w, h int) []string {
	vw := 0
	switch {
	case w >= 70:
		vw = 18
	case w >= 48:
		vw = 12
	}
	kw := w
	var vbox []string
	if vw > 0 {
		kw = w - vw - 1
		vbox = m.vaultsBox(vw, h)
	}
	kbox := m.keysBox(kw, h)
	if vw == 0 {
		return kbox
	}
	out := make([]string, h)
	for i := range out {
		out[i] = vbox[i] + " " + kbox[i]
	}
	return out
}

func (m *Model) vaultsBox(w, h int) []string {
	var lines []string
	add := func(i int, label string) {
		mark := "  "
		if i == m.vaultSel {
			mark = "• "
			if m.focus == paneVaults {
				mark = "▸ "
			}
		}
		line := mark + label
		if i == m.vaultSel && m.focus == paneVaults {
			line = m.st.sel(pad(line, w-4))
		}
		lines = append(lines, line)
	}
	add(0, "All")
	for i, v := range m.snap.Vaults {
		g := "🔒"
		switch {
		case v.Err != "":
			g = "⚠"
		case m.vaultUnlocked(v):
			g = "🔓"
		}
		add(i+1, pad(clean(v.Name), max(w-4-2-3, 3))+" "+g)
	}
	top := 0
	if m.vaultSel >= h-2 {
		top = m.vaultSel - (h - 3)
	}
	if top < len(lines) {
		lines = lines[top:]
	}
	return box("Vaults", lines, w, h, m.focus == paneVaults, m.st)
}

func (m *Model) keysBox(w, h int) []string {
	iw := w - 4
	rs := m.rows()
	q := "/ " + clean(m.query)
	switch {
	case m.mode == modeSearch:
		q += "█"
	case m.query == "":
		q = m.st.dim("/ search")
	}
	lines := []string{q}
	lh := max(h-3, 1)
	top := 0
	if len(rs) > lh {
		top = min(max(m.keySel-lh/2, 0), len(rs)-lh)
	}
	nw, vw := 8, 5
	for _, r := range rs {
		if r.vault == nil {
			nw = max(nw, ansi.StringWidth(clean(r.key.Name)))
			vw = max(vw, ansi.StringWidth(clean(r.key.Vault)))
		}
	}
	nw = min(nw, max(iw/3, 10))
	vw = min(vw, 12)
	if len(rs) == 0 && m.loaded {
		switch {
		case m.query != "":
			lines = append(lines, m.st.dim("  No keys match."))
		case len(m.snap.Vaults) == 0:
			lines = append(lines, m.st.dim("  No vaults yet. Create one with: vault init NAME --path DIR"))
		default:
			lines = append(lines, m.st.dim("  No keys yet. Press a to add one."))
		}
	}
	for i := top; i < len(rs) && i < top+lh; i++ {
		r := rs[i]
		mark := "  "
		if i == m.keySel {
			mark = "› "
			if m.focus == paneKeys {
				mark = "▸ "
			}
		}
		var line string
		if r.vault != nil {
			line = mark + m.st.err("⚠ "+clean(r.vault.Name)+": ") + clean(firstLine(r.vault.Err))
		} else {
			k := r.key
			line = mark + pad(clean(k.Name), nw) + "  " + pad(clean(k.Vault), vw) + "  " + clean(k.Description)
		}
		line = pad(line, iw)
		if i == m.keySel && m.focus == paneKeys {
			line = m.st.sel(line)
		}
		lines = append(lines, line)
	}
	return box("Keys", lines, w, h, m.focus == paneKeys, m.st)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// --- bottom: detail, or the dialog ---

func (m *Model) bottom(w, h int) []string {
	switch {
	case m.mode == modePrompt && m.pr != nil:
		return m.promptBox(w, h)
	case m.mode == modeConfirm && m.conf != nil:
		return box("Delete", []string{m.st.warn(m.conf.text)}, w, h, true, m.st)
	}
	return m.detailBox(w, h)
}

func (m *Model) promptBox(w, h int) []string {
	p := m.pr
	var lines []string
	for _, n := range m.dialogNote() {
		lines = append(lines, m.st.dim(n))
	}
	in := string(p.buf)
	if p.hidden {
		in = strings.Repeat("•", len(p.buf))
	} else {
		in = clean(in)
	}
	// Show the end of long input so the cursor stays visible.
	room := w - 4 - ansi.StringWidth(p.label) - 1
	if r := []rune(in); len(r) > room && room > 0 {
		in = "…" + string(r[len(r)-room+1:])
	}
	lines = append(lines, p.label+in+"█")
	return box(p.title, lines, w, h, true, m.st)
}

func (m *Model) detailBox(w, h int) []string {
	r, ok := m.selectedRow()
	if !ok {
		return box("Details", []string{m.st.dim("No key selected.")}, w, h, false, m.st)
	}
	if r.vault != nil {
		var lines []string
		code := ""
		if r.vault.Verify {
			code = " (exit code 5: this vault failed verification)"
		}
		lines = append(lines, m.st.err("! "+clean(r.vault.Name)+" cannot be listed"+code))
		for _, l := range strings.Split(clean2(r.vault.Err), "\n") {
			lines = append(lines, wrapLine(l, w-4)...)
		}
		return box(clean(r.vault.Name), lines, w, h, false, m.st)
	}
	k := r.key
	iw := w - 4
	val := m.st.dim(strings.Repeat("•", 16)) + "   " + m.st.dim("(space: reveal "+itoa(int(RevealFor.Seconds()))+"s · c: copy, clears in "+itoa(int(ClipboardClear.Seconds()))+"s)")
	if m.vaultIsLocked(k.Vault) {
		val = m.st.dim(strings.Repeat("•", 16)) + "   " + m.st.dim("(locked: space or u asks to unlock)")
	}
	if m.rev != nil && m.rev.vault == k.Vault && m.rev.name == k.Name {
		left := max(m.rev.until.Sub(m.now()), 0)
		secs := int((left + time.Second - 1) / time.Second)
		shown := fit(clean(string(m.rev.val)), max(iw-10-24, 8))
		val = m.st.warn(shown) + "   " + m.st.dim("(hides in "+itoa(secs)+"s · space hides now)")
	}
	tags := "–"
	if len(k.Tags) > 0 {
		tags = clean(strings.Join(k.Tags, ", "))
	}
	upd := "–"
	if !k.Updated.IsZero() {
		upd = k.Updated.Local().Format("2006-01-02 15:04")
		if k.UpdatedBy != "" {
			upd += " by " + clean(k.UpdatedBy)
		}
	}
	lines := []string{
		"Value     " + val,
		"Vault     " + pad(clean(k.Vault), 14) + "Tags  " + tags,
		"Updated   " + upd,
	}
	return box(clean(k.Name), lines, w, h, false, m.st)
}

func (m *Model) vaultIsLocked(name string) bool {
	for _, v := range m.snap.Vaults {
		if v.Name == name {
			return !m.vaultUnlocked(v)
		}
	}
	return true
}

// clean2 is clean but keeps line breaks (an error may have several lines).
func clean2(s string) string {
	ls := strings.Split(s, "\n")
	for i, l := range ls {
		ls[i] = clean(l)
	}
	return strings.Join(ls, "\n")
}

func wrapLine(s string, w int) []string {
	if w < 8 {
		return []string{fit(s, w)}
	}
	var out []string
	for ansi.StringWidth(s) > w {
		cut := strings.LastIndexByte(s[:min(len(s), w)], ' ')
		if cut <= 0 {
			cut = min(len(s), w)
		}
		out = append(out, s[:cut])
		s = strings.TrimLeft(s[cut:], " ")
	}
	return append(out, s)
}

// --- status and footer ---

func (m *Model) statusLine(w int) string {
	s := m.status
	switch {
	case m.statusErr && s != "":
		return pad(m.st.err("! "+s), w)
	case s != "":
		return pad(m.st.ok(s), w)
	}
	return pad("", w)
}

func (m *Model) hints() []string {
	switch m.mode {
	case modePrompt:
		return []string{"enter OK", "esc cancel"}
	case modeConfirm:
		return []string{"y delete", "any other key cancels"}
	case modeSearch:
		return []string{"type to filter", "enter keep", "esc clear"}
	}
	return []string{"/ search", "a add", "e edit value", "d describe", "t tag", "m move", "r rename", "x delete",
		"u unlock", "l lock", "c copy", "space reveal", "q quit"}
}

// box draws a titled frame exactly w cells wide and h lines tall.
func box(title string, lines []string, w, h int, focused bool, st styles) []string {
	if w < 6 {
		w = 6
	}
	if h < 3 {
		h = 3
	}
	t := " " + fit(title, max(w-6, 1)) + " "
	if focused {
		t = st.bold(t)
	}
	fill := max(w-2-ansi.StringWidth(t)-1, 0)
	out := []string{"┌─" + t + strings.Repeat("─", fill) + "┐"}
	for i := 0; i < h-2; i++ {
		l := ""
		if i < len(lines) {
			l = lines[i]
		}
		out = append(out, "│ "+pad(l, w-4)+" │")
	}
	return append(out, "└"+strings.Repeat("─", w-2)+"┘")
}
