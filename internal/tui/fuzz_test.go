package tui

import (
	"strings"
	"testing"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// FuzzClean: whatever a vault holds, what reaches the screen has no control
// characters, so no escape sequence can get through.
func FuzzClean(f *testing.F) {
	for _, s := range []string{"", "plain", "a\x1b[31mred", "\x1b]0;title\x07", "x\u202ey", "tab\there", "line\nbreak", "\x9b31m"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := clean(s)
		for _, r := range out {
			if unicode.IsControl(r) || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 {
				t.Fatalf("%U survived in %q", r, out)
			}
		}
		if w := ansi.StringWidth(fit(out, 10)); w > 10 {
			t.Fatalf("fit gave %d cells", w)
		}
	})
}

// FuzzKeys: any key sequence and window size must not panic, overflow the
// window or draw a control character.
func FuzzKeys(f *testing.F) {
	f.Add("jj kx/xero\nax", uint8(80), uint8(24))
	f.Add("a\x1b\x1bq", uint8(20), uint8(10))
	f.Fuzz(func(t *testing.T, keys string, w, h uint8) {
		fk := standard()
		m := New(fk, Options{NoColor: true})
		m.Update(tea.WindowSizeMsg{Width: int(w), Height: int(h)})
		s, _ := fk.Snapshot()
		m.Update(snapMsg{snap: s})
		for _, r := range keys {
			var km tea.KeyMsg
			switch r {
			case '\n':
				km = tea.KeyMsg{Type: tea.KeyEnter}
			case 0x1b:
				km = tea.KeyMsg{Type: tea.KeyEsc}
			case '\t':
				km = tea.KeyMsg{Type: tea.KeyTab}
			case 0x7f:
				km = tea.KeyMsg{Type: tea.KeyBackspace}
			case ' ':
				km = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
			default:
				km = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
			}
			// Do not run commands: the fuzz is about the model's own state.
			_, _ = m.Update(km)
			if m.quitting {
				return
			}
			m.busy = ""
			v := m.View()
			for i, l := range strings.Split(v, "\n") {
				if ansi.StringWidth(l) > max(int(w), 20) {
					t.Fatalf("line %d too wide (%d): %q", i, ansi.StringWidth(l), l)
				}
			}
			for _, c := range v {
				if c != '\n' && unicode.IsControl(c) {
					t.Fatalf("control %U on screen", c)
				}
			}
		}
	})
}
