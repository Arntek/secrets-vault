package tui

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func contains(t *testing.T, s string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(s, p) {
			t.Errorf("screen does not contain %q:\n%s", p, s)
		}
	}
}

func lacks(t *testing.T, s string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if strings.Contains(s, p) {
			t.Errorf("screen contains %q:\n%s", p, s)
		}
	}
}

func TestLayout80x24(t *testing.T) {
	h := newHarness(t, standard())
	v := h.view()
	ls := strings.Split(v, "\n")
	if len(ls) != 24 {
		t.Fatalf("got %d lines, want 24:\n%s", len(ls), v)
	}
	for i, l := range ls {
		if w := ansi.StringWidth(l); w > 80 {
			t.Errorf("line %d is %d wide: %q", i, w, l)
		}
	}
	contains(t, v, "2 vaults · 5 keys", "personal 🔓 4h41m", "ebcfo 🔒", "Vaults", "Keys", "All",
		"XERO_CLIENT_ID", "OPENAI_API_KEY", "Value", "••••••••••••••••", "/ search", "a add", "space reveal", "q quit")
	t.Log("\n" + v)
}

func TestNavigationAndVaultFilter(t *testing.T) {
	h := newHarness(t, standard())
	if h.selected() != "personal/GITHUB_TOKEN" {
		t.Fatalf("first row is %s", h.selected())
	}
	h.typ("j")
	if h.selected() != "personal/OPENAI_API_KEY" {
		t.Fatalf("after j: %s", h.selected())
	}
	h.press(tea.KeyUp)
	h.typ("G")
	if h.selected() != "ebcfo/XERO_WEBHOOK_KEY" {
		t.Fatalf("after G: %s", h.selected())
	}
	h.press(tea.KeyDown) // clamps at the end
	if h.selected() != "ebcfo/XERO_WEBHOOK_KEY" {
		t.Fatalf("clamped: %s", h.selected())
	}
	// Focus the vaults pane, pick ebcfo, keys filter to it.
	h.press(tea.KeyTab)
	h.typ("j")
	h.typ("j")
	h.press(tea.KeyTab)
	v := h.view()
	contains(t, v, "XERO_CLIENT_ID")
	lacks(t, v, "OPENAI_API_KEY", "GITHUB_TOKEN")
	h.typ("g")
	if h.selected() != "ebcfo/XERO_CLIENT_ID" {
		t.Fatalf("after g: %s", h.selected())
	}
}

func TestSearch(t *testing.T) {
	h := newHarness(t, standard())
	h.typ("/")
	h.typ("xero ids")
	if got := len(h.m.rows()); got != 0 {
		t.Fatalf("'xero ids' matched %d rows", got)
	}
	contains(t, h.view(), "No keys match.")
	h.press(tea.KeyBackspace)
	h.press(tea.KeyBackspace)
	h.press(tea.KeyBackspace)
	if got := len(h.m.rows()); got != 3 {
		t.Fatalf("'xero ' matched %d rows, want 3", got)
	}
	h.typ("secret")
	h.enter()
	if h.selected() != "ebcfo/XERO_CLIENT_SECRET" {
		t.Fatalf("selected %s", h.selected())
	}
	contains(t, h.view(), "secret")
	h.esc() // clears the filter
	if len(h.m.rows()) != 5 || h.m.query != "" {
		t.Fatalf("filter not cleared: %d rows %q", len(h.m.rows()), h.m.query)
	}
	// Matches tags and descriptions too.
	h.typ("/")
	h.typ("reporting")
	if got := len(h.m.rows()); got != 2 {
		t.Fatalf("description match: %d", got)
	}
	h.esc()
	h.typ("/")
	h.typ("ai")
	h.enter()
	if h.selected() != "personal/OPENAI_API_KEY" {
		t.Fatalf("tag match: %s", h.selected())
	}
}

func TestRevealTimesOutAndRemasks(t *testing.T) {
	f := standard()
	h := newHarness(t, f)
	h.typ(" ") // GITHUB_TOKEN in the unlocked personal vault
	if h.m.rev == nil {
		t.Fatal("not revealed")
	}
	contains(t, h.view(), "gh-token-value", "hides in 10s")
	h.tick(9 * time.Second)
	contains(t, h.view(), "gh-token-value", "hides in 1s")
	h.tick(time.Second)
	if h.m.rev != nil {
		t.Fatal("still revealed after 10s")
	}
	lacks(t, h.view(), "gh-token-value")
	contains(t, h.view(), "••••")
}

func TestRevealRemasksOnFocusAndSelectionChange(t *testing.T) {
	for name, act := range map[string]func(h *harness){
		"move down":    func(h *harness) { h.typ("j") },
		"tab":          func(h *harness) { h.press(tea.KeyTab) },
		"search":       func(h *harness) { h.typ("/") },
		"escape":       func(h *harness) { h.esc() },
		"space toggle": func(h *harness) { h.typ(" ") },
		"lock":         func(h *harness) { h.typ("l") },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, standard())
			h.typ(" ")
			if h.m.rev == nil {
				t.Fatal("not revealed")
			}
			act(h)
			if h.m.rev != nil {
				t.Fatal("still revealed")
			}
			lacks(t, h.view(), "gh-token-value")
		})
	}
}

func TestLockedVaultAsksForPassphraseInTheUI(t *testing.T) {
	f := standard()
	h := newHarness(t, f)
	h.typ("G") // XERO_WEBHOOK_KEY in locked ebcfo
	h.typ(" ")
	if h.m.mode != modePrompt {
		t.Fatalf("no prompt; mode %v, status %q", h.m.mode, h.m.status)
	}
	v := h.view()
	contains(t, v, "Unlock", "Passphrase for 'ebcfo':")
	// Wrong first: the backend asks again, with its note.
	h.typ("not the pass")
	lacks(t, h.view(), "not the pass")
	contains(t, h.view(), "••••••••••••")
	h.enter()
	if h.m.mode != modePrompt {
		t.Fatal("expected a second prompt")
	}
	contains(t, h.view(), "Wrong passphrase.", "Passphrase for 'ebcfo':")
	h.typ("ebcfo pass")
	lacks(t, h.view(), "ebcfo pass")
	h.enter()
	if h.m.rev == nil || string(h.m.rev.val) != "xero-webhook-value" {
		t.Fatalf("not revealed; status %q", h.m.status)
	}
	contains(t, h.view(), "xero-webhook-value", "ebcfo 🔓")
}

func TestUnlockPromptCancelled(t *testing.T) {
	h := newHarness(t, standard())
	h.typ("G")
	h.typ(" ")
	h.typ("abc")
	h.esc()
	if h.m.rev != nil {
		t.Fatal("revealed after cancel")
	}
	if h.m.mode != modeBrowse || h.m.busy != "" {
		t.Fatalf("mode %v busy %q", h.m.mode, h.m.busy)
	}
	contains(t, h.view(), "! cancelled")
	lacks(t, h.view(), "xero-webhook-value")
}

func TestUnlockAndLockKeys(t *testing.T) {
	f := standard()
	h := newHarness(t, f)
	h.typ("G")
	h.typ("u")
	h.typ("ebcfo pass")
	h.enter()
	contains(t, h.view(), "ebcfo 🔓", "Unlocked ebcfo.")
	h.typ("l")
	contains(t, h.view(), "ebcfo 🔒", "Locked ebcfo.")
	h.typ("L")
	contains(t, h.view(), "personal 🔒", "Locked every vault.")
}

func TestAddKeyFlow(t *testing.T) {
	f := standard()
	h := newHarness(t, f)
	h.typ("a") // All selected, two vaults: asks which vault first
	contains(t, h.view(), "Vault (personal, ebcfo):")
	h.typ("nowhere")
	h.enter()
	contains(t, h.view(), "! No vault called that")
	h.typ("a")
	h.typ("personal")
	h.enter()
	contains(t, h.view(), "Key name")
	h.typ("bad name")
	h.enter()
	contains(t, h.view(), "! that name is not allowed")
	h.typ("a")
	h.typ("personal")
	h.enter()
	h.typ("STRIPE_KEY")
	h.enter()
	contains(t, h.view(), "Value for STRIPE_KEY (hidden)")
	h.typ("sk_live_typed_secret")
	contains(t, h.view(), "••••••••••••••••••••")
	lacks(t, h.view(), "sk_live_typed_secret")
	h.enter()
	contains(t, h.view(), "Description (optional)")
	lacks(t, h.view(), "sk_live_typed_secret")
	h.typ("Stripe live key")
	h.enter()
	if last := f.calls[len(f.calls)-1]; last != "set personal/STRIPE_KEY value=sk_live_typed_secret desc=Stripe live key" {
		t.Fatalf("backend call %q", last)
	}
	if h.selected() != "personal/STRIPE_KEY" {
		t.Fatalf("new key not selected: %s", h.selected())
	}
	contains(t, h.view(), "Saved STRIPE_KEY.", "Stripe live key")
	if h.m.pending != nil {
		t.Fatal("typed value kept")
	}
	lacks(t, h.view(), "sk_live_typed_secret")
}

func TestAddInSelectedVaultSkipsVaultQuestion(t *testing.T) {
	h := newHarness(t, standard())
	h.press(tea.KeyTab)
	h.typ("jj") // ebcfo
	h.press(tea.KeyTab)
	h.typ("a")
	contains(t, h.view(), "Key name")
}

func TestAddCancelWipesValue(t *testing.T) {
	h := newHarness(t, standard())
	h.press(tea.KeyTab)
	h.typ("j")
	h.press(tea.KeyTab)
	h.typ("a")
	h.typ("NEW_KEY")
	h.enter()
	h.typ("thevalue")
	h.enter() // now at the description prompt, value pending
	if h.m.pending == nil {
		t.Fatal("value not pending")
	}
	h.esc()
	if h.m.pending != nil {
		t.Fatal("value kept after cancel")
	}
	for _, c := range h.f.calls {
		if strings.HasPrefix(c, "set") {
			t.Fatalf("saved anyway: %s", c)
		}
	}
}

func TestEditValueDescribeTagMoveRename(t *testing.T) {
	f := standard()
	h := newHarness(t, f)
	h.typ("G") // ebcfo/XERO_WEBHOOK_KEY
	h.typ("e")
	h.typ("newer-value")
	h.enter()
	// ebcfo is locked: the passphrase prompt comes up from Set.
	h.typ("ebcfo pass")
	h.enter()
	if got := f.values["ebcfo/XERO_WEBHOOK_KEY"]; got != "newer-value" {
		t.Fatalf("value %q", got)
	}
	if last := f.calls[len(f.calls)-1]; !strings.HasSuffix(last, "desc=<keep>") {
		t.Fatalf("edit must keep the description: %s", last)
	}

	h.typ("d")
	if string(h.m.pr.buf) != "Webhook signing key" {
		t.Fatalf("describe not prefilled: %q", string(h.m.pr.buf))
	}
	h.typ(" v2")
	h.enter()
	contains(t, h.view(), "Webhook signing key v2")

	h.typ("t")
	h.typ(", reporting, extra")
	h.enter()
	if last := f.calls[len(f.calls)-1]; last != "tag ebcfo/XERO_WEBHOOK_KEY add=[reporting extra] rm=[]" {
		t.Fatalf("tag call %q", last)
	}
	h.typ("t")
	if string(h.m.pr.buf) != "reporting, extra" {
		t.Fatalf("tags prefill %q", string(h.m.pr.buf))
	}
	h.enter() // unchanged
	contains(t, h.view(), "Tags unchanged.")

	h.typ("r")
	h.typ("2")
	h.enter()
	if h.selected() != "ebcfo/XERO_WEBHOOK_KEY2" {
		t.Fatalf("after rename: %s", h.selected())
	}
	h.typ("m")
	h.typ("nope")
	h.enter()
	contains(t, h.view(), "! No vault called that")
	h.typ("m")
	h.typ("personal")
	h.enter()
	if h.selected() != "personal/XERO_WEBHOOK_KEY2" && h.m.status != "Moved XERO_WEBHOOK_KEY2 to personal." {
		t.Fatalf("after move: %s %q", h.selected(), h.m.status)
	}
	contains(t, h.view(), "Moved XERO_WEBHOOK_KEY2 to personal.")
}

func TestDeleteNeedsConfirmation(t *testing.T) {
	f := standard()
	h := newHarness(t, f)
	h.typ("x")
	contains(t, h.view(), "Delete GITHUB_TOKEN from 'personal'?", "30 days", "y delete")
	h.typ("n")
	contains(t, h.view(), "Cancelled.")
	h.typ("x")
	h.press(tea.KeyEnter) // Enter is not a yes
	for _, c := range f.calls {
		if strings.HasPrefix(c, "delete") {
			t.Fatalf("deleted without a y: %s", c)
		}
	}
	h.typ("x")
	h.typ("y")
	if f.calls[len(f.calls)-1] != "delete personal/GITHUB_TOKEN" {
		t.Fatalf("calls %v", f.calls)
	}
	lacks(t, h.view(), "GITHUB_TOKEN from")
	if len(h.m.rows()) != 4 {
		t.Fatalf("%d rows", len(h.m.rows()))
	}
}

func TestCopy(t *testing.T) {
	h := newHarness(t, standard())
	h.typ("c")
	contains(t, h.view(), "Copied GITHUB_TOKEN; the clipboard clears in 30s.")
	lacks(t, h.view(), "gh-token-value")
}

func TestFailedVaultShowsErrorInsteadOfKeys(t *testing.T) {
	f := standard()
	f.snap.Vaults = append(f.snap.Vaults, Vault{Name: "shared", Err: "vault 'shared': the vault's history was changed or rolled back", Verify: true})
	h := newHarness(t, f)
	v := h.view()
	contains(t, v, "⚠ shared:", "shared ⚠")
	// The error row comes first and is selectable; ops refuse.
	if _, ok := h.m.selectedKey(); ok {
		t.Fatal("error row counted as a key")
	}
	contains(t, v, "exit code 5", "rolled back")
	h.typ("x")
	if h.m.mode != modeBrowse {
		t.Fatal("delete started on an error row")
	}
	contains(t, h.view(), "! Pick a key first.")
	// Filtered to the failed vault: only the error shows.
	h.press(tea.KeyTab)
	h.typ("G")
	h.press(tea.KeyTab)
	lacks(t, h.view(), "OPENAI_API_KEY")
	contains(t, h.view(), "⚠ shared:")
}

func TestHostileTextIsNeutralised(t *testing.T) {
	f := newFake()
	f.addVault("v", true, "p")
	f.addKey("v", "EVIL\x1b[2JNAME", "desc \x1b]0;pwned\x07 \u202egnp.exe", "val\x1b[31m\nline2", "t\x1bg")
	h := newHarness(t, f)
	h.typ(" ")
	for _, fr := range h.frames {
		for _, r := range fr {
			if r != '\n' && (unicode.IsControl(r) || (r >= 0x202a && r <= 0x202e)) {
				t.Fatalf("control or bidi char %U in:\n%q", r, fr)
			}
		}
	}
	contains(t, h.view(), "val·[31m⏎line2")
}

func TestQuitWipesAndBlanksScreen(t *testing.T) {
	h := newHarness(t, standard())
	h.typ(" ")
	if h.m.rev == nil {
		t.Fatal("not revealed")
	}
	_, cmd := h.m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil || !h.m.quitting {
		t.Fatal("q did not quit")
	}
	if h.m.rev != nil {
		t.Fatal("value kept")
	}
	if h.view() != "" {
		t.Fatalf("last frame not blank: %q", h.view())
	}
}

func TestCtrlCQuitsFromAnyModeAndReleasesBackend(t *testing.T) {
	h := newHarness(t, standard())
	h.typ("G")
	h.typ(" ") // passphrase prompt, backend goroutine waiting
	if h.m.mode != modePrompt {
		t.Fatal("no prompt")
	}
	h.typ("half-typed")
	_, cmd := h.m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil || !h.m.quitting {
		t.Fatal("ctrl-c did not quit")
	}
	if h.m.pr != nil && len(h.m.pr.buf) != 0 {
		t.Fatal("typed text kept")
	}
	h.pump() // the backend goroutine was told "cancelled" and finishes
	if h.inflight != nil {
		t.Fatal("backend still waiting")
	}
}

func TestQuitCancelsPendingOnlyOnce(t *testing.T) {
	h := newHarness(t, standard())
	h.typ("q")
	h.press(tea.KeyCtrlC) // second quit must not panic or block
}

func TestResizeNeverOverflows(t *testing.T) {
	f := standard()
	f.addKey("ebcfo", strings.Repeat("LONG_NAME_", 12), strings.Repeat("long description ", 20), "v")
	f.snap.Vaults = append(f.snap.Vaults, Vault{Name: "broken", Err: strings.Repeat("it failed ", 30), Verify: true})
	h := newHarness(t, f)
	for _, sz := range [][2]int{{80, 24}, {60, 20}, {48, 14}, {40, 12}, {30, 10}, {20, 10}, {120, 40}, {200, 60}, {1, 1}} {
		h.resize(sz[0], sz[1])
		for _, act := range []func(){func() {}, func() { h.typ("/") }, func() { h.typ("x") }, func() { h.esc() }, func() { h.typ("a") }, func() { h.esc() }} {
			act()
			w := max(sz[0], 20)
			for i, l := range h.lines() {
				if ansi.StringWidth(l) > w {
					t.Fatalf("%dx%d line %d is %d wide: %q", sz[0], sz[1], i, ansi.StringWidth(l), l)
				}
			}
			if n := len(h.lines()); n > max(sz[1], 10) {
				t.Fatalf("%dx%d: %d lines", sz[0], sz[1], n)
			}
		}
	}
}

func TestNoColorHasNoEscapes(t *testing.T) {
	h := newHarness(t, standard())
	if strings.Contains(h.view(), "\x1b") {
		t.Fatal("NO_COLOR output contains escapes")
	}
	m := New(standard(), Options{})
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	if !m.st.color {
		t.Fatal("colour should default on")
	}
}

func TestBackendErrorsAreShown(t *testing.T) {
	f := standard()
	f.failWith = errors.New("cannot save the key: disk full")
	h := newHarness(t, f)
	h.typ("e")
	h.typ("v")
	h.enter()
	contains(t, h.view(), "! cannot save the key: disk full")
	if h.m.busy != "" {
		t.Fatal("still busy after error")
	}
}

func TestOnlyOneOperationAtATime(t *testing.T) {
	h := newHarness(t, standard())
	h.m.busy = "Saving"
	_, cmd := h.m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	if cmd != nil || h.m.mode != modeBrowse {
		t.Fatal("key accepted while busy")
	}
}

func TestEmptyStates(t *testing.T) {
	f := newFake()
	h := newHarness(t, f)
	contains(t, h.view(), "No vaults yet.", "0 vaults · 0 keys")
	h.typ("a")
	contains(t, h.view(), "! No vaults yet.")
	f.addVault("v", true, "p")
	h.run(h.m.loadSnap())
	contains(t, h.view(), "No keys yet. Press a to add one.")
}

type panicBackend struct{ *fakeBackend }

func (p panicBackend) ValidateName(string) error { panic("CANARY-panic-payload " + canaryStored) }

// A crash inside Update wipes what the model holds and re-panics with a
// fixed message, so a value cannot end up in a panic trace.
func TestPanicIsSanitisedAndWipes(t *testing.T) {
	f := standard()
	h := newHarness(t, f)
	m := New(panicBackend{f}, Options{NoColor: true, Now: h.m.now})
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	s, _ := f.Snapshot()
	m.Update(snapMsg{snap: s})
	m.rev = &revealed{vault: "personal", name: "x", val: []byte(canaryStored)}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}}) // rename prompt
	m.hide()
	m.rev = &revealed{vault: "personal", name: "x", val: []byte(canaryStored)}
	defer func() {
		r := recover()
		if r != "vault ui: internal error" {
			t.Fatalf("panic value %v", r)
		}
		if m.rev != nil {
			t.Fatal("value kept after panic")
		}
	}()
	m.Update(tea.KeyMsg{Type: tea.KeyEnter}) // submit calls ValidateName, which panics
	t.Fatal("no panic")
}
