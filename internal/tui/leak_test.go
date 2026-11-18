package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

const (
	canaryStored = "CANARY-stored-7c1e9a40-must-not-leak"
	canaryTyped  = "CANARY-typed-5d02b6f3-must-not-leak"
	canaryPass   = "CANARY-pass-91ab33de-must-not-leak"
)

// TestLeakValuesNeverOnScreenOutsideReveal drives the model through every
// action with canary values and checks every rendered frame: the stored
// value may appear only while it is revealed (between the press and the
// re-mask), and values typed into prompts and passphrases never appear.
func TestLeakValuesNeverOnScreenOutsideReveal(t *testing.T) {
	f := newFake()
	f.addVault("personal", true, "pp")
	f.addVault("locked", false, canaryPass)
	f.addKey("personal", "TOKEN", "a token", canaryStored)
	f.addKey("locked", "SECRET", "another", canaryStored+"-locked")
	h := newHarness(t, f)

	frames := 0
	check := func(step string) {
		t.Helper()
		v := h.view()
		frames++
		if h.m.rev == nil && strings.Contains(v, canaryStored) {
			t.Fatalf("%s: stored value on screen while masked:\n%s", step, v)
		}
		for _, c := range []string{canaryTyped, canaryPass} {
			if strings.Contains(v, c) {
				t.Fatalf("%s: %s on screen:\n%s", step, c, v)
			}
		}
		if h.m.rev == nil && strings.Contains(h.m.status, canaryStored) {
			t.Fatalf("%s: value in status", step)
		}
	}
	for i, fr := range h.frames { // frames from setup
		_ = i
		if strings.Contains(fr, canaryStored) {
			t.Fatal("value on screen at start")
		}
	}

	// Reveal, wait, re-mask by timeout.
	h.goTo(t, "personal/TOKEN")
	check("select")
	h.typ(" ")
	if !strings.Contains(h.view(), canaryStored) {
		t.Fatal("explicit reveal did not show the value")
	}
	check("revealed")
	h.tick(5 * time.Second)
	check("revealed +5s")
	h.tick(5 * time.Second)
	if strings.Contains(h.view(), canaryStored) {
		t.Fatal("value still shown 10s after reveal")
	}
	check("after timeout")

	// Reveal then each focus-changing action.
	for name, act := range map[string]func(){
		"tab":    func() { h.press(tea.KeyTab); h.press(tea.KeyTab) },
		"down":   func() { h.typ("j"); h.typ("k") },
		"search": func() { h.typ("/"); h.esc() },
		"lock": func() {
			h.typ("l")
			h.f.unlocked["personal"] = true
			h.run(h.m.loadSnap())
		},
		"esc": func() { h.esc() },
	} {
		h.goTo(t, "personal/TOKEN")
		h.typ(" ")
		if h.m.rev == nil {
			t.Fatalf("%s: not revealed", name)
		}
		act()
		check("after " + name)
	}

	// Copy never shows the value.
	h.goTo(t, "personal/TOKEN")
	h.typ("c")
	check("copy")

	// Locked vault: passphrase typed in the UI, then reveal, then quit.
	h.goTo(t, "locked/SECRET")
	h.typ(" ")
	h.typ(canaryPass)
	check("passphrase typed")
	h.enter()
	check("passphrase entered")
	h.tick(10 * time.Second)
	check("locked value hidden")

	// Add and edit: typed values stay off screen, including the saved view.
	h.typ("a")
	h.typ("personal")
	h.enter()
	h.typ("NEW_KEY")
	h.enter()
	h.typ(canaryTyped)
	check("add value typed")
	h.enter()
	check("add description")
	h.enter()
	check("add saved")
	h.typ("e")
	h.typ(canaryTyped)
	check("edit typed")
	h.enter()
	check("edit saved")

	// Every frame ever rendered obeys the rule too.
	for i, fr := range h.frames {
		if strings.Contains(fr, canaryTyped) || strings.Contains(fr, canaryPass) {
			t.Fatalf("frame %d holds a typed secret:\n%s", i, fr)
		}
	}

	// Reveal and quit: the last frame is blank and nothing is held.
	h.goTo(t, "personal/TOKEN")
	h.typ(" ")
	h.typ("q")
	if h.view() != "" || h.m.rev != nil {
		t.Fatal("value left after quit")
	}
	t.Logf("checked %d frames", frames)
}

// goTo moves the selection to vault/name (searching from the top).
func (h *harness) goTo(t *testing.T, want string) {
	t.Helper()
	h.typ("g")
	for i := 0; i < 30 && h.selected() != want; i++ {
		h.typ("j")
	}
	if h.selected() != want {
		t.Fatalf("cannot select %s (at %q, mode %v, status %q)\n%s", want, h.selected(), h.m.mode, h.m.status, h.view())
	}
}
