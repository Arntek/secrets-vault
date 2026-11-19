package tui

import (
	"errors"
	"fmt"
	"io"

	tea "github.com/charmbracelet/bubbletea"

	_ "github.com/Arntek/secrets-vault/internal/tui/quiet" // before bubbletea's init: no terminal probe
)

// Run shows the UI until the person quits. It uses the alternate screen, so
// nothing it draws reaches the scrollback, and clears it on the way out
// (Ctrl-C and a panic included). in and out must be the terminal.
func Run(b Backend, o Options, in io.Reader, out io.Writer) (err error) {
	m := New(b, o)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithInput(in), tea.WithOutput(out))
	m.send = p.Send
	defer func() {
		m.wipe()
		// Belt and braces: leave the alternate screen (its contents go with
		// it) even if the program ended abnormally. Harmless if already done.
		// The normal screen is never cleared.
		_, _ = io.WriteString(out, "\x1b[?1049l")
	}()
	_, rerr := p.Run()
	if m.Crashed() {
		return errors.New("the terminal UI hit an internal error and closed")
	}
	switch {
	case rerr == nil, errors.Is(rerr, tea.ErrProgramKilled):
		return nil
	case errors.Is(rerr, tea.ErrProgramPanic):
		return errors.New("the terminal UI hit an internal error and closed")
	}
	if m.Crashed() {
		return errors.New("the terminal UI hit an internal error and closed")
	}
	return fmt.Errorf("the terminal UI could not run: %w", rerr)
}

// Attach tells the model how to deliver messages to the running program. Run
// does this itself; it is exported so tests in other packages can drive the
// model without a terminal.
func (m *Model) Attach(send func(tea.Msg)) { m.send = send }
