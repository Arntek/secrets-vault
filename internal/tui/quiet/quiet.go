// Package quiet stops Bubble Tea from probing the terminal at program start.
//
// Bubble Tea v1 runs lipgloss.HasDarkBackground() in an init function, which
// writes an OSC 11 colour query to the terminal and waits for the reply, in
// every process that links it, not only when the UI runs. That would make
// every `vault get` or `vault list` typed in a terminal emit escape
// sequences, and stall for seconds on a terminal that does not answer.
//
// Setting the background explicitly makes lipgloss skip the query. Go runs
// package initialisers in import-path order among packages whose imports are
// ready, and this package (path ".../Arntek/...", importing only lipgloss)
// sorts before github.com/charmbracelet/bubbletea, so this init runs first.
// To re-check after upgrading Bubble Tea: run `vault version` in a pseudo
// terminal and make sure no ESC ] 11 ; ? or ESC [ 6 n comes out (the QA steps
// on issue r1q.3 have a ready script).
package quiet

import "github.com/charmbracelet/lipgloss"

func init() { lipgloss.SetHasDarkBackground(true) }
