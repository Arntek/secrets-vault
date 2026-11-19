// Package testguard makes code that touches the person's real desktop fail
// loudly under `go test` instead of acting: a macOS password dialog, a Touch
// ID sheet, the system clipboard. Tests must use fakes; if one reaches the
// real thing by mistake, Forbid panics so it shows up as a failure, not as a
// dialog popping up on someone's screen.
package testguard

import "testing"

// Forbid panics when running inside a test binary. what names the action.
func Forbid(what string) {
	if testing.Testing() {
		panic("testguard: a test reached the real " + what + "; inject a fake instead")
	}
}
