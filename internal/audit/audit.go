// Package audit is the local read log behind `vault log`: which key was
// read or changed, when, from which vault, by which program.
//
// The Event type deliberately has no field that could hold a value. Never
// add one. Leak tests run the audit log through package leaktest.
//
// Responsibilities:
//   - Appending events to a per-user log file (0600) outside any vault folder.
//   - Reading them back for `vault log` and for listing keys a removed member
//     may have seen (package members uses this to suggest rotations).
//
// Dependency rule: audit imports only the standard library. Any package may
// import it.
//
// Owned by Phase 2 (vault log); the Logger interface is fixed now so Phase 1
// code records events from the start.
package audit

import "time"

// Action is what happened to a key.
type Action string

// Actions recorded in the audit log.
const (
	ActionRead   Action = "read"
	ActionSet    Action = "set"
	ActionDelete Action = "delete"
	ActionMove   Action = "move"
	ActionRename Action = "rename"
	ActionUnlock Action = "unlock"
	ActionLock   Action = "lock"
)

// Event is one audit record. It holds names only, never values.
type Event struct {
	Time    time.Time `json:"time"`
	Vault   string    `json:"vault"`
	Key     string    `json:"key,omitempty"`
	Action  Action    `json:"action"`
	Program string    `json:"program,omitempty"` // calling program, e.g. "python3"
	User    string    `json:"user,omitempty"`
}

// Logger records audit events.
type Logger interface {
	Record(Event) error
}

// Nop is a Logger that discards events, for tests and until Phase 2.
type Nop struct{}

// Record discards e.
func (Nop) Record(Event) error { return nil }
