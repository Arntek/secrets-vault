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
// The Logger interface was fixed in Phase 1 so code recorded events from the
// start; File (file.go) is the real logger and Nop discards events.
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
	// Membership and passphrase changes. Event.Member names the person.
	ActionMemberAdd    Action = "member-add"
	ActionMemberRemove Action = "member-remove"
	ActionPasswd       Action = "passwd"
	// ActionSetAside: `doctor --set-aside-unknown` moved files the write
	// guard could not account for into quarantine/ (after a typed
	// confirmation). Nothing is deleted.
	ActionSetAside Action = "set-aside"
)

// Event is one audit record. It holds names only, never values.
type Event struct {
	Time    time.Time `json:"time"`
	Vault   string    `json:"vault"`
	Key     string    `json:"key,omitempty"`
	Action  Action    `json:"action"`
	Program string    `json:"program,omitempty"` // calling program, e.g. "python3"
	PID     int       `json:"pid,omitempty"`     // process ID of the calling program
	Command string    `json:"command,omitempty"` // the vault command, e.g. "get"
	Member  string    `json:"member,omitempty"`  // member added or removed
	Via     string    `json:"via,omitempty"`     // how a vault was unlocked: "dialog"
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
