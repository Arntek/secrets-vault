// Package tui is the full-screen terminal interface behind `vault ui`.
//
// It runs inside the vault process: no server, no port, no network. The
// package holds no vault logic and imports no other internal package. It
// talks to the vault only through Backend, which package cli implements by
// calling the same operations the CLI commands use, so the index, the audit
// hook, membership verification and exit-code semantics are identical.
//
// Secret handling rules (checked by leak_test.go):
//   - a value is masked unless the person pressed space on it, and is
//     re-masked after RevealFor, on any focus or selection change, on lock
//     and on exit;
//   - the screen is the terminal's alternate screen, wiped on exit
//     (including Ctrl-C and a panic), so nothing reaches scrollback;
//   - everything shown (names, descriptions, values) has control characters
//     removed, so a hostile entry cannot send escape sequences to the
//     terminal.
package tui

import "time"

// RevealFor is how long a revealed value stays on screen.
const RevealFor = 10 * time.Second

// Prompter asks the person a question inside the UI and blocks until they
// answer. hidden prompts are not echoed. text is the question; a multi-line
// text shows its earlier lines as a note. It returns ErrCancelled if the
// person pressed Esc.
type Prompter func(text string, hidden bool) ([]byte, error)

// Backend is what the UI needs from the vault. Every method may block (Touch
// ID, a prompt, disk) and is called from one goroutine at a time.
type Backend interface {
	// SetPrompter gives the backend a way to ask for passphrases and
	// confirmations inside the UI. Called once before anything else.
	SetPrompter(Prompter)
	// Snapshot reads every registered vault's index. It never unlocks.
	Snapshot() (Snapshot, error)
	// ValidateName reports why a key name is not allowed, or nil.
	ValidateName(name string) error

	// Reveal decrypts one value (unlocking if needed) and records the read.
	// The caller zeroes the result.
	Reveal(vault, name string) ([]byte, error)
	// Copy puts the value on the clipboard; willClear reports that clearing
	// it after ClipboardClear was scheduled.
	Copy(vault, name string) (willClear bool, err error)
	// Set adds or updates a key. vault "" means the default vault. desc nil
	// keeps an existing description. value is zeroed by the caller.
	Set(vault, name string, value []byte, desc *string) error
	Describe(vault, name, text string) error
	// Tag adds and removes tags (either may be empty).
	Tag(vault, name string, add, remove []string) error
	Move(vault, name, to string) error
	Rename(vault, name, newName string) error
	Delete(vault, name string) error
	Unlock(vault string) error
	Lock(vault string) error
	LockAll() error
}

// ClipboardClear is how long a copied value stays on the clipboard.
const ClipboardClear = 30 * time.Second

// Snapshot is the state shown on screen.
type Snapshot struct {
	Vaults []Vault
	Keys   []Key
}

// Vault is one registered vault.
type Vault struct {
	Name     string
	Keys     int
	Unlocked bool
	Expires  time.Time // when it locks again, if unlocked
	// Err is why the vault could not be listed (it failed verification or
	// could not be read). The UI shows it instead of keys.
	Err string
	// Verify is true when the error is a verification failure (exit code 5:
	// tampered, substituted, rolled back, behind a state code).
	Verify bool
}

// Key is one index entry. It never holds a value.
type Key struct {
	Name        string
	Vault       string
	Description string
	Tags        []string
	Updated     time.Time
	UpdatedBy   string
}
