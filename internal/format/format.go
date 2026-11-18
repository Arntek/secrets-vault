// Package format defines the on-disk layout of a vault folder and the data
// types stored in it. It is the common format every vault uses (design D6).
//
// A vault folder looks like this:
//
//	<vault dir>/
//	  vault.json          VaultFile: format version, vault id, name, wrapped vault keys
//	  index.json          Index: key names, descriptions, tags. Readable without unlocking.
//	  secrets/NAME.age    one age-encrypted file per key
//	  secrets/.trash/     deleted keys, kept 30 days
//	  requests/           member join requests (see package members)
//
// Responsibilities:
//   - Go types for vault.json, index.json and unlocker records.
//   - Strict parsing and validation of those files: unknown fields, oversize
//     input, bad versions and malformed names are rejected, never half-read.
//   - Validating key names, which become file names under secrets/.
//   - Path helpers that map a vault dir and key name to file paths.
//   - Sync-safe writes (write temp file in the same dir, fsync, rename).
//
// Not here: any cryptography. format stores wrapped keys and ciphertext as
// opaque bytes; package crypto produces and consumes them. format depends on
// the standard library only, so every other package may import it.
//
// Every parser in this package must have a Go fuzz target (FuzzXxx) so the
// nightly fuzz job covers it.
package format

import (
	"errors"
	"time"
)

// CurrentVersion is the vault format version written by this build.
const CurrentVersion = 1

// File and directory names inside a vault folder.
const (
	VaultFileName = "vault.json"
	IndexFileName = "index.json"
	SecretsDir    = "secrets"
	TrashDir      = ".trash"
	RequestsDir   = "requests"
	SecretExt     = ".age"
)

// MaxFileSize bounds how much of any vault metadata file is read, so a
// tampered or corrupt file cannot exhaust memory.
const MaxFileSize = 1 << 20 // 1 MiB

// ErrNotImplemented is returned by stubs that later issues fill in.
var ErrNotImplemented = errors.New("format: not implemented")

// UnlockerType names one way of opening a vault key.
type UnlockerType string

// Unlocker types defined by the design. The passphrase unlocker is always
// present: it is the recovery route.
const (
	UnlockerPassphrase UnlockerType = "passphrase"
	UnlockerTouchID    UnlockerType = "touchid"
	UnlockerMember     UnlockerType = "member"
)

// Unlocker is one wrapped copy of the vault key, stored in vault.json.
// WrappedKey is opaque to this package; package crypto (or a KeyWrapper such
// as touchid) creates and opens it.
type Unlocker struct {
	Type UnlockerType `json:"type"`
	// Label identifies the unlocker to humans: the device name for touchid,
	// the member name for member. Empty for passphrase.
	Label string `json:"label,omitempty"`
	// Recipient is a public identifier for the wrapping key (an age recipient
	// string or Secure Enclave public key). Never secret.
	Recipient string `json:"recipient,omitempty"`
	// WrappedKey is the vault key encrypted to this unlocker.
	WrappedKey []byte    `json:"wrapped_key"`
	Created    time.Time `json:"created"`
}

// VaultFile is the content of vault.json.
type VaultFile struct {
	Version   int        `json:"version"`
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Unlockers []Unlocker `json:"unlockers"`
}

// IndexEntry describes one key without revealing its value.
type IndexEntry struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Updated     time.Time `json:"updated"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
}

// Index is the content of index.json. It is readable without unlocking
// (design D2) and is rebuilt from secrets/ if it drifts.
type Index struct {
	Version int          `json:"version"`
	Private bool         `json:"private,omitempty"`
	Entries []IndexEntry `json:"entries"`
}

// ParseVaultFile strictly decodes vault.json. Owned by issue 6j5.
func ParseVaultFile(data []byte) (*VaultFile, error) {
	_ = data
	return nil, ErrNotImplemented
}

// ParseIndex strictly decodes index.json. Owned by issue 6j5.
func ParseIndex(data []byte) (*Index, error) {
	_ = data
	return nil, ErrNotImplemented
}
