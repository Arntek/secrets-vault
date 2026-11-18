// Package index authenticates a vault's index.json and detects rollback of
// single secret files (docs/design/index-auth.md, issues ue1.7 and ue1.12).
//
// Every index entry carries a MAC under a key derived from the vault key
// (package crypto); every secret file carries its version in its age
// header; each machine keeps a local snapshot of the entries it has
// verified. This package turns those three into answers:
//
//   - Load verifies the folder's index with the vault key and cross-checks
//     it against the files and the snapshot (View);
//   - Locked answers what `list` may show without the key (LockedView);
//   - Session.Commit is the compare-and-swap write loop every key-changing
//     command uses, merging concurrent writers entry by entry.
//
// Reading never writes the folder. The package imports format and crypto
// only: the caller (cli) supplies facts about the verified membership chain
// through small callbacks.
package index
