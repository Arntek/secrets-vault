# Vault format and crypto API

How `internal/format` and `internal/crypto` fit together, for the CLI, agent, members and Touch ID code. Godoc on each function has the details; this page is the map.

## On disk

```
<vault dir>/
  vault.json                      version 2: vault id, name, key_id, members, unlockers, signed membership log
  rotation.lease                  only while a member rotates the key (signed, advisory)
  requests/NAME.json              signed join requests
  index.json                      names, descriptions, tags, updated, updated_by (readable without unlocking)
  secrets/NAME.age                one age file per key
  secrets/.trash/NAME.<UTC>.age   deleted keys, purged after 30 days
  secrets/.sv-rotate-<key id>/    only during a key rotation
```

- **`vault.json` version 2** carries the **membership log**: hash-chained records, each signed (Ed25519) by a member of the state before it, from a genesis record signed by the owner it creates. `members` and the unlocker list must match the head record's hashes exactly. Package `members` verifies it (`members.Verify`, `members.Load`) and nothing may use a `vault.json` before that. The design, threat by threat: [design/membership-auth.md](design/membership-auth.md). Version 1 files (pre-release) are parsed only so a personal vault can be migrated.
- **`key_id`** in `vault.json` is a public fingerprint of the current vault key (`crypto.VaultKey.ID()`, HKDF-SHA256). It changes on rotation.
- **Secret files** are standard age files with one custom recipient stanza, `sv-vaultkey2 <key id> <salt>`. Its file key is wrapped with AES-256-GCM under `HKDF(vault key, salt, "secrets-vault/v2 secret file key\0" + NAME)`. Files of the earlier `sv-vaultkey` / v1-label form are still read and are re-sealed in the new form by migration and before writes (`crypto.UpgradeSecrets`), so builds from before the membership log can neither open nor rotate them (ue1.8). Because the key name is in the derivation, a file only opens under its own name: swapping `A.age` and `B.age` is detected. The age header MAC and STREAM payload authenticate everything else.
- **Unlockers** wrap the raw 32-byte vault key as an age file: X25519 recipient for each `member` (one per member, label = name), scrypt recipient for at most one `passphrase` (recovery). Version 2 has no vault-level `touchid` unlockers: Touch ID protects each person's identity instead, so a rotation never drops it. The plaintext of every wrapped key this build writes is `"secrets-vault/v2 wrapped key\0"` followed by the 32 key bytes; earlier builds expect the bare 32 bytes and so can't unwrap it (ue1.8). Bare keys are still accepted when reading (migration, older identity files).

## Parsing rules (every file)

Strict, and never half-read: size limits (`MaxFileSize`, `MaxVaultFileSize` (4 MiB, for the log), `MaxSecretFileSize`, `MaxRecordSize`), valid UTF-8, no duplicate or non-lower-case JSON keys, no unknown fields, no trailing data, nesting depth 16, version check first (`ErrUnsupportedVersion` for newer files). Labels, descriptions and `updated_by` may not contain control or bidi-override characters, so a tampered index cannot rewrite what `vault list` prints. Errors wrap `format.ErrMalformed` and never quote input. Vault files are opened with `O_NOFOLLOW` and must be regular files. Every function that writes, renames or deletes under a vault first calls `format.CheckVaultDirs`: the vault folder, `secrets/`, `secrets/.trash/`, `requests/` and staging folders must be real directories (not symlinks) owned by the user. A log entry is exactly `{body, by, sig}`; `body` is the record's exact JSON bytes (base64), so signatures are over exactly what was signed.

## Typical calls

| Task | Calls |
|---|---|
| Create a vault | `members.NewVault(dir, name, key, ownerIdentity, passphraseWrapper, now)` |
| Open a vault | `chain, _, err := members.Load(dir, registeredID)`; `members.Classify(chain, pin)`; then `crypto.Unlock(chain.File, wrapper)`; for writes `crypto.RecoverRotation(dir, key)` (only for a verified rotation) and `members.CheckFolder` |
| Read a key | `crypto.ReadSecret(dir, name, key)` (caller zeroes the result) |
| Write a key | `crypto.WriteSecret(dir, name, key, value)`, then `idx.Upsert(...)` + `format.WriteIndex` |
| List without unlocking | `format.ReadIndex(dir)`; if missing or broken, `format.RebuildIndex(dir, old)` |
| Delete / restore | `format.TrashSecret`, `format.RestoreSecret`, `format.ListTrash`, `format.PurgeTrash(dir, now)` |
| Add a member | `members.ApproveRequest(dir, chain, key, signer, name, typedFingerprint, readd, now)` |
| Remove a member | `members.Remove(dir, chain, key, signer, name, members.RotateOptions{...})` (rotates) |
| Change the passphrase | `members.Passwd(dir, chain, key, signer, newPass, rotate, opt)` |
| Any vault.json change | `chain.Append(signer, members.Change{...})`, then `format.WriteVaultFileCAS(dir, next, chain.Raw)` |
| Doctor | `format.FindConflicts(dir)`, `format.PendingRotations(dir)` |

## Wrappers

- `crypto.NewPassphraseWrapper(pass)`: scrypt work factor 18. Tests use `NewPassphraseWrapperWithWorkFactor(pass, crypto.MinScryptWorkFactor)`. Unwrap refuses stored work factors above 20. The wrapper has `Destroy()` to zero its copy (age needs a Go string internally, which can't be zeroed).
- `crypto.NewMemberWrapper(label, "age1...")`: wrap only, for adding someone else.
- `crypto.NewMemberIdentityWrapper(label, *age.X25519Identity)`: wrap and unwrap, for yourself.
- `touchid.Wrapper(device)`: implements `crypto.KeyWrapper` from package touchid.

`crypto.Unlock` tries the wrapper on every unlocker of its type, so a wrapper's `Unwrap` must return `ErrWrongKey` quickly for unlockers that aren't its own (compare `Recipient` first). For Touch ID this means no sheet for another Mac's unlocker.

## Key rotation

`crypto.Rotate` decrypts every live and trashed secret with the old key (or one of `ExtraKeys`), stages the re-encrypted files in `secrets/.sv-rotate-<new key id>/` with a `MANIFEST`, asks `Next` for the new `vault.json` (package `members` wraps the key for the verified members and appends the signed record), writes it with a compare-and-swap on the bytes the caller verified (the commit point), re-reads it, then moves the staged files into place. A failure before `vault.json` is written changes nothing. A failure after it is finished by `crypto.RecoverRotation(dir, key)`, which the CLI calls after verifying and unlocking, only for a key a verified rotation introduced, and which checks that every staged file opens under that key before moving anything. If another change replaced `vault.json` right after the write, `Rotate` leaves the files (`crypto.ErrRotationRace`) for the race to be repaired. Rotation refuses to run while sync-conflict copies exist (`crypto.ErrConflicts`).

## Known limits

- **Rollback of single files.** An older copy of a `NAME.age` (same key) still opens; `index.json` is not authenticated. Issue ue1.7.
- **Offline members.** A member who hasn't opened the vault since a removal can be fooled by a removed member who kept folder write access and restored the whole folder (see the design's Threat 4); the write guard, the state code and the required folder-access step narrow this.
- **Concurrent edits.** Two machines writing `index.json` at once: last write wins; `RebuildIndex` restores missing names. Two membership changes at once: the losing machine re-applies its change (or refuses, if the other change could weaken it).
- **Private index** (`index.json` `private: true`) is parsed but not yet encrypted.
