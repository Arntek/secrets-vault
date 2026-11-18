# Vault format and crypto API

How `internal/format` and `internal/crypto` fit together, for the CLI, agent, members and Touch ID code. Godoc on each function has the details; this page is the map.

## On disk

```
<vault dir>/
  vault.json                      format version, vault id, name, key_id, unlockers
  index.json                      names, descriptions, tags, updated, updated_by (readable without unlocking)
  secrets/NAME.age                one age file per key
  secrets/.trash/NAME.<UTC>.age   deleted keys, purged after 30 days
  secrets/.sv-rotate-<key id>/    only during a key rotation
```

- **`key_id`** in `vault.json` is a public fingerprint of the current vault key (`crypto.VaultKey.ID()`, HKDF-SHA256). It changes on rotation.
- **Secret files** are standard age files with one custom recipient stanza, `sv-vaultkey <key id> <salt>`. Its file key is wrapped with AES-256-GCM under `HKDF(vault key, salt, "secrets-vault/v1 secret file key\0" + NAME)`. Because the key name is in the derivation, a file only opens under its own name: swapping `A.age` and `B.age` is detected. The age header MAC and STREAM payload authenticate everything else.
- **Unlockers** wrap the raw 32-byte vault key as an age file: scrypt recipient for `passphrase`, X25519 recipient for `member`, and whatever `touchid` produces.

## Parsing rules (every file)

Strict, and never half-read: size limits (`MaxFileSize`, `MaxSecretFileSize`), valid UTF-8, no duplicate or non-lower-case JSON keys, no unknown fields, no trailing data, nesting depth 16, version check first (`ErrUnsupportedVersion` for newer files). Labels, descriptions and `updated_by` may not contain control or bidi-override characters, so a tampered index cannot rewrite what `vault list` prints. Errors wrap `format.ErrMalformed` and never quote input. Vault files are opened with `O_NOFOLLOW` and must be regular files.

## Typical calls

| Task | Calls |
|---|---|
| Create a vault | `key := crypto.NewVaultKey()`; `vf := crypto.NewVaultFile(name, key, wrappers)`; `format.CreateVault(dir, vf)` |
| Open a vault | `vf := format.ReadVaultFile(dir)`; `format.RecoverRotation(dir, vf.KeyID)`; then `crypto.Unlock(vf, wrapper)` |
| Read a key | `crypto.ReadSecret(dir, name, key)` (caller zeroes the result) |
| Write a key | `crypto.WriteSecret(dir, name, key, value)`, then `idx.Upsert(...)` + `format.WriteIndex` |
| List without unlocking | `format.ReadIndex(dir)`; if missing or broken, `format.RebuildIndex(dir, old)` |
| Delete / restore | `format.TrashSecret`, `format.RestoreSecret`, `format.ListTrash`, `format.PurgeTrash(dir, now)` |
| Change passphrase | `crypto.Unlock` with the old wrapper, `newW.Wrap(key)`, `vf.SetUnlocker(u)`, `format.WriteVaultFile` |
| Add Touch ID / member | `w.Wrap(key)`, `vf.SetUnlocker(u)`, `format.WriteVaultFile` (secret files untouched) |
| Remove a member | `crypto.Rotate(dir, key, remainingWrappers)` returns the new key |
| Doctor | `format.FindConflicts(dir)`, `format.PendingRotations(dir)` |

## Wrappers

- `crypto.NewPassphraseWrapper(pass)`: scrypt work factor 18. Tests use `NewPassphraseWrapperWithWorkFactor(pass, crypto.MinScryptWorkFactor)`. Unwrap refuses stored work factors above 20. The wrapper has `Destroy()` to zero its copy (age needs a Go string internally, which can't be zeroed).
- `crypto.NewMemberWrapper(label, "age1...")`: wrap only, for adding someone else.
- `crypto.NewMemberIdentityWrapper(label, *age.X25519Identity)`: wrap and unwrap, for yourself.
- `touchid.Wrapper(device)`: implements `crypto.KeyWrapper` from package touchid.

`crypto.Unlock` tries the wrapper on every unlocker of its type, so a wrapper's `Unwrap` must return `ErrWrongKey` quickly for unlockers that aren't its own (compare `Recipient` first). For Touch ID this means no sheet for another Mac's unlocker.

## Key rotation

`crypto.Rotate` decrypts every live and trashed secret with the old key, stages the re-encrypted files in `secrets/.sv-rotate-<new key id>/` with a `MANIFEST`, writes `vault.json` (the commit point), then moves the staged files into place. A failure before `vault.json` is written changes nothing. A failure after it is finished by `format.RecoverRotation`, which the CLI must call whenever it opens a vault. Rotation refuses to run while sync-conflict copies exist (`crypto.ErrConflicts`).

## Known limits

- **Key substitution by folder writers.** Anyone who can write the folder can replace `vault.json` with one whose key they chose (member and Touch ID unlockers are wrapped to public keys). `crypto.Unlock` checks the unwrapped key against `key_id`, which stops copied-in unlockers, but not a wholesale replacement. The CLI should remember each vault's `key_id` in the registry and warn when it changes outside a rotation it ran.
- **Rollback.** An older copy of a `NAME.age` (same key) still opens. Not detected.
- **Concurrent edits.** Two machines writing `index.json` at once: last write wins; `RebuildIndex` restores missing names. A secret written with the old key on another machine during a rotation becomes unreadable (`crypto.ErrOtherKey`).
- **Private index** (`index.json` `private: true`) is parsed but not yet encrypted.
