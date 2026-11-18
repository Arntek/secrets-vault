# Vault format and crypto API

How `internal/format` and `internal/crypto` fit together, for the CLI, agent, members and Touch ID code. Godoc on each function has the details; this page is the map.

## On disk

```
<vault dir>/
  vault.json                      version 3: vault id, name, key_id, members, unlockers, signed membership log (version 2 is read and upgraded)
  rotation.lease                  only while a member rotates the key (signed, advisory)
  requests/NAME.json              signed join requests
  index.json                      version 2: per entry name, description, tags, updated, updated_by, version, rev, deleted, mac (readable without unlocking, verified with the key)
  secrets/NAME.age                one age file per key
  secrets/.trash/NAME.<UTC>.age   deleted keys, purged after 30 days
  secrets/.sv-rotate-<key id>/    only during a key rotation
```

- **`vault.json` version 2 and 3** carry the **membership log**: hash-chained records, each signed (Ed25519) by a member of the state before it, from a genesis record signed by the owner it creates. `members` and the unlocker list must match the head record's hashes exactly. Package `members` verifies it (`members.Verify`, `members.Load`) and nothing may use a `vault.json` before that. The design, threat by threat: [design/membership-auth.md](design/membership-auth.md). **The vault format is part of the signed history:** a genesis record carries `format: 3` (new vaults), an `upgrade-format` record moves a format-2 vault to 3, the format never decreases, and `vault.json`'s `version` must equal the chain's format, so a downgrade by a folder writer is refused. Version 1 files (pre-release) are parsed only so a personal vault can be migrated.
- **`key_id`** in `vault.json` is a public fingerprint of the current vault key (`crypto.VaultKey.ID()`, HKDF-SHA256). It changes on rotation.
- **Index entries** (`index.json` v2) each carry `mac = HMAC-SHA256(K_idx, domain || enc(vault id, key id, name, version, rev, deleted, description, tags, updated, updated_by))` with `K_idx = HKDF(vault key, "secrets-vault/v3 index mac key")`; only a key holder can make or change one, a rotation invalidates all of them (and re-seals them), and an entry from another vault fails. `version` counts value writes (it is also sealed into the secret file), `rev` counts every change to the entry, `deleted` marks a tombstone (kept until the next rotation). The file-level `vault_id` is advisory. Design: [design/index-auth.md](design/index-auth.md).
- **Secret files** are standard age files with one custom recipient stanza, `sv-vaultkey3 <key id> <salt> <version>`: the version (1 to 2^31-1) is the file's own write counter, bound into the file key's GCM as associated data and covered by age's header MAC, with HKDF label `secrets-vault/v3 secret file key\0`. `crypto.VersionOf` reads it without decrypting. Files of the earlier forms (`sv-vaultkey2 <key id> <salt>`, and `sv-vaultkey`) are still read as version 0 and are stamped version 1 by `vault upgrade` (`crypto.UpgradeToV3`). Its file key is wrapped with AES-256-GCM under `HKDF(vault key, salt, "secrets-vault/v2 secret file key\0" + NAME)`. Files of the earlier `sv-vaultkey` / v1-label form are still read and are re-sealed in the new form by migration and before writes (`crypto.UpgradeSecrets`), so builds from before the membership log can neither open nor rotate them (ue1.8). Because the key name is in the derivation, a file only opens under its own name: swapping `A.age` and `B.age` is detected. The age header MAC and STREAM payload authenticate everything else.
- **Unlockers** wrap the raw 32-byte vault key as an age file: X25519 recipient for each `member` (one per member, label = name), scrypt recipient for at most one `passphrase` (recovery). Version 2 has no vault-level `touchid` unlockers: Touch ID protects each person's identity instead, so a rotation never drops it. The plaintext of every wrapped key this build writes is `"secrets-vault/v2 wrapped key\0"` followed by the 32 key bytes; earlier builds expect the bare 32 bytes and so can't unwrap it (ue1.8). Bare keys are still accepted when reading (migration, older identity files).

## Parsing rules (every file)

Strict, and never half-read: size limits (`MaxFileSize`, `MaxVaultFileSize` (4 MiB, for the log), `MaxSecretFileSize`, `MaxRecordSize`), valid UTF-8, no duplicate or non-lower-case JSON keys, no unknown fields, no trailing data, nesting depth 16, version check first (`ErrUnsupportedVersion` for newer files). Labels, descriptions and `updated_by` may not contain control or bidi-override characters, so a tampered index cannot rewrite what `vault list` prints. Errors wrap `format.ErrMalformed` and never quote input. Vault files are opened with `O_NOFOLLOW` and must be regular files. Every function that writes, renames or deletes under a vault first calls `format.CheckVaultDirs`: the vault folder, `secrets/`, `secrets/.trash/`, `requests/` and staging folders must be real directories (not symlinks) owned by the user. A log entry is exactly `{body, by, sig}`; `body` is the record's exact JSON bytes (base64), so signatures are over exactly what was signed.

## Typical calls

| Task | Calls |
|---|---|
| Create a vault | `members.NewVault(dir, name, key, ownerIdentity, passphraseWrapper, now)` |
| Open a vault | `chain, _, err := members.Load(dir, registeredID)`; `members.Classify(chain, pin)`; then `crypto.Unlock(chain.File, wrapper)`; for writes `crypto.RecoverRotation(dir, key)` (only for a verified rotation) and `members.CheckFolder` |
| Read a key | `crypto.ReadSecret(dir, name, key)` (caller zeroes the result) |
| Write a key | `v, _ := sess.Load()`; `ver, _ := v.NextVersion(name)`; `crypto.WriteSecretVersion(dir, name, key, value, ver)`; `sess.Commit(v, index.Edit{...})` (package `index`; compare-and-swap, merges with concurrent writers) |
| Read a key | `crypto.ReadSecretVersion(dir, name, key)`, then `view.Verdict(name, version, true)` must be readable |
| List without unlocking | `index.Locked(dir, vaultID, legacy, snapshot)`: the last verified view plus flags; never the folder's claims as truth |
| Upgrade a format-2 vault | `crypto.UpgradeToV3`, the new index, then `chain.UpgradeFormat(signer, now)` and `members.WriteUpgrade` (the commit) |
| Delete / restore | `format.TrashSecret`, `format.RestoreSecret`, `format.ListTrash`, `format.PurgeTrash(dir, now)` |
| Add a member | `members.ApproveRequest(dir, chain, key, signer, name, typedFingerprint, readd, now)` |
| Remove a member | `members.Remove(dir, chain, key, signer, name, members.RotateOptions{...})` (rotates) |
| Change the passphrase | `members.Passwd(dir, chain, key, signer, newPass, rotate, opt)` |
| Any vault.json change | `chain.Append(signer, members.Change{...})`, then `format.WriteVaultFileCAS(dir, next, chain.Raw)` |
| Verify the index | `index.Session{...}.Load()` after the membership chain is verified; the local snapshot comes from `index.Store` and is used only if `Snapshot.Anchored` on the chain |
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

- **Rollback of single files** (ue1.7, fixed): a `NAME.age` older than its signed entry is refused on any machine; a consistent rollback of index and file together is refused only on a machine whose snapshot saw the newer state. See the threat model's residual risks.
- **Offline members.** A member who hasn't opened the vault since a removal can be fooled by a removed member who kept folder write access and restored the whole folder (see the design's Threat 4); the write guard, the state code and the required folder-access step narrow this.
- **Concurrent edits.** Two machines writing `index.json` at once: each key's entry is merged by compare-and-swap, a conflict copy is merged by the next write (entries must verify under the current key), and a lost entry is rebuilt from this machine's snapshot. Two membership changes at once: the losing machine re-applies its change (or refuses, if the other change could weaken it).
- **Private index** (`index.json` `private: true`) is parsed but not yet encrypted; its local snapshot is label-free (HMAC'd names).
- **Counters** (`version`, `rev`) stop at 2^31-1; a change that would pass it is refused.
