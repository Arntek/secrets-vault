# Design: authenticated index and secret-file rollback (issues ue1.7, ue1.12)

Status: **implemented** (revision 2, Security verdict: holds, with three implementation notes). Deviations from the text above are under Implementation notes at the end.

Covers `ue1.7` (authenticate `index.json`, detect rollback of a single `secrets/NAME.age`) and the polish items in `ue1.12`. Builds on [membership-auth.md](membership-auth.md); read its sections 4-8 and 10 first.

## Changes in revision 2 (Security review of b845619)

| Item | Where | Change |
|---|---|---|
| IM1 (must-fix) | Verification step 1 | Legacy mode comes **only** from the verified chain's `State.Format` (2). In a format-3 vault a missing, v1, unparseable or wrong-`vault_id` index is **"index damaged"**: no key is readable unless the snapshot vouches for it (file version >= snapshot version, entry reconstructed from the snapshot); otherwise exit 5. |
| IM2 (must-fix) | Rotation, merge, repair | Only entries that verify under the **verified head's current key** are ever carried forward. Rotation (`Rotate`, `RecoverRotation`), conflict-copy merge and lost-race repair never accept an entry under a retired key. K3 -> K4 repair re-MACs only this machine's own pending entries (from its pending record), not the index found in the folder. |
| IS1 | Tombstones | Kept until the next rotation, and in the snapshot; the trash purge removes files, not tombstones. A rotation drops tombstones that have no file or trash copy left. |
| IS2 | Verification 3 | Entry whose file is missing: exit 5 (not found would hide a deletion by a folder writer). |
| IS3 | Snapshot | Records the trust pin's seq/head and `key_id` it was verified against. `trust --accept-rollback` shows the snapshot in its confirmation and resets it (every key then reads as first use on this Mac); `rebuild` creates a fresh one for the new vault id. |
| IS4 | Verification 2 | Entries are parsed one by one: MAC failures are dropped first, duplicates are checked only among verified entries. A planted duplicate can't make the parser reject the file or knock out the real entry. |
| IS5 | Snapshot | Private index: a label-free form (HMAC'd name under a key derived from the vault key, `rev`, `version`, `deleted`, `mac`), so rollback detection still works; nothing readable is stored. |
| IS6 | Verification 4 | Lost-update reconstruction honours a snapshot tombstone: a trashed file moved back into `secrets/` is not reconstructed. |
| IS7 | Counters | `version` and `rev` stop at 2^31-1: a write that would pass it is refused ("this key has reached its change limit; save it under a new name and delete this one"). Never wraps. A rename starts the new name's own counter. |
| IS8 | Resolution | An unverified-only candidate never triggers an unlock prompt for a vault the person didn't name; the command stops with the "name the vault with --vault" message. |
| Q3 | Unlisted files | `vault doctor VAULT --adopt NAME`: after unlock, shows the file's version and timestamps, asks for confirmation, writes an entry (`rev` above any snapshot value). Refuses a file older than the snapshot or tombstone. |

## The problem

Anyone who can write the shared folder (a Dropbox/Box collaborator, a compromised sync account, the provider) but does not hold the vault key can today:

| # | Attack | Effect |
|---|---|---|
| A1 | Edit `index.json`: change a description or tags | An agent that picks keys by description uses the wrong one. |
| A2 | Add an index entry or a junk `NAME.age` for a name another vault also has | The name is ambiguous across vaults (exit 2): a denial of service. |
| A3 | Delete entries | Keys vanish from `list`. |
| A4 | Roll `index.json` back to an older copy | A1 again, with real-looking labels; deleted keys reappear. |
| A5 | Replace one `secrets/NAME.age` with an older copy sealed under the current key | `get` returns a stale value. Rotation re-encrypts everything, so this never crosses a member removal, but within one key epoch it works. |
| A6 | A5 plus A4 together, consistent with each other | Same, and no mismatch to notice. |

Values are never disclosed by any of these. What matters is that people and agents act on wrong labels or stale values without a signal.

## Approach in one paragraph

Every index entry carries a **MAC under a key derived from the vault key**, so only a key holder (a member) can create or change an entry. Every secret file carries its own **version number inside its age header** (authenticated by the header MAC, like the key id), and the entry records the same number. Each entry also has a **`rev`** that rises on any change, including a description edit. Each Mac keeps a **local verified snapshot** of the entries it has seen (names, labels, MACs, `rev`, `version`) outside the folder. Together:

- a forged, edited or foreign entry fails its MAC (A1, A2);
- a single file older than its entry has a lower version than the entry (A5);
- an entry older than what this Mac has verified has a lower `rev` (A4, A6, on any Mac that saw the newer one);
- while **locked**, `list` shows the snapshot (verified) and flags everything else as unverified, because nothing can be checked without the key.

## Decisions and why

**D-a. Per-entry MACs, not one MAC over the whole index.** A whole-index MAC (with a head seq/epoch) forces writers to serialise: two machines adding different keys offline produce two index files neither of which verifies the other's change, and Dropbox's conflict copy can't be merged without the key. Per-entry MACs make the index a set of independently verifiable records that merge by name and `rev`. Removal is a signed state too (tombstones, below), so no set-level MAC is needed: the cross-checks below cover dropped entries.

**D-b. The MAC is bound to the vault id and the current `key_id`, not to the membership head seq/hash.** Binding to the head would rewrite every entry on every membership change (adding a member never changes who holds the key) and make every writer contend on the whole index. What the head would add is already given by the key id: after a removal the vault key rotates, and an entry MAC'd under the retired key fails under the new one. A removed member who holds the old key and folder write access therefore can't forge entries for the current state. If Security wants the head seq in the MAC anyway, the cost is stated above and the change is local to `crypto.EntryMAC`.

**D-c. Versions live in the age header, not only in the index.** An entry-only version could never be checked against the file it describes without a hash, and a hash can't tell "file rolled back" from "index rolled back". A version sealed inside the file (in the `sv-vaultkey3` stanza, covered by age's header MAC) lets any machine compare file against entry directly, and lets a file whose entry is lost be recovered at its true version.

**D-d. Two counters per entry.** `version` counts value writes (copied into the file header). `rev` counts every change to the entry, including `describe` and `tag`, which don't touch the file. Index-only relabelling and rollback are detected by `rev`; file rollback by `version`.

**D-e. The local snapshot is the only defence against a consistent rollback of index and file together (A6).** A valid older entry plus its valid older file is indistinguishable from the real thing to a machine that never saw anything newer. This is the same limit as the stale-writer gap in the membership design, and it is stated as residual risk, not hidden.

**D-f. Reads never write** (design principle from membership-auth 6). Everything that writes the folder (migration, adopting an unlisted file, merging conflict copies) happens only in write commands.

## Format changes

### Version bump (old builds must refuse, as in ue1.8)

| What | Before | After |
|---|---|---|
| `vault.json` `version` | 2 | **3** |
| `index.json` `version` | 1 | **2** (v1 parsed only for migration and for legacy display) |
| Secret-file stanza | `sv-vaultkey2 <key id> <salt>` | **`sv-vaultkey3 <key id> <salt> <version>`**; HKDF label `secrets-vault/v3 secret file key\0`; the GCM that wraps the file key takes the version as associated data |
| Membership record | no format field | new optional field **`format`** and a new op **`upgrade-format`** (see below) |

A build from before this change reads `vault.json` first and refuses version 3 with its "upgrade" message. If a folder writer rewrites `vault.json` as version 2 to get past that, it can't open a v3 stanza (unknown type, new HKDF label), so it can't read, write or rotate; and a new build refuses the downgrade (below). Index v2 and the new record op are refused by older parsers independently.

### `index.json` version 2

```json
{
  "version": 2,
  "vault_id": "…",
  "private": false,
  "entries": [
    { "name": "STRIPE_KEY", "description": "…", "tags": ["prod"],
      "updated": "2026-11-20T10:00:00Z", "updated_by": "alice",
      "version": 7, "rev": 9, "deleted": false, "mac": "<hex>" }
  ]
}
```

- `vault_id` is advisory (an early reject for a copied-in index); nothing trusts it. There is no authenticated index header: entries are the only authority.
- `mac = HMAC-SHA256(K_idx, "secrets-vault/v3 index entry\0" || enc(vault_id, key_id, name, version, rev, deleted, description, tags in order, updated, updated_by))`, where `enc` is length-prefixed fields (our own encoding, as for the membership digests, so it is deterministic), `key_id` is the **verified head's** key id (never read from the file), and `K_idx = HKDF-SHA256(vault key, salt empty, info "secrets-vault/v3 index mac key")`. Verify with `hmac.Equal`.
- **Tombstones.** `rm` sets `deleted: true`, `rev+1`, keeps `version` and clears description and tags. The entry stays **until the next rotation** (IS1), and stays in the snapshot; the trash purge removes files only. A rotation drops tombstones that have no file or trash copy left, since anything sealed under the old key can no longer be opened by a rolled-back file. A resurrected file (a deleted key's file put back) therefore has no live entry.
- Limits as today (`MaxIndexEntries`, 1 MiB, strict parsing, no control or bidi characters); `mac` must be 64 hex characters.

### Secret-file header

`sv-vaultkey3 <key id> <salt> <version>`: version is decimal, 1 to 2^31-1. `crypto.Sealer.Seal` takes the version; `Open` returns it; `crypto.VersionOf(ct)` reads it from the header without decrypting (like `KeyIDOf`). **Rotation preserves each file's version** (re-seal at the same number). `mv`/`rename` seals the new name at old version + 1 and tombstones the old name.

### Membership chain: the format is part of signed history

A bare `version: 3` in `vault.json` can be rewritten by a folder writer, and a Mac with no pin yet (first use) would accept a version-2 file and "upgrade" it. So the format is recorded in the signed log:

- Records gain `format` (int). `genesis` of a new vault carries `format: 3`. A new op **`upgrade-format`** (any member may sign, same `authorise` rule as every op) carries `format: 3` and changes nothing else.
- Replay tracks `State.Format`: from the latest record that has one, **never decreasing**, 2 if none. `Verify` requires `vault.json` `version == State.Format`. A version-3 file whose chain says 2, or a version-2 file whose chain says 3, is refused as tampered.
- Downgrade by a folder writer: restoring the pre-upgrade `vault.json` is a lower head seq, which every pinned machine already refuses as a rollback (membership 8c); a first-use machine is in the same TOFU position as for any other cut-off chain (state code, S2).

## Verification (needs the vault key)

`index.Verify(dir, chain, key, pin) → View` runs after the usual open order (membership-auth 6) and before any value is used:

1. Read `index.json`. **Legacy mode exists only if the verified chain says format 2** (see Migration). In a format-3 vault, a missing, v1, unparseable or wrong-`vault_id` index is **"index damaged"** (IM1): every key is refused with exit 5 ("the index of 'X' is missing or damaged; names it lists can't be trusted") **unless the snapshot vouches for it**: the name is in the snapshot, not tombstoned, and the file's `version >= snapshot.version`. Such keys are readable and the next write rebuilds the index from the snapshot (re-MAC'd under the current key, `rev+1`). Everything else waits for `doctor --adopt`. Without this, deleting `index.json` after rolling back one file would turn A5 into a free pass on a Mac that never saw the key.
2. Parse entries one by one (IS4). Per entry: MAC check with the chain's head `key_id`. Failures are **dropped from the view** and counted ("3 entries failed verification"), never half-trusted. Only then are duplicates looked for, **among verified entries**: a duplicate verified pair (two members racing) keeps the higher `rev`, and a tie keeps the one whose `version` matches the file. A planted duplicate has no valid MAC and so never reaches this point.
3. Cross-check each surviving entry against its file's header (`VersionOf`, `KeyIDOf`; no decrypt):
   - `file.version == entry.version` → good.
   - `file.version < entry.version` → **rolled back, or the file hasn't synced yet.** The key is refused (exit 5, "X is older than the index says; it may still be syncing; if it persists someone restored an old copy").
   - `file.version > entry.version` → the **index is behind** (stale or still syncing). The file is authentic (header MAC) so the value is readable; a warning says the index lags and the next write repairs it.
   - Tombstoned entry with a live file, or a live file with no entry: **unlisted**. Not readable by name, not listed as a key; `doctor` reports it (A2, A3).
   - Entry with no file (IS2): **exit 5** ("X is listed but its file is missing; it may have been deleted outside secrets-vault, or is still syncing"), listed by `doctor`. A tombstoned entry with no file is the normal deleted state.
4. Compare with the pin snapshot, per name: `entry.rev < snap.rev` or `entry.version < snap.version` → **rolled back** (A4, A6): the entry is dropped and the key refused with exit 5. A snapshot name absent from the folder's index while its file is present, not tombstoned in the snapshot (IS6), and `file.version >= snap.version` is a **lost update** (two writers raced): the entry is reconstructed from the snapshot (in memory on reads; written, re-MAC'd with `rev+1`, on the next write). A snapshot name absent *and* its file older than `snap.version` is a rollback.
5. The verified view replaces the snapshot (it only moves forward, per name, to the highest `rev`/`version` seen) and the snapshot's display fields.

A failed entry never blocks other keys, and a membership change (`member rm`, `passwd`) is **never** blocked by index damage: rotation re-MACs what verifies and reports what it dropped.

## The local snapshot (pin)

`~/.config/vault/index/<registered vault id>.json` (0600, directory 0700, outside the synced folder, next to `trust/`):

```json
{ "version": 1, "vault_id": "…", "key_id": "…",
  "entries": [ { "name": "…", "rev": 9, "version": 7, "deleted": false, "mac": "<hex>",
                 "description": "…", "tags": [], "updated": "…", "updated_by": "…" } ] }
```

- Also records `pin_seq`, `pin_head` and `key_id` of the trust pin it was verified against (IS3), so a snapshot that doesn't belong to this pin is dropped rather than trusted.
- Strictly parsed and fuzzed like the trust pin. Entries only move forward. `detach` deletes it. `trust --accept-rollback` lists it in its confirmation and resets it; `rebuild` starts a fresh one.
- **Private index** (IS5): stored label-free: `name_tag = HMAC(K_idx, "snapshot name\0" || name)` in place of name and no description, tags or `updated*`. Rollback detection (`rev`, `version`, `deleted`, `mac`) still works when unlocked; locked `list` says the index is private and shows nothing.
- A snapshot older-format file, or none, means "never verified on this Mac".
- Downgrade protection on this Mac: a snapshot at format 3 for a vault whose folder presents format 2 is refused as a downgrade even before the chain check.

## While locked (`list`, `info`, `search`, name resolution)

Nothing can be verified without the key, and these commands must not prompt (and must not unlock a `touch-every-read` vault). So:

- Rows come from the **snapshot where it has the name**, using the *snapshot's* labels. A folder entry whose `mac`, `rev` or presence differs from the snapshot is a **pending change**, never shown as truth.
- Names the snapshot lacks are listed as **unverified** (`verified: false` in `--json`, a marker in the table).
- Output states it once per vault: `index verified when last unlocked (2026-11-20 10:02); 2 changes in the folder are not verified yet: unlock to check them`, or `index not verified on this Mac yet`. `--json` gets `index_state: "verified" | "pending-changes" | "unverified"` and per-row `verified`.
- **Resolution** (`get NAME` with several vaults): candidates that are verified beat unverified ones; an unverified-only candidate set never prompts to unlock a vault the person didn't name (IS8); ambiguity is declared (exit 2) only among candidates of the same class, and says "unverified entries: name the vault with --vault, or unlock one to verify". An unverified candidate that resolves is checked by the MAC as soon as the vault is unlocked, before any value is read, so a planted entry (A2) can't make a wrong vault answer.
- Every command that holds the key (`unlock`, `get`, `set`, `run`, …) refreshes the snapshot, so a vault becomes verified the first time it is used after a change.

This answers "what does `list` show while locked": the last verified view, plus honest flags. No prompts, no new agent protocol (the agent is untouched).

## Concurrent writers and Dropbox/Box

The index write is a **compare-and-swap on the exact bytes read** (`format.WriteIndexCAS`, same as `WriteVaultFileCAS`), with a retry loop (up to 5).

`set X`: verify, then
1. `v = max(file.version, entry.version, snap.version) + 1`; seal and write `secrets/X.age` at version `v`.
2. New entry: `rev = max(entry.rev, snap.rev) + 1`, fresh MAC, upsert into the index just read, `WriteIndexCAS`.
3. If the CAS fails because the index changed: re-read, re-verify, re-apply **only this entry** (`rev` recomputed), retry. Other keys' changes are kept (merge, not last-write-wins).
4. Re-read file header and entry afterwards; if X's entry was changed by someone else in the meantime (same key, same moment), say "alice changed X at the same moment; the value saved last is the one in the vault now: check it". No silent lost update.

`describe`/`tag`/`rm`/`restore`/`mv`: the same loop on entries (and file versions where a file is rewritten). `restore` from trash re-seals the file at `version + 1` and writes a live entry, so a resurrected file can't be told from a rolled-back one.

**Conflict copies.** If Dropbox/Box makes `index (conflicted copy).json` because two machines wrote offline, the next write merges every conflict copy whose entries **verify** into the result: per name the higher `rev` wins; equal `rev` with different MACs (rare) keeps the one whose `version` matches the file and warns. Merged copies are left in place; `vault doctor` says a copy is already merged ("safe to delete") when all its entries are `<=` the main index's. Entries that don't verify are ignored. Because every entry authenticates alone, no key is needed to *produce* a merge candidate and none can be forged.

**Rotation (`member rm`, `passwd`, lost-race rebase).** `crypto.Rotate` already re-seals every file into a staging folder committed by `vault.json`. It now also stages **`index.json`**: re-MAC'd under the new key, carrying forward **only entries that verify under the verified head's current key at the time of the rotation** (IM2: never under a retired key, so a member removed in an earlier epoch can't plant entries that the next rotation launders), tombstones kept except the droppable ones (IS1), `rev`/`version` unchanged and moves it with the rest in `CommitStaged`. `RecoverRotation` verifies the staged index's MACs under the new key like it does for secrets. Until the moves finish, readers see an index that doesn't verify under the new key and treat everything as unverified with the existing "unfinished rotation" message; nothing is lost.

**Lost rotation race.** The loser's files are re-sealed K3 -> K4 at their existing versions (membership 10). The index is rebuilt in the same rotation from **this machine's own pending entries** (its snapshot and the files it moved under K3) and from folder entries that verify under the winner's current key only; nothing MAC'd under a retired key, including K3's neighbours, is carried (IM2). Conflict-copy merge has the same rule: only entries that verify under the current key.

## Migration from format 2 (`vault upgrade NAME`)

Explicit, not on first write, because it makes every member upgrade their build at once and needs the identity to sign:

- Reads of a format-2 vault (as decided by the **chain**, never by the index file: IM1) keep working in **legacy mode** (v1 index shown, flagged unverified; secret files read without versions; a one-line notice says to upgrade). **Every write command refuses** with "run: vault upgrade NAME (every member must upgrade secrets-vault first)". Agents and scripts fail loudly, never silently on an un-authenticated index.
- `vault upgrade` (needs the key and the identity): verify, `prepareWrite`; re-seal all live and trashed files into `sv-vaultkey3` at version 1 (idempotent; existing `UpgradeSecrets` pattern); write index v2 from the old index (descriptions, tags kept; names with no file dropped; files with no entry get a bare entry), `rev 1`, MAC'd; append the signed `upgrade-format` record and write `vault.json` version 3 with CAS **last** (commit point). A crash before it leaves a format-2 vault whose files older builds can no longer open; rerunning finishes it.
- **Smooth one-off (coordinator requirement; v0.1.0 ships format-2 vaults):** a personal vault upgrades with just the identity unlock (no passphrase prompt); in a shared vault any member can run it (the signed record is the only authority). Every command that can't proceed on a format-2 vault prints one line naming `vault upgrade NAME`, plus the brew/npm upgrade hint for members on older builds. A test upgrades a format-2 vault created by the current main build (773be93, built in the test and driven through the CLI).
- **The existing index is trusted once**: whatever labels are in a v1 index at upgrade time are blessed. The command says so and tells the person to look over `vault list` after. Files are adopted at whatever value they have.
- New vaults (`init`, `rebuild`) start at format 3.

## Threat by threat

| Attack | Stopped by | What remains |
|---|---|---|
| A1 edit labels | Entry MAC (key holders only). Locked: shown from the snapshot, folder's version flagged as pending. Unlocked: entry dropped, key refused. | A **member** can still relabel (they hold the key). `updated_by` is a member's claim, not a signature. |
| A2 planted entry / junk file | Entry fails MAC and is ignored; unlisted files aren't keys; locked resolution prefers verified candidates; unverified-only ambiguity is explained and resolved by `--vault`. | While locked and never verified on this Mac, names are unverified: a planted name can still make an *unverified* ambiguity until the first unlock. Denial of service only; values never affected. |
| A3 delete entries | Unlisted files are reported; snapshot reconstructs a lost entry on the next write. | A pinless Mac that never saw the entry can't know it existed. |
| A4 old index | `rev`/`version` below the snapshot refused; `file.version > entry.version` shows the index lags. | A Mac with no snapshot of the newer state (first use, new Mac) accepts an old consistent index. |
| A5 one file rolled back | `file.version < entry.version`: refused, on **any** Mac, with no snapshot needed. | None for files whose entry is current. |
| A6 file + entry rolled back together | Snapshot on any Mac that saw the newer `rev`/`version`. | Machines that never saw it (new Macs, or offline since before), exactly the membership design's stale-writer limit. Removal still can't be crossed: rotation re-keys. |
| Rolling back `vault.json` to format 2 | Chain format (never decreases; head must match file version); pinned Macs refuse a lower seq. | First-use TOFU, as for any cut-off chain. |
| Old build against a v3 vault | Refuses on `vault.json` version, stanza type, HKDF label, index version, record op; a v2-form file it writes into a v3 vault has version 0 < entry and is refused. | Nothing: it can't open anything. |
| Removed member with old key | Entry MACs are under the retired key and fail; rotation re-MACs; their stanza version bumps are bound to the old key. | Anything they wrote before removal is as trusted as before. |
| Torn two-step writes (file then index) | A reader sees `file.version > entry.version` (benign, repaired) or the reverse only if sync reorders (refused as "still syncing", retry). | A short window of exit 5 on a slow sync. |

## ue1.12 polish

1. **Index-only commands honour an unmet expectation** (`info`, `list`, `search`, `--json`). They call a new `a.openQuiet(v)`: the same verify-and-classify as `open` (including `pin.Expect` and rollback), but never prompts and, for a first use, returns the vault as *unverified* instead of asking. Failures give exit 5 and the `{vault, error}` entry in `list --json`, as in ue1.10. They never write the folder.
2. **Malformed `vault.json` exits 5.** `loadVault` maps `format.ErrMalformed` (a `vault.json` that exists but doesn't parse, or fails verification structurally: planted unlocker, bad entry) to `verifyErrf` with "vault.json was damaged or altered"; a truncated half-synced file gets the same wording plus "if a sync is still running, wait and retry". `ErrUnsupportedVersion`, a missing folder and unreadable files stay exit 1.
3. **`doctor` wording for unusable staging.** A staging folder under the current rotation-introduced key whose files don't open reads "cannot be finished: a staged file does not open under the vault key; if no member is rotating the key now, move it aside with `doctor VAULT --quarantine-staging`" (status in text and `--json`), not "the next change finishes it". Decided by trying `RecoverRotation`'s open-check in a read-only mode when the key is available, otherwise by listing it as "unverified; finish or quarantine with --quarantine-staging".

## What changes where

A new package **`internal/index`** (imports `format`, `crypto`; listed in `arch_test.go` and `docs/architecture.md`) holds the logic that is neither a file format nor membership: `Verify`, `Reconcile`, `Merge`, the snapshot store. `cli` imports it.

| Package | Change |
|---|---|
| `format` | `Index` v2 (`vault_id`), `IndexEntry` (`version`, `rev`, `deleted`, `mac`); v1 parser kept for migration; `WriteIndexCAS`; staging accepts `index.json`; limits and strict parsing; `VaultVersion = 3`; record `format` field and `OpUpgradeFormat` types. |
| `crypto` | `EntryMAC`, `VerifyEntryMAC`, `IndexKey` (HKDF); stanza `sv-vaultkey3` with version, `Seal(…, version)`, `Open` returning the version, `VersionOf`; `Rotate` stages the re-MAC'd index; `RecoverRotation` checks it; `UpgradeSecrets` also writes v3. |
| `members` | `State.Format`, genesis/`upgrade-format` records, `Verify` rule (file version == chain format), `authorise` unchanged. |
| `index` (new) | Verification, cross-checks, snapshot store, conflict-copy merge, the write loop used by every key-writing command. |
| `cli` | `set`/`rm`/`restore`/`mv`/`rename`/`describe`/`tag`/`copy` use the write loop; locked `list`/`info`/`search`/resolution read the snapshot; `vault upgrade`; `openQuiet`; `unlock` refreshes the snapshot; `doctor` wording and index conflict reporting; `detach` deletes the snapshot; exit-code mapping. In clearly separated functions (another developer is editing `unlock.go`). |

## Tests (step 2)

- **IM1:** A5 plus a deleted `index.json`, and A5 plus a v1 index, on a Mac with no snapshot: refused (exit 5); with a snapshot that vouches, readable and repaired on the next write. **IM2:** an entry MAC'd under a retired key is dropped by rotation, by merge and by lost-race repair, never re-MAC'd. **IS1-IS8**, one test each (tombstone resurrection after trash purge, missing file exit 5, `--accept-rollback` resets the snapshot, planted duplicate, private-index snapshot has no labels, snapshot tombstone vs a trashed file moved back, counter ceiling, unverified-only resolution doesn't prompt, `doctor --adopt`).
- **A1:** edited description, tags, `updated_by` each fail MAC; locked `list` shows the snapshot and flags the change; unlocked `get` refuses the key. **A2:** planted entry and junk file; ambiguity resolved by verified-first; unverified ambiguity message; the entry never reaches a read. **A3:** deleted entry, file unlisted, `get` refuses, snapshot reconstructs on write. **A4:** old index below the snapshot's `rev`; below a file's version (index lags, benign). **A5:** one file replaced by an older sealed copy: refused with no snapshot at all. **A6:** index+file together, refused on a Mac with a snapshot, accepted on one without (documented). Resurrected file after `rm`.
- **Concurrent writers:** two goroutines `set` different keys against one folder (no lost entry); same key (warning, one consistent final state); CAS retry; a conflict copy merged; a conflict copy with a forged entry ignored; interleaved `set` and rotation.
- **Rotation:** index re-MAC'd, tombstones and counters preserved, a forged entry dropped and reported, old-key entries fail afterwards, crash between commit and move recovers.
- **Old builds:** a build of the pre-change main (773be93) refuses a format-3 vault, and a downgraded `vault.json` gives it nothing; a v2-form file written into a v3 vault is refused; downgrade of `vault.json` with the chain refused.
- **Migration:** `vault upgrade` end to end, interrupted halfway, rerun; writes refused before it; legacy-mode reads.
- **ue1.12:** `info`/`list --json` exit 5 after a failed `--expect`; malformed `vault.json` exits 5; doctor wording.
- **Fuzz:** index v2 parser, entry MAC encoding, stanza header with version, snapshot file, membership record with `format`. **Leak tests** over upgrade, set, list (locked) and merge with canaries (descriptions are not secret, but values, keys and the index MAC key never appear). `make test`, `make lint`, `make fuzz FUZZTIME=10s`, linux and windows `CGO_ENABLED=0` builds.

## Residual risks (to threat-model.md)

- A member can relabel or rewrite entries, and `updated_by` is attribution, not a signature.
- A Mac with no snapshot (first use, new Mac) accepts an older **consistent** index and file; the same limit as the stale-writer gap, and it can't cross a rotation.
- While locked and never verified, names are unverified; a planted name causes a clearly explained ambiguity (denial of service).
- Migration trusts the existing v1 index once.
- A short window of "still syncing" refusals when a sync delivers a new index before its file.
- Same-key concurrent writes: last write wins, both writers are told.

## Questions for Security

1. **D-b:** is the key id enough, or do you want the head seq in the MAC despite the contention cost?
2. **D-c/D-d:** a version in the header plus `rev` and `version` in the entry: any way to make them disagree usefully that I missed?
3. **Unlisted files are not keys** (not adopted automatically): too strict, or right?
4. **The snapshot is trusted local state** like the trust pin: anything else it should record (for example the head of the chain it was verified against)?
5. **Chain `format`** (answered: right, not heavy): is a signed `upgrade-format` record the right way to stop downgrade on first-use Macs, or too heavy?

## Implementation notes

What the code does where this document was not specific, or differs slightly:

- **The snapshot is "anchored", not equal to the pin** (Security note 1): its `pin_head` must be the record at `pin_seq` on the verified chain and its `key_id` one of the vault's keys. The pin itself moves on every membership change, so an equality test would drop the snapshot after any change and lose rollback protection; an ancestor check is the stale-snapshot test. A snapshot for a vault whose chain says format 2 is a downgrade (exit 5).
- **Tombstones at rotation** (note 2): dropped only when no file under any key, live or trashed, exists for the name. A pre-rotation trashed copy brought back afterwards fails by key id (`ErrOtherKey`).
- **First pin of a format-2 vault** (note 3): `headLine` ends with ", format 2 (not upgraded)".
- **Damaged index and name resolution:** a vault whose folder index is missing, version 1, unparseable or for another vault is "damaged" while locked too; a name found nowhere then exits 5 (not 4), unless `set` is creating a new key (the repair).
- **Lists show the snapshot's labels** for an entry whose folder copy differs in any field, including a relabel that kept its old MAC.
- **`describe` and `tag` need an unlock** (they used to work locked); `rm` unlocks to write the tombstone.
- **Conflict-copy merge and snapshot reconstruction** take only entries that verify under the current key (IM2); `doctor` calls an index conflict copy "safe to delete" when every verified entry in it is already in the index at the same or a higher rev.
- **Retries:** the index compare-and-swap retries up to ten times; within one process the check and write are one step (a mutex), across machines it is best effort like `vault.json`'s.
- **`vault upgrade`** refuses without `--yes` when there is no terminal. Reads of a format-2 vault print a one-line notice; every write exits 1 with `Run: vault upgrade NAME` and the brew/npm hint.
- Not built, as the design allowed: nothing here changes the agent protocol; the agent still holds only the vault key.

### After the re-test (ue1.13, ue1.14, ue1.15)

- **A name missing from an otherwise valid index** is never "key not found" (ue1.13). A locked listing also shows names this machine verified that the folder's index no longer lists, if their file is there (flagged `pending_change`); unlocked, the entry is rebuilt from the snapshot and the next write repairs the index. A file with no entry and nothing vouching for it exits 5 ("no signed entry"), and `set` may still create the key. `doctor` lists rebuilt-from-snapshot entries as "missing from the index".
- **A rotation over an index that doesn't verify** (ue1.14) starts from the verified folder entries and fills every name this machine's anchored snapshot vouches for (live: file present and not older than the entry; tombstones as tombstones), then reports how many entries were dropped. Lost-race repair and `rebuild` pass the same entries. A repairing write also writes back snapshot tombstones.
- **A file sealed under a retired key does not abort a rotation** (ue1.15): it is left in place unopened and reported by name. A file under the *current* key that fails to open still aborts.
