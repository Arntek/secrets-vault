# Design: authenticated membership (issue ue1.1)

Status: **proposal, awaiting review.** No code yet.

Covers `ue1.1` (planted unlockers), and the findings with the same root cause, the CLI trusting the shared folder: `ue1.2` (rollback by a removed member), `ue1.4` (recovery before verification, symlinked folders) and `ue1.6` (passphrase survives removal; `passwd` doesn't rotate).

## The problem

`vault.json`'s unlocker list is unauthenticated. Anyone who can write the shared folder can add a member unlocker, and the next `member rm` re-wraps the rotated vault key for it (`members.Remove` builds its wrappers from whatever `vault.json` lists). A MAC of the list under the vault key does not fix it: a removed member still holds the old key, and a folder writer can replace the whole file with one for a key they made.

The fix: every change to who can open a vault becomes a **record signed by someone who was allowed to make it**, the records form a **hash chain**, and each client **pins the last head it verified on its own disk**, never only in the shared folder.

## Attackers

Each can write any file in the shared folder (Dropbox/Box collaborator, compromised sync account, the provider).

| # | Attacker | Stopped by |
|---|---|---|
| 1 | Non-member plants an unlocker, edits a label, duplicates a name | Head record commits to the exact unlocker list; a member set only changes through a signed record |
| 2 | Replaces `vault.json` with a fresh vault (own key, wrapped to real members' public keys) | Local pin: the new chain doesn't contain the pinned head. First-time attach: fingerprint check on the signer |
| 3 | Removed member (knows old vault key) forges an "authorised" change | Authority comes only from **member signing keys in the previous state**, never from vault-key material. After the removal record, their key no longer counts |
| 4 | Rollback to an older valid `vault.json` | Pinned sequence number and head hash: lower or forked heads are refused |
| 5 | Edits or swaps a join request after the approver checked it | Fingerprint covers both public keys; approval re-reads and compares; the signed record holds exactly the checked keys; requests are self-signed |
| 6 | Plants a staging folder or symlinks so a member's own client overwrites secrets (`ue1.4`) | Nothing writes until vault.json is verified and unlocked; recovery checks each staged file opens under the verified key; symlinked directories refused |
| 7 | Anyone who ever knew the vault passphrase, after `member rm` or `passwd` (`ue1.6`) | `member rm` drops the passphrase by default (keeping it is a signed, visible choice); `passwd` rotates the key by default |

Details per attacker are under [Threat by threat](#threat-by-threat).

## Building blocks

### 1. Identity gets a signing key

Each personal identity holds an **Ed25519 signing key** next to its age X25519 key. It is random (not derived from the X25519 key, so no custom bech32 decoding and no cross-use of one secret), sealed in the identity file exactly like the X25519 key (`crypto.Sealer`, name `SIGNING`), and carried by `identity export/import`.

- `members.Identity` gains `SignKey` (32-byte Ed25519 public key, hex in files).
- `members.Unlocked` gains `Sign(domain, msg)`; the private key never leaves the type and has the same redacting `String`/`LogValue`.
- **Fingerprint v3** = scrypt over `"secrets-vault/v3 member fingerprint\0" || recipient || "\0" || signkey-hex`, same shape (`MAPLE-RIVER-OTTER-4417`, ~46 bits) and cost. So checking a fingerprint aloud checks both keys.
- Identity file version 2. A version-1 identity is upgraded the first time it is unlocked (generate a signing key, re-save). Its fingerprint changes; that is fine before release (see Migration).

### 2. The membership log in `vault.json`

`vault.json` version 2:

```json
{
  "version": 2,
  "id": "…", "name": "team", "key_id": "…",
  "unlockers": [ … as today … ],
  "log": [
    { "body": "<base64 of the record's JSON bytes>", "auth": { "by": "alice", "sig": "<base64>" } },
    { "body": "…", "auth": { "mac": "<base64>" } }
  ]
}
```

Records are signed over their **exact bytes** (`body` is base64 of the JSON), so there is no JSON canonicalisation problem: verify the bytes, then strict-parse them.

Record body:

```json
{
  "seq": 3,
  "prev": "<hex SHA-256 of the previous record's body bytes; empty for seq 0>",
  "vault_id": "…",
  "time": "2026-11-20T10:00:00Z",
  "op": "create | share | add-member | remove-member | set-unlocker | remove-unlocker | rotate",
  "subject": "dan",
  "key_id": "<vault key id after this op>",
  "members": [ { "name": "alice", "recipient": "age1…", "sign_key": "<hex>", "role": "owner", "added_by": "alice" } ],
  "unlockers_hash": "<hex SHA-256 of the canonical unlocker list after this op>"
}
```

- `members` is the **full member set after the op**, sorted by name, names unique, recipients and sign keys unique. It is small (about 150 bytes a member).
- `unlockers_hash` commits to the top-level `unlockers` array: SHA-256 over a length-prefixed encoding of each unlocker's `type`, `label`, `recipient`, `SHA-256(wrapped_key)` and `created`, in file order. Encoded by our own code, not JSON, so it's deterministic.
- `op` and `subject` are for humans (`vault member log`) and for the "who added me" check; authority comes from the member sets, not the op name.
- **The state of the vault is the head record.** Member list, roles and `added_by` come from it. `members.json` is deleted: it was unauthenticated display data and the log now holds the same information, authenticated.

Signature: `Ed25519(signer, "secrets-vault/v2 membership record\0" || body)`.
MAC (personal vaults only, below): `HMAC-SHA256(HKDF(vault key, "secrets-vault/v2 state mac"), "secrets-vault/v2 membership record\0" || body)`.

### 3. Who may write record n

Decided by the **state at n-1**, never by record n itself:

- **Shared vault** (state n-1 has at least one member): `auth.by` names a member of state n-1 and `auth.sig` verifies under that member's `sign_key` from state n-1. Any member may sign by default (today any member may approve or remove). The rule lives in one function, `members.authorise(prev State, op, signer Member) error`, used by both the writer and the verifier, so "only owners may remove" is a one-line policy change; `role` stays in every member entry for that. A record may not change `key_id` unless `op` is `rotate`.
- **Personal vault** (state n-1 has no members): `auth.mac` under the vault key whose id is state n-1's `key_id`. Only someone holding the vault key (passphrase or Touch ID) can produce it.
- **Personal rotation** (`passwd` now rotates, see 8): the `rotate` record is MAC'd under the **old** key, as the rule says, and carries `prev_key`: the old key sealed under the new key (AES-256-GCM, record seq and both key ids as associated data). Another Mac that unlocks with the new passphrase opens `prev_key`, checks its id equals the pinned `key_id`, and verifies the MAC with it. That proves whoever rotated held the old key, so no `--accept-key-change` prompt is needed anywhere. Several rotations chain back the same way. (Shared vaults don't need `prev_key`: their rotations are signed.)
- **Genesis** (seq 0): personal → MAC under the new key; never signed by an identity at `init` (init stays passphrase-first, as today).
- Turning a personal vault into a shared one is one `share` record (MAC, adds the first member as owner). After that only signatures count. If the last member is removed, the vault becomes personal again from the next record on.

### 4. Verifying a `vault.json` (every open)

`members.Verify(vf, pin, key)` where `key` may be nil (not yet unlocked):

1. Strict parse (format): version 2, log 1-1000 records, each body strictly parsed, `seq` = index, `prev` hashes link, `vault_id` and top-level `id` match.
2. Head consistency: top-level `key_id` = head `key_id`; hash of top-level `unlockers` = head `unlockers_hash`; every member unlocker's (label, recipient) belongs to a head member and every head member has exactly one member unlocker. **Any extra, missing or edited unlocker → refuse.**
3. Pin check (see 5): log[pin.seq] hashes to pin.head, and head.seq ≥ pin.seq. Otherwise refuse: "rollback or substitution".
4. Records after the pin: each is authorised by the rule in 3. Signatures are checked without the vault key. MAC records need the key, so for personal vaults this step completes right after unlocking; a key held by the agent is checked too (an HMAC, microseconds).
5. On success, the CLI advances the pin to the head.

Re-wrapping (`member rm`, rotation) uses **only the verified head's member set**, never the recipients in the unlocker list.

### 5. The local pin

Per user, per vault id: `~/.config/vault/trust/<vault-id>.json` (0600, directory 0700), outside any synced folder:

```json
{ "version": 1, "vault_id": "…", "seq": 7, "head": "<hex SHA-256 of record 7's body>", "key_id": "…" }
```

Keyed by vault id rather than registry name, so `detach` + `attach` keeps it, and two registry names cannot point one vault at two pins. It replaces `key_id` in `config.toml` (read once as a fallback pin for upgrade, then dropped). Strictly parsed, fuzzed.

### 6. Order of operations on open (`ue1.4`)

Nothing in the vault folder is written, renamed or deleted before the vault is verified and unlocked:

1. `Lstat` every path component from the vault folder down: the vault folder itself, `secrets/`, `secrets/.trash/`, `requests/` and any `secrets/.sv-rotate-*` folder must each be a real directory (not a symlink) and, on Unix, owned by the current user. Otherwise refuse. Files are already opened with `O_NOFOLLOW`; this closes the parent-directory gap. (The path *to* the vault folder is the user's own choice in the registry and may contain symlinks, e.g. `~/Dropbox`.)
2. Parse `vault.json` and verify it against the pin (4 above) **before any write of any kind**. Signed parts need no key.
3. Read-only commands (`info`, `list`, `get`, `member list`, `status`) **never write**: no recovery, no pin-file writes other than advancing the local pin, no trash purge. Those that don't unlock stop here; they report "an interrupted key rotation will be finished the next time the vault is unlocked".
4. Unlock; finish MAC verification (personal vaults); advance the pin.
5. Only now `crypto.RecoverRotation(dir, key)` (moved from format to crypto so it can use the key): it runs only if the staging folder's key id equals the verified head `key_id` and `key` matches it; every MANIFEST entry must be a regular file **and open under `key` with its own name** before anything is renamed. A staging folder for any other key id is left alone and reported by `doctor`.

`format.CommitStaged` keeps the file moves and gains the regular-file and directory checks; the decision to call it moves up to crypto.

### 7. Trust on first use

A machine with no pin cannot know the history, so the first pin is confirmed by a person, the same way join requests are:

- **The record that added me was signed by me** (my second Mac, after `identity import`): pin silently. Nobody else holds my signing key.
- **Added by someone else** (a new member's first unlock after approval): show "Added to 'team' by alice, fingerprint MOSS-HARBOR-…-0932. Does this match what alice sees?" and pin only on yes. Non-interactive: `--signer-fingerprint FP`. The approver is told to read out their own fingerprint (`member approve` prints it), so the check is mutual.
- **Personal vault, or passphrase-only user of a shared vault**: pin on first successful unlock and print the member list with fingerprints. Weaker (no person to compare with); documented.
- **Re-trusting** (after a fork from a sync conflict, or a deliberate rebuild): `vault trust VAULT` shows the head, its signer and the members with fingerprints, and re-pins after the same fingerprint confirmation. It only moves the pin to a head with **seq at least the pinned one**: a lower seq is reported as "rollback: this vault.json is older than one this Mac has already seen" with no override in the CLI. (The deliberate escape hatch for a rebuilt vault is deleting the trust file by hand, which the error message does not suggest.)
On TOFU the whole chain is still verified as far as possible: every signed record, and MAC records under the current key. Older MAC records can't be checked without old keys and are accepted, because the person is vouching for the head.
- `unlock --accept-key-change` is removed. Shared-vault key changes are signed `rotate` records and personal ones carry `prev_key`, so a key change is either verified or refused; there is no "expected if a member was removed" prompt any more (`ue1.2`).

### 8. Passphrase unlockers on removal and `passwd` (`ue1.6`)

The passphrase unlocker is the one unlocker not tied to a person, so anyone who ever learned it is invisible to membership.

**`member rm`** (always a shared vault: personal vaults have no members) **removes the passphrase unlocker by default**:

- default: the rotated key gets no passphrase unlocker. Output: "The vault passphrase no longer opens 'team'. To set a new one: vault passwd team". The signed `remove-member` record has `"passphrase": "dropped"`.
- `--new-passphrase` (prompt twice, or `--new-passphrase-stdin`): set a new passphrase in the same rotation, so there is no second rotation. Record: `"passphrase": "replaced"`.
- `--keep-passphrase`: explicit opt-out; re-wrap under the current passphrase (proved first, as today). Output: "The vault passphrase was kept: anyone who knows it still has access." Record: `"passphrase": "kept"`, so `vault member log` shows who chose to keep it and when.
- Refused if dropping it would leave no unlocker. If only one member remains and the passphrase is dropped, the existing "only one way in" warning is printed.
- The `passphrase` field is part of the signed body, and verification checks it against the unlocker hash (dropped means no passphrase unlocker in the new state), so it can't be faked.

Trade-off: the vault loses its recovery route until someone runs `passwd`, and the passphrase in the safe or password manager must be replaced after each removal. Keeping it silently made removal ineffective against the person most likely to know it, so dropping it is the default and keeping it is a signed, visible choice.

**`passwd` rotates the vault key, in both kinds of vault.** In a **shared** vault this is always a signed `rotate` record, with no opt-out: rotation is what cuts off people who only ever had a shared passphrase (D3), since they can't be removed by name. In a **personal** vault it rotates by default, with `--no-rotate` for the old, instant behaviour. Without rotation, anyone with the old passphrase and any old copy of `vault.json` (their own, or Dropbox/Box version history) gets the unchanged key and every future secret. Rotation re-encrypts all secrets (seconds for a normal vault), needs no conflict copies, and loses a secret another machine writes under the old key at the same moment (`ErrOtherKey`, as for `member rm`). Output always says whether the key was rotated; with `--no-rotate` it adds "anyone who knew the old passphrase can still open old copies of this vault". Touch ID unlockers of other Macs are dropped by a rotation and must be re-enrolled, as with `member rm` today.

Why personal vaults rotate too: people change a passphrase because someone saw it, it was shared, or it was weak. In all three cases the old passphrase plus any old `vault.json` (Dropbox and Box keep versions for 30-180 days) gives the unchanged key and every future secret, so a change that doesn't rotate protects nothing against the person who prompted it. The costs are a few seconds of re-encryption and re-enrolling Touch ID on the user's other Macs. `--no-rotate` stays for the rare case of just making a passphrase easier to type, and says what it doesn't do.

**`member rm` also prints, every time and in `--json`, that the person's access to the shared folder must be removed at Box/Dropbox** (`ue1.2`): without that they can still roll back the folder for members who are offline (see Residual risks).

## Threat by threat

**1. Non-member planting.** A planted, edited or duplicated unlocker changes the unlocker hash, so open fails before anything is wrapped. Adding a member needs a record signed by a current member (shared) or a MAC under the vault key (personal); a non-member has neither. Duplicate member names are rejected by the parser in both the log and the unlocker list. `member rm` re-wraps only for verified head members, so even a bug in step 2 would not hand the new key to a planted recipient. The `ue1.1` sequence (mallory appends a "bob" unlocker, alice runs `member rm carol`) now stops at alice's open with "vault.json was changed outside secrets-vault".

**2. Whole-file substitution.** The attacker can build a valid-looking chain only with their own signing key (or, personal, their own vault key). Every pinned client sees a chain that doesn't contain its pinned head and refuses. A new member's first unlock shows the attacker as the signer of the record that added them, and the fingerprint check fails. A machine that already holds the vault's members can't be fooled by "added by alice" either, because alice's signing key isn't the attacker's.

**3. Removed member.** Holding the old vault key gives no authority in a shared vault: only signatures by members of the previous state count, and the removal record dropped them. Their only option is a **fork from before their removal** (records signed while they were still a member). Every client pinned at or after the removal refuses it. A client that has been offline since before the removal and never saw the honest records cannot tell the fork from the truth; that is inherent without a server. If the removed member also restores the old secret files, the stale client reads stale values and could write under the old key; that is the stale-writer gap, handled under 4. Every up-to-date member gets a loud fork error. Documented remedy: when you remove someone, also remove their folder access.

**4. Rollback (`ue1.2`).** A lower head seq, or a log whose record at the pinned seq hashes differently, is refused outright with a "rollback" error, never a prompt. This also covers `key_id`: a rollback to before a rotation is a lower seq. A machine with no pin can be rolled back, but an old state never lists a member added later, so a new member can't unlock it; a passphrase-only newcomer could (documented).

*The stale-writer gap* (the core of `ue1.2`). Bob pinned seq n while carol was a member. Alice removes carol at n+1 (new key K2) and writes secrets under K2. Carol, who kept folder write access, restores her seq-n `vault.json` and her copies of `secrets/` (all under K1), and deletes anything sealed under K2. Bob's pin is n, so the folder is byte-for-byte a state he has already accepted, signed by people who were members then. Any signal written into the folder can be removed by carol, and any record she can't forge (signed after her removal) is exactly what she deletes. So **this cannot be fully closed without a channel outside the folder.** What the design does:

1. **Write guard: writes fail loudly on any evidence.** Before every write (`set`, `rm`, `restore`, `passwd`, membership changes), the CLI reads the header of every `secrets/*.age` and trash file (the `sv-vaultkey <key id>` stanza; no decryption, a few hundred bytes each) and refuses the write if any file is sealed under a key id other than the head's. Also refused: a `secrets/.sv-rotate-*` folder for an unknown key id, or a sync-conflict copy of `vault.json` that verifies and has a higher seq than the head. The error says "this vault shows signs of being rolled back or forked: a newer key or vault.json exists. Nothing was written. Check with the other members, then run vault trust." Reads still work (the reader already has whatever is there). This catches any partial rollback: a single K2 file left behind, or a conflict copy of the newer `vault.json`.
2. **Exposure report after the fact.** When a client later verifies a chain whose `rotate` record retired key K1, any secret still sealed under K1 is listed with its name: "written under a key retired at seq n+1 when carol was removed; it may have been exposed; rotate it at the provider". So bob's stale writes are found and named as soon as anyone sees the honest state again.
3. **Folder access is part of removal.** `member rm` prints, every time and in `--json` (`"revoke_folder_access": "carol"`), that carol's access to the shared folder must be removed at Box/Dropbox now. With no write access there is no rollback.
4. **State code (out of band).** `member rm` prints a short code for the new head (seq plus three words of its hash), e.g. `team@5 CANDLE-ORBIT-SWIFT`, to send to the other members; `vault trust team --expect CODE` pins exactly that head (and refuses anything older). About 50 lines; I recommend building it, since it's the only thing that protects bob before he next sees the honest folder.

Considered and rejected: a commitment in the `rotate` record that the old key can't forge (carol deletes the record, so bob never sees it); refusing writes when the pin is older than N days (membership changes are rare, so it would fire on every quiet vault and train people to run `vault trust`); file modification times (set by the sync service and by carol).

**What remains, exactly:** a member whose client has not seen any state after the removal, in a folder that the removed member (who still has write access) restored completely and consistently, reads stale values and can write new secrets the removed member can read, with no warning. This needs all three of: folder access not revoked, the member not having opened the vault since the removal, and a complete restoration. Writes fail loudly in every other rolled-back state.

**5. Request tampering.** Request files (version 2) carry `recipient`, `sign_key` and a self-signature over their body (`"secrets-vault/v2 join request\0"`), so a request names keys its filer controls. The fingerprint covers both keys. `ApproveRequest` re-reads the request after the human confirmed and compares fingerprints (as today), and the signed `add-member` record holds exactly those keys. Swapping the file between the check and the write changes the fingerprint and fails; swapping it after is irrelevant because the record is already signed.

**6. Planted staging folder or symlinks (`ue1.4`).** Recovery now needs a verified head whose `key_id` names the staging folder, an unlocked key that matches it, and every staged file opening under that key with its own name; read-only commands never recover. A forged key id fails verification before anything is touched. Symlinked vault directories are refused before any write, rename or delete.

**7. Old passphrase holders (`ue1.6`).** See 8: removal drops the passphrase by default and `passwd` rotates, so knowing an old passphrase (plus an old `vault.json` copy) opens only what existed before the change.

## What changes where

Package boundaries hold; `internal/arch` needs no change (Ed25519, HMAC and HKDF are standard library; members already imports crypto and format).

| Package | Change |
|---|---|
| `format` | Directory checks (`Lstat`, not a symlink, owned by the user) before every write, rename and delete under the vault; `CommitStaged` requires regular staged files. `VaultFile` v2 with `Log []LogEntry{Body []byte, Auth}`; `ParseRecordBody`; `UnlockersDigest`; limits (1000 records, `vault.json` max size raised to 4 MiB); duplicate member labels rejected. No crypto beyond SHA-256 for chaining (stdlib hash, not a key). |
| `crypto` | `StateMAC(key, body)`; `SealPrevKey`/`OpenPrevKey`; `Rotate` takes a `commit func(next *format.VaultFile, newKey *VaultKey) error` hook so the `rotate` record is written in the same `vault.json` write (the commit point stays single); `RecoverRotation(dir, key)` moves here and checks every staged file opens under the verified key. |
| `members` | Signing key in identities; fingerprint v3; request v2; `Verify`, `Pin`, record builders (`Genesis`, `Share`, `AddMember`, `RemoveMember`, `SetUnlocker`, `RemoveUnlocker`); `ApproveRequest`/`Remove` take the signer (`*Unlocked`); `List`/`Inspect` read the verified head; `members.json` removed. |
| `cli` | Pin store (`trust/`); verify on every open; approve/rm/passwd/touchid unlock the identity to sign (one extra Touch ID or passphrase prompt for those rare commands); first-unlock confirmation; `vault trust` (no lower seq); `--accept-key-change` removed; open order from 6 (no recovery in read-only commands); `member rm` passphrase choice and folder-access line; `passwd` rotates by default (`--no-rotate`); `member log`; first `approve` in a personal vault makes the approver the owner (`share`), creating their identity if needed. |

Commands that change the unlocker list in a **shared** vault (passwd, Touch ID on/off) need a member's signature, so a person who only knows a shared passphrase can read and write secrets but can't change who has access. In a **personal** vault they keep working with just the vault key (MAC).

## Single-user (personal) vaults: the trade-off

A personal vault has no identities, so its records are MAC'd with the vault key. That defeats attackers 1, 2 and 4 for a pinned machine (they don't hold the key, and substitution or rollback breaks the pin). It does not give attacker-3 protection: anyone who holds the current vault key could write a valid record. Since `passwd` now rotates by default, that means people who know the *current* passphrase, which is the definition of having access. Someone who knew only an older passphrase is cut off by the rotation (their key can't produce a MAC under the new key, and `prev_key` lets the owner's other Macs follow the rotation without a prompt). Users who share a folder with others should share the vault with members, not a passphrase.

## Migration and version bump

- `vault.json` moves to version 2 (`format.VaultFileVersion = 2`; `index.json` keeps version 1 under its own constant). Version 1 `vault.json` files are read only by the migration path.
- **Personal v1 vault** (no member unlockers): upgraded on first unlock: genesis record MAC'd under the key, committing to the current unlockers, then pin. This is exactly the trust a v1 vault had.
- **Shared v1 vault** (has member unlockers): refused outright with "made by a pre-release build; create a new vault and share it again". The unlocker list is the thing we can't trust, so we won't import it, and there is no reset command (no real shared vaults exist; less code, less attack surface).
- Identity v1 → v2 on first unlock (new signing key, new fingerprint). Request v1 files are listed as unreadable ("re-run attach").
- Registry `key_id` is read once as a fallback pin, then dropped. `--accept-key-change` is removed (an unknown-flag error names `vault trust`).

## Not covered here: index authentication and secret-file rollback

Not cheap with this design: secrets are written by any key holder on any machine, often concurrently, so pinning them needs a per-write counter in an authenticated index plus conflict handling, which is a separate piece of work. A folder writer can still replace `secrets/NAME.age` with an older copy under the current key, or roll back `index.json`. Since a rotation re-encrypts everything, a rollback can never cross a removal. The same goes for authenticating `index.json` (relabelling keys, ambiguity DoS): it's written on every `set` by any key holder, so it needs the same per-write design. I'll file one issue (P2): "Authenticate index.json and detect secret-file rollback (MAC'd index with per-entry ciphertext hash and pinned counter)".

## Residual risks (documented in threat-model.md)

- The stale-writer gap (`ue1.2`, exact conditions under Threat 4): a member who hasn't opened the vault since a removal, in a folder the removed member restored completely, can write under the old key. Mitigated by the folder-access step, the write guard, the exposure report and the state code; not preventable without a channel outside the folder.
- A client that is offline across a removal and has no newer pin can follow a removed member's fork (but can't read the re-encrypted secrets).
- First use is trust-on-first-use, protected only by the fingerprint check; a passphrase-only newcomer has no fingerprint to check.
- Two members changing membership at the same moment: one change is lost to the sync conflict and the losing machine reports a fork; `vault trust` after checking with the others.
- Denial of service: any folder writer can corrupt or delete `vault.json`. We fail closed with a clear message; backups (Dropbox/Box version history) are the remedy.

## Tests (step 2)

- `ue1.1` end to end through the CLI: mallory appends a "bob" unlocker; alice's `member rm carol` refuses; mallory gets nothing.
- `ue1.2` (poc2): carol restores her snapshot; alice and any member who opened after the removal get the rollback error; with one K2 file left behind (or a newer `vault.json` conflict copy) bob's `set` fails and writes nothing; after the honest state returns, bob's K1 write is listed as exposed; `--expect CODE` refuses carol's state; `--accept-key-change` is gone.
- `ue1.4` (poc3): planted staging folder plus edited key id; `info` changes nothing; unlock refuses; symlinked `secrets/`, `.trash`, `requests/` and staging folders are refused before any write.
- `ue1.6`: after `member rm` (default) the old passphrase opens nothing and the record says `dropped`; `--keep-passphrase` says so and is recorded; a forged `passphrase` field fails verification; after `passwd` an old `vault.json` copy plus the old passphrase can't read a secret written afterwards; `--no-rotate` warns.
- One test per attacker 1-5, plus: fork after removal, TOFU signer mismatch, personal-vault MAC tamper, sync-conflict fork message, migration of v1 personal and refusal of v1 shared.
- Fuzz: record body, log entry, pin file, request v2, identity v2, unlockers digest round trip.
- Leak tests over approve/rm/trust with canaries; existing suites; `make lint`, `make fuzz FUZZTIME=10s`, linux/windows `CGO_ENABLED=0` builds.
