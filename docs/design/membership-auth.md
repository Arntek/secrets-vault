# Design: authenticated membership (issue ue1.1)

Status: **implemented** (revision 4, Security verdict: holds). Deviations from the text below are listed under Implementation notes at the end. No code yet.

Covers `ue1.1` (planted unlockers) and the findings with the same root cause, the CLI trusting the shared folder: `ue1.2` (rollback by a removed member), `ue1.4` (recovery before verification, symlinked folders) and `ue1.6` (passphrase survives removal; `passwd` doesn't rotate).

## Changes in revision 4 (Security review of 002638e)

| Item | Where | Change |
|---|---|---|
| N1 (must-fix) | 8b, 10 | Auto-rebase only when the winning branch can't weaken our ops: every record signed by someone still a member after our ops, no member added, no passphrase added or replaced. Anything else is a hard refusal. A lost rotation's files are re-sealed to the **re-applied rotation's new key**, never the winner's. |
| S1 | 8 | State code has 66 bits (seq + six words); `--expect` also takes the full head hash. |
| S2 | 7 | A first pin is never silent: show head seq, time, signer and members, and ask for the state code from another machine (Enter to skip; `--expect` for scripts). Named in the residual risks. |
| S3 | 10 | Pending rotation keys are deleted on `detach` and on `--accept-rollback`. |
| M3 note | Migration | "Unlocked via the passphrase" means a fresh passphrase unwrap in this command, never an agent-cached key. |
| M4 note | 6 | Every write re-reads and re-verifies the exact `vault.json` bytes it replaces (compare-and-swap). |

## Changes in revision 3 (since 37e4d18)

| Item | Where | Change |
|---|---|---|
| Coordinator: Touch ID protects identities | 1, 9 | Every user has an identity and every vault has at least one member (its owner). Touch ID only ever wraps identities, so rotations never drop it. Vault-level `touchid` unlockers are gone. |
| Follows from that | 3 | **Every record is signed. The HMAC mode and `prev_key` are removed.** Lost-identity recovery is a rebuild, not a special authority. |
| M1 | 5 | Registry stores `vault_id` at init/attach; the pin is looked up by it; a `vault.json` with another id is refused. |
| M2 | 3 | No MAC records exist, so no member is ever created without a member's signature. Genesis is signed by the owner it creates. |
| M3 | Migration | v1 → v2 only with no v2 pin, with the v1 key id matching the legacy pin, and unlocked by the **passphrase only**. `member reset` dropped. |
| M4 | 6 | Nothing (recovery, agent hand-off, unlocker choice) acts on an unverified record. Recovery only for a staging folder whose key id a verified rotation introduced and the verified head still uses. |
| G1 | 2 | A log entry is exactly `{body, by, sig}`; anything else is malformed. |
| G2 | 8 | Forks are classified: extension, lost race (auto-rebase), rollback/substitution (hard refusal). |
| G3 | 2 | Records are deltas (about 400-600 bytes); cap 4096 records; at the cap membership changes are refused and the vault must be rebuilt. |
| G4 | 7 | Approve and signer checks need the fingerprint **typed**, not y/N. |
| G5 | — | Moot: no MACs. |
| G6 | 10, Threat 4 | Rotation lease file; the loser re-encrypts onto the winner's key; required "folder access removed" confirmation on `member rm`; write guard on unknown key ids; head seq/time/signer in `vault status`. |
| G7 | Threat 5 | `vault_id` and `created` in the signed request; warning plus re-typed fingerprint when re-adding a removed key. |
| `added_by` | 2 | Not stored: derived from the `by` of the record that added the member, so it can't disagree. |
| Coordinator (c) | 8 | State code `vault trust --expect CODE` will be built. |

## The problem

`vault.json`'s unlocker list is unauthenticated. Anyone who can write the shared folder can add a member unlocker, and the next `member rm` re-wraps the rotated vault key for it. A MAC of the list under the vault key does not fix it: a removed member still holds the old key, and a folder writer can replace the whole file with one for a key they made.

The fix: every change to who can open a vault is a **record signed by a member who was allowed to make it**, the records form a **hash chain**, and each machine **pins the last head it verified on its own disk**, keyed by the vault id it registered.

## Attackers

Each can write any file in the shared folder (Dropbox/Box collaborator, compromised sync account, the provider).

| # | Attacker | Stopped by |
|---|---|---|
| 1 | Non-member plants an unlocker, edits a label, duplicates a name | Head commits to the exact unlocker list and member set; members change only by signed records |
| 2 | Replaces `vault.json` with a fresh vault (own key, wrapped to members' public keys), with the same or a new vault id | Registered vault id (M1) plus local pin; first use needs a typed fingerprint of whoever added you |
| 3 | Removed member (knows old vault keys) forges a change | Authority is only member signatures from state n-1; no vault-key authority exists anywhere |
| 4 | Rollback to an older valid `vault.json` (+ `secrets/`) | Pinned seq and head hash; write guard; exposure report; state code; folder-access step |
| 5 | Edits, swaps or replays a join request | Fingerprint over both keys, typed by the approver; self-signed request bound to the vault id; warning for removed keys |
| 6 | Plants a staging folder or symlinks so a member's client overwrites secrets (`ue1.4`) | Verify first; recovery only for a verified rotation and files that open under its key; symlinked directories refused |
| 7 | Anyone who knew the vault passphrase, after `member rm` or `passwd` (`ue1.6`) | `member rm` drops the passphrase by default; `passwd` rotates |
| 8 | Downgrades a v2 vault to a v1 file (M3) | Migration only without a v2 pin, with the legacy key id, via the passphrase |

## Building blocks

### 1. Every user has an identity

An identity is the person's age X25519 key plus an **Ed25519 signing key** (random, not derived from the X25519 key), both sealed in the identity file (`crypto.Sealer`, names `IDENTITY` and `SIGNING`) under an identity key wrapped by the personal passphrase and, on each Mac, Touch ID. `identity export/import` carries both.

- `members.Identity` gains `SignKey` (32-byte Ed25519 public key, hex in files). `members.Unlocked` gains `Sign(domain, msg)`; the private key never leaves the type (redacting `String`/`LogValue`).
- **Fingerprint v3** = scrypt over `"secrets-vault/v3 member fingerprint\0" || recipient || "\0" || signkey-hex`. Same shape (`MAPLE-RIVER-OTTER-4417`, ~46 bits) and cost. Reading one aloud checks both keys.
- Identity file version 2. A v1 identity gains a signing key the first time it is unlocked (new fingerprint; fine before release).
- **`vault init` creates the identity if this user has none** (name from `--as` or the login name, personal passphrase, Touch ID offered), then the vault. The person who creates a vault is always its first member, with role `owner`. A "personal vault" is simply a vault with one member.

Cost: a first-time user's `init` asks for two passphrases (personal identity, then the vault's recovery passphrase). It happens once per person, and the vault passphrase can be skipped with `--no-passphrase` (then the usual "only one way in" warning). In return there is one kind of vault, one authority rule and one unlock path, and Touch ID survives every rotation.

### 2. The membership log in `vault.json`

`vault.json` version 2:

```json
{
  "version": 2,
  "id": "…", "name": "team", "key_id": "…",
  "members": [ { "name": "alice", "recipient": "age1…", "sign_key": "<hex>", "role": "owner" } ],
  "unlockers": [ … ],
  "log": [ { "body": "<base64 of the record's JSON bytes>", "by": "alice", "sig": "<base64>" } ]
}
```

Each log entry has exactly three fields, `body`, `by` and `sig` (G1: no other auth form is parsed). Records are signed over their **exact bytes**, so there is no JSON canonicalisation problem: verify the bytes, then strict-parse them.

Signature: `Ed25519(signer, "secrets-vault/v2 membership record\0" || body)`.

Record body (a **delta**, G3):

```json
{
  "seq": 3,
  "prev": "<hex SHA-256 of record 2's body bytes; empty for seq 0>",
  "vault_id": "…",
  "time": "2026-11-20T10:00:00Z",
  "op": "genesis | add-member | remove-member | rotate | set-unlocker | remove-unlocker",
  "member": { "name": "dan", "recipient": "age1…", "sign_key": "<hex>", "role": "member" },
  "passphrase": "dropped | replaced | kept",
  "key_id": "<vault key id after this record>",
  "members_hash": "<hex SHA-256 of the member set after this record>",
  "unlockers_hash": "<hex SHA-256 of the unlocker list after this record>"
}
```

- `member` is present for `genesis`, `add-member` and `remove-member` (for removal only the name is used). `passphrase` is present for `remove-member` and `rotate` (see 11).
- The state after record n is computed by **replaying from genesis**: genesis creates `{owner}`, `add-member` adds one entry (name, recipient and sign key all unique), `remove-member` removes one, other ops keep the set. The replayed set must hash to `members_hash`. `key_id` may change only on `rotate` and `remove-member` (which always rotates).
- `members_hash` and `unlockers_hash` use our own length-prefixed encoding (not JSON) so they're deterministic. The unlocker encoding covers `type`, `label`, `recipient`, `SHA-256(wrapped_key)` and `created`, in file order.
- The top-level `members` array is the head's set, for display and re-wrapping; it must equal the replayed set. **`added`/`added_by` are not stored anywhere**: `member list` derives them from the time and `by` of the record that added each member, so they can't disagree with the signatures.
- `members.json` is deleted.
- Size: a record is about 400-600 bytes. Cap: **4096 records** and 4 MiB for `vault.json`. At the cap, any further membership change is refused with "this vault's history is full; create a new vault and move the secrets (`vault rebuild`)". At realistic rates (a few changes a month) that is decades away. Verification always replays from genesis: 4096 Ed25519 checks take well under a second, and a typical vault has tens.

### 3. Who may write record n

Decided by the **state at n-1**, in one function, `members.authorise(prev State, rec Record, signer Member) error`, used by both writer and verifier:

- `by` names a member of state n-1 and `sig` verifies under that member's `sign_key` **from state n-1**.
- Policy (decided, Q3): **any current member may sign any op**; the product is for high-trust teams. `authorise` is the only place this rule lives, so a stricter policy later is a one-line change; `role` stays in member entries for that.
- **Genesis** (seq 0) has no state n-1: it must add exactly one member with role `owner`, and it must be signed by **that member** (self-consent). Its trust comes from TOFU (7).
- There is no MAC, no `share` op and no `prev_key`. No record is ever authorised by vault-key material, so a removed member's old keys give no authority (M2, attacker 3), and there is nothing to verify "under the key just unwrapped" (M4).
- **Lost identity, no other member:** the vault passphrase still opens the vault and reads every secret, but can't sign. `vault rebuild VAULT` creates a new vault (new id, new genesis under the person's new identity) in the same folder and moves every secret into it. Other Macs then see a different vault id and refuse (M1) until `detach` + `attach`. Lost identity with other members: another member re-adds you, as the original design says. `init` and `member list` recommend `vault identity export` to a safe place.
- **One-member warning** (kept from today): when a vault has only one member, `member list`, `init` and `status` warn that losing that identity leaves only the passphrase (or nothing, with `--no-passphrase`), and suggest **adding a second trusted member as the recovery route**: "vault member approve" after they attach. A second member can re-add you without a rebuild.

### 4. Verifying a `vault.json`

`members.Verify(vf, registeredID, pin)`, needing no key:

1. Strict parse (format): version 2; 1-4096 entries; each body strictly parsed; `seq` = index; `prev` links; every `vault_id` = top-level `id` = **the registered vault id** (M1).
2. Replay and authorise every record from genesis (3). Check each `members_hash`.
3. Head consistency: top-level `key_id`, `members` and the unlocker hash match the head. Every member unlocker's (label, recipient) belongs to a head member; every head member has exactly one member unlocker; non-member unlockers are only `passphrase` (at most one). **Any extra, missing or edited unlocker → refuse.**
4. Pin (5) and fork classification (8).

Re-wrapping (`member rm`, `passwd`, any rotation) uses **only the verified head's `members`**, never recipients read from the unlocker list.

### 5. The local pin

- The registry entry (`config.toml`) gains `id`: the vault id recorded at `init` or `attach`. Everything is looked up by it (M1). A `vault.json` whose id differs is refused: "this folder now holds a different vault. If you rebuilt it, run: vault detach NAME, then vault attach NAME DIR". `attach` keeps refusing an id already registered under another name.
- The pin: `~/.config/vault/trust/<registered id>.json` (0600, directory 0700), outside any synced folder:

  ```json
  { "version": 1, "vault_id": "…", "seq": 7, "head": "<hex SHA-256 of record 7's body>", "key_id": "…",
    "own": [ { "seq": 7, "body": "<base64>", "sig": "<base64>" } ] }
  ```

  `own` holds the records this machine wrote that it hasn't yet seen extended by anyone else (normally 0-1 entries, capped at 16), for rebasing a lost race (8). Bodies are public (they're in the shared folder too). Strictly parsed and fuzzed.
- It replaces `key_id` in `config.toml`, which is read only by migration (M3), then dropped.
- `vault status` shows each vault's head seq, time and signer (G6) so members can compare.

### 6. Order of operations on open (`ue1.4`, M4)

Nothing in the vault folder is written, renamed or deleted, and no key is used, before the vault is verified:

1. `Lstat` every path component from the vault folder down: the folder, `secrets/`, `secrets/.trash/`, `requests/` and any `secrets/.sv-rotate-*` must each be a real directory (not a symlink) and, on Unix, owned by the current user. Otherwise refuse. (The path *to* the vault folder is the user's registry entry and may contain symlinks, e.g. `~/Dropbox`.) Files are opened with `O_NOFOLLOW` as today.
2. Verify `vault.json` (4) against the registered id and pin, **before any write of any kind**.
3. Read-only commands (`info`, `list`, `get`, `member list`, `status`) **never write** to the vault folder: no recovery, no purge. The only thing they write is the local pin advance.
4. Unlock (9) using unlockers of the **verified** head only, then check the key against the verified `key_id`. Only then is the key handed to the agent, which caches it under the registered id.
5. Then, for writing commands, `crypto.RecoverRotation(dir, key)` (moved from format to crypto so it can use the key). It acts on a staging folder only if its key id is the verified head's `key_id` **and** that key id was introduced by a verified `rotate`/`remove-member` record. Every MANIFEST entry must be a regular file and **open under `key` with its own name** before anything is renamed. Staging folders for any other key id are left alone; `doctor` reports them, and the write guard (Threat 4) treats an unknown one as evidence.
6. Write guard (Threat 4), then the write. Every write of `vault.json` is a compare-and-swap: immediately before the rename, re-read the file and require the **exact bytes** that were verified in step 2; if they changed, verify the new file from scratch (step 2 onwards) and rebuild the change on top, or stop.

`format.CommitStaged` keeps the file moves and gains the regular-file and directory checks.

### 7. Trust on first use

A machine with no pin for the registered id can't know the history, so a person confirms the first pin:

- **The record that added me was signed by me** (my vault, or my second Mac after `identity import`): no fingerprint question, because nobody else holds my signing key (this includes genesis by me). **But never a silent pin** (S2): a removed member could present the chain cut off before their removal, which still contains my own genesis. So the first pin always prints the head (`team@12, 2026-11-20 10:02, signed by alice`) and the members with fingerprints, then **asks for the state code**: "Type the state code from `vault status` on another member's machine (or press Enter to trust what's shown):". A typed code that the head doesn't match or extend is refused. `--expect CODE` gives it non-interactively. Without a terminal and without `--expect`, the head is printed and pinned (scripts), as the residual risk says.
- **Added by someone else:** "You were added to 'team' by alice. Type alice's fingerprint as alice reads it to you:" and pin only if it matches exactly (case and separators ignored). `--signer-fingerprint FP` for scripts. `member approve` prints the approver's own fingerprint so they can read it out: the check is mutual.
- **Passphrase-only user** (not a member): pin on first successful unlock and print the members with fingerprints. Weaker; documented.
- **Approve** (G4): `member approve` also requires the requester's fingerprint to be **typed**, not y/N. `--fingerprint FP` stays for scripts and agents (accepted risk in the threat model).
- On first use the whole chain is verified from genesis anyway (4); the person is vouching only for who added them.

### 8. Forks and `vault trust`

When the folder's chain doesn't simply extend the pin, the client classifies it (G2):

- **(a) Extension:** the record at `pin.seq` hashes to `pin.head`. Advance the pin. No prompt.
- **(b) Lost race:** the chains diverge at some seq d < pin.seq, and **every** pinned record after d is in `own` (written by this machine, never extended by anyone else). This is treated as two honest writers at once **only if the winning branch (records after d) cannot weaken our ops** (N1):
  - every winning record is signed by someone who is **still a member after our own ops are re-applied** (so not anyone our lost ops removed);
  - no winning record adds a member;
  - no winning record adds or replaces a passphrase unlocker (`set-unlocker` of a passphrase, or a rotation with `"passphrase": "replaced"`).

  If all three hold, verify the winning branch from d and **re-apply our own ops on top**, re-signed (an `add-member` still pending, a `remove-member` of someone still present, an unlocker change). Ops that no longer apply are dropped and reported ("dan was already added by bob"). A lost rotation is handled by 10. No prompt; one line of output. **If any check fails, it is case (c)**, and the refusal shows both branches. That covers the N1 attack: carol, being removed by alice, signs a race branch adding her second identity. Two honest members happening to change the passphrase and remove someone at the same moment also get (c); that's rare, and safer than guessing.
- **(c) Anything else:** a lower head seq than the pin, divergence that includes records this machine didn't write, or a chain without the pinned head. **Hard refusal:** "vault.json for 'team' is older than, or different from, what this Mac has already verified. Nothing was read or written. Someone may have restored an old copy of the folder. Check with the other members." There's no flag on normal commands. The separate path is `vault trust team --accept-rollback`. It shows both branches (heads, signers, members, and which members each branch removed), requires typing the fingerprint of the folder branch's head signer, lists every secret that may have been exposed, and then re-pins. The error message doesn't mention it; the docs do.
- **`vault trust team --expect CODE`** (state code, coordinator (c)): `member rm` and `passwd` print the new head as `team@5 CANDLE-ORBIT-SWIFT-MAPLE-RIVER-OTTER`: seq plus **six** BIP-39 words from the head hash (66 bits, S1). At 33 bits an ex-member could grind a matching record of their own in about an hour; 66 bits puts that out of reach. `--expect` also accepts the full hex head hash (`vault status --full`). Another member runs `--expect` with it: if the verified folder head is that state or extends it, the pin moves there; if the folder is behind it or doesn't contain it, a hard refusal. It's also accepted on `attach` and first unlock (7). This is the out-of-band signal for members who were offline.
- `unlock --accept-key-change` is removed. A key change is either a verified record or a refusal.

### 9. Touch ID and the unlock chain

- Touch ID wraps only the **identity key** (as `members.Store.AddUnlocker` already supports). The vault-level `touchid` unlocker type is not valid in v2. Each vault has one `member` unlocker per member and at most one `passphrase` unlocker.
- Unlock order: agent → identity (Touch ID, else personal passphrase) → that member's unlocker → vault passphrase. The Touch ID sheet still names the vault and program (`WrapperForVault` passes the reason text).
- A rotation re-wraps the new key for every member's X25519 recipient from the verified head, so **Touch ID on every Mac keeps working after `member rm` and `passwd`**. Only a passphrase unlocker is affected, by design (11).
- `touch-every-read` unlocks the identity with Touch ID on every read, as before.
- Fallback for identity-less setups: I recommend **none**. Every machine that runs the CLI can have an identity (Windows/npm too, passphrase-protected). The only identity-less users are shared-passphrase users (D3); their way to Touch ID is to become members, which is also how they become removable. A vault-level Touch ID unlocker would bring back the "re-enrol after every rotation" problem and a second code path, and nobody needs it.
- Commands that change membership or unlockers need the identity unlocked to sign. That's the same Touch ID that unlocks the vault, so usually there's no extra prompt.

### 10. Concurrent rotations (G6)

Two members rotating at once (`member rm`, `passwd`) produce two rotation records from one parent, two new keys and two staging folders, and their file moves can interleave through sync.

- **Lease:** before rotating, write `secrets/.sv-rotate.lease` (signed by the rotator: `vault_id`, base seq, new key id, time). If a valid lease by someone else, under 15 minutes old, exists for the current head, refuse: "bob started changing the vault key at 10:02; try again shortly". It's removed after the moves. It's advisory, so it narrows the race but can't close it.
- **Re-check before moving:** after writing `vault.json`, re-read it; if our record is no longer the head's ancestor, don't move files.
- **Loser re-encrypts:** until its rotation is seen extended in the verified chain, the rotator keeps its new key in `~/.config/vault/pending/<vault id>-<key id>.age`, age-encrypted to its **own identity recipient** (same protection as the identity; deleted once confirmed, and also deleted on `detach` and on `vault trust --accept-rollback`, S3). A lost race (8b, only when the winning branch passed the N1 checks) is resolved like this:
  - If our lost op was a rotation (`member rm`, `passwd`), we re-apply it as a **new** rotation on top of the winning head, with a fresh key K4 wrapped for the head's members after our op. Files the winner sealed are re-encrypted from the winner's key to K4 by that rotation as usual. Files we moved under our losing key K3 are re-sealed **from K3 straight to K4, never to the winner's key** (N1). The winner's key can be held by people our removal was meant to cut off, so nothing of ours is ever sealed to it.
  - If our lost op wasn't a rotation, there are no files under a key of ours to fix.
- If a member whose rotation lost never comes back, its moved files stay sealed under a key only it held. `doctor` and the write guard report them by name; recovery is that member's machine. Documented.

### 11. Passphrase unlocker on removal and `passwd` (`ue1.6`)

The passphrase unlocker is the one way in not tied to a person.

- **`member rm` removes the passphrase unlocker by default.** Output: "The vault passphrase no longer opens 'team'. To set a new one: vault passwd team". Record: `"passphrase": "dropped"`.
- `--new-passphrase` (prompt twice, or `--new-passphrase-stdin`) sets a new one in the same rotation: `"replaced"`.
- `--keep-passphrase` is the explicit opt-out (current passphrase proved first). Output: "The vault passphrase was kept: anyone who knows it still has access." Record: `"kept"`, so `member log` shows who chose it and when.
- `passphrase` is signed and checked against the unlocker hash (dropped means no passphrase unlocker in the new state), so it can't be faked.
- **`passwd` rotates the vault key**: a signed `rotate` record with `"passphrase": "replaced"`, in every vault. Without rotation, the old passphrase plus any old `vault.json` (Dropbox/Box keep versions for 30-180 days) gives the unchanged key and every future secret. People change passphrases because someone saw it, it was shared, or it was weak, so a change that doesn't rotate protects nothing against the person who prompted it. `--no-rotate` stays for personal convenience (and still writes a signed `set-unlocker` record), with output saying "anyone who knew the old passphrase can still open old copies of this vault". Cost: seconds of re-encryption. Thanks to 9, Touch ID is no longer dropped on other Macs.
- `passwd` is also how a vault cuts off shared-passphrase users (D3), who can't be removed by name.

Trade-off: after a removal the vault has no recovery passphrase until someone runs `passwd`, and the copy in the safe or password manager must be replaced. Keeping it silently made removal ineffective against the person most likely to know it, so dropping it is the default and keeping it is signed and visible.

## Threat by threat

**1. Non-member planting.** A planted, edited or duplicated unlocker changes the unlocker hash, or fails the member/unlocker correspondence, so open refuses before anything is wrapped. Adding a member needs a signature by a member of the previous state. Duplicate names, recipients or sign keys fail replay. Re-wrapping uses only the verified head's members. The `ue1.1` sequence stops at alice's open: "vault.json was changed outside secrets-vault".

**2. Whole-file substitution.**
- **Same id:** the attacker's chain needs a genesis and records signed by them, so it doesn't contain the pinned head: hard refusal (8c).
- **New id (M1):** refused because it's not the registered id.
- **First use** (no pin): the record that added the victim is signed by the attacker, so the typed fingerprint check fails. Genesis must be self-signed by its owner, so the attacker can't make a genesis that "I added myself" passes (M2).

**3. Removed member.** Their old vault keys carry no authority anywhere. Their signature counts only in states where they were a member, so they can only fork from before their removal. Every machine pinned at or after the removal refuses that (8c). The rest is the stale-writer gap below.

**4. Rollback (`ue1.2`).** A lower head seq or a missing pinned head is a hard refusal, never a prompt. Rolling back across a rotation is a lower seq.

*The stale-writer gap.* Bob pinned seq n while carol was a member. Alice removes carol at n+1 (new key K2) and writes under K2. Carol, who kept folder write access, restores her seq-n `vault.json` and her copies of `secrets/` (all under K1) and deletes anything under K2. Bob's pin is n, and the folder is exactly a state he already accepted. Any evidence in the folder can be deleted by carol, so **this can't be fully closed without a channel outside the folder.** What the design does, in order of value:

1. **Folder access is part of removal.** `member rm` requires confirming "carol's access to the shared folder has been removed" (interactive y, or `--folder-access-removed`). If not, it cancels and says to remove access first; removing access before the rotation also stops carol taking a fresh snapshot. `--json` includes it.
2. **State code** (8): the remover passes `team@n+1 WORD-WORD-WORD` to the others, and `vault trust --expect` makes bob's machine refuse carol's state.
3. **Write guard:** before every write (`set`, `rm`, `restore`, `passwd`, membership changes), read the key-id stanza of every `secrets/*.age` and trash file (a header line, no decryption), plus staging folder names and verified sync-conflict copies of `vault.json`. Refuse the write if any key id is **unknown to the verified chain** (evidence of a newer state), or a conflict copy verifies with a higher seq. "This vault shows signs of a newer state than the one this Mac verified. Nothing was written. Check with the other members." Reads still work.
4. **Exposure report:** a file sealed under a key the chain **retired** (known, but no longer the head's) is reported by name: "written under a key retired at seq n+1 when carol was removed; it may have been exposed; set a new value and rotate it at the provider". Writes are allowed, so it can be fixed with `set`. That's how bob's stale writes are found once he sees the honest state again.
5. **`vault status`** shows head seq, time and signer for members to compare.

Rejected: a commitment in the rotation the old key can't forge (carol deletes the record), refusing writes when the pin is N days old (fires on every quiet vault and trains people to override), mtimes (set by the sync service and by carol).

**What remains, exactly:** a member whose machine has seen no state after the removal, who hasn't run `--expect`, in a folder the removed member restored completely and consistently despite the required folder-access step, reads stale values and can write secrets the removed member can read. Written to the threat model.

**5. Request tampering (G7).** Request v2 body: `vault_id`, `name`, `recipient`, `sign_key`, `created`, self-signed (`"secrets-vault/v2 join request\0"`). A request for another vault id is rejected. The fingerprint covers both keys and is typed by the approver. `ApproveRequest` re-reads the request after the check and compares, and the signed `add-member` record holds exactly those keys. If the recipient or sign key appears in an earlier `remove-member` record, approve says "this key was removed from 'team' on 2026-11-20 by alice" and needs `--readd` plus the fingerprint typed again.

**6. Staging folder or symlinks (`ue1.4`).** See 6: recovery needs a verified rotation, a matching unlocked key and files that open under it. Read-only commands never recover. Symlinked vault directories are refused before any write.

**7. Old passphrase holders (`ue1.6`).** See 11.

**8. Downgrade (M3).** See Migration.

## Migration and version bump

- `vault.json` moves to version 2 (`format.VaultFileVersion = 2`; `index.json` keeps its own version 1).
- **Personal v1 vault** (no member unlockers). Upgraded on first unlock **only if all of these hold**:
  - no v2 pin exists for the registered id;
  - the v1 `key_id` equals the registry's legacy `key_id` pin, if one exists;
  - the vault was unlocked with a **fresh unwrap of the v1 passphrase unlocker in this command**, never a v1 Touch ID unlocker and never a key cached in the agent. A folder writer can wrap a key to this Mac's public Secure Enclave key but can't produce a passphrase unlocker the user opens.

  The upgrade writes a genesis signed by the user's identity (created first if needed), keeps the passphrase unlocker, replaces v1 Touch ID unlockers with a member unlocker (Touch ID now lives on the identity), and pins. If any check fails, refuse: "this folder holds an older vault format than this Mac has seen: possible downgrade".
- **Shared v1 vault** (has member unlockers): refused outright, "made by a pre-release build; create a new vault and share it again". No `member reset`.
- A legacy registry entry without `id` gets it from the migration above, or for a v2 file from first use (7).
- Identity v1 → v2 on first unlock. Request v1 files are listed as unreadable ("re-run attach").

## What changes where

Package boundaries hold; `internal/arch` needs no change (Ed25519 and SHA-256 are standard library; members already imports crypto and format).

| Package | Change |
|---|---|
| `format` | `VaultFile` v2 (`members`, `log` entries of exactly `body/by/sig`); `ParseRecordBody`; `MembersDigest`, `UnlockersDigest`; limits (4096 records, 4 MiB); directory checks (`Lstat`, not a symlink, owned by the user) before every write/rename/delete; `CommitStaged` requires regular files; `touchid` unlocker type refused in v2; v1 parser kept for migration only. |
| `crypto` | `Rotate` takes a `commit func(next *format.VaultFile, newKey *VaultKey) error` hook so the signed record is in the same `vault.json` write; `RecoverRotation(dir, key)` moves here; `KeyIDOf(ciphertext)` header read for the write guard. |
| `members` | Signing key, fingerprint v3, request v2; `State`, `Replay`, `Verify`, `authorise`, record builders, fork classification and rebase; pin file type and parser; `ApproveRequest`/`Remove`/`Rotate` take the signer `*Unlocked`; `members.json` removed. |
| `touchid` | No API change; used only as an identity unlocker. |
| `cli` | Registry `id`; pin store; open order (6); write guard; TOFU with typed fingerprints; `vault trust` (`--expect`, `--accept-rollback`); `vault rebuild`; `member log`; `member rm` passphrase and folder-access options; `passwd` rotates; `init` creates the identity; `status` shows the head; `--accept-key-change` removed. |

Not touched: `internal/agent`, and the CLI's run/copy/alias code (ue1.3/ue1.5 are with another developer).

## Not covered here

`index.json` authentication and single-file rollback under the current key: issue `the-secrets-vault-ue1.7`.

## Residual risks (to threat-model.md)

- The stale-writer gap, exactly as stated under Threat 4.
- A machine offline across a removal, with no newer pin, can follow a removed member's fork (8c then fires on its next contact with the honest chain).
- **First pin of a member's own vault on a new Mac** (S2): a removed member can present the chain cut off before their removal, which the new Mac would pin because it contains the owner's own genesis. Mitigated by always showing the head and asking for the state code; not prevented if the person skips it.
- First use is TOFU behind a typed fingerprint; a passphrase-only user has no fingerprint to check.
- A lost rotation race whose loser never returns leaves that member's moved files unreadable to others (10).
- Denial of service: any folder writer can corrupt or delete `vault.json`. We fail closed with a clear message; Dropbox/Box version history is the remedy.

## Tests (step 2)

- **`ue1.1` regression**, end to end through the CLI: mallory appends a "bob" unlocker; alice's `member rm carol` refuses; mallory gets nothing.
- **Attackers 1-8**, one test each:
  - 2 is tested with the same id and with a new id;
  - 4 includes poc2 (machines that saw the removal refuse; a K2 leftover blocks bob's `set`; the exposure report after recovery; `--expect` refuses carol's state);
  - 6 is poc3 plus symlinked `secrets/`, `.trash`, `requests/` and staging;
  - 7: the old passphrase opens nothing after `member rm` or `passwd`, `--keep-passphrase` is recorded, a forged `passphrase` field fails.
- **M1:** fresh-id substitution of a pinned vault. **M2:** an attacker genesis "adding" the victim, on a second Mac with an imported identity. **M3:** v1 downgrade of a pinned v2 vault; v1 opened via Touch ID is not migrated. **M4:** a planted staging folder for an unverified key id is never touched, and the agent never receives a key before verification.
- **G1:** an entry with a `mac` field, or extra auth fields, is malformed. **N1:** a removal race where the winning branch adds a member signed by the removed person → hard refusal, and nothing is re-sealed to the winning key; an honest lost rotation is re-sealed from K3 to the re-applied key K4. **S1:** the state code has 66 bits, and a full-hash `--expect` works. **S2:** the first pin of one's own vault prints the head, and `--expect` on attach refuses a cut-off chain. **S3:** pending keys are removed on `detach` and `--accept-rollback`. **M4 CAS:** `vault.json` changed between verify and write → no write. **G2:** extension (no prompt), lost race (auto-rebase, including a dropped op), rollback (hard refusal), `--accept-rollback` requires the typed fingerprint. **G3:** record 4097 is refused. **G4:** a mistyped fingerprint fails. **G6:** a concurrent rotation is resolved without data loss, the lease refuses, and rotation can't proceed without the folder-access confirmation. **G7:** wrong `vault_id` in a request; re-adding a removed key needs `--readd`.
- Touch ID survives `member rm` on a second identity unlocker (fake wrapper).
- Fuzz targets: record body, log entry, pin file, request v2, identity v2, both digests, lease file.
- Leak tests over approve/rm/trust/passwd/rebuild with canaries; the existing suites; `make lint`, `make fuzz FUZZTIME=10s`, linux/windows `CGO_ENABLED=0` builds.

## Implementation notes

What the code does where this document was not specific, or differs slightly:

- **Lost race on read-only commands.** A read-only command never writes, so it reads from the winning state and prints a note; the next write (or `vault trust VAULT`) re-applies this machine's change. Re-applying a change that needs a passphrase (`--keep-passphrase`, `passwd`) asks for it again; without a terminal it stops and says so.
- **One identity unlock per command.** A command unlocks the identity at most once (Touch ID or personal passphrase) and uses it both to open the vault and to sign.
- **`--no-rotate`** on `passwd` is refused for a vault with more than one member.
- **Registry entries from before this change** get their vault ID on first use; a legacy `key_id` pin must appear in the chain's history, or the vault is refused.
- **`rebuild`** keeps the secrets and the index, makes a new vault ID and genesis (signed by the person rebuilding), and needs a new recovery passphrase.
- **Index writes.** Reading no longer writes a rebuilt `index.json`; the next write stores it.

## Older builds (issue ue1.8)

Builds from before this design can't verify anything, so they are kept from *using* a version-2 vault at all, rather than trusted to check it:

- **Versions.** Every file whose format changed is written with a higher version than older builds accept: `vault.json` 2, identity files 2, join requests 2. Older builds refuse them ("not supported by this build; upgrade"). New builds say how to upgrade: "vault 'team' was saved by a newer secrets-vault. Upgrade to open it: brew upgrade secrets-vault (Homebrew) or npm update -g secrets-vault (npm)."
- **Downgrade by a folder writer** (rewriting a version-2 `vault.json` as version 1, with a planted unlocker) gives an older build nothing to work with:
  - every wrapped vault key (member and passphrase unlockers) now carries a marker (`"secrets-vault/v2 wrapped key\0"` before the 32 key bytes); older builds expect exactly 32 bytes, so they can't unlock the vault at all;
  - secret files use a new stanza type and HKDF label (`sv-vaultkey2`, `"secrets-vault/v2 secret file key\0"`); older builds can't open them, so even with a key their rotation fails before `vault.json` is written. Migration re-seals version-1 files in the new format (`crypto.UpgradeSecrets`), and every write re-checks.
  - A fixed build refuses the downgraded file (M3: version 1 with member unlockers, or with a v2 pin, is never migrated).
- **Registry.** Older builds rewrite `config.toml` and drop fields they don't know, so the registered vault ID (M1) lives in `registry.toml`, which older builds never write. If an entry has no registered ID while this machine has a trust pin for that folder, the vault is refused ("lost its record of which vault this is"); `detach` + `attach` registers it again.
- Checked against a build of `main` from before the fix (3f8902d): it refuses a genuine version-2 vault, and on a downgraded file it can't unlock (`unlock`, `get`, `member rm` all fail) and changes nothing.

A member running an outdated build is protected because it refuses newer vaults, not because it can verify them. Upgrading is required to use a shared vault.

## Follow-ups from the re-test (ue1.9, ue1.10)

- **A failed state code is remembered** (ue1.9): if `--expect` finds the folder behind the code (or not containing it), the expectation is saved in the trust pin, and every command refuses the vault until the folder reaches it, or `vault trust VAULT --accept-rollback` is run with the signer's fingerprint. When it is met, it is cleared.
- **Exit code 5** (ue1.10): any refusal because a vault failed verification exits 5, so a script or agent can't mistake it for "key not found" (4). `list --json` names such vaults with an error.
- **First pin in `--json`**: `state_code_checked` and `first_pin` (state, signer, members with fingerprints) are part of the JSON result, not only stderr.
- **`vault doctor --quarantine-staging`** moves a staging folder that can't be used (planted, or for a key the vault never had) to `quarantine/`, after verification; it never deletes.
- **Lost-race detection** (ue1.11): the divergence point is the newest of this machine's own records that the folder still has (an owner who wrote every record no longer gets a false rollback). A race needs another member's record in place of ours: if our records are simply missing and nothing replaced them, it is a rollback (hard refusal), not a race.
