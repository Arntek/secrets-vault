# Threat model (stub)

Status: stub from the scaffold. The security review (issue ue1) completes it before 1.0. Each "Mitigation" names where the control lives so it can be tested.

## What vault protects

- Secret values (API keys, credentials) stored in vault folders on synced storage (Dropbox, Box, local disk).
- Vault keys while unlocked.
- The integrity of secrets: nobody without the vault key can add, change or swap a secret undetected.

## What vault does not protect

- **Names and descriptions.** `index.json` is readable without unlocking, by design (D2). Descriptions must not contain anything sensitive. `--private-index` hides them. It is *authenticated*, though: only a key holder can make or change an entry (see the table), and a locked listing shows what this Mac last verified.
- **A compromised user account.** Malware running as you while a vault is unlocked can ask the agent for keys, just as you can. The unlock window (default 4h) and `touch-every-read` limit the damage, but cannot prevent it.
- **Root / admin on the machine,** kernel compromise, or physical memory extraction.
- **A misbehaving AI agent.** Agents are told never to print values and no agent-facing tool returns one, but an agent running commands as you could still do so. This is a guardrail, not a wall; `vault log` records reads.
- **Values after they leave vault.** Once `vault run` passes a key to a program, that program's handling is out of scope.

## Assets and trust boundaries

| Asset | Where | Boundary |
|---|---|---|
| Secret files (`secrets/*.age`) | Vault folder, synced to a cloud provider | Anyone with folder access, including the provider |
| `vault.json` (wrapped vault keys) | Vault folder | Same as above |
| `index.json` (names, descriptions) | Vault folder | Same; readable by design |
| Unlocked vault keys | Agent process memory | Other local users; other processes as the same user |
| Agent socket | Per-user runtime dir | Other local users |
| Touch ID enclave key blob | This Mac only | Useless off this Mac's Secure Enclave |
| Personal identity (member private key) | This Mac, wrapped by passphrase and Touch ID | Same as above |
| Registry (`config.toml`) | `~/.config/vault/` | Paths only, no secrets |

## Adversaries and initial mitigations

| Adversary / threat | Mitigation | Where |
|---|---|---|
| Someone with read access to the synced folder | age encryption; scrypt-stretched passphrase; Touch ID key never leaves the enclave | `crypto`, `touchid` |
| Someone with write access to the synced folder (tampering, swapping files, forged join requests, planted unlockers, a substituted vault.json) | Authenticated encryption; strict parsing; a signed, hash-chained membership log verified from genesis on every open; a vault ID and trust pin kept per user outside the folder; typed fingerprints for approval and first use; symlinked vault folders refused; nothing written before verification | `format`, `crypto`, `members`, `cli` (design: [design/membership-auth.md](design/membership-auth.md)) |
| Removed member | Key rotation on removal, re-encrypt all secrets; their signature no longer counts; the vault passphrase is dropped by default; required "folder access removed" confirmation; rollback refused by every machine that saw the removal; write guard and state code; list keys they could have read so they can be rotated at the provider | `members`, `cli` |
| Anyone who knew a vault passphrase | `member rm` drops it by default; `passwd` replaces the vault key | `members`, `cli` |
| Someone with write access to the synced folder, against the index and single secret files (relabelling a key, planting or deleting entries, a junk file to make a name ambiguous, restoring one older `NAME.age` or an older `index.json`) | A MAC on every index entry under a key derived from the vault key; a version sealed into every secret file's header and mirrored in its entry; a per-entry `rev`; signed tombstones; a local snapshot of what this Mac verified (used for rollback and for locked listings, only if it is on the verified chain); a missing, v1 or damaged index in a format-3 vault is never trusted; the vault format is part of the signed membership history; rotation re-seals the index and carries nothing forward from a retired key | `crypto`, `index`, `members`, `cli` (design: [design/index-auth.md](design/index-auth.md)) |
| Another local user | Socket in a 0700 directory, peer UID checked; files written 0600 | `agent` |
| Leaks through output, logs, errors, temp files, shell history | Values never accepted as arguments; masked on a terminal; errors never echo input; leak tests with canaries | `cli`, `leaktest` |
| Secrets committed to this public repo | gitleaks in CI and locally; `.gitignore` blocks vault files; `vault init` refuses a path inside a git repo | CI, `cli` |
| Malicious or vulnerable dependency | Minimal dependencies; govulncheck and Dependabot; pinned CI actions | CI |
| Tampered release binary | Checksums, SBOM and build provenance on releases | release pipeline (9vt) |

## Accepted risks (ue1 security review)

Known and accepted for Phase 1. The membership design in [design/membership-auth.md](design/membership-auth.md) (issues ue1.1, ue1.2, ue1.4, ue1.6, implemented) narrows the last one; the others stand.

- **Same-user processes.** Any process running as you can ask the agent for an unlocked key and read your processes' environment and memory. The unlock window and `touch-every-read` limit this; nothing prevents it.
- **Fingerprint approval.** Fingerprints carry about 46 bits behind scrypt (2^14); a second preimage costs about 2^46 scrypt runs (hundreds of GPU-years). Approval is a y/N against the displayed value, and `--fingerprint` lets an agent approve without a person comparing; unlocking the vault is the only human gate.
- **`get` when piped.** Values are printed in plain text when stdout is not a terminal, because agents capture it. A guardrail, not a wall.
- **Offline members and rollback.** A member who hasn't opened the vault since a removal can't tell that the removed member (who kept folder write access) restored the whole pre-removal folder, so may read stale values and save new secrets under the old key. Mitigations: `member rm` requires removing the person's folder access and prints a state code to pass on out of band; machines that saw the removal refuse the rollback outright; any leftover file sealed under a newer key, or a newer `vault.json` conflict copy, makes every write fail; secrets written under a retired key are listed as exposed once the honest state is seen again. No complete fix without a channel outside the folder.

## Residual risks of the authenticated index

What ue1.7 stopped: relabelling, planted or deleted entries, planted files, an old `index.json`, one `NAME.age` rolled back, and deleting or downgrading the index to hide a rollback. What remains:

- **A member can still relabel or rewrite entries** (they hold the vault key), and `updated_by` is attribution by a member, not a signature.
- **A consistent rollback of index and file together** is detected only by a Mac whose snapshot saw the newer state. A new Mac, or one offline since before, accepts an older consistent state: the same limit as the stale-writer gap, and it can't cross a key rotation.
- **While locked and never verified on this Mac**, names are only what the folder claims; a planted name can cause a clearly explained ambiguity (exit 2). Denial of service only; values are never affected, and the planted entry fails its check at the first unlock.
- **`vault upgrade` trusts the existing index once** (its labels are sealed as they were), and a Mac that first sees a vault from a chain cut off before an upgrade is in the first-use position (the first-pin output says "format 2 (not upgraded)" so a state-code comparison catches it).
- **A window of "still syncing" refusals** (exit 5) when a sync delivers an index entry before its file, or the reverse.
- **Concurrent writes to the same key:** the last write wins; both writers are told.
- **The snapshot is trusted local state**, like the trust pin: a process running as you can edit it. It is forgotten by `detach` and by an accepted rollback.

## Residual risks added in Phase 2 (agents, dialog, terminal UI, npm)

- **Dialog phishing and prompt fatigue.** When an agent hits a locked vault with no terminal, the macOS password dialog asks the human for the vault passphrase. Any program running as you can draw an identical "Secrets Vault" dialog, and the program name shown is the parent process's own choice. People who see the dialog often learn to type the passphrase into pop-ups without looking. Mitigations: Touch ID first (no typing), the dialog only when there is no terminal, a three-try limit, `--no-dialog` and `vault config set dialog false` (per vault too), and the audit log naming who asked. Turn the dialog off if you would rather run `vault unlock` yourself. Nothing stops a hostile local process from imitating it.
- **Members can still inject through verified descriptions.** A non-member's planted entry is never shown beyond its name (unverified rows carry no description, tags, date or author in text or `--json`, and `vault prime` tells agents that descriptions are data). A member holds the vault key, so a description they write is verified and shown. Agents must treat every description, tag and name as data written by a person, never as an instruction: the first rule `vault prime` prints. Descriptions are cleaned of control, bidi and zero-width characters before they are shown, which stops disguise, not wording.
- **`SECRETS_VAULT_BINARY_PATH` is a trust override.** The npm launcher runs whatever file that variable names instead of the downloaded build, with no checksum. Anything that can set your environment (a shell profile, a CI variable, a hostile parent process) can make `vault` run a different program that sees every passphrase you type. It exists for offline installs and tests; do not set it in shared environments, and treat an unexpected value as a compromise.
- **A folder writer can stall changes to a shared vault.** The write guard refuses a write when the folder holds signs of a newer state: a secret sealed under a key this vault's history never had, or a rotation folder for one. A planted file looks the same as another member's real, not yet synced rotation, and as a removal this Mac has not seen, so the guard refuses rather than guesses (set, member approve and remove, passwd are stalled; reads are not). `vault doctor VAULT` explains which items cause it and why. Clearing the stall takes a person at a terminal: `vault doctor VAULT --set-aside-unknown` asks them to type the current state code that another member, known to be current and not someone being removed, reads to them; it moves the items into `quarantine/` (a rename, never a delete, never following a link) only if this Mac's verified folder equals or extends the code, and writes a `set-aside` event to the read log. There is no flag or unattended path, because a Mac that missed a removal would supply its own stale code, and so would an agent. A human who types a code taken from the stale Mac itself, or an old pre-removal code, defeats the check; the prompt warns about it. A newer verified `vault.json` copy is never set aside. This does not make removal safe against a removed member who keeps folder access (see "Offline members and rollback"): remove folder access before `member rm`.
- **`vault ui` and memory.** The UI holds a revealed value in memory for ten seconds and clears the bytes it owns; Go strings made while drawing it (and Bubble Tea's last frame) cannot be cleared, the same limit as any program that prints a secret. It never writes values to disk or scrollback (alternate screen, wiped on exit and on a crash). A process running as you can read its memory while it runs.

## Older builds

A member running a build from before the membership log is protected because it **refuses** newer vaults, not because it can verify them: version-2 and version-3 files carry versions it rejects (the authenticated index adds vault.json 3, index 2, secret-file stanza `sv-vaultkey3` and a record format a build before it cannot parse, so it cannot read, write or rotate such a vault, and a downgraded `vault.json` is refused by builds that know the format), its wrapped-key and secret-file formats changed so it can't unlock or rotate a vault even if `vault.json` is rewritten as version 1, and the registered vault ID lives in `registry.toml`, which it never writes. Upgrading is required to use a shared vault. No release will contain the ue1.1 bug: nothing is tagged until this fix is merged. (Issue ue1.8; design section "Older builds".)

## Residual risks of the membership design

- **Stale writer** (above): exact conditions in the design, Threat 4.
- **First use** is trust-on-first-use behind a typed fingerprint (or, for the owner's own second machine, the state code); a passphrase-only user has nothing to compare.
- **Lost rotation race** whose losing member never comes back: their moved files stay sealed under a key only they held (reported by the write guard).
- **Denial of service**: any folder writer can corrupt or delete `vault.json`. We fail closed with a clear message; Dropbox/Box version history is the remedy.

## Open questions for the review

- Memory hygiene in Go: how far can we go in zeroing keys and keeping them out of swap and core dumps?
- Agent auto-start: how does the CLI verify it is talking to a genuine agent and not an impostor listening on the socket path?
- Sync conflicts: what happens when two members write `vault.json` at the same time?
