# Threat model (stub)

Status: stub from the scaffold. The security review (issue ue1) completes it before 1.0. Each "Mitigation" names where the control lives so it can be tested.

## What vault protects

- Secret values (API keys, credentials) stored in vault folders on synced storage (Dropbox, Box, local disk).
- Vault keys while unlocked.
- The integrity of secrets: nobody without the vault key can add, change or swap a secret undetected.

## What vault does not protect

- **Names and descriptions.** `index.json` is readable without unlocking, by design (D2). Descriptions must not contain anything sensitive. `--private-index` hides them.
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
| Another local user | Socket in a 0700 directory, peer UID checked; files written 0600 | `agent` |
| Leaks through output, logs, errors, temp files, shell history | Values never accepted as arguments; masked on a terminal; errors never echo input; leak tests with canaries | `cli`, `leaktest` |
| Secrets committed to this public repo | gitleaks in CI and locally; `.gitignore` blocks vault files; `vault init` refuses a path inside a git repo | CI, `cli` |
| Malicious or vulnerable dependency | Minimal dependencies; govulncheck and Dependabot; pinned CI actions | CI |
| Tampered release binary | Checksums, SBOM and build provenance on releases | release pipeline (9vt) |

## Accepted risks (ue1 security review)

Known and accepted for Phase 1. The membership design in [design/membership-auth.md](design/membership-auth.md) (issues ue1.1, ue1.2, ue1.4, ue1.6, implemented) narrows the last one; the others stand.

- **Same-user processes.** Any process running as you can ask the agent for an unlocked key and read your processes' environment and memory. The unlock window and `touch-every-read` limit this; nothing prevents it.
- **Unauthenticated index.** Names, descriptions and tags in `index.json` can be edited by any folder writer: relabelling a key so an agent picks the wrong one, or planting a junk `NAME.age` so a name is ambiguous across vaults (exit 2, a denial of service only). Values are never affected. Tracked as a separate issue.
- **Fingerprint approval.** Fingerprints carry about 46 bits behind scrypt (2^14); a second preimage costs about 2^46 scrypt runs (hundreds of GPU-years). Approval is a y/N against the displayed value, and `--fingerprint` lets an agent approve without a person comparing; unlocking the vault is the only human gate.
- **`get` when piped.** Values are printed in plain text when stdout is not a terminal, because agents capture it. A guardrail, not a wall.
- **Single-file rollback.** A folder writer can replace one `secrets/NAME.age` with an older copy sealed under the current key. A rotation re-encrypts everything, so this never crosses a member removal. Tracked with the index issue.
- **Offline members and rollback.** A member who hasn't opened the vault since a removal can't tell that the removed member (who kept folder write access) restored the whole pre-removal folder, so may read stale values and save new secrets under the old key. Mitigations: `member rm` requires removing the person's folder access and prints a state code to pass on out of band; machines that saw the removal refuse the rollback outright; any leftover file sealed under a newer key, or a newer `vault.json` conflict copy, makes every write fail; secrets written under a retired key are listed as exposed once the honest state is seen again. No complete fix without a channel outside the folder.

## Older builds

A member running a build from before the membership log is protected because it **refuses** newer vaults, not because it can verify them: version-2 files carry versions it rejects, its wrapped-key and secret-file formats changed so it can't unlock or rotate a vault even if `vault.json` is rewritten as version 1, and the registered vault ID lives in `registry.toml`, which it never writes. Upgrading is required to use a shared vault. No release will contain the ue1.1 bug: nothing is tagged until this fix is merged. (Issue ue1.8; design section "Older builds".)

## Residual risks of the membership design

- **Stale writer** (above): exact conditions in the design, Threat 4.
- **First use** is trust-on-first-use behind a typed fingerprint (or, for the owner's own second machine, the state code); a passphrase-only user has nothing to compare.
- **Lost rotation race** whose losing member never comes back: their moved files stay sealed under a key only they held (reported by the write guard).
- **Denial of service**: any folder writer can corrupt or delete `vault.json`. We fail closed with a clear message; Dropbox/Box version history is the remedy.

## Open questions for the review

- Memory hygiene in Go: how far can we go in zeroing keys and keeping them out of swap and core dumps?
- Agent auto-start: how does the CLI verify it is talking to a genuine agent and not an impostor listening on the socket path?
- Sync conflicts: what happens when two members write `vault.json` at the same time?
