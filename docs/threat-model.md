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
| Someone with write access to the synced folder (tampering, swapping files, forged join requests) | Authenticated encryption; strict parsing that rejects rather than half-reads; fingerprint confirmation before approving a member | `format`, `crypto`, `members` |
| Removed member | Key rotation on removal, re-encrypt all secrets; list keys they could have read so they can be rotated at the provider | `members`, `audit` |
| Another local user | Socket in a 0700 directory, peer UID checked; files written 0600 | `agent` |
| Leaks through output, logs, errors, temp files, shell history | Values never accepted as arguments; masked on a terminal; errors never echo input; leak tests with canaries | `cli`, `leaktest` |
| Secrets committed to this public repo | gitleaks in CI and locally; `.gitignore` blocks vault files; `vault init` refuses a path inside a git repo | CI, `cli` |
| Malicious or vulnerable dependency | Minimal dependencies; govulncheck and Dependabot; pinned CI actions | CI |
| Tampered release binary | Checksums, SBOM and build provenance on releases | release pipeline (9vt) |

## Open questions for the review

- Memory hygiene in Go: how far can we go in zeroing keys and keeping them out of swap and core dumps?
- Agent auto-start: how does the CLI verify it is talking to a genuine agent and not an impostor listening on the socket path?
- Sync conflicts: what happens when two members write `vault.json` at the same time?
