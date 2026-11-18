# CLI behaviour

How `internal/cli` turns the packages into commands. The command list and one-line help are the table in `internal/cli/cli.go` (`sv help`); this page covers what the help does not.

## Registry

`~/.config/vault/config.toml` (or `$XDG_CONFIG_HOME/vault/config.toml`; `SECRETS_VAULT_CONFIG` overrides the file, and the identity, Touch ID key, `trust/` pins and `pending/` rotation keys live next to it). Written atomically, mode 0600. No secrets.

```toml
default_ttl = "4h"
default_vault = "personal"
touch_every_read = false     # ask for Touch ID on every read
dialog = "auto"              # Phase 2: native password dialog for agents
aliases = ["sv"]             # short names added by `alias add`

[vaults.personal]
path = "/path/to/folder"
description = "..."
ttl = "8h"                   # per-vault overrides: ttl, touch_every_read, dialog
id = "..."                   # vault id recorded at init/attach, see Trust below
```

## Unlock flow

Before anything else the vault is verified (`app.open`, see Trust): nothing is read, written or unlocked from an unverified `vault.json`.

1. A key held by the agent (it must match the verified `key_id`, otherwise it is dropped).
2. This person's member key: the identity, opened with Touch ID (when this Mac's Touch ID protects it) or the personal passphrase.
3. The vault passphrase, on a terminal (or `--passphrase-stdin`).
4. Otherwise exit 3: `Vault 'NAME' is locked. Run: <short name> unlock NAME`. The macOS password dialog for agents is Phase 2: `app.dialogPassphrase` is the hook.

A successful unlock is handed to the agent with the vault's TTL. `init` does the same with the new key, so the first `set` needs no passphrase; if the agent can't be reached, `init` still creates the vault, prints `The vault is locked: the unlock agent could not be reached. Run: <short name> unlock NAME` and exits 0 (`--json` adds `"unlocked": true|false`).

Before a write, the CLI also re-applies a change of this machine's that lost a race (if any), finishes an interrupted rotation (only for a verified rotation, and only if every staged file opens under the key), and runs the write guard (refuses if any secret is sealed under a key the vault's history doesn't know). Read-only commands never write to the vault folder.

## Agent errors

The socket path must fit in 100 bytes (macOS limit is 104). When `~/Library/Caches/secrets-vault` would be too long, `DefaultDir` falls back to `<temp dir>/secrets-vault-<uid>` (0700, owner-checked). An explicit `SECRETS_VAULT_AGENT_DIR` is never replaced: if it is too long or not private, `unlock` shows the real reason (`the unlock agent cannot start: agent: socket path too long (N bytes, max M). Set SECRETS_VAULT_AGENT_DIR to a short folder that only you can use`). "the unlock agent is not available on this system" is only for platforms with no agent (Windows).

## Non-interactive use

- `--passphrase-stdin` (any command): each passphrase prompt reads one line of stdin instead of the terminal, without a repeat prompt. Used by scripts and tests. A value piped to `set` comes after any passphrase lines.
- `set` reads the value from the hidden prompt or from stdin, never from arguments.
- `rm` needs `--yes` without a terminal; `member rm` needs `--yes` and `--folder-access-removed`, plus `--keep-passphrase`, `--new-passphrase` or `--new-passphrase-stdin` to choose what happens to the vault passphrase (default: dropped).
- `member approve` needs a terminal (the approver types the requester's fingerprint), or `--fingerprint FP`. A member's first use of a vault someone else added them to needs a terminal or `--signer-fingerprint FP`. `--expect CODE` (any command) checks the vault against a state code.
- `get` prints the plain value when stdout is not a terminal and a masked placeholder on a terminal unless `--reveal`.

## Trust

Design: [design/membership-auth.md](design/membership-auth.md). In short:

- The registry entry's `id` is the vault ID recorded at `init`/`attach`. A `vault.json` with another ID is refused ("this folder now holds a different vault").
- `trust/<vault id>.json` is this machine's pin: the last membership-log head it verified, plus the records it wrote itself that nobody has extended yet. A folder that extends the pin is accepted silently; one that is older or different is refused with no override flag (`vault trust VAULT --accept-rollback` is the deliberate way, with a typed fingerprint). A change of this machine's that lost a race with another member's is re-applied on the next write, or by `vault trust VAULT`.
- First use: a member added by someone else types that person's fingerprint; the owner's own second machine is shown the head and asked for the state code from another machine (Enter skips). A passphrase-only user pins on the first successful unlock.
- `pending/` holds the new keys of this machine's unconfirmed rotations, encrypted to its own identity, so a lost race can be repaired. They are deleted when confirmed, on `detach` and on `--accept-rollback`.
- `unlock --accept-key-change` no longer exists: key changes are signed, so they are verified or refused.

## Testing

`cli.Run` runs in-process. Tests inject a fake terminal, a software "Secure Enclave" and a fake clipboard through `testHook`; the test binary re-executes itself as the agent (`TestMain`), so the agent path is the real one. No test needs a finger.
