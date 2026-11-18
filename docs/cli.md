# CLI behaviour

How `internal/cli` turns the packages into commands. The command list and one-line help are the table in `internal/cli/cli.go` (`sv help`); this page covers what the help does not.

## Registry

`~/.config/vault/config.toml` (or `$XDG_CONFIG_HOME/vault/config.toml`; `SECRETS_VAULT_CONFIG` overrides the file, and the identity and Touch ID key files live next to it). Written atomically, mode 0600. No secrets.

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
key_id = "..."               # pinned vault key id, see below
```

## Unlock flow

1. A key held by the agent (it must match `vault.json`'s `key_id`, otherwise it is dropped).
2. Touch ID, when the vault has a Touch ID unlocker for this Mac and it works now. A cancelled sheet falls through.
3. This person's member key (identity opened with Touch ID or the personal passphrase).
4. The vault passphrase, on a terminal.
5. Otherwise exit 3: `Vault 'NAME' is locked. Run: <short name> unlock NAME`. The macOS password dialog for agents is Phase 2: `app.dialogPassphrase` is the hook.

A successful unlock is handed to the agent with the vault's TTL. `init` does the same with the new key, so the first `set` needs no passphrase; if the agent can't be reached, `init` still creates the vault, prints `The vault is locked: the unlock agent could not be reached. Run: <short name> unlock NAME` and exits 0 (`--json` adds `"unlocked": true|false`).

## Agent errors

The socket path must fit in 100 bytes (macOS limit is 104). When `~/Library/Caches/secrets-vault` would be too long, `DefaultDir` falls back to `<temp dir>/secrets-vault-<uid>` (0700, owner-checked). An explicit `SECRETS_VAULT_AGENT_DIR` is never replaced: if it is too long or not private, `unlock` shows the real reason (`the unlock agent cannot start: agent: socket path too long (N bytes, max M). Set SECRETS_VAULT_AGENT_DIR to a short folder that only you can use`). "the unlock agent is not available on this system" is only for platforms with no agent (Windows).

## Non-interactive use

- `--passphrase-stdin` (any command): each passphrase prompt reads one line of stdin instead of the terminal, without a repeat prompt. Used by scripts and tests. A value piped to `set` comes after any passphrase lines.
- `set` reads the value from the hidden prompt or from stdin, never from arguments.
- `rm` and `member rm` need `--yes` without a terminal. `member approve` needs a terminal, or `--fingerprint FP` after checking the fingerprint with the person.
- `get` prints the plain value when stdout is not a terminal and a masked placeholder on a terminal unless `--reveal`.

## Key pinning

The registry remembers each vault's `key_id`. If `vault.json` shows a different one outside a rotation this Mac ran (for example someone with write access to the folder swapped it, or a member was removed elsewhere), unlock is refused until the user runs `unlock VAULT --accept-key-change`.

## Testing

`cli.Run` runs in-process. Tests inject a fake terminal, a software "Secure Enclave" and a fake clipboard through `testHook`; the test binary re-executes itself as the agent (`TestMain`), so the agent path is the real one. No test needs a finger.

## Hardening notes

- **Clock:** the agent expires keys on the wall clock, so time the Mac spends asleep counts against the unlock window. If the wall clock moves back by more than 3 minutes, the agent locks everything.
- **Agent environment:** an auto-started agent gets only `HOME`, `PATH`, `TMPDIR`, `LANG` and `SECRETS_VAULT_*`, never the environment of the command that started it (so a value injected by `vault run` cannot linger in the agent).
- **Clipboard:** `copy` uses `/usr/bin/pbcopy` and `/usr/bin/pbpaste` (never PATH), sends the value on stdin, and clears the clipboard after 30 seconds only if it still holds that value. Linux and Windows print "not supported yet".
- **Aliases:** `alias add NAME --force` never deletes anything. It refuses if a file other than a link to this program is at that path, and names the file.
