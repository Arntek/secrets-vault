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
```

`registry.toml` (written only by this build) holds `[vaults.NAME] id = "...", path = "..."`: the vault ID registered for each name and folder. See Trust.

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
- Exit code 5 means the vault failed verification (tampered, substituted, rolled back, behind a state code, or this machine lost its record of it). `get`, `info`, `rm` and the rest never report such a vault as "key not found" (4); `list --json` and `search --json` add it as `{"vault": "...", "error": "..."}`.
- A command that pins a vault for the first time adds `"state_code_checked": true|false` and `"first_pin": {vault, state, signed_by, members}` to its `--json` output (and says so on stderr).

## Terminal UI (`vault ui`)

A full-screen interface that runs inside the vault process: no web server, no open port, nothing a browser extension or another program could reach (design decision D9). It needs a terminal on stdin and stdout (otherwise exit 1) and has no `--json`.

```
 vault ─ 2 vaults · 5 keys                       personal 🔓 3h41m   ebcfo 🔒
 ┌─ Vaults ───────┐ ┌─ Keys ──────────────────────────────────────────────┐
 │ ▸ All          │ │ / search                                            │
 │   personal  🔓 │ │ ▸ XERO_CLIENT_ID      ebcfo   Xero app "EBCFO ..."  │
 │   ebcfo     🔒 │ │   XERO_CLIENT_SECRET  ebcfo   Xero app "EBCFO ..."  │
 └────────────────┘ └─────────────────────────────────────────────────────┘
 ┌─ XERO_CLIENT_ID ────────────────────────────────────────────────────────┐
 │ Value     ••••••••••••••••   (space: reveal 10s · c: copy, clears in 30s)│
 └─────────────────────────────────────────────────────────────────────────┘
```

Keys: `↑/↓` or `j/k` move, `g`/`G` first/last, `Tab` or `←/→` switch between the Vaults and Keys panes, `/` search (names, descriptions, tags, vault; Enter keeps the filter, Esc clears it), `a` add, `e` edit value, `d` describe, `t` tag (edit the comma list), `m` move, `r` rename, `x` delete (asks `y`), `u` unlock, `l` lock (`L` locks every vault), `c` copy (clears after 30 seconds), space reveal, `R` re-read the vaults, `q` or Ctrl-C quit. Hints are always shown at the bottom.

- **Same operations as the commands.** Every action calls the function the matching command calls (`setKey`, `describeKey`, `tagKey`, `moveKey`, `renameKey`, `deleteKey`, `unlockVault`, `lockVault`, `copyValue`, `revealValue` in `internal/cli`), so the index, audit hook, membership verification, trust pins, write guard and exit-code rules are identical. The audit hook for a value read is `revealValue` (one call site for `get`, `copy` and the UI).
- **Masked by default.** A value shows only after space, hides after 10 seconds, on any selection, focus, search or vault change, on lock, and on exit. It is never written to scrollback: the UI uses the alternate screen and blanks it on exit, including Ctrl-C and a crash. Text from a vault (names, descriptions, values) is shown with control characters and bidirectional overrides replaced, so an entry cannot send escape sequences to the terminal. Typed values and passphrases are shown as bullets.
- **Locked vaults list their keys** from the index. Opening a value (or `u`, or any write) runs the normal unlock flow: Touch ID, then the personal passphrase, then the vault passphrase, asked inside the UI. Esc cancels the whole operation.
- **A vault that fails verification** (exit code 5: changed outside secrets-vault, replaced, rolled back, behind a state code) shows its error in the Keys list and detail pane instead of keys.
- Works at 80x24 and resizes; below about 48 columns the Vaults pane is hidden. `NO_COLOR` turns colour off (the selected row, focus and errors are marked with glyphs and text, not colour alone).

## Trust

Design: [design/membership-auth.md](design/membership-auth.md). In short:

- The vault ID recorded at `init`/`attach` is kept in `registry.toml` next to `config.toml` (name, ID, path), not in `config.toml`: builds from before the membership log rewrite `config.toml` and would drop it (ue1.8). A `vault.json` with another ID is refused ("this folder now holds a different vault"). An entry with no registered ID, for a folder this machine already has a trust pin for, is refused too ("lost its record"); `detach` + `attach` fixes it.
- `trust/<vault id>.json` is this machine's pin: the last membership-log head it verified, plus the records it wrote itself that nobody has extended yet. A folder that extends the pin is accepted silently; one that is older or different is refused with no override flag (`vault trust VAULT --accept-rollback` is the deliberate way, with a typed fingerprint). A change of this machine's that lost a race with another member's is re-applied on the next write, or by `vault trust VAULT`.
- First use: a member added by someone else types that person's fingerprint; the owner's own second machine is shown the head and asked for the state code from another machine (Enter skips). A passphrase-only user pins on the first successful unlock.
- `pending/` holds the new keys of this machine's unconfirmed rotations, encrypted to its own identity, so a lost race can be repaired. They are deleted when confirmed, on `detach` and on `--accept-rollback`.
- `unlock --accept-key-change` no longer exists: key changes are signed, so they are verified or refused.
- A state code (`--expect`) the folder doesn't meet is saved in the pin: every command refuses the vault (exit 5, "behind the state code you were given") until the folder reaches it, or the person runs `vault trust VAULT --accept-rollback` (ue1.9).
- `vault doctor VAULT` reports sync-conflict copies and key-rotation staging folders. With `--quarantine-staging` it finishes a verified interrupted rotation if every staged file opens under the key, and moves any other staging folder to `quarantine/` in the vault folder (never deletes). Writes blocked by such a folder say so.

## Testing

`cli.Run` runs in-process. Tests inject a fake terminal, a software "Secure Enclave" and a fake clipboard through `testHook`; the test binary re-executes itself as the agent (`TestMain`), so the agent path is the real one. No test needs a finger.

## Hardening notes

- **Clock:** the agent expires keys on the wall clock, so time the Mac spends asleep counts against the unlock window. If the wall clock moves back by more than 3 minutes, the agent locks everything.
- **Agent environment:** an auto-started agent gets only `HOME`, `PATH`, `TMPDIR`, `LANG` and `SECRETS_VAULT_*`, never the environment of the command that started it (so a value injected by `vault run` cannot linger in the agent).
- **Clipboard:** `copy` uses `/usr/bin/pbcopy` and `/usr/bin/pbpaste` (never PATH), sends the value on stdin, and clears the clipboard after 30 seconds only if it still holds that value. Linux and Windows print "not supported yet".
- **Aliases:** `alias add NAME --force` never deletes anything. It refuses if a file other than a link to this program is at that path, and names the file.
