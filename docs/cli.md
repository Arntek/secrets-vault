# CLI behaviour

How `internal/cli` turns the packages into commands. The command list and one-line help are the table in `internal/cli/cli.go` (`sv help`); this page covers what the help does not.

## Registry

`~/.config/vault/config.toml` (or `$XDG_CONFIG_HOME/vault/config.toml`; `SECRETS_VAULT_CONFIG` overrides the file, and the identity, Touch ID key, `trust/` pins and `pending/` rotation keys live next to it). Written atomically, mode 0600. No secrets.

```toml
default_ttl = "4h"
default_vault = "personal"
touch_every_read = false     # ask for Touch ID on every read
dialog = true                # native password dialog for agents (macOS; default true)
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
4. No terminal (stdin is not a TTY and no `--passphrase-stdin`), on macOS, and the dialog is on: a native password dialog (`dialog.go`) names the vault and the calling program (the parent process: name and pid) and asks for the vault passphrase. Wrong passphrase: asked again, up to 3 times. Never shown when stdin is a terminal or `--passphrase-stdin` is given, and never off macOS.
5. Otherwise (cancelled, timed out after 120 s, no GUI session such as SSH, `--no-dialog`, or `dialog = false`) exit 3: `Vault 'NAME' is locked. Run: <short name> unlock NAME`.

The dialog is `/usr/bin/osascript` with a constant AppleScript (`display dialog ... with hidden answer`). The message, which holds the vault and program names, is passed as an argument after `--`, never spliced into the script, so no name can inject AppleScript. The passphrase is read from osascript's stdout into memory, cleared after use, and never logged. `dialog` is set per vault (`--vault`) or globally; a vault's own setting wins; `true`/`false` (older `"auto"`/`"off"` are still read). The program name is informative, not proof: any program can pick its own name.

## Read log (`vault log`)

`internal/audit` writes one JSON line per event to `audit.log` in the config folder (`~/.config/vault/audit.log`; mode 0600, folder 0700), rotated at 5 MB to `audit.log.1` and `.2` (three files kept). Fields: `time`, `vault`, `key`, `action`, `program`, `pid`, `command`, plus `member` (member changes) and `via` (`dialog` when the dialog unlocked the vault). There is no field for a value or a passphrase.

Recorded: every read of a value (`get`, each key of `run`, `copy`; the terminal UI's reveal uses the same `app.record`), `set`, `rename`, `mv`, `rm`, `unlock`, `lock`, `passwd`, and members added or removed (`member-add`, `member-remove`). A failure to write the log never blocks the command: it prints one warning (`could not write the read log`) and carries on.

`vault log` flags: `--vault V`, `--since 90m|24h|7d`, `--name KEY`, `--json` (an array of events, oldest first). It reads the live file and the rotated ones; lines that don't parse are skipped.

A successful unlock is handed to the agent with the vault's TTL. `init` does the same with the new key, so the first `set` needs no passphrase; if the agent can't be reached, `init` still creates the vault, prints `The vault is locked: the unlock agent could not be reached. Run: <short name> unlock NAME` and exits 0 (`--json` adds `"unlocked": true|false`).

Before a write, the CLI also re-applies a change of this machine's that lost a race (if any), finishes an interrupted rotation (only for a verified rotation, and only if every staged file opens under the key), and runs the write guard (refuses if any secret is sealed under a key the vault's history doesn't know). Read-only commands never write to the vault folder.

## Agent errors

The socket path must fit in 100 bytes (macOS limit is 104). When `~/Library/Caches/secrets-vault` would be too long, `DefaultDir` falls back to `<temp dir>/secrets-vault-<uid>` (0700, owner-checked). An explicit `SECRETS_VAULT_AGENT_DIR` is never replaced: if it is too long or not private, `unlock` shows the real reason (`the unlock agent cannot start: agent: socket path too long (N bytes, max M). Set SECRETS_VAULT_AGENT_DIR to a short folder that only you can use`). "the unlock agent is not available on this system" is only for platforms with no agent (Windows).

## AI agent setup

- `prime [--json]` prints the six agent rules (with exit code 5 as "stop and tell the human"), the exit codes, and each registered vault with its lock state and time left. It uses the command name it was run as. It reads no secret, never prompts and never starts the unlock agent, so it works with every vault locked. `--json` gives `{command, intro, rules[], exit_codes{}, vaults[{name, description, state, seconds_left, time_left}], note}`; `state` is `locked`, `unlocked` or `unavailable`.
- `setup claude` writes `<claude dir>/skills/vault/SKILL.md` (frontmatter `name`, `description`; the body says to run `<name> prime` and follow it). `<claude dir>` is `$CLAUDE_CONFIG_DIR`, else `~/.claude`. `--claude-md` also appends a block to `<claude dir>/CLAUDE.md`. `setup agents [--path DIR]` does the block in `DIR/AGENTS.md` (default: the current folder). The skill and block name the command as run (`sv`, `vault` or `secrets-vault`).
- Additive only (D8): the skill file is recognised as ours by a `<!-- secrets-vault:sha256 ... -->` line at its end (a checksum of what precedes it), and the block by `<!-- secrets-vault:start -->` / `<!-- secrets-vault:end -->` plus a checksum line inside. Nothing else is read for meaning, changed or deleted. Re-running updates in place (`unchanged` if identical). A skill file or block that is not ours, or was edited by hand, is refused (exit 1, with the reason) unless `--force`. A file with unbalanced or repeated markers is refused. Symlinked targets (or a symlinked `skills/vault` folder) are refused. Writes go to a temporary file in the same folder, then rename, keeping the original permissions; new files are 0644.
- `--remove` deletes the skill file (and its folder if then empty) only if it is ours and unedited (any version); with `--claude-md` it also removes the CLAUDE.md block. For `setup agents`, it removes the block. The block comes out with the blank line added before it, so the file is byte-identical to before; a file that is then empty is deleted (we may have created it). `--dry-run` prints the diff and writes nothing (`--json` adds `dry_run` and `results[{path, action, diff}]`).
- These are rules an agent follows, not enforcement.

## Non-interactive use

- `--passphrase-stdin` (any command): each passphrase prompt reads one line of stdin instead of the terminal, without a repeat prompt. Used by scripts and tests. A value piped to `set` comes after any passphrase lines.
- `set` reads the value from the hidden prompt or from stdin, never from arguments.
- `rm` needs `--yes` without a terminal; `member rm` needs `--yes` and `--folder-access-removed`, plus `--keep-passphrase`, `--new-passphrase` or `--new-passphrase-stdin` to choose what happens to the vault passphrase (default: dropped).
- `member approve` needs a terminal (the approver types the requester's fingerprint), or `--fingerprint FP`. A member's first use of a vault someone else added them to needs a terminal or `--signer-fingerprint FP`. `--expect CODE` (any command) checks the vault against a state code.
- `get` prints the plain value when stdout is not a terminal and a masked placeholder on a terminal unless `--reveal`.
- Exit code 5 means the vault failed verification (tampered, substituted, rolled back, behind a state code, a `vault.json` that is damaged or doesn't parse, or this machine lost its record of it), or a key failed its check against the authenticated index (rolled back, missing file, index damaged). `get`, `info`, `rm` and the rest never report such a vault as "key not found" (4), and the index-only commands (`info`, `list`, `search`) honour an unmet `--expect` too; `list --json` and `search --json` add it as `{"vault": "...", "error": "..."}`.
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
- **Index state is shown, not hidden.** A locked vault's keys come from the local verified snapshot (see "The authenticated index and the local snapshot"). A locked vault the Mac has not verified shows `unverified` in the header, and `changed` when the folder has changed since; an entry only the folder vouches for is marked `? ` (never verified here) or `~ ` (the folder changed it), and the detail pane has an Index line saying so. Unlocking clears the marks. Describe and tag change a sealed index entry, so on a locked vault they ask to unlock first, like every other write.
- **Reads are logged.** Reveal and copy go through the same `revealValue`/`copyValue` as `get` and `copy`, so each is a `vault log` read event.
- **A vault that fails verification** (exit code 5: changed outside secrets-vault, replaced, rolled back, behind a state code, a missing or damaged index) shows its error in the Keys list and detail pane instead of keys.
- Works at 80x24 and resizes; below about 48 columns the Vaults pane is hidden. `NO_COLOR` turns colour off (the selected row, focus and errors are marked with glyphs and text, not colour alone).

## Trust

Design: [design/membership-auth.md](design/membership-auth.md). In short:

- The vault ID recorded at `init`/`attach` is kept in `registry.toml` next to `config.toml` (name, ID, path), not in `config.toml`: builds from before the membership log rewrite `config.toml` and would drop it (ue1.8). A `vault.json` with another ID is refused ("this folder now holds a different vault"). An entry with no registered ID, for a folder this machine already has a trust pin for, is refused too ("lost its record"); `detach` + `attach` fixes it.
- `trust/<vault id>.json` is this machine's pin: the last membership-log head it verified, plus the records it wrote itself that nobody has extended yet. A folder that extends the pin is accepted silently; one that is older or different is refused with no override flag (`vault trust VAULT --accept-rollback` is the deliberate way, with a typed fingerprint). A change of this machine's that lost a race with another member's is re-applied on the next write, or by `vault trust VAULT`.
- First use: a member added by someone else types that person's fingerprint; the owner's own second machine is shown the head and asked for the state code from another machine (Enter skips). A passphrase-only user pins on the first successful unlock.
- `pending/` holds the new keys of this machine's unconfirmed rotations, encrypted to its own identity, so a lost race can be repaired. They are deleted when confirmed, on `detach` and on `--accept-rollback`.
- `unlock --accept-key-change` no longer exists: key changes are signed, so they are verified or refused.
- A state code (`--expect`) the folder doesn't meet is saved in the pin: every command refuses the vault (exit 5, "behind the state code you were given") until the folder reaches it, or the person runs `vault trust VAULT --accept-rollback` (ue1.9).
- `vault doctor VAULT [--quarantine-staging] [--adopt NAME]` reports sync-conflict copies, key-rotation staging folders and, if the vault is unlocked, index problems (below). A staging folder under the current key whose files don't open is reported as one that **cannot be finished**, with the way out. With `--quarantine-staging` it finishes a verified interrupted rotation if every staged file opens under the key, and moves any other staging folder to `quarantine/` in the vault folder (never deletes). Writes blocked by such a folder say so. A conflict copy of `index.json` whose entries are all in the index already is called "safe to delete".

## The authenticated index and the local snapshot

Design: [design/index-auth.md](design/index-auth.md). Format 3 vaults carry a MAC on every index entry and a version in every secret file.

- **Locked** (`list`, `search`, `info`, name resolution): nothing can be verified without the vault key, and these commands never prompt. They show what this machine **last verified** (the snapshot in `index/<vault id>.json` next to `trust/`) and flag the rest: `--json` rows have `verified` (false for a name only the folder claims), `pending_change` (the folder holds a different entry than the verified one shown, whose values are shown), and `index_state` (`verified`, `pending-changes`, `unverified`, `private`, `legacy`). A note on stderr says so once per vault. Every command that holds the key (`unlock`, `get`, `set`, `run`, ...) verifies the index and refreshes the snapshot, so `unlock` is how a vault becomes verified on this Mac.
- **Name resolution** (a name in several vaults): verified entries beat unverified ones; ambiguity is declared (exit 2) only among entries of the same class, and never causes an unlock prompt for a vault you didn't name.
- **Reading a key** checks its file against the verified entry. Exit 5 (never "not found") when the file is older than the entry or the snapshot (rolled back, or not synced yet), when a listed key's file is missing, when the entry is older than what this Mac verified, or when the index is missing or damaged and the snapshot doesn't vouch for the key. A file newer than its entry is readable (the index lags) with a warning. Names the index doesn't list are not keys; `doctor` reports their files and `doctor VAULT --adopt NAME` gives one a signed entry after you confirm.
- **Writing** (`set`, `describe`, `tag`, `rm`, `rename`, `mv`) unlocks the vault (entries are sealed with the vault key, so `describe` and `tag` no longer work locked), then merges your change entry by entry with a compare-and-swap, so changes from other machines are kept. If someone changed the same key at the same moment you are told. `rm` leaves a signed tombstone until the next key rotation.
- **`vault upgrade VAULT [--yes]`** moves a vault made by an earlier version (format 2) to format 3: files are stamped with versions, the index is sealed (its labels taken as they are, once), and a signed record makes the format part of the vault's history. Any member can run it; a personal vault needs only your identity unlock. Until then reads work (with a notice) and every write exits 1 with `Run: vault upgrade NAME`. Every member must upgrade their secrets-vault first: older builds refuse the upgraded vault. `trust --accept-rollback` and `detach` forget the snapshot.

## Testing

`cli.Run` runs in-process. Tests inject a fake terminal, a software "Secure Enclave" and a fake clipboard through `testHook`; the test binary re-executes itself as the agent (`TestMain`), so the agent path is the real one. No test needs a finger.

## Hardening notes

- **Clock:** the agent expires keys on the wall clock, so time the Mac spends asleep counts against the unlock window. If the wall clock moves back by more than 3 minutes, the agent locks everything.
- **Agent environment:** an auto-started agent gets only `HOME`, `PATH`, `TMPDIR`, `LANG` and `SECRETS_VAULT_*`, never the environment of the command that started it (so a value injected by `vault run` cannot linger in the agent).
- **Clipboard:** `copy` uses `/usr/bin/pbcopy` and `/usr/bin/pbpaste` (never PATH), sends the value on stdin, and clears the clipboard after 30 seconds only if it still holds that value. Linux and Windows print "not supported yet".
- **Aliases:** `alias add NAME --force` never deletes anything. It refuses if a file other than a link to this program is at that path, and names the file.
