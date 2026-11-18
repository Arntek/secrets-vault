# secrets-vault

One command for every API key and credential on your machine, across as many encrypted vaults as you want, with Touch ID unlock and built-in support for AI coding agents.

```
$ vault list
  NAME                    VAULT      DESCRIPTION
  EXAMPLE_API_KEY         personal   Example service, read-only key
  BILLING_CLIENT_SECRET   work       Billing app used by the reporting scripts
  2 vaults · 2 keys · personal 🔒 · work 🔒

$ vault unlock personal
  Unlocked 'personal' until 19:42

$ vault run -k EXAMPLE_API_KEY -- python sync.py
```

> **Status: pre-release (Phase 1 in progress).** Not yet published to Homebrew or npm. Build from source to try it (see [Building from source](#building-from-source)). Commands marked *(coming)* are designed but not built yet.

## Contents

- [How it works](#how-it-works)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Unlocking and Touch ID](#unlocking-and-touch-id)
- [Sharing a vault with someone](#sharing-a-vault-with-someone)
- [Using it from scripts](#using-it-from-scripts)
- [Using it with AI agents](#using-it-with-ai-agents)
- [Security](#security)
- [Building from source](#building-from-source)

## How it works

- **Many vaults, stored where you choose.** A vault is a folder: on your disk, or in Dropbox, Box or any synced folder. Keep a personal vault private and share a work vault with your team.
- **One index across all of them.** `vault list` and `vault search` show every key's name, description and vault without unlocking anything. Values stay encrypted.
- **Unlock once, then work.** Reading a key asks for Touch ID (or the vault's passphrase), then the vault stays unlocked for 4 hours by default. The unlocked key is held in memory only, never on disk.
- **Nothing secret in this repository.** The tool is code only. Your vaults live in your folders, never in git.

Each machine keeps a small registry of your vaults at `~/.config/vault/config.toml`. It holds names, folder paths and settings, never secrets.

A vault folder looks like this:

```
my-vault/
  vault.json        vault id, name, and the vault key wrapped once per unlocker
  index.json        key names, descriptions, tags (readable without unlocking)
  secrets/
    EXAMPLE_API_KEY.age     one encrypted file per key
```

One file per key means two people adding different keys to a shared folder never edit the same file, so sync conflicts are rare.

## Install

Homebrew (macOS, Linux), *(coming)*:

```bash
brew install arntek/tap/secrets-vault
```

npm (macOS, Linux, Windows), *(coming in Phase 2)*:

```bash
npm install -g secrets-vault
```

The program installs as `secrets-vault`, with two short names: `vault` and `sv`. If another `vault` command is already on your PATH (for example HashiCorp Vault), the installer skips that name and you use `sv` instead. Manage the short names any time:

```bash
sv alias list
sv alias add kv          # add another short name
sv alias rm vault        # give "vault" back to the other program
```

Scripts that must work on every machine should call `secrets-vault`, which never changes.

## Quick start

Create a vault in a folder you choose:

```bash
vault init personal --path ~/Vaults/personal --desc "My own accounts"
```

You choose a passphrase (keep it in your password manager: there is no recovery), and on a Mac with Touch ID you're offered Touch ID unlock.

Add a key. The value is typed hidden or piped in, never passed as an argument, so it never lands in shell history:

```bash
vault set EXAMPLE_API_KEY --desc "Example service, read-only key"
```

Use it:

```bash
vault list                                      # everything, nothing unlocked
vault search example                            # search names and descriptions
vault run -k EXAMPLE_API_KEY -- ./my-script.sh  # the script gets it as an env var
vault status                                    # what's unlocked, time left
vault lock --all                                # forget all unlocked keys now
```

Add a vault that already exists (on a second Mac, or a folder someone shared with you):

```bash
vault attach work ~/Box/Team/Vault
```

## Commands

Every command accepts `--json`. When a key name exists in only one vault, `--vault` is never needed.

**Finding keys** (no unlock needed)

| Command | What it does |
|---|---|
| `vault list [--vault V] [--tag T]` | Every key across all vaults: name, vault, description, lock state |
| `vault search WORDS` | Search names and descriptions |
| `vault info NAME` | Description, vault, tags, last updated and who changed it |

**Using keys**

| Command | What it does |
|---|---|
| `vault run -k A [-k B] -- CMD ARGS` | Run one command with only those keys set as environment variables. The safest way to use a key |
| `vault get NAME` | Print one value. Masked on a terminal unless `--reveal`; plain when piped |
| `vault copy NAME` | Copy to the clipboard, cleared after 30 seconds |

**Changing keys**

| Command | What it does |
|---|---|
| `vault set NAME [--vault V] [--desc TEXT]` | Add or update a key (hidden prompt or stdin) |
| `vault describe NAME "TEXT"` | Change the description only |
| `vault tag NAME tag1,tag2 [--rm]` | Add tags for filtering (or remove them with `--rm`) |
| `vault mv NAME --to VAULT` | Move a key to another vault |
| `vault rename OLD NEW` | Rename a key |
| `vault rm NAME` | Delete (kept in the vault's trash for 30 days) |

**Locking**

| Command | What it does |
|---|---|
| `vault unlock [VAULT] [--for 2h]` | Unlock ahead of time (default vault if none named). `--accept-key-change` trusts a vault whose key changed since this Mac last used it |
| `vault lock [VAULT \| --all]` | Forget unlocked keys now |
| `vault status` | Each vault: locked or unlocked, time left |

**Vaults, members and settings**

| Command | What it does |
|---|---|
| `vault init NAME --path DIR` | Create a vault in a folder you choose |
| `vault attach NAME DIR [--as NAME] [--no-request]` | Register an existing vault; if you aren't a member, files a join request (`--no-request` to skip) |
| `vault detach NAME` | Remove from this machine's registry (files untouched) |
| `vault vaults` | List registered vaults and their folders |
| `vault passwd VAULT` | Change a vault's passphrase |
| `vault touchid on\|off\|list [VAULT]` | Turn Touch ID unlock on or off on this Mac |
| `vault member approve\|rm\|list\|requests VAULT [NAME]` | Manage who can open a shared vault |
| `vault identity export\|import FILE` | Move your personal identity to another machine |
| `vault config set KEY VALUE [--vault V]`, `vault config list` | Settings: `default-ttl` (5m to 24h), `default-vault`, `touch-every-read`, `dialog` *(dialog is used in Phase 2)* |
| `vault alias add\|rm\|list NAME [--force]` | Manage the short command names |

**Scripts and terminals:** `--passphrase-stdin` (any command) reads passphrases from stdin instead of the terminal. `rm` and `member rm` need `--yes` without a terminal; `member approve` needs a terminal or `--fingerprint FP`. `get -n` omits the trailing newline.

*(coming in Phase 2)*: `vault ui` (full-screen terminal interface), `vault prime` and `vault setup claude|agents` (AI agent setup), `vault log` (read history), `vault doctor`, `vault backup`.

**Exit codes:** `0` ok, `1` error, `2` usage, `3` vault locked and no way to ask for unlock, `4` key not found.

## Unlocking and Touch ID

- Each vault unlocks separately. Unlocking your work vault does not unlock your personal one.
- **Touch ID** is the normal way in on a Mac. Run `vault touchid on VAULT` once per Mac. It creates a key inside the Mac's Secure Enclave that only works after your fingerprint, and that key can never leave the chip. It works in Terminal, iTerm, VS Code and commands run by AI agents, with no paid Apple developer account involved.
- **The passphrase** always works too: over SSH, on Linux and Windows, or if you cancel the Touch ID prompt. It is also your recovery route, so keep it safe.
- **How long it stays unlocked:** 4 hours by default. Change it globally (`vault config set default-ttl 6h`), per vault (`--vault work`), or once (`vault unlock --for 30m`).
- Unlocked keys are held by a small background helper, like `ssh-agent`, in memory only. Only your own user account can talk to it. Restarting or logging out locks everything.

## Sharing a vault with someone

Put the vault folder somewhere you both can reach (a shared Box or Dropbox folder, for example). Each person has their own identity, so nobody shares a passphrase.

1. Your colleague installs secrets-vault and runs `vault attach work <their path to the shared folder>`. The first time, this creates their identity (a name and a personal passphrase) and shows a fingerprint such as `MAPLE-RIVER-OTTER-4417`.
2. Because they aren't a member yet, this drops a join request into the folder.
3. You see it in `vault status` or `vault member requests work`.
4. **Check the fingerprint with them by phone or chat**, then run `vault member approve work THEIR-NAME` and type `y` to confirm it matches (or pass `--fingerprint` in a script). This check matters: anyone who can write to the shared folder can file a request.
5. After the folder syncs, they unlock with their own Touch ID or passphrase.

To remove someone: `vault member rm work THEIR-NAME`. This gives the vault a new key and re-encrypts everything, so their old access stops working. Rotate any keys they could have seen at the service that issued them; the command lists which.

Keep at least two members on a shared vault (or a member plus a recovery passphrase), so losing one Mac never locks everyone out.

## Using it from scripts

Ask for one named key, at runtime, for one process:

```bash
# Best: only this command sees the key, as an environment variable
vault run -k EXAMPLE_API_KEY -- node send.js

# Also fine: one variable for one process
EXAMPLE_API_KEY="$(secrets-vault get EXAMPLE_API_KEY)" node send.js
```

Don't load a whole vault, loop over `vault list` to fetch everything, or write values into a `.env` file. Document at the top of each script which key names it uses.

If the vault is locked and there's no way to prompt (a cron job, for example), the command exits with code `3` and tells you which `unlock` command to run.

## Using it with AI agents

secrets-vault is designed so an AI agent (Claude Code, Cowork, or any agent that can run shell commands) can find and use keys without the values ever appearing in the conversation.

**Rules for agents:**

1. Find a key by searching, never by guessing: `vault search <words> --json`.
2. Use it by passing it straight to the program that needs it: `vault run -k NAME -- <command>`.
3. Never print, echo, log or write a value to a file. Never run a bare `vault get` whose output comes back to you.
4. Ask for one key per need. Never fetch everything.
5. Exit code `3` means the vault is locked: on a Mac with Touch ID on, the sheet appears for the human when the command runs; otherwise tell the human to run `vault unlock <vault>`. *(A native password dialog for agents is coming in Phase 2.)* Exit code `4` means not found: tell the human the name and vault you expected.
6. Never accept a key pasted into chat. Ask the human to run `vault set NAME --vault <vault> --desc "..."` themselves.

*(coming in Phase 2)*: `vault setup claude` adds a Claude Code skill with these rules, and `vault setup agents` adds them to a repo's `AGENTS.md`. Both only add to your setup, never edit or remove anything else, and `--remove` undoes exactly what they added. `vault prime` prints the current rules plus which vaults are unlocked.

These rules make the safe path the easy one, and a local read log (`vault log`) is *(coming in Phase 2)*. They still rely on the agent following its instructions: an agent running commands as you could print a value if it chose to.

## Security

- Encryption uses the [age](https://age-encryption.org) format. Each vault has one random vault key; each secret is its own age file; the vault key is wrapped separately for each way of unlocking it (passphrase via scrypt, Touch ID via the Secure Enclave, each member's X25519 key).
- Key names and descriptions in `index.json` are readable without unlocking. Don't put anything sensitive in a description.
- Every change is checked in CI with race-tested unit tests, leak tests (canary values must never appear in any output, log, error or temp file), tamper tests, fuzzing of every file parser, `gosec`, `govulncheck`, CodeQL and `gitleaks`.
- See [SECURITY.md](SECURITY.md) to report a vulnerability privately, and [docs/threat-model.md](docs/threat-model.md) for what this does and doesn't protect against.

## Building from source

Requirements: Go 1.27+, and on macOS the Xcode Command Line Tools (for the Touch ID Swift library).

```bash
git clone https://github.com/Arntek/secrets-vault.git
cd secrets-vault
make tools   # install the pinned linters (once)
make build   # binary at bin/secrets-vault
make test    # tests with -race
make lint    # gofmt, vet, staticcheck, gosec, govulncheck, gitleaks, actionlint
make fuzz    # run every fuzz target briefly
```

If Swift fails to build on macOS with `redefinition of module 'SwiftBridging'`, that's a known Command Line Tools packaging bug. The Makefile works around it automatically with a compiler overlay, without changing system files.

Developer docs: [docs/architecture.md](docs/architecture.md) (packages and how they fit), [docs/vault-format.md](docs/vault-format.md) (on-disk format and crypto API).
