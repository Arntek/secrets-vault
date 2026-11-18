# secrets-vault (npm)

Command-line secrets manager: encrypted vaults in folders you choose (Dropbox, Box, any synced folder), unlocked by passphrase, and by Touch ID on a Mac. Full documentation: <https://github.com/Arntek/secrets-vault#readme>.

```bash
npm install -g secrets-vault
```

This package contains no program of its own. When you install it, a small script (`lib/install.js`, plain Node, no dependencies) downloads the matching build from the GitHub Release with the **same version number as this package**, over HTTPS only, checks its SHA-256 against a value **pinned inside this package** (not against anything it downloaded, so a replaced release or a mirror cannot get a different program installed), and unpacks it. Any mismatch or error stops the install and nothing is left behind. No telemetry, no other network calls.

## Names

It installs three commands: `secrets-vault` (never changes, use it in scripts), `sv`, and `vault`.

**`vault` clashes with HashiCorp Vault.** If another program called `vault` is already in npm's bin folder, `npm install -g secrets-vault` stops with `EEXIST` and installs nothing. npm cannot skip just one name. Your options: use another install (Homebrew skips `vault` by itself), remove the other `vault` first, or `npm install -g secrets-vault --force` (which overwrites the other program's link: only do this if you mean to). `sv` is the safe short name everywhere.

## Platforms

macOS (Touch ID included), Linux and Windows, on x64 or arm64. On **Windows** vaults open with a passphrase only: there is no unlock agent (each command that needs a key asks for the passphrase, or exits with code 3 if there is no console) and no Touch ID or Windows Hello yet.

## Corporate and offline installs

| Variable | Effect |
|---|---|
| `SECRETS_VAULT_BINARY_PATH` | Use this existing program. Nothing is downloaded. Also read every time you run `sv`. |
| `SECRETS_VAULT_MIRROR` | Where to get `secrets-vault_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows): an `https://` address or a local folder. The pinned checksum is still verified. |

Both decide which program receives your passphrases and keys, so never set them from untrusted places (CI config, `.env` files).

```bash
# Offline: copy the release's archives into a folder, then
SECRETS_VAULT_MIRROR=/path/to/folder npm install -g secrets-vault
```

Don't install with `--ignore-scripts`: that skips the download, and the commands will say the program is missing.
