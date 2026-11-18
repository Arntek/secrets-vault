# Releasing

A release is a `v*` tag. Pushing the tag runs `.github/workflows/release.yml`, which tests, builds with GoReleaser and uploads to GitHub Releases. Nothing is signed or notarised (no paid Apple account).

## What gets built

| Target | Build | Touch ID |
|---|---|---|
| darwin/arm64, darwin/amd64 | cgo plus a Swift static library built per architecture by `make touchid-lib` (GoReleaser `before` hooks), `touchid` tag | yes |
| linux/amd64, linux/arm64 | `CGO_ENABLED=0` | no |
| windows/amd64, windows/arm64 | `CGO_ENABLED=0`, `.zip` archive (`secrets-vault.exe`) | no (passphrase only; no unlock agent, no Windows Hello yet) |

Each gets a `secrets-vault_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows; binary, LICENSE, README) and a shared `checksums.txt`. The CLI's `version` command prints the tag (`-X .../internal/cli.Version={{ .Tag }}`). An SBOM is not part of releases yet. The npm installer depends on these exact archive names, and `scripts/npm-pin-checksums.js` pins their hashes from `checksums.txt` at publish time, so don't rename them.

The macOS job runs on a GitHub macOS runner so Xcode and the Swift SDK are present; `scripts/swift-env.sh` hands their paths to the cgo link flags.

## Cut a release

1. `main` is green (CI, CodeQL) and `make test` and `make lint` pass locally.
2. Try the build: `make snapshot` (macOS, needs `brew install goreleaser`). Archives land in `dist/`.
3. Tag and push (this is what publishes):
   ```bash
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```
4. Watch the Release workflow, then check the GitHub Release has six archives and `checksums.txt`.

## Homebrew formula

The formula lives in `packaging/homebrew/secrets-vault.rb`. Its version and sha256 lines are placeholders that `scripts/render-formula.sh FORMULA VERSION checksums.txt [BASE_URL]` fills from a release's `checksums.txt`.

Design of the short names: the formula links `sv` always, and `vault` only when no other program called `vault` is in Homebrew's bin, `/usr/local/bin`, `/opt/local/bin` or `/usr/bin`. Homebrew runs `install` with a filtered PATH and hides the user's own, so a `vault` in a personal folder is not detected; caveats tell the user to check `which -a vault` and run `sv alias rm vault` if needed. The links are made in `install`, so Homebrew tracks, upgrades and removes them. `post_install` running `alias add` was rejected: it runs in Homebrew's sandbox, edits the user's config during an install, and its links aren't tracked by Homebrew (they dangle after upgrade or uninstall). Caveats explain `sv alias add vault --force` and `sv alias rm vault`.

Test locally (needs up-to-date Command Line Tools, or Homebrew refuses to install unbottled formulae):

```bash
make snapshot
mkdir -p /tmp/rel && cp dist/*.tar.gz dist/checksums.txt /tmp/rel/
cp packaging/homebrew/secrets-vault.rb /tmp/f.rb
VER=$(basename dist/secrets-vault_*_darwin_arm64.tar.gz .tar.gz); VER=${VER#secrets-vault_}; VER=${VER%_darwin_arm64}
./scripts/render-formula.sh /tmp/f.rb "$VER" /tmp/rel/checksums.txt file:///tmp/rel
brew tap-new --no-git local/svtest
cp /tmp/f.rb "$(brew --repository local/svtest)/Formula/secrets-vault.rb"
brew install local/svtest/secrets-vault && brew test local/svtest/secrets-vault
brew uninstall secrets-vault && brew untap local/svtest
```

To check the skipped-`vault` case, put an executable file named `vault` in `/opt/homebrew/bin` before `brew install` (and remove it afterwards).

## Publishing to the tap (not yet enabled)

The `homebrew-tap` job in the release workflow is written but off. To turn it on:

1. Create the public repo `Arntek/homebrew-tap` (Arnold's call) with a `Formula/` folder.
2. Create a fine-grained token with `contents: write` on that repo only, and store it as the secret `HOMEBREW_TAP_TOKEN` in this repo.
3. Set the repository variable `ENABLE_HOMEBREW_TAP` to `true`.

After that each tag renders the formula with the release's checksums and pushes it to the tap. Until then, copy a rendered formula to the tap by hand.

## npm package

`packaging/npm/` is the package `secrets-vault`. It ships no program: its `postinstall` (`lib/install.js`, plain Node, no dependencies) downloads `secrets-vault_<version>_<os>_<arch>` for the package's own version from `https://github.com/Arntek/secrets-vault/releases/download/v<version>/`, over HTTPS only (redirects too), verifies the SHA-256 against a value **pinned inside the npm package** (`packaging/npm/checksums.json`; never against anything downloaded), unpacks only the one program file with its own small tar/zip reader, and fails closed on any mismatch, missing entry or error. Version in `package.json` is a placeholder (`0.0.0`); the publish job sets it from the tag. The package exposes the bins `secrets-vault`, `sv` and `vault` (`bin/*.js`, which start the downloaded program with the typed name as argv[0] so help says `sv` when you ran `sv`).

Environment for corporate and offline installs: `SECRETS_VAULT_BINARY_PATH` (use an existing program, download nothing; also read at run time) and `SECRETS_VAULT_MIRROR` (an `https://` base address or a local folder holding the archive; the pinned checksum is still verified, so a mirror cannot serve a different program). Both name the program that receives passphrases and values, so never take them from untrusted environment (CI config, `.env` files). No telemetry.

**Pinned checksums.** The release's `checksums.txt` lives next to the archives, so anyone who can replace release assets (or runs a mirror) could replace both. The npm package is a separate trust root (registry integrity, lockfiles), so the hashes go there. The committed `packaging/npm/checksums.json` is a placeholder (`0.0.0`, no archives) that makes a source checkout refuse to download anything. At release time `scripts/npm-pin-checksums.js VERSION checksums.txt` writes the real file from GoReleaser's `checksums.txt` and fails unless all six archives are present exactly once; the `npm-publish` job runs it before `npm publish` (`make npm-pin PIN_VERSION=0.1.0 CHECKSUMS=dist/checksums.txt` does the same by hand). The installer fails closed if the file is missing, is for another version, or has no entry for the machine's platform. It's not a substitute for checking provenance: verifying GitHub build attestations when online is a possible follow-up.

**The `vault` name.** npm cannot skip a single clashing bin: with another `vault` already in npm's bin folder (HashiCorp Vault, for instance), `npm install -g` aborts with `EEXIST` and installs nothing (checked with a local prefix). The README says so and names `sv` as the safe name. If that proves too harsh, drop `vault` from the `bin` map in `packaging/npm/package.json`; Windows then gets `sv` and `secrets-vault` only, since `sv alias` is not supported there.

Tests (no network; a local fake release folder): `cd packaging/npm && npm test`. CI runs them on Linux and Windows. To try a real install from a snapshot build, make a scratch copy of `packaging/npm` with `npm version <snapshot version> --no-git-tag-version`, then `SECRETS_VAULT_MIRROR=$PWD/dist npm install -g ./copy --prefix /tmp/prefix`.

### Publishing to npm (not yet enabled)

The `npm-publish` job in the release workflow is written but off (it runs after the GitHub Release exists, so the installer can download it). To turn it on:

1. Create an npm account or organisation and make sure the name `secrets-vault` is free (Arnold's call; check `npm view secrets-vault`).
2. Create an npm access token that can publish that package (granular, publish only, or an automation token) and store it as the secret `NPM_TOKEN` in this repo.
3. Set the repository variable `ENABLE_NPM_PUBLISH` to `true`.

After that each tag runs the package tests, sets the version from the tag, and publishes with provenance. Until then nothing is published; publishing a version before its GitHub Release exists would give people an install that fails.

## Script helpers

`helpers/python/secrets_vault.py` and `helpers/node/index.js` are single files to copy into a project (README in each). They are not published to PyPI or npm yet; if wanted, each could become its own small package later. Tests run in CI: `python -m unittest discover -s helpers/python -p "test_*.py"` and `npm test` in `helpers/node`.

## Windows

Windows builds are passphrase-only: `internal/agent` has no Windows agent (a named-pipe agent is future work), so every command that needs a key asks for the passphrase, or exits 3 with no console. The config folder is `%LOCALAPPDATA%\vault`. The program does not read or check Windows ACLs (that would need Windows-only syscalls, and mode bits mean nothing there); the README tells people to keep their folders private, and files under a user profile are private by default. CI runs `go test ./...` on `windows-latest`; tests that need the Unix agent, permission bits, symlinks or a shell skip themselves there, with the reason in the test. Not yet run on a real Windows machine by a person: try `init`, `set`, `get`, `run` and `unlock` (which should say there is no agent) once a build exists.

## Later

- Shell completions (the CLI has none yet), then install them from the formula.
- SBOM (syft) and release signing with cosign or GitHub attestations.
