# Releasing

A release is a `v*` tag. Pushing the tag runs `.github/workflows/release.yml`, which tests, builds with GoReleaser and uploads to GitHub Releases. Nothing is signed or notarised (no paid Apple account).

## What gets built

| Target | Build | Touch ID |
|---|---|---|
| darwin/arm64, darwin/amd64 | cgo plus a Swift static library built per architecture by `make touchid-lib` (GoReleaser `before` hooks), `touchid` tag | yes |
| linux/amd64, linux/arm64 | `CGO_ENABLED=0` | no |

Each gets a `secrets-vault_<version>_<os>_<arch>.tar.gz` (binary, LICENSE, README) and a shared `checksums.txt`. The CLI's `version` command prints the tag (`-X .../internal/cli.Version={{ .Tag }}`). Windows builds and an SBOM are not part of releases yet.

The macOS job runs on a GitHub macOS runner so Xcode and the Swift SDK are present; `scripts/swift-env.sh` hands their paths to the cgo link flags.

## Cut a release

1. `main` is green (CI, CodeQL) and `make test` and `make lint` pass locally.
2. Try the build: `make snapshot` (macOS, needs `brew install goreleaser`). Archives land in `dist/`.
3. Tag and push (this is what publishes):
   ```bash
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```
4. Watch the Release workflow, then check the GitHub Release has four archives and `checksums.txt`.

## Homebrew formula

The formula lives in `packaging/homebrew/secrets-vault.rb`. Its version and sha256 lines are placeholders that `scripts/render-formula.sh FORMULA VERSION checksums.txt [BASE_URL]` fills from a release's `checksums.txt`.

Design of the short names: the formula links `sv` always, and `vault` only when no other program called `vault` is on the installer's PATH or in Homebrew's bin. The links are made in `install`, so Homebrew tracks, upgrades and removes them. `post_install` running `alias add` was rejected: it runs in Homebrew's sandbox, edits the user's config during an install, and its links aren't tracked by Homebrew (they dangle after upgrade or uninstall). Caveats explain `sv alias add vault --force` and `sv alias rm vault`.

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

To check the skipped-`vault` case, put an executable file named `vault` earlier on PATH before `brew install`.

## Publishing to the tap (not yet enabled)

The `homebrew-tap` job in the release workflow is written but off. To turn it on:

1. Create the public repo `Arntek/homebrew-tap` (Arnold's call) with a `Formula/` folder.
2. Create a fine-grained token with `contents: write` on that repo only, and store it as the secret `HOMEBREW_TAP_TOKEN` in this repo.
3. Set the repository variable `ENABLE_HOMEBREW_TAP` to `true`.

After that each tag renders the formula with the release's checksums and pushes it to the tap. Until then, copy a rendered formula to the tap by hand.

## Later

- npm package (Phase 2) that downloads these archives.
- Shell completions (the CLI has none yet), then install them from the formula.
- SBOM (syft) and release signing with cosign or GitHub attestations.
