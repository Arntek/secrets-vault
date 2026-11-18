# Architecture

secrets-vault is one Go binary (`cmd/secrets-vault`) installed as `secrets-vault`, with the short names `vault` and `sv` pointing at it. All code lives under `internal/`, so nothing outside this module can import it.

## Packages

| Package | Job | Owner issue |
|---|---|---|
| `internal/format` | On-disk layout of a vault folder: `vault.json`, `index.json`, `secrets/NAME.age`. Go types, strict parsers, key-name validation, sync-safe writes. No cryptography. | 6j5 |
| `internal/crypto` | `VaultKey` (generate, hold, zero), the `KeyWrapper` interface every unlocker implements, passphrase (scrypt) and member (age X25519) wrappers, encrypting and decrypting secrets with age. | 6j5 |
| `internal/touchid` | Touch ID unlocker: Secure Enclave key via a Swift CryptoKit static library linked through cgo (`darwin && cgo && touchid` build tag, set by the Makefile), implementing `crypto.KeyWrapper`. Returns `ErrUnsupported` in every other build. | p1d |
| `internal/agent` | Memory-only unlock agent (like ssh-agent) and its `Client`: holds unlocked keys per vault with a TTL (default 4h, 5m to 24h) behind a user-only socket. | 244 |
| `internal/members` | Personal identities, fingerprints (`MAPLE-RIVER-4417`), join requests, approve, remove with key rotation. | p2h |
| `internal/audit` | Local read log (`vault log`). Events hold names only; the type has no field for a value. | Phase 2 (interface fixed now) |
| `internal/cli` | Commands, flags, prompts, `--json`, masking, exit codes, registry (`~/.config/vault/config.toml`), aliases. Orchestrates; holds no business rules. | rn5 |
| `internal/leaktest` | Test-only harness: runs code with canary secrets and fails if one appears in stdout, stderr, logs, temp files or HOME. | ii6 |
| `internal/arch` | Test-only: enforces the dependency rules below. | ii6 |

## Dependency direction

Arrows point from importer to imported. Nothing may import "upwards".

```
layer 0  cmd/secrets-vault
layer 1  internal/cli
layer 2  internal/members   internal/agent   internal/touchid
layer 3  internal/crypto    internal/audit
layer 4  internal/format
```

A package may import only packages in lower layers, and only those listed in the table below (for example `agent` may not import `audit`).

Allowed internal imports (non-test code), enforced by `internal/arch/arch_test.go`:

| Package | May import |
|---|---|
| `format`, `audit`, `leaktest` | standard library only |
| `crypto` | `format` |
| `agent` | `crypto`, `format` |
| `touchid` | `crypto`, `format` |
| `members` | `crypto`, `format`, `audit` |
| `cli` | any internal package except `leaktest` and `arch` |
| `cmd/secrets-vault` | `cli` |

Production code never imports `leaktest`; tests in any package may. When you add a package, add it to both this table and `arch_test.go`, or the test fails.

## Interfaces between packages

These are fixed by the scaffold so sessions can work in parallel. Change them only by agreement with the coordinator.

File layout, parsing rules and the call sequences for these two packages are in [vault-format.md](vault-format.md).

- **`format.VaultFile.KeyID`**: public fingerprint of the current vault key (`crypto.VaultKey.ID()`); changes on rotation.
- **`format.Unlocker`**: one wrapped copy of the vault key in `vault.json` (`type`, `label`, `recipient`, `wrapped_key`, `created`). `WrappedKey` is opaque to `format`.
- **`crypto.VaultKey`**: always passed by pointer; `Destroy()` zeroes it; `String`, `GoString` and `LogValue` print a placeholder so a key that reaches a log or `fmt` call never shows its bytes.
- **`crypto.KeyWrapper`**: `Type()`, `Wrap(*VaultKey) (format.Unlocker, error)`, `Unwrap(format.Unlocker) (*VaultKey, error)`. Implemented by the passphrase and member wrappers (crypto) and Touch ID (touchid). Any unwrap failure returns `crypto.ErrWrongKey`, so callers can't distinguish a wrong passphrase from tampered data.
- **`touchid`**: `Available`, `Enroll(label, keyPath)`, `Wrapper(*Device)` and (added in p1d) `WrapperForVault(*Device, vault)`, which names the vault and the calling program on the Touch ID sheet. `Unwrap` returns `ErrCancelled` when the user dismisses the sheet (fall back to the passphrase), `ErrUnsupported` when Touch ID can't be used (SSH, no sensor), and `crypto.ErrWrongKey` for everything else. `Enroll` refuses to overwrite an existing key file (`ErrEnrolled`).
- **`crypto.Sealer`**: `Seal` / `Open` a secret value with a `VaultKey`. Get one from `crypto.NewSealer(name)`: the key name is bound into the encryption. Open failures return `crypto.ErrDecrypt`.
- **`agent.Client`**: `Unlock(vaultID, key, ttl)`, `Key(vaultID)`, `Lock`, `LockAll`, `Status`, `Close`. Unlocking (Touch ID or passphrase prompt) happens in the CLI process; only the unwrapped key goes to the agent. `agent.ErrLocked` maps to exit code 3.
- **`audit.Logger`**: `Record(audit.Event) error`. Use `audit.Nop{}` until Phase 2.
- **`cli.Run(args, stdin, stdout, stderr) int`**: the whole program, testable in-process. Exit codes: 0 ok, 1 error, 2 usage, 3 locked, 4 key not found.

## Unlock flow (target)

1. `cli` reads the registry to find the vault folder and `format` parses `vault.json`.
2. `cli` asks `agent.Client.Key(vaultID)`. If unlocked, go to 5.
3. `cli` picks an unlocker: `touchid.Wrapper` if enrolled on this Mac and usable, else the passphrase prompt via `crypto.NewPassphraseWrapper`.
4. `KeyWrapper.Unwrap` returns the `VaultKey`; `cli` hands it to `agent.Client.Unlock` with the vault's TTL.
5. `crypto.Sealer.Open` decrypts `secrets/NAME.age`; `audit.Logger` records the read (name only).

## Rules for all packages

- Never put a secret value, key, passphrase or user-supplied argument in an error message, log line or panic. Rejected inputs are described, not echoed.
- Every parser of untrusted bytes (vault files, index, identities, requests) gets a `FuzzXxx` target; `scripts/fuzz.sh` and the nightly job pick them up automatically.
- Any code path that handles a secret gets a test through `leaktest`.
- Tamper tests: corrupted, truncated or swapped vault files must be rejected cleanly, never half-read.
- Keep dependencies minimal. Expected: `filippo.io/age`. Anything else needs a reason in the PR.
