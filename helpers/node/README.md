# Node helper

`index.js`: one file, no dependencies (Node 18+). Copy it next to your script and `require` it.

```js
const { getSecret, VaultLockedError } = require('./index.js');

const apiKey = await getSecret('EXAMPLE_API_KEY', { vault: 'work' }); // vault is optional
// or blocking: getSecretSync('EXAMPLE_API_KEY')
```

It runs `secrets-vault get NAME -n` with `execFile`: never through a shell, stdout captured, stdin closed so it cannot prompt or hang. The value only lives in your variable; it is never logged and never in an error message.

| Exit code | Error |
|---|---|
| 3 (locked, nowhere to ask for a passphrase) | `VaultLockedError` |
| 4 (no such key) | `SecretNotFoundError` |
| 5 (vault failed verification) | `VaultUnverifiedError` |
| anything else, timeout, program missing | `SecretsVaultError` / `SecretsVaultNotInstalledError` |

All extend `SecretsVaultError`, which has `.exitCode`. Options: `executable` (path to the program), `timeout` (milliseconds, default 60000), `interactive: true` (async only: the program gets your terminal's stdin and stderr, so it can show its prompt and read the passphrase; needed on Windows where nothing stays unlocked). The program is found from `SECRETS_VAULT_BINARY_PATH`, then the npm install of `secrets-vault` (its real `.exe` on Windows), then `PATH`. On Windows only an absolute `PATH` entry (or npm's global folder) is used, never the current folder. `SECRETS_VAULT_BINARY_PATH` decides which program gets your passphrase and values: never take it from untrusted environment (CI config, `.env` files).

Prefer `secrets-vault run -k NAME -- node your-script.js` when you can: then the script never holds the value at all.

Tests: `npm test` in this folder (a fake program, never a real vault).
