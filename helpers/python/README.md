# Python helper

`secrets_vault.py`: one file, standard library only (Python 3.8+). Copy it next to your script, or put this folder on `PYTHONPATH`.

```python
from secrets_vault import get_secret, VaultLockedError, SecretNotFoundError

api_key = get_secret("EXAMPLE_API_KEY", vault="work")   # vault is optional
```

It runs `secrets-vault get NAME -n` as a subprocess: never through a shell, stdout captured, stdin closed so it cannot prompt on the terminal or hang. On a Mac with the `dialog` setting on (the default) and a locked vault, the program shows its native password dialog to the human instead; set `vault config set dialog false`, or unlock first (`vault unlock`), to avoid it. The value only lives in your variable; it is never logged and never in an exception message.

| Exit code | Exception |
|---|---|
| 3 (locked, nowhere to ask for a passphrase) | `VaultLockedError` |
| 4 (no such key) | `SecretNotFoundError` (also a `LookupError`) |
| 5 (vault failed verification) | `VaultUnverifiedError` |
| anything else, timeout, program missing | `SecretsVaultError` / `SecretsVaultNotInstalledError` |

All derive from `SecretsVaultError`, which has `.exit_code`. Options: `executable=` (path to the program), `timeout=` (seconds, default 60), `interactive=True` (let the program ask for the passphrase on the terminal, needed on Windows where nothing stays unlocked). The program is found from `SECRETS_VAULT_BINARY_PATH`, then `PATH`. On Windows only an absolute `PATH` entry (or npm's global folder) is used, never the current folder. `SECRETS_VAULT_BINARY_PATH` decides which program gets your passphrase and values: never take it from untrusted environment (CI config, `.env` files).

Prefer `secrets-vault run -k NAME -- python your_script.py` when you can: then the script never holds the value at all.

Tests: `python -m unittest discover -s helpers/python -p "test_*.py"` (they use a fake program, never a real vault).
