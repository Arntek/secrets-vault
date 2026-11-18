"""Read one secret from secrets-vault, for one script, without leaking it.

    from secrets_vault import get_secret
    api_key = get_secret("EXAMPLE_API_KEY", vault="work")

It runs ``secrets-vault get NAME`` as a subprocess: no shell, stdout
captured, so the value only ever lives in your variable. Exit codes become
exceptions. The value is never logged and never put in an exception message.
Standard library only (Python 3.8+).

Prefer ``secrets-vault run -k NAME -- your-command`` when you can: then the
script never holds the value at all. Use this helper when it must.
"""

import ntpath
import os
import shutil
import subprocess
import sys

__all__ = [
    "get_secret",
    "SecretsVaultError",
    "VaultLockedError",
    "SecretNotFoundError",
    "VaultUnverifiedError",
    "SecretsVaultNotInstalledError",
]

_EXE = "secrets-vault"
_MAX_STDERR = 500


class SecretsVaultError(Exception):
    """secrets-vault failed. ``exit_code`` is its exit code (None if it did not run)."""

    def __init__(self, message, exit_code=None):
        super().__init__(message)
        self.exit_code = exit_code


class VaultLockedError(SecretsVaultError):
    """Exit 3: the vault is locked and there was no way to ask for the passphrase."""


class SecretNotFoundError(SecretsVaultError, LookupError):
    """Exit 4: no key with that name (in that vault)."""


class VaultUnverifiedError(SecretsVaultError):
    """Exit 5: the vault failed verification (tampered, rolled back, or untrusted)."""


class SecretsVaultNotInstalledError(SecretsVaultError):
    """The secrets-vault program could not be found."""


_NOT_INSTALLED = (
    "the secrets-vault program was not found; install it (brew or npm install -g secrets-vault) "
    "or set SECRETS_VAULT_BINARY_PATH"
)


def _find_executable(executable=None, env=None, os_name=None):
    env = os.environ if env is None else env
    os_name = os.name if os_name is None else os_name
    if executable:
        return executable
    override = env.get("SECRETS_VAULT_BINARY_PATH")
    if override:
        return override
    if os_name == "nt":
        # npm installs a .cmd shim that cannot be run without a shell; the
        # real program is the .exe. Always return an absolute path found on
        # PATH (absolute entries only) or in npm's global folder, never a
        # bare name: CreateProcess would look in the current folder first and
        # could run a secrets-vault.exe planted there.
        for d in env.get("PATH", "").split(";"):
            if d and ntpath.isabs(d):
                p = ntpath.join(d, _EXE + ".exe")
                if os.path.isfile(p):
                    return p
        appdata = env.get("APPDATA")
        if appdata and ntpath.isabs(appdata):
            p = ntpath.join(appdata, "npm", "node_modules", "secrets-vault", "vendor", _EXE + ".exe")
            if os.path.isfile(p):
                return p
        raise SecretsVaultNotInstalledError(_NOT_INSTALLED)
    return shutil.which(_EXE) or _EXE


def _clean(text):
    text = (text or "").strip().replace("\r", "")
    return text[:_MAX_STDERR]


def get_secret(name, vault=None, *, executable=None, timeout=60, interactive=False):
    """Return the value of key ``name`` as a ``str``.

    vault        vault name; default is the configured default vault.
    executable   path to the program (default: SECRETS_VAULT_BINARY_PATH, else PATH).
    timeout      seconds before giving up.
    interactive  False (default): never prompts; a locked vault raises
                 VaultLockedError. True: the program may ask for the passphrase
                 on the terminal (its prompt goes to stderr, not to you).
    """
    if not isinstance(name, str) or not name or name.startswith("-") or any(c in name for c in "\0\r\n"):
        raise ValueError("invalid secret name")
    if vault is not None and (not isinstance(vault, str) or not vault or vault.startswith("-") or any(c in vault for c in "\0\r\n")):
        raise ValueError("invalid vault name")

    exe = _find_executable(executable)  # raises SecretsVaultNotInstalledError
    # -n: no trailing newline, so the value comes back exactly as stored.
    cmd = [exe, "get", name, "-n"]
    if vault is not None:
        cmd += ["--vault", vault]

    kwargs = {"stdout": subprocess.PIPE, "shell": False}
    if interactive:
        kwargs["stdin"] = None  # inherit, so a prompt can read the passphrase
        kwargs["stderr"] = None
    else:
        kwargs["stdin"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.PIPE

    try:
        proc = subprocess.run(cmd, timeout=timeout, check=False, **kwargs)  # noqa: S603 - no shell, fixed argv
    except FileNotFoundError:
        raise SecretsVaultNotInstalledError(_NOT_INSTALLED) from None
    except subprocess.TimeoutExpired:
        raise SecretsVaultError("secrets-vault timed out") from None
    except OSError as e:
        raise SecretsVaultError("could not run secrets-vault (%s)" % (e.strerror or type(e).__name__)) from None

    code = proc.returncode
    detail = _clean(proc.stderr.decode("utf-8", "replace")) if proc.stderr else ""
    where = "key '%s'" % name + (" in vault '%s'" % vault if vault else "")
    if code == 0:
        try:
            return proc.stdout.decode("utf-8")
        except UnicodeDecodeError:
            raise SecretsVaultError("the value of %s is not valid UTF-8 text" % where, 0) from None
    if code == 3:
        raise VaultLockedError(detail or "the vault is locked and cannot ask for a passphrase here", 3)
    if code == 4:
        raise SecretNotFoundError(detail or ("%s was not found" % where), 4)
    if code == 5:
        raise VaultUnverifiedError(detail or "the vault failed verification", 5)
    raise SecretsVaultError(detail or ("secrets-vault failed (exit %s)" % code), code)


if __name__ == "__main__":  # pragma: no cover
    sys.stderr.write("This is a library: from secrets_vault import get_secret\n")
    sys.exit(2)
