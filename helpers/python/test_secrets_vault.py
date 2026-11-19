"""Tests use a fake `secrets-vault` script; they never touch a real vault."""

import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrets_vault as sv  # noqa: E402

CANARY = "CANARY-VALUE-9f3a"

POSIX_ONLY = unittest.skipIf(os.name == "nt", "the stand-in program is a shell script")


def fake(script):
    d = tempfile.mkdtemp(prefix="svpy-")
    p = os.path.join(d, "secrets-vault")
    with open(p, "w") as f:
        f.write("#!/bin/sh\n" + script)
    os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
    return p


@POSIX_ONLY
class GetSecret(unittest.TestCase):
    def test_returns_exact_value_and_passes_argv(self):
        exe = fake('printf "%s" "$*" > "$0.args"; printf "%s" "' + CANARY + '"\n')
        self.assertEqual(sv.get_secret("MY_KEY", "work", executable=exe), CANARY)
        with open(exe + ".args") as f:
            self.assertEqual(f.read(), "get MY_KEY -n --vault work")

    def test_no_shell_so_metacharacters_are_literal(self):
        exe = fake('printf "%s" "$2" > "$0.arg"; printf ok\n')
        sv.get_secret("A;touch pwned", executable=exe)
        with open(exe + ".arg") as f:
            self.assertEqual(f.read(), "A;touch pwned")
        self.assertFalse(os.path.exists("pwned"))

    def test_value_keeps_its_newline(self):
        exe = fake('printf "line\\n"\n')
        self.assertEqual(sv.get_secret("K", executable=exe), "line\n")

    def test_exit_codes_map_to_exceptions(self):
        cases = [(3, sv.VaultLockedError), (4, sv.SecretNotFoundError), (5, sv.VaultUnverifiedError), (1, sv.SecretsVaultError)]
        for code, exc in cases:
            exe = fake('echo "message from program" >&2; exit %d\n' % code)
            with self.assertRaises(exc) as cm:
                sv.get_secret("K", executable=exe)
            self.assertEqual(cm.exception.exit_code, code)
            self.assertIn("message from program", str(cm.exception))
        self.assertTrue(issubclass(sv.SecretNotFoundError, LookupError))

    def test_value_never_in_exception_even_if_program_prints_it_on_failure(self):
        exe = fake('echo "' + CANARY + '"; exit 1\n')  # stdout, then failure
        with self.assertRaises(sv.SecretsVaultError) as cm:
            sv.get_secret("K", executable=exe)
        self.assertNotIn(CANARY, str(cm.exception))
        self.assertNotIn(CANARY, repr(cm.exception))

    def test_stdin_is_closed_so_it_cannot_hang_or_prompt(self):
        exe = fake('if read x; then echo got >&2; exit 1; fi; printf ok\n')
        self.assertEqual(sv.get_secret("K", executable=exe), "ok")

    def test_missing_program(self):
        with self.assertRaises(sv.SecretsVaultNotInstalledError):
            sv.get_secret("K", executable="/nonexistent/secrets-vault")

    def test_timeout(self):
        exe = fake("sleep 5\n")
        with self.assertRaises(sv.SecretsVaultError) as cm:
            sv.get_secret("K", executable=exe, timeout=0.2)
        self.assertIn("timed out", str(cm.exception))

    def test_env_override(self):
        exe = fake("printf fromenv\n")
        old = os.environ.get("SECRETS_VAULT_BINARY_PATH")
        os.environ["SECRETS_VAULT_BINARY_PATH"] = exe
        try:
            self.assertEqual(sv.get_secret("K"), "fromenv")
        finally:
            if old is None:
                del os.environ["SECRETS_VAULT_BINARY_PATH"]
            else:
                os.environ["SECRETS_VAULT_BINARY_PATH"] = old

    def test_invalid_utf8(self):
        exe = fake('printf "\\377\\376"\n')
        with self.assertRaises(sv.SecretsVaultError) as cm:
            sv.get_secret("K", executable=exe)
        self.assertNotIn("377", str(cm.exception))


class WindowsLookup(unittest.TestCase):
    def test_never_a_bare_name_or_the_current_folder(self):
        d = tempfile.mkdtemp(prefix="svpy-win-")
        with open(os.path.join(d, "secrets-vault.exe"), "w") as f:
            f.write("x")
        old = os.getcwd()
        os.chdir(d)  # a secrets-vault.exe sits in the current folder
        try:
            for path in ["", ".", ";;", "relative\\dir;.", "C:\\definitely\\not\\here"]:
                with self.assertRaises(sv.SecretsVaultNotInstalledError, msg=path):
                    sv._find_executable(None, {"PATH": path}, "nt")
            self.assertEqual(sv._find_executable("X:\\mine.exe", {}, "nt"), "X:\\mine.exe")
            self.assertEqual(sv._find_executable(None, {"SECRETS_VAULT_BINARY_PATH": "X:\\e.exe"}, "nt"), "X:\\e.exe")
        finally:
            os.chdir(old)

    @unittest.skipUnless(os.name == "nt", "needs real Windows paths")
    def test_finds_absolute_path_entry(self):
        d = tempfile.mkdtemp(prefix="svpy-win-")
        p = os.path.join(d, "secrets-vault.exe")
        with open(p, "w") as f:
            f.write("x")
        self.assertEqual(sv._find_executable(None, {"PATH": ".;" + d}, "nt"), p)


class Validation(unittest.TestCase):
    def test_bad_names_rejected_before_running_anything(self):
        for bad in ["", "-x", "a\nb", "a\0b", None, 5]:
            with self.assertRaises(ValueError):
                sv.get_secret(bad, executable="/nonexistent")
        for bad in ["", "--evil", "v\n"]:
            with self.assertRaises(ValueError):
                sv.get_secret("K", bad, executable="/nonexistent")


if __name__ == "__main__":
    unittest.main()
