'use strict';
// Tests use a fake `secrets-vault` script; they never touch a real vault.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const sv = require('./index.js');

const CANARY = 'CANARY-VALUE-9f3a';
const skip = process.platform === 'win32' ? 'the stand-in program is a shell script' : false;

function fake(script) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'svnode-'));
  const p = path.join(dir, 'secrets-vault');
  fs.writeFileSync(p, `#!/bin/sh\n${script}`, { mode: 0o755 });
  return p;
}

test('returns the exact value and passes the right arguments', { skip }, async () => {
  const exe = fake(`printf "%s" "$*" > "$0.args"; printf "%s" "${CANARY}"\n`);
  assert.strictEqual(await sv.getSecret('MY_KEY', { vault: 'work', executable: exe }), CANARY);
  assert.strictEqual(fs.readFileSync(`${exe}.args`, 'utf8'), 'get MY_KEY -n --vault work');
  assert.strictEqual(sv.getSecretSync('MY_KEY', { executable: exe }), CANARY);
});

test('no shell: metacharacters stay literal', { skip }, async () => {
  const exe = fake('printf "%s" "$2" > "$0.arg"; printf ok\n');
  await sv.getSecret('A;touch pwned', { executable: exe });
  assert.strictEqual(fs.readFileSync(`${exe}.arg`, 'utf8'), 'A;touch pwned');
  assert.ok(!fs.existsSync('pwned'));
});

test('exit codes become typed errors, async and sync', { skip }, async () => {
  const cases = [[3, sv.VaultLockedError], [4, sv.SecretNotFoundError], [5, sv.VaultUnverifiedError], [1, sv.SecretsVaultError]];
  for (const [code, Cls] of cases) {
    const exe = fake(`echo "message from program" >&2; exit ${code}\n`);
    await assert.rejects(sv.getSecret('K', { executable: exe }), (e) => e instanceof Cls && e.exitCode === code && /message from program/.test(e.message));
    assert.throws(() => sv.getSecretSync('K', { executable: exe }), (e) => e instanceof Cls && e.exitCode === code);
  }
});

test('the value is never in an error, even if the program prints it before failing', { skip }, async () => {
  const exe = fake(`echo "${CANARY}"; exit 1\n`);
  await assert.rejects(sv.getSecret('K', { executable: exe }), (e) => !e.message.includes(CANARY) && !String(e.stack).includes(CANARY));
  assert.throws(() => sv.getSecretSync('K', { executable: exe }), (e) => !e.message.includes(CANARY));
});

test('stdin is closed, so it cannot hang or prompt', { skip }, async () => {
  const exe = fake('if read x; then echo got >&2; exit 1; fi; printf ok\n');
  assert.strictEqual(await sv.getSecret('K', { executable: exe }), 'ok');
});

test('missing program, timeout, bad names, bad UTF-8', { skip }, async () => {
  await assert.rejects(sv.getSecret('K', { executable: '/nonexistent/secrets-vault' }), sv.SecretsVaultNotInstalledError);
  await assert.rejects(sv.getSecret('K', { executable: fake('sleep 5\n'), timeout: 200 }), /timed out/);
  for (const bad of ['', '-x', 'a\nb', 'a\0b', null, 5]) await assert.rejects(sv.getSecret(bad, { executable: '/x' }), TypeError);
  await assert.rejects(sv.getSecret('K', { vault: '--evil', executable: '/x' }), TypeError);
  await assert.rejects(sv.getSecret('K', { executable: fake('printf "\\377\\376"\n') }), (e) => e instanceof sv.SecretsVaultError && !/377/.test(e.message));
});

test('SECRETS_VAULT_BINARY_PATH is used when no executable is given', { skip }, async () => {
  const exe = fake('printf fromenv\n');
  const old = process.env.SECRETS_VAULT_BINARY_PATH;
  process.env.SECRETS_VAULT_BINARY_PATH = exe;
  try {
    assert.strictEqual(await sv.getSecret('K'), 'fromenv');
  } finally {
    if (old === undefined) delete process.env.SECRETS_VAULT_BINARY_PATH; else process.env.SECRETS_VAULT_BINARY_PATH = old;
  }
});
