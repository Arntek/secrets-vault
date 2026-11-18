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

test('interactive: the program gets the real stdin (not a pipe we made) and its stderr', { skip }, async () => {
  // Fake program reads its stdin; the driver's stdin is a file, so what comes
  // back is that file's content only if stdin was inherited.
  const exe = fake('v=$(cat); printf "%s" "$v"\n');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'svnode-in-'));
  const input = path.join(dir, 'in.txt');
  fs.writeFileSync(input, 'typed-passphrase');
  const driver = path.join(dir, 'driver.js');
  fs.writeFileSync(driver, `require(${JSON.stringify(path.join(__dirname, 'index.js'))}).getSecret('K',{interactive:true,executable:${JSON.stringify(exe)}}).then(v=>process.stdout.write(v))`);
  const fd = fs.openSync(input, 'r');
  const { spawnSync } = require('node:child_process');
  const r = spawnSync(process.execPath, [driver], { stdio: [fd, 'pipe', 'pipe'], encoding: 'utf8', timeout: 10000 });
  fs.closeSync(fd);
  assert.strictEqual(r.stdout, 'typed-passphrase');
});

test('Windows lookup never uses a bare name or the current folder', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'svnode-win-'));
  fs.writeFileSync(path.join(dir, 'secrets-vault.exe'), 'x');
  const old = process.cwd();
  process.chdir(dir); // a secrets-vault.exe sits in the current folder
  try {
    for (const PATH of ['', '.', ';;', 'relative\\dir;.', 'C:\\definitely\\not\\here']) {
      assert.throws(() => sv.findExecutable({}, { PATH }, 'win32'), sv.SecretsVaultNotInstalledError, PATH);
    }
    assert.strictEqual(sv.findExecutable({ executable: 'X:\\mine\\sv.exe' }, {}, 'win32'), 'X:\\mine\\sv.exe');
    assert.strictEqual(sv.findExecutable({}, { SECRETS_VAULT_BINARY_PATH: 'X:\\e.exe' }, 'win32'), 'X:\\e.exe');
  } finally {
    process.chdir(old);
  }
});

test('Windows lookup finds an absolute PATH entry', { skip: process.platform === 'win32' ? false : 'needs real Windows paths' }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'svnode-win-'));
  fs.writeFileSync(path.join(dir, 'secrets-vault.exe'), 'x');
  assert.strictEqual(sv.findExecutable({}, { PATH: `.;${dir}` }, 'win32'), path.join(dir, 'secrets-vault.exe'));
});
