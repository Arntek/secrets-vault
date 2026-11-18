'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { install, expectedHash, get } = require('../lib/install.js');
const { target, archiveName } = require('../lib/platform.js');
const { fromTarGz, fromZip } = require('../lib/extract.js');
const { makeRelease, tarGz, zip, tmp } = require('./fixture.js');

const V = '1.2.3';
const quiet = () => {};

function opts(extra = {}) {
  return { version: V, root: tmp(), log: quiet, env: {}, ...extra };
}

test('installs from a local mirror folder and verifies the checksum', async () => {
  for (const [platform, arch] of [['linux', 'x64'], ['darwin', 'arm64'], ['win32', 'x64'], ['win32', 'arm64']]) {
    const rel = makeRelease(V, { platform, arch });
    const o = opts({ platform, arch, env: { SECRETS_VAULT_MIRROR: rel.dir } });
    const r = await install(o);
    assert.strictEqual(r.downloaded, true);
    assert.strictEqual(fs.readFileSync(r.path, 'utf8'), rel.program);
    assert.ok(r.path.endsWith(target(platform, arch).exe));
    if (platform !== 'win32') assert.ok(fs.statSync(r.path).mode & 0o100, 'executable');
  }
});

test('a checksum mismatch fails and installs nothing', async () => {
  const rel = makeRelease(V, { tamper: true });
  const o = opts({ env: { SECRETS_VAULT_MIRROR: rel.dir } });
  await assert.rejects(install(o), /checksum mismatch/);
  assert.ok(!fs.existsSync(path.join(o.root, 'vendor')));
});

test('an archive missing from checksums.txt fails', async () => {
  const rel = makeRelease(V, { omit: true });
  await assert.rejects(install(opts({ env: { SECRETS_VAULT_MIRROR: rel.dir } })), /no entry for/);
});

test('a missing checksums.txt fails closed', async () => {
  const rel = makeRelease(V);
  fs.rmSync(path.join(rel.dir, 'checksums.txt'));
  await assert.rejects(install(opts({ env: { SECRETS_VAULT_MIRROR: rel.dir } })), /checksums.txt is not in the mirror/);
});

test('a release for another platform is not used (wrong platform fails)', async () => {
  const rel = makeRelease(V, { platform: 'linux', arch: 'x64' });
  await assert.rejects(install(opts({ platform: 'darwin', arch: 'arm64', env: { SECRETS_VAULT_MIRROR: rel.dir } })), /no entry for secrets-vault_1.2.3_darwin_arm64/);
});

test('an unsupported platform or CPU fails', async () => {
  await assert.rejects(install(opts({ platform: 'freebsd', arch: 'x64' })), /no build for freebsd\/x64/);
  await assert.rejects(install(opts({ platform: 'linux', arch: 'ia32' })), /no build for linux\/ia32/);
});

test('SECRETS_VAULT_BINARY_PATH installs nothing and downloads nothing', async () => {
  const bin = path.join(tmp(), 'my-secrets-vault');
  fs.writeFileSync(bin, 'x');
  const o = opts({ env: { SECRETS_VAULT_BINARY_PATH: bin } });
  const r = await install(o);
  assert.deepStrictEqual(r, { path: bin, downloaded: false });
  assert.ok(!fs.existsSync(path.join(o.root, 'vendor')));
  await assert.rejects(install(opts({ env: { SECRETS_VAULT_BINARY_PATH: path.join(tmp(), 'nope') } })), /does not point to a file/);
});

test('plain http and other schemes are refused', async () => {
  await assert.rejects(install(opts({ env: { SECRETS_VAULT_MIRROR: 'http://example.invalid/rel' } })), /https:\/\/ address or a local folder/);
  await assert.rejects(install(opts({ env: { SECRETS_VAULT_MIRROR: 'ftp://example.invalid/rel' } })), /https:\/\/ address or a local folder/);
  await assert.rejects(get('http://example.invalid/x'), /non-HTTPS/);
});

test('a placeholder or malformed version is refused', async () => {
  await assert.rejects(install(opts({ version: '0.0.0' })), /no release version/);
  await assert.rejects(install(opts({ version: '../../x' })), /no release version/);
});

test('checksums.txt parsing is exact', () => {
  const h = 'b'.repeat(64);
  assert.strictEqual(expectedHash(`${h}  a.tar.gz\n`, 'a.tar.gz'), h);
  assert.strictEqual(expectedHash(`${h}  a.tar.gz.sig\n`, 'a.tar.gz'), null);
  assert.strictEqual(expectedHash(`${h}  x/a.tar.gz\n`, 'a.tar.gz'), null);
  assert.strictEqual(expectedHash('short  a.tar.gz\n', 'a.tar.gz'), null);
});

test('archive readers take only the named file and reject damage', () => {
  const files = { 'dir/../evil': 'bad', LICENSE: 'l', 'secrets-vault': 'prog' };
  assert.strictEqual(fromTarGz(tarGz(files), 'secrets-vault').toString(), 'prog');
  assert.throws(() => fromTarGz(tarGz({ LICENSE: 'l' }), 'secrets-vault'), /not in the archive/);
  assert.throws(() => fromTarGz(Buffer.from('not gzip'), 'secrets-vault'));
  assert.strictEqual(fromZip(zip({ LICENSE: 'l', 'secrets-vault.exe': 'prog' }), 'secrets-vault.exe').toString(), 'prog');
  assert.throws(() => fromZip(zip({ LICENSE: 'l' }), 'secrets-vault.exe'), /not in the archive/);
  assert.throws(() => fromZip(Buffer.from('not a zip at all, just bytes'), 'secrets-vault.exe'), /not a zip/);
});

test('archive names match the GoReleaser template', () => {
  assert.strictEqual(archiveName('0.1.0', target('darwin', 'arm64')), 'secrets-vault_0.1.0_darwin_arm64.tar.gz');
  assert.strictEqual(archiveName('0.1.0', target('win32', 'x64')), 'secrets-vault_0.1.0_windows_amd64.zip');
});

test('package.json exposes the three names and has no dependencies', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.deepStrictEqual(Object.keys(pkg.bin).sort(), ['secrets-vault', 'sv', 'vault']);
  assert.strictEqual(pkg.dependencies, undefined);
  for (const f of Object.values(pkg.bin)) assert.ok(fs.existsSync(path.join(__dirname, '..', f)));
});
