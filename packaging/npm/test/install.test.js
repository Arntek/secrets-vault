'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { install, pinnedHash, get } = require('../lib/install.js');
const { target, archiveName } = require('../lib/platform.js');
const { fromTarGz, fromZip } = require('../lib/extract.js');
const { makeRelease, tarGz, zip, tmp, pin } = require('./fixture.js');

const V = '1.2.3';
const quiet = () => {};

// opts builds an install() call whose package root pins `rel`'s archive, as
// a published package would. Pass pins: false for a root with no checksums.json.
function opts(rel, extra = {}) {
  const root = tmp();
  const platform = extra.platform || process.platform;
  const arch = extra.arch || process.arch;
  if (rel && extra.pins !== false) pin(root, V, { [archiveName(V, target(platform, arch))]: rel.hash });
  return { version: V, root, log: quiet, env: rel ? { SECRETS_VAULT_MIRROR: rel.dir } : {}, ...extra, pins: undefined };
}

test('installs from a local mirror folder and verifies the pinned checksum', async () => {
  for (const [platform, arch] of [['linux', 'x64'], ['darwin', 'arm64'], ['win32', 'x64'], ['win32', 'arm64']]) {
    const rel = makeRelease(V, { platform, arch });
    const r = await install(opts(rel, { platform, arch }));
    assert.strictEqual(r.downloaded, true);
    assert.strictEqual(fs.readFileSync(r.path, 'utf8'), rel.program);
    assert.ok(r.path.endsWith(target(platform, arch).exe));
    if (platform !== 'win32') assert.ok(fs.statSync(r.path).mode & 0o100, 'executable');
  }
});

test('a checksum mismatch against the pin fails and installs nothing', async () => {
  const rel = makeRelease(V, { tamper: true });
  const o = opts(rel);
  await assert.rejects(install(o), /checksum mismatch/);
  assert.ok(!fs.existsSync(path.join(o.root, 'vendor')));
});

test('a mirror that swaps the archive AND its checksums.txt is still refused', async () => {
  const honest = makeRelease(V);
  // The attacker's mirror: a different program, with a checksums.txt that matches it.
  const evil = makeRelease(V, { program: '#!/bin/sh\necho stolen\n' });
  const o = opts(honest); // the package pins the honest hash
  o.env = { SECRETS_VAULT_MIRROR: evil.dir };
  await assert.rejects(install(o), /checksum mismatch/);
  assert.ok(!fs.existsSync(path.join(o.root, 'vendor')));
});

test('checksums.txt in the mirror is not used or needed', async () => {
  const rel = makeRelease(V);
  fs.rmSync(path.join(rel.dir, 'checksums.txt'));
  const r = await install(opts(rel));
  assert.strictEqual(fs.readFileSync(r.path, 'utf8'), rel.program);
});

test('fails closed when the package has no pin for this platform', async () => {
  const rel = makeRelease(V);
  const o = opts(rel);
  pin(o.root, V, { 'secrets-vault_1.2.3_plan9_amd64.tar.gz': 'a'.repeat(64) });
  await assert.rejects(install(o), /no pinned checksum for/);
  assert.ok(!fs.existsSync(path.join(o.root, 'vendor')));
});

test('fails closed with no checksums.json, a wrong version, a placeholder or a bad hash', async () => {
  const rel = makeRelease(V);
  await assert.rejects(install(opts(rel, { pins: false })), /no pinned checksums/);
  const name = archiveName(V, target());
  let o = opts(rel);
  pin(o.root, '9.9.9', { [name]: rel.hash });
  await assert.rejects(install(o), /pinned checksums are for 9.9.9/);
  o = opts(rel);
  fs.writeFileSync(path.join(o.root, 'checksums.json'), '{"version":"0.0.0","archives":{}}');
  await assert.rejects(install(o), /no release version|pinned checksums are for/);
  o = opts(rel);
  pin(o.root, V, { [name]: 'not-a-hash' });
  await assert.rejects(install(o), /no pinned checksum for/);
  o = opts(rel);
  fs.writeFileSync(path.join(o.root, 'checksums.json'), '[1,2');
  await assert.rejects(install(o), /no pinned checksums/);
});

test('a release for another platform is not used (wrong platform fails)', async () => {
  const rel = makeRelease(V, { platform: 'linux', arch: 'x64' });
  // The package pins only the linux archive; a darwin/arm64 machine has no pin.
  const o = opts(rel, { platform: 'darwin', arch: 'arm64' });
  pin(o.root, V, { [archiveName(V, target('linux', 'x64'))]: rel.hash });
  await assert.rejects(install(o), /no pinned checksum for secrets-vault_1.2.3_darwin_arm64/);
});

test('an unsupported platform or CPU fails', async () => {
  await assert.rejects(install(opts(null, { platform: 'freebsd', arch: 'x64' })), /no build for freebsd\/x64/);
  await assert.rejects(install(opts(null, { platform: 'linux', arch: 'ia32' })), /no build for linux\/ia32/);
});

test('SECRETS_VAULT_BINARY_PATH installs nothing and downloads nothing', async () => {
  const bin = path.join(tmp(), 'my-secrets-vault');
  fs.writeFileSync(bin, 'x');
  const o = opts(null, { env: { SECRETS_VAULT_BINARY_PATH: bin } });
  const r = await install(o);
  assert.deepStrictEqual(r, { path: bin, downloaded: false });
  assert.ok(!fs.existsSync(path.join(o.root, 'vendor')));
  await assert.rejects(install(opts(null, { env: { SECRETS_VAULT_BINARY_PATH: path.join(tmp(), 'nope') } })), /does not point to a file/);
});

test('plain http and other schemes are refused', async () => {
  const rel = makeRelease(V);
  for (const m of ['http://example.invalid/rel', 'ftp://example.invalid/rel']) {
    const o = opts(rel);
    o.env = { SECRETS_VAULT_MIRROR: m };
    await assert.rejects(install(o), /https:\/\/ address or a local folder/);
  }
  await assert.rejects(get('http://example.invalid/x'), /non-HTTPS/);
});

test('a placeholder or malformed version is refused', async () => {
  await assert.rejects(install(opts(null, { version: '0.0.0' })), /no release version/);
  await assert.rejects(install(opts(null, { version: '../../x' })), /no release version/);
});

test('pin lookup is exact', () => {
  const h = 'b'.repeat(64);
  const pins = { version: '1.0.0', archives: { 'a.tar.gz': h.toUpperCase(), 'b.zip': 'short' } };
  assert.strictEqual(pinnedHash(pins, '1.0.0', 'a.tar.gz'), h);
  assert.throws(() => pinnedHash(pins, '1.0.0', 'b.zip'), /no pinned checksum/);
  assert.throws(() => pinnedHash(pins, '1.0.0', 'a.tar.gz.sig'), /no pinned checksum/);
  assert.throws(() => pinnedHash(pins, '1.0.0', '__proto__'), /no pinned checksum/);
  assert.throws(() => pinnedHash(pins, '1.0.1', 'a.tar.gz'), /pinned checksums are for/);
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
