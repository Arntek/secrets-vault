'use strict';
// The publish-time script that writes checksums.json from checksums.txt.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { tmp } = require('./fixture.js');

const script = path.join(__dirname, '..', '..', '..', 'scripts', 'npm-pin-checksums.js');
const V = '0.4.0';
const names = [];
for (const os of ['darwin', 'linux', 'windows']) for (const a of ['amd64', 'arm64']) names.push(`secrets-vault_${V}_${os}_${a}.${os === 'windows' ? 'zip' : 'tar.gz'}`);
const line = (n, i) => `${String(i + 1).repeat(64).slice(0, 64)}  ${n}`;

function run(lines, version = V) {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'checksums.txt'), lines.join('\n') + '\n');
  const out = path.join(d, 'checksums.json');
  const r = spawnSync(process.execPath, [script, version, path.join(d, 'checksums.txt'), out], { encoding: 'utf8' });
  return { r, out };
}

test('pins all six archives and ignores other lines', () => {
  const { r, out } = run([...names.map(line), `${'f'.repeat(64)}  something_else.sbom`]);
  assert.strictEqual(r.status, 0, r.stderr);
  const j = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.strictEqual(j.version, V);
  assert.deepStrictEqual(Object.keys(j.archives), names);
  assert.strictEqual(j.archives[names[0]], '1'.repeat(64));
});

test('fails when a platform is missing, duplicated, or the version is bad', () => {
  let x = run(names.slice(1).map(line));
  assert.strictEqual(x.r.status, 1);
  assert.match(x.r.stderr, /missing/);
  assert.ok(!fs.existsSync(x.out));
  x = run([...names.map(line), line(names[0], 8)]);
  assert.strictEqual(x.r.status, 1);
  assert.match(x.r.stderr, /duplicate/);
  assert.strictEqual(run(names.map(line), '0.0.0').r.status, 2);
  assert.strictEqual(run(names.map(line), '../x').r.status, 2);
});
