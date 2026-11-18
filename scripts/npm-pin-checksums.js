#!/usr/bin/env node
'use strict';
// Writes packaging/npm/checksums.json from a release's checksums.txt, so the
// npm package carries the SHA-256 of every archive it may download.
//
//   node scripts/npm-pin-checksums.js VERSION checksums.txt [OUT.json]
//
// Fails unless all six archives (macOS, Linux, Windows x amd64, arm64) are
// present exactly once with a valid hash. Used by the npm-publish job and
// `make npm-pin`.

const fs = require('node:fs');
const path = require('node:path');

const [version, sumsFile, out = path.join(__dirname, '..', 'packaging', 'npm', 'checksums.json')] = process.argv.slice(2);
if (!version || !sumsFile) {
  console.error('usage: npm-pin-checksums.js VERSION checksums.txt [OUT.json]');
  process.exit(2);
}
if (!/^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$/.test(version) || version === '0.0.0') {
  console.error(`not a release version: ${version}`);
  process.exit(2);
}

const want = [];
for (const os of ['darwin', 'linux', 'windows']) {
  for (const arch of ['amd64', 'arm64']) want.push(`secrets-vault_${version}_${os}_${arch}.${os === 'windows' ? 'zip' : 'tar.gz'}`);
}
const archives = {};
for (const line of fs.readFileSync(sumsFile, 'utf8').split(/\r?\n/)) {
  const m = /^([0-9a-fA-F]{64})[ \t]+\*?(.+?)\s*$/.exec(line);
  if (!m || !want.includes(m[2])) continue;
  if (archives[m[2]]) { console.error(`duplicate entry for ${m[2]}`); process.exit(1); }
  archives[m[2]] = m[1].toLowerCase();
}
const missing = want.filter((n) => !archives[n]);
if (missing.length) {
  console.error(`checksums.txt is missing: ${missing.join(', ')}`);
  process.exit(1);
}
fs.writeFileSync(out, `${JSON.stringify({ version, archives: Object.fromEntries(want.map((n) => [n, archives[n]])) }, null, 2)}\n`);
console.error(`pinned ${want.length} archives for ${version} in ${out}`);
