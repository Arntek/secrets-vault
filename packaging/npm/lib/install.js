#!/usr/bin/env node
'use strict';
// postinstall: fetch the secrets-vault program for this machine.
//
//   - Downloads the release whose version equals this package's version,
//     over HTTPS only, from GitHub Releases (or a mirror you name).
//   - Verifies the archive's SHA-256 against the value PINNED INSIDE THIS
//     npm package (checksums.json, written at publish time from the
//     release's checksums.txt). The download location, GitHub or a mirror,
//     is never trusted for the hash, so replacing release assets or running
//     a mirror cannot get a different program installed. Any mismatch,
//     missing pin or error stops the install: it fails closed.
//   - No dependencies, no telemetry, no other network calls.
//
// Environment:
//   SECRETS_VAULT_BINARY_PATH  use this existing program, download nothing
//                              (also read at run time by the launcher)
//   SECRETS_VAULT_MIRROR       base location holding the archive: an
//                              https:// URL or a local folder (an offline
//                              mirror). The pinned checksum is still
//                              verified; checksums.txt is not used.
//   Both name the program that will receive your passphrases and values:
//   never take them from an untrusted environment (CI config, .env files).

const crypto = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');
const path = require('node:path');
const { target, archiveName, vendorPath } = require('./platform.js');
const { fromTarGz, fromZip } = require('./extract.js');

const DEFAULT_BASE = 'https://github.com/Arntek/secrets-vault/releases/download';
const MAX_DOWNLOAD = 100 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 60000;

function fail(msg) {
  const e = new Error(msg);
  e.installError = true;
  return e;
}

// HTTPS GET into memory. Redirects are followed only to https URLs.
function get(url, redirects = MAX_REDIRECTS) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch { return reject(fail('not a valid download address')); }
    if (u.protocol !== 'https:') return reject(fail(`refusing a non-HTTPS download address (${u.protocol})`));
    const req = https.get(u, { headers: { 'user-agent': 'secrets-vault-npm-installer' }, timeout: TIMEOUT_MS }, (res) => {
      const code = res.statusCode || 0;
      if ([301, 302, 303, 307, 308].includes(code) && res.headers.location) {
        res.resume();
        if (redirects <= 0) return reject(fail('too many redirects'));
        return resolve(get(new URL(res.headers.location, u).toString(), redirects - 1));
      }
      if (code !== 200) { res.resume(); return reject(fail(`download failed: HTTP ${code} for ${u.pathname.split('/').pop()}`)); }
      const chunks = [];
      let n = 0;
      res.on('data', (c) => {
        n += c.length;
        if (n > MAX_DOWNLOAD) { req.destroy(fail('download is larger than expected')); return; }
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(fail('download timed out')));
    req.on('error', reject);
  });
}

// Reads `name` from the mirror: an https URL or a local folder.
async function fetchFile(base, name) {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(base) && !/^https:\/\//i.test(base)) {
    throw fail('SECRETS_VAULT_MIRROR must be an https:// address or a local folder');
  }
  if (/^https:\/\//i.test(base)) return get(`${base.replace(/\/+$/, '')}/${name}`);
  const file = path.join(base, name);
  const st = fs.statSync(file, { throwIfNoEntry: false });
  if (!st || !st.isFile()) throw fail(`${name} is not in the mirror folder`);
  if (st.size > MAX_DOWNLOAD) throw fail(`${name} is larger than expected`);
  return fs.readFileSync(file);
}

// The pinned hashes shipped in this package: { version, archives: {name: sha256} }.
function loadPins(root) {
  let j;
  try {
    j = JSON.parse(fs.readFileSync(path.join(root, 'checksums.json'), 'utf8'));
  } catch {
    throw fail('this package has no pinned checksums (checksums.json); install it from the npm registry');
  }
  if (!j || typeof j !== 'object' || typeof j.version !== 'string' || !j.archives || typeof j.archives !== 'object') {
    throw fail('checksums.json is malformed');
  }
  return j;
}

function pinnedHash(pins, version, name) {
  if (pins.version !== version) throw fail(`pinned checksums are for ${pins.version}, not ${version}`);
  const h = Object.prototype.hasOwnProperty.call(pins.archives, name) ? pins.archives[name] : undefined;
  if (typeof h !== 'string' || !/^[0-9a-fA-F]{64}$/.test(h)) throw fail(`no pinned checksum for ${name}`);
  return h.toLowerCase();
}

async function install(opts = {}) {
  const env = opts.env || process.env;
  const t = target(opts.platform, opts.arch);
  const root = opts.root || path.join(__dirname, '..');
  const version = opts.version || JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
  const log = opts.log || ((m) => process.stderr.write(`${m}\n`));

  const given = env.SECRETS_VAULT_BINARY_PATH;
  if (given) {
    if (!fs.statSync(given, { throwIfNoEntry: false })?.isFile()) throw fail('SECRETS_VAULT_BINARY_PATH does not point to a file');
    log(`secrets-vault: using the program at SECRETS_VAULT_BINARY_PATH; nothing downloaded`);
    return { path: given, downloaded: false };
  }

  if (!/^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$/.test(version) || version === '0.0.0') {
    throw fail(`this package has no release version (${version}); install it from the npm registry`);
  }
  const name = archiveName(version, t);
  const want = pinnedHash(opts.pins || loadPins(root), version, name); // before any download
  const base = env.SECRETS_VAULT_MIRROR || `${DEFAULT_BASE}/v${version}`;
  log(`secrets-vault: fetching ${name}`);

  const archive = await fetchFile(base, name);
  const got = crypto.createHash('sha256').update(archive).digest('hex');
  if (got !== want) throw fail(`checksum mismatch for ${name}: refusing to install`);

  let exe;
  try {
    exe = t.windows ? fromZip(archive, t.exe) : fromTarGz(archive, t.exe);
  } catch (e) {
    throw fail(`could not unpack ${name}: ${e.message}`);
  }
  const dest = vendorPath(t, root);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  const tmp = `${dest}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, exe, { mode: 0o755 });
  fs.renameSync(tmp, dest);
  log(`secrets-vault: installed ${version} (${t.os}/${t.arch})`);
  return { path: dest, downloaded: true };
}

if (require.main === module) {
  install().catch((e) => {
    process.stderr.write(`secrets-vault install failed: ${e.installError ? e.message : (e.code || e.message)}\n`);
    process.stderr.write('Nothing was installed. See the README for SECRETS_VAULT_MIRROR and SECRETS_VAULT_BINARY_PATH.\n');
    process.exit(1);
  });
}

module.exports = { install, loadPins, pinnedHash, get };
