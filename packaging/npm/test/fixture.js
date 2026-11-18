'use strict';
// Builds a fake release folder (archives + checksums.txt) in a temp dir, so
// installer tests never touch the network.

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { target, archiveName } = require('../lib/platform.js');

function tarEntry(name, data) {
  const h = Buffer.alloc(512);
  h.write(name, 0, 'utf8');
  h.write('0000755\0', 100, 'ascii');
  h.write('0000000\0', 108, 'ascii');
  h.write('0000000\0', 116, 'ascii');
  h.write(data.length.toString(8).padStart(11, '0') + '\0', 124, 'ascii');
  h.write('00000000000\0', 136, 'ascii');
  h.write('        ', 148, 'ascii');
  h.write('0', 156, 'ascii');
  h.write('ustar\0' + '00', 257, 'ascii');
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'ascii');
  const pad = Buffer.alloc((512 - (data.length % 512)) % 512);
  return Buffer.concat([h, data, pad]);
}

function tarGz(files) {
  const parts = Object.entries(files).map(([n, d]) => tarEntry(n, Buffer.from(d)));
  parts.push(Buffer.alloc(1024));
  return zlib.gzipSync(Buffer.concat(parts));
}

function crc32(buf) {
  let c, crc = 0xffffffff;
  for (const b of buf) {
    c = (crc ^ b) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crc = (crc >>> 8) ^ c;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function zip(files) {
  const locals = [];
  const central = [];
  let off = 0;
  for (const [name, d] of Object.entries(files)) {
    const data = Buffer.from(d);
    const comp = zlib.deflateRawSync(data);
    const nm = Buffer.from(name);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(8, 8);
    lh.writeUInt32LE(crc32(data), 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(nm.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(8, 10);
    ch.writeUInt32LE(crc32(data), 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(nm.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, nm, comp);
    central.push(ch, nm);
    off += 30 + nm.length + comp.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(files).length, 8); end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}

// makeRelease writes the archive for `platform/arch` plus checksums.txt.
// Options: tamper (change the archive after hashing), omit (leave the
// archive's line out of checksums.txt).
function makeRelease(version, { platform = process.platform, arch = process.arch, program = '#!/bin/sh\necho fake secrets-vault\n', tamper = false, omit = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'svnpm-rel-'));
  const t = target(platform, arch);
  const name = archiveName(version, t);
  const files = { LICENSE: 'MIT', 'README.md': 'readme', [t.exe]: program };
  const data = t.windows ? zip(files) : tarGz(files);
  const hash = crypto.createHash('sha256').update(data).digest('hex');
  const other = `${'a'.repeat(64)}  secrets-vault_${version}_plan9_amd64.tar.gz\n`;
  fs.writeFileSync(path.join(dir, 'checksums.txt'), other + (omit ? '' : `${hash}  ${name}\n`));
  fs.writeFileSync(path.join(dir, name), tamper ? Buffer.concat([data, Buffer.from('x')]) : data);
  return { dir, name, program, hash };
}

// pinned writes checksums.json into a package root, as the publish step does.
function pin(root, version, archives) {
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, 'checksums.json'), JSON.stringify({ version, archives }));
}

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'svnpm-'));
}

module.exports = { makeRelease, tarGz, zip, tmp, pin };
