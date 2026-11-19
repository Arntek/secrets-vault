'use strict';
// Minimal, dependency-free readers for the two archive formats the releases
// use. Each returns the bytes of ONE named file and never touches the disk,
// so a hostile archive cannot write anywhere: entry names are only compared,
// never used as paths.

const zlib = require('node:zlib');

const MAX_FILE = 200 * 1024 * 1024; // the program is ~6 MB; refuse anything absurd

function baseName(n) {
  const parts = String(n).split(/[\\/]+/).filter(Boolean);
  return parts[parts.length - 1] || '';
}

// tar.gz (ustar/GNU/pax): find a regular file whose base name is `want`.
function fromTarGz(buf, want) {
  const tar = zlib.gunzipSync(buf, { maxOutputLength: 2 * MAX_FILE });
  let off = 0;
  let longName = null;
  while (off + 512 <= tar.length) {
    const h = tar.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    let name = h.toString('utf8', 0, 100).replace(/\0.*$/s, '');
    const prefix = h.toString('utf8', 345, 500).replace(/\0.*$/s, '');
    if (prefix) name = `${prefix}/${name}`;
    const size = parseInt(h.toString('ascii', 124, 136).replace(/\0.*$/s, '').trim() || '0', 8);
    const type = String.fromCharCode(h[156] || 48);
    if (!Number.isFinite(size) || size < 0 || size > MAX_FILE) throw new Error('archive entry has a bad size');
    const start = off + 512;
    const end = start + size;
    if (end > tar.length) throw new Error('archive is truncated');
    if (type === 'L') {
      longName = tar.toString('utf8', start, end).replace(/\0.*$/s, '');
    } else if (type === '0' || type === '\0') {
      if (baseName(longName || name) === want) return Buffer.from(tar.subarray(start, end));
      longName = null;
    } else {
      longName = null;
    }
    off = start + Math.ceil(size / 512) * 512;
  }
  throw new Error(`${want} is not in the archive`);
}

// zip: read the central directory, inflate the entry named `want`.
function fromZip(buf, want) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('not a zip archive');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) throw new Error('zip directory is damaged');
    const method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20);
    const usize = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28);
    const elen = buf.readUInt16LE(p + 30);
    const clen = buf.readUInt16LE(p + 32);
    const lho = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nlen);
    p += 46 + nlen + elen + clen;
    if (name.endsWith('/') || baseName(name) !== want) continue;
    if (usize > MAX_FILE) throw new Error('archive entry is too large');
    if (lho + 30 > buf.length || buf.readUInt32LE(lho) !== 0x04034b50) throw new Error('zip entry is damaged');
    const start = lho + 30 + buf.readUInt16LE(lho + 26) + buf.readUInt16LE(lho + 28);
    if (start + csize > buf.length) throw new Error('archive is truncated');
    const raw = buf.subarray(start, start + csize);
    let out;
    if (method === 0) out = Buffer.from(raw);
    else if (method === 8) out = zlib.inflateRawSync(raw, { maxOutputLength: MAX_FILE });
    else throw new Error('zip uses an unsupported compression method');
    if (out.length !== usize) throw new Error('zip entry size does not match');
    return out;
  }
  throw new Error(`${want} is not in the archive`);
}

module.exports = { fromTarGz, fromZip };
