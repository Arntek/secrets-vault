'use strict';
// Maps Node's platform names to the names used in release archives, and
// computes the archive name and where the program is kept.

const path = require('node:path');

const OS = { darwin: 'darwin', linux: 'linux', win32: 'windows' };
const ARCH = { x64: 'amd64', arm64: 'arm64' };

function target(platform = process.platform, arch = process.arch) {
  const os = OS[platform];
  const cpu = ARCH[arch];
  if (!os || !cpu) {
    throw new Error(`secrets-vault has no build for ${platform}/${arch} (supported: macOS, Linux and Windows on x64 or arm64)`);
  }
  const windows = os === 'windows';
  return { os, arch: cpu, windows, ext: windows ? 'zip' : 'tar.gz', exe: windows ? 'secrets-vault.exe' : 'secrets-vault' };
}

function archiveName(version, t) {
  return `secrets-vault_${version}_${t.os}_${t.arch}.${t.ext}`;
}

// The installed program: <package>/vendor/secrets-vault[.exe].
function vendorPath(t, root = path.join(__dirname, '..')) {
  return path.join(root, 'vendor', t.exe);
}

module.exports = { target, archiveName, vendorPath };
