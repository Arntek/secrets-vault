'use strict';
// Starts the real program. sv, vault and secrets-vault are three tiny
// scripts that call run() with their own name, which is passed on as the
// program's argv[0] so help and messages use the name the user typed.

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const { target, vendorPath } = require('./platform.js');

function binaryPath() {
  const override = process.env.SECRETS_VAULT_BINARY_PATH;
  if (override) return override;
  return vendorPath(target());
}

function run(name) {
  let bin;
  try {
    bin = binaryPath();
  } catch (e) {
    process.stderr.write(`${name}: ${e.message}\n`);
    process.exit(1);
  }
  if (!fs.existsSync(bin)) {
    process.stderr.write(
      `${name}: the secrets-vault program is missing (${bin}).\n` +
        'The install step that downloads it did not run (npm --ignore-scripts?). ' +
        'Reinstall with: npm install -g secrets-vault\n'
    );
    process.exit(1);
  }
  const r = spawnSync(bin, process.argv.slice(2), {
    stdio: 'inherit',
    argv0: name,
    windowsHide: true,
  });
  if (r.error) {
    process.stderr.write(`${name}: could not start the program: ${r.error.code || 'error'}\n`);
    process.exit(1);
  }
  if (r.signal) {
    process.kill(process.pid, r.signal);
    return;
  }
  process.exit(r.status === null ? 1 : r.status);
}

module.exports = { run, binaryPath };
