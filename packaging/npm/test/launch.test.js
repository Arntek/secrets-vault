'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { tmp } = require('./fixture.js');

const bin = (n) => path.join(__dirname, '..', 'bin', `${n}.js`);
const skip = process.platform === 'win32' ? 'uses a shell-script stand-in' : false;

function fake() {
  const p = path.join(tmp(), 'fake-sv');
  // Prints argv[0] as the program sees it, its arguments, and exits with code 7.
  fs.writeFileSync(p, '#!/bin/sh\necho "name=$0 args=$*"\nexit 7\n', { mode: 0o755 });
  return p;
}

test('each bin starts the program, passes arguments and the exit code', { skip }, () => {
  for (const n of ['sv', 'vault', 'secrets-vault']) {
    const r = spawnSync(process.execPath, [bin(n), 'get', 'A_KEY'], { env: { ...process.env, SECRETS_VAULT_BINARY_PATH: fake() }, encoding: 'utf8' });
    assert.strictEqual(r.status, 7);
    assert.match(r.stdout, /args=get A_KEY/);
  }
});

test('a missing program gives a clear message and exit 1', () => {
  const r = spawnSync(process.execPath, [bin('sv')], { env: { ...process.env, SECRETS_VAULT_BINARY_PATH: path.join(tmp(), 'nope') }, encoding: 'utf8' });
  assert.strictEqual(r.status, 1);
  assert.match(r.stderr, /program is missing/);
});
