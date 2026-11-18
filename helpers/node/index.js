'use strict';
// Read one secret from secrets-vault, for one script, without leaking it.
//
//   const { getSecret } = require('./index.js');
//   const apiKey = await getSecret('EXAMPLE_API_KEY', { vault: 'work' });
//
// Runs `secrets-vault get NAME` with execFile: no shell, stdout captured.
// Exit codes become typed errors. The value is never logged and never put in
// an error message. Node 18+, no dependencies.
//
// Prefer `secrets-vault run -k NAME -- your-command` when you can: then the
// script never holds the value. Use this when it must.

const { execFile, execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

class SecretsVaultError extends Error {
  constructor(message, exitCode = null) {
    super(message);
    this.name = this.constructor.name;
    this.exitCode = exitCode;
  }
}
class VaultLockedError extends SecretsVaultError {} // exit 3
class SecretNotFoundError extends SecretsVaultError {} // exit 4
class VaultUnverifiedError extends SecretsVaultError {} // exit 5
class SecretsVaultNotInstalledError extends SecretsVaultError {}

const EXE = 'secrets-vault';
const MAX_STDERR = 500;
const MAX_VALUE = 2 * 1024 * 1024;

function badName(s) {
  return typeof s !== 'string' || s === '' || s.startsWith('-') || /[\0\r\n]/.test(s);
}

// Finds the real program. npm's Windows shim is a .cmd that execFile cannot
// run, so look for the .exe it wraps.
function findExecutable(opts = {}, env = process.env) {
  if (opts.executable) return opts.executable;
  if (env.SECRETS_VAULT_BINARY_PATH) return env.SECRETS_VAULT_BINARY_PATH;
  try {
    const { target, vendorPath } = require(require.resolve('secrets-vault/lib/platform.js'));
    const p = vendorPath(target(), path.dirname(require.resolve('secrets-vault/package.json')));
    if (fs.existsSync(p)) return p;
  } catch {
    // secrets-vault is not an npm dependency here; use PATH.
  }
  if (process.platform === 'win32') {
    for (const d of (env.PATH || '').split(path.delimiter)) {
      const p = path.join(d, `${EXE}.exe`);
      if (d && fs.existsSync(p)) return p;
    }
    if (env.APPDATA) {
      const p = path.join(env.APPDATA, 'npm', 'node_modules', 'secrets-vault', 'vendor', `${EXE}.exe`);
      if (fs.existsSync(p)) return p;
    }
    return `${EXE}.exe`;
  }
  return EXE;
}

function buildArgs(name, opts) {
  if (badName(name)) throw new TypeError('invalid secret name');
  if (opts.vault !== undefined && badName(opts.vault)) throw new TypeError('invalid vault name');
  // -n: no trailing newline, so the value comes back exactly as stored.
  const args = ['get', name, '-n'];
  if (opts.vault !== undefined) args.push('--vault', opts.vault);
  return args;
}

function mapFailure(name, opts, code, stderr, spawnCode, timedOut) {
  if (timedOut) return new SecretsVaultError('secrets-vault timed out');
  if (spawnCode === 'ENOENT') {
    return new SecretsVaultNotInstalledError(
      'the secrets-vault program was not found; install it (brew or npm install -g secrets-vault) or set SECRETS_VAULT_BINARY_PATH'
    );
  }
  if (typeof code !== 'number') return new SecretsVaultError(`could not run secrets-vault (${spawnCode || 'error'})`);
  const detail = String(stderr || '').replace(/\r/g, '').trim().slice(0, MAX_STDERR);
  const where = `key '${name}'${opts.vault ? ` in vault '${opts.vault}'` : ''}`;
  if (code === 3) return new VaultLockedError(detail || 'the vault is locked and cannot ask for a passphrase here', 3);
  if (code === 4) return new SecretNotFoundError(detail || `${where} was not found`, 4);
  if (code === 5) return new VaultUnverifiedError(detail || 'the vault failed verification', 5);
  return new SecretsVaultError(detail || `secrets-vault failed (exit ${code})`, code);
}

function execOptions(opts) {
  const o = { timeout: opts.timeout ?? 60000, maxBuffer: MAX_VALUE, windowsHide: true, encoding: 'buffer', shell: false };
  return o;
}

// getSecret(name, { vault, executable, timeout (ms), interactive }) -> Promise<string>
// interactive: false (default) never prompts, so a locked vault rejects with
// VaultLockedError. true lets the program ask for the passphrase on the
// terminal (its prompt goes to stderr, which is then passed through).
function getSecret(name, opts = {}) {
  return new Promise((resolve, reject) => {
    let args;
    try { args = buildArgs(name, opts); } catch (e) { return reject(e); }
    let piped = false;
    const child = execFile(findExecutable(opts), args, { ...execOptions(opts) }, (err, stdout, stderr) => {
      if (piped) { process.stdin.unpipe(child.stdin); process.stdin.pause(); }
      if (!err) {
        try {
          return resolve(new TextDecoder('utf-8', { fatal: true }).decode(stdout));
        } catch {
          return reject(new SecretsVaultError(`the value of key '${name}' is not valid UTF-8 text`, 0));
        }
      }
      reject(mapFailure(name, opts, typeof err.code === 'number' ? err.code : null, stderr && stderr.toString('utf8'), err.code, err.killed && err.signal));
    });
    if (opts.interactive) {
      // Let the program read the passphrase from the terminal and show its prompt.
      if (process.stdin.isTTY) { process.stdin.pipe(child.stdin); piped = true; }
      child.stderr.pipe(process.stderr);
    } else {
      child.stdin.end();
    }
  });
}

// Same, blocking. Not interactive.
function getSecretSync(name, opts = {}) {
  const args = buildArgs(name, opts);
  try {
    const out = execFileSync(findExecutable(opts), args, { ...execOptions(opts), stdio: ['ignore', 'pipe', 'pipe'] });
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(out);
    } catch {
      throw new SecretsVaultError(`the value of key '${name}' is not valid UTF-8 text`, 0);
    }
  } catch (err) {
    if (err instanceof SecretsVaultError) throw err;
    throw mapFailure(name, opts, typeof err.status === 'number' ? err.status : null, err.stderr && err.stderr.toString('utf8'), err.code, err.code === 'ETIMEDOUT');
  }
}

module.exports = {
  getSecret,
  getSecretSync,
  SecretsVaultError,
  VaultLockedError,
  SecretNotFoundError,
  VaultUnverifiedError,
  SecretsVaultNotInstalledError,
};
