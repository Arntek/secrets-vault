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

const { spawn, execFileSync } = require('node:child_process');
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
const NOT_INSTALLED = 'the secrets-vault program was not found; install it (brew or npm install -g secrets-vault) or set SECRETS_VAULT_BINARY_PATH';

function badName(s) {
  return typeof s !== 'string' || s === '' || s.startsWith('-') || /[\0\r\n]/.test(s);
}

// Finds the real program. npm's Windows shim is a .cmd that cannot be run
// without a shell, so look for the .exe it wraps. On Windows the result is
// always an absolute path found on PATH (absolute entries only, never the
// current folder) or the npm global folder; a bare name would let
// CreateProcess pick up a secrets-vault.exe lying in the current folder.
function findExecutable(opts = {}, env = process.env, platform = process.platform) {
  if (opts.executable) return opts.executable;
  if (env.SECRETS_VAULT_BINARY_PATH) return env.SECRETS_VAULT_BINARY_PATH;
  if (platform !== 'win32') {
    try {
      const { target, vendorPath } = require(require.resolve('secrets-vault/lib/platform.js'));
      const p = vendorPath(target(), path.dirname(require.resolve('secrets-vault/package.json')));
      if (fs.existsSync(p)) return p;
    } catch {
      // secrets-vault is not an npm dependency here; use PATH.
    }
    return EXE;
  }
  try {
    const { vendorPath, target } = require(require.resolve('secrets-vault/lib/platform.js'));
    const p = vendorPath(target(), path.dirname(require.resolve('secrets-vault/package.json')));
    if (path.win32.isAbsolute(p) && fs.existsSync(p)) return p;
  } catch {
    // not an npm dependency here
  }
  for (const d of (env.PATH || '').split(';')) {
    if (!d || !path.win32.isAbsolute(d)) continue; // "" and "." mean the current folder
    const p = path.win32.join(d, `${EXE}.exe`);
    if (fs.existsSync(p)) return p;
  }
  if (env.APPDATA && path.win32.isAbsolute(env.APPDATA)) {
    const p = path.win32.join(env.APPDATA, 'npm', 'node_modules', 'secrets-vault', 'vendor', `${EXE}.exe`);
    if (fs.existsSync(p)) return p;
  }
  throw new SecretsVaultNotInstalledError(NOT_INSTALLED);
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
    return new SecretsVaultNotInstalledError(NOT_INSTALLED);
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
// VaultLockedError. true gives the program your terminal (stdin and stderr
// are inherited, so it can show its prompt and read the passphrase); only
// stdout, the value, is captured.
function getSecret(name, opts = {}) {
  return new Promise((resolve, reject) => {
    let args;
    let exe;
    try {
      args = buildArgs(name, opts);
      exe = findExecutable(opts);
    } catch (e) {
      return reject(e);
    }
    const interactive = Boolean(opts.interactive);
    const child = spawn(exe, args, {
      stdio: interactive ? ['inherit', 'pipe', 'inherit'] : ['ignore', 'pipe', 'pipe'],
      windowsHide: !interactive,
      shell: false,
    });
    const out = [];
    const err = [];
    let outLen = 0;
    let timedOut = false;
    let overflow = false;
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, opts.timeout ?? 60000);
    child.stdout.on('data', (c) => {
      outLen += c.length;
      if (outLen > MAX_VALUE) { overflow = true; child.kill(); return; }
      out.push(c);
    });
    if (child.stderr) child.stderr.on('data', (c) => { if (err.length < 64) err.push(c); });
    child.on('error', (e) => { clearTimeout(timer); reject(mapFailure(name, opts, null, '', e.code, false)); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (timedOut) return reject(mapFailure(name, opts, null, '', null, true));
      if (overflow) return reject(new SecretsVaultError('the value is larger than expected'));
      if (code === 0) {
        try {
          return resolve(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(out)));
        } catch {
          return reject(new SecretsVaultError(`the value of key '${name}' is not valid UTF-8 text`, 0));
        }
      }
      reject(mapFailure(name, opts, code, Buffer.concat(err).toString('utf8'), null, false));
    });
  });
}

// Same, blocking. Not interactive.
function getSecretSync(name, opts = {}) {
  const args = buildArgs(name, opts);
  const exe = findExecutable(opts);
  try {
    const out = execFileSync(exe, args, { ...execOptions(opts), stdio: ['ignore', 'pipe', 'pipe'] });
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
  findExecutable,
  getSecret,
  getSecretSync,
  SecretsVaultError,
  VaultLockedError,
  SecretNotFoundError,
  VaultUnverifiedError,
  SecretsVaultNotInstalledError,
};
