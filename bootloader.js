/**
 * DevGuard Secured-Export Runtime Bootloader
 *
 * Verifies manifest integrity (Ed25519 signature + payload hash),
 * retrieves or validates AES-256-GCM decryption key, decrypts
 * server payload purely in RAM, and executes in memory (0 disk writes).
 *
 * Requirements: Node.js >= 16.0.0 (Standard built-ins only: crypto, fs, path, vm)
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const vm = require('vm');

/**
 * Computes canonical signable string for manifest integrity.
 */
function computeCanonicalSignableString(manifest) {
  if (!manifest) throw new Error('Manifest is required');
  return `${manifest.projectId}:${manifest.payloadHash}:${manifest.iv}:${manifest.authTag}:${manifest.mode}`;
}

/**
 * Verifies manifest signature and payload SHA-256 hash.
 */
function verifyManifestIntegrity(payloadBuffer, manifest, publicKeyOverride = null) {
  if (!Buffer.isBuffer(payloadBuffer)) {
    throw new Error('INTEGRITY_CHECK_FAILED: Payload buffer must be a valid Buffer');
  }
  if (!manifest || typeof manifest !== 'object') {
    throw new Error('INTEGRITY_CHECK_FAILED: Manifest must be an object');
  }

  // 1. Verify payload SHA-256 hash
  const computedHash = 'sha256:' + crypto.createHash('sha256').update(payloadBuffer).digest('hex');
  if (computedHash !== manifest.payloadHash) {
    throw new Error(`INTEGRITY_CHECK_FAILED: Payload hash mismatch (expected ${manifest.payloadHash}, got ${computedHash})`);
  }

  // 2. Verify Ed25519 signature
  const publicKey = publicKeyOverride || manifest.publicKey;
  if (!publicKey) {
    throw new Error('INTEGRITY_CHECK_FAILED: Missing public key for signature verification');
  }
  if (!manifest.signature) {
    throw new Error('INTEGRITY_CHECK_FAILED: Missing signature in manifest');
  }

  const canonical = computeCanonicalSignableString(manifest);
  const data = Buffer.from(canonical, 'utf8');
  const signatureBuffer = Buffer.from(manifest.signature, 'hex');

  const isValid = crypto.verify(null, data, publicKey, signatureBuffer);
  if (!isValid) {
    throw new Error('INTEGRITY_CHECK_FAILED: Ed25519 manifest signature verification failed');
  }

  return true;
}

/**
 * Normalizes an AES-256 key into a 32-byte Buffer.
 */
function normalizeKeyBuffer(keyInput) {
  if (!keyInput) return null;
  if (Buffer.isBuffer(keyInput)) {
    if (keyInput.length !== 32) {
      throw new Error(`Invalid key length: expected 32 bytes, got ${keyInput.length}`);
    }
    return keyInput;
  }
  if (typeof keyInput === 'string') {
    const trimmed = keyInput.trim();
    if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
      return Buffer.from(trimmed, 'hex');
    }
    const buf = Buffer.from(trimmed, 'utf8');
    if (buf.length === 32) {
      return buf;
    }
  }
  throw new Error('Invalid key format: expected 32-byte Buffer or 64-character hex string');
}

/**
 * Resolves the AES-256 decryption key.
 * 1. Checks local release key (env DEVGUARD_RELEASE_KEY or options.releaseKey)
 * 2. If absent, fetches per-boot key from DevGuard API endpoint
 */
async function resolveDecryptionKey(options = {}, manifest = {}) {
  // Option B: Local release key (Offline / Permanent)
  const localRaw = options.releaseKey || options.key || process.env.DEVGUARD_RELEASE_KEY;
  if (localRaw) {
    return normalizeKeyBuffer(localRaw);
  }

  // Option A: Per-Boot API key release
  const projectId = options.projectId || manifest.projectId || process.env.DEVGUARD_PROJECT_ID;
  if (!projectId) {
    throw new Error('KEY_RESOLUTION_FAILED: Missing projectId for remote key release');
  }

  const apiUrl = (options.apiUrl || process.env.DEVGUARD_API_URL || 'https://api.devguard.uk').replace(/\/+$/, '');
  const apiKey = options.apiKey || process.env.DEVGUARD_API_KEY;

  if (typeof options.fetchKey === 'function') {
    try {
      const fetched = await options.fetchKey({ projectId, apiUrl, apiKey });
      return normalizeKeyBuffer(typeof fetched === 'object' && fetched.key ? fetched.key : fetched);
    } catch (fetchErr) {
      const msg = fetchErr.message.includes('KEY_RELEASE_DENIED')
        ? fetchErr.message
        : `KEY_RELEASE_DENIED: ${fetchErr.message}`;
      const err = new Error(msg);
      err.status = fetchErr.status;
      throw err;
    }
  }

  const endpoint = `${apiUrl}/api/v1/projects/${encodeURIComponent(projectId)}/secured-export/key`;
  const headers = {
    'Accept': 'application/json',
    'User-Agent': 'DevGuard-Secured-Export-Bootloader/1.0.0',
  };
  if (apiKey) {
    headers['Authorization'] = `Bearer ${apiKey}`;
    headers['X-DevGuard-Key'] = apiKey;
  }

  if (typeof globalThis.fetch !== 'function') {
    throw new Error('KEY_RESOLUTION_FAILED: global fetch is not available in current Node runtime.');
  }

  let res;
  try {
    res = await globalThis.fetch(endpoint, {
      method: 'GET',
      headers,
    });
  } catch (netErr) {
    throw new Error(`KEY_RESOLUTION_FAILED: Network error fetching decryption key (${netErr.message})`);
  }

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const errJson = await res.json();
      detail = errJson.message || errJson.error || detail;
    } catch (_) {}
    const err = new Error(`KEY_RELEASE_DENIED: ${detail}`);
    err.status = res.status;
    throw err;
  }

  const body = await res.json();
  if (!body || !body.key) {
    throw new Error('KEY_RELEASE_DENIED: API response did not contain decryption key');
  }

  return normalizeKeyBuffer(body.key);
}

/**
 * Decrypts in-memory AES-256-GCM ciphertext buffer.
 */
function decryptPayload(payloadBuffer, manifest, keyBuffer) {
  const normKey = normalizeKeyBuffer(keyBuffer);
  const ivBuffer = Buffer.from(manifest.iv, 'hex');
  const authTagBuffer = Buffer.from(manifest.authTag, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', normKey, ivBuffer);
  decipher.setAuthTag(authTagBuffer);

  try {
    const decrypted = Buffer.concat([decipher.update(payloadBuffer), decipher.final()]);
    return decrypted;
  } catch (err) {
    throw new Error(`DECRYPTION_FAILED: AES-256-GCM decryption failed (${err.message})`);
  }
}

/**
 * Evaluates decrypted code purely in memory via Node.js vm (Zero disk writes).
 */
function executeInMemory(decryptedSource, context = {}) {
  const dirname = context.dirname || process.cwd();
  const filename = context.filename || path.join(dirname, context.entry || 'entry.js');
  const parentRequire = context.require || require;

  const customModule = {
    exports: {},
    id: filename,
    filename,
    loaded: false,
    children: [],
    paths: [],
  };

  const customRequire = function (modulePath) {
    if (modulePath.startsWith('./') || modulePath.startsWith('../')) {
      return parentRequire(path.resolve(dirname, modulePath));
    }
    return parentRequire(modulePath);
  };

  // Inherit standard require properties
  try {
    customRequire.resolve = (id, opts) => parentRequire.resolve(id, opts || { paths: [dirname] });
    customRequire.main = process.mainModule || parentRequire.main;
    customRequire.cache = parentRequire.cache;
  } catch (_) {}

  const sourceStr = Buffer.isBuffer(decryptedSource) ? decryptedSource.toString('utf8') : String(decryptedSource);
  const wrapper = `(function (exports, require, module, __filename, __dirname) {\n${sourceStr}\n})`;

  const script = new vm.Script(wrapper, {
    filename,
    lineOffset: 0,
    displayErrors: true,
  });

  const fn = script.runInThisContext();
  fn(customModule.exports, customRequire, customModule, filename, dirname);
  customModule.loaded = true;

  return customModule.exports;
}

/**
 * Main bootloader orchestrator.
 */
async function boot(options = {}) {
  const baseDir = options.dir || (options.manifestPath ? path.dirname(options.manifestPath) : __dirname);
  const manifestPath = options.manifestPath || path.join(baseDir, 'manifest.json');
  const payloadPath = options.payloadPath || path.join(baseDir, 'payload.enc');

  if (!fs.existsSync(manifestPath)) {
    throw new Error(`BOOT_FAILED: Manifest file not found at ${manifestPath}`);
  }
  if (!fs.existsSync(payloadPath)) {
    throw new Error(`BOOT_FAILED: Encrypted payload not found at ${payloadPath}`);
  }

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const payloadBuffer = fs.readFileSync(payloadPath);

  // 1. Verify integrity
  verifyManifestIntegrity(payloadBuffer, manifest, options.publicKey);

  // 2. Resolve decryption key
  const keyBuffer = await resolveDecryptionKey(options, manifest);

  // 3. Decrypt in memory
  const decrypted = decryptPayload(payloadBuffer, manifest, keyBuffer);

  // 4. Execute in memory (Zero disk writes)
  const exportsResult = executeInMemory(decrypted, {
    dirname: baseDir,
    filename: path.join(baseDir, manifest.entry || 'entry.js'),
    require: options.require || require,
    entry: manifest.entry,
    ...options.context,
  });

  return exportsResult;
}

/**
 * Synchronous boot helper when local release key is provided.
 */
function bootSync(options = {}) {
  const baseDir = options.dir || (options.manifestPath ? path.dirname(options.manifestPath) : __dirname);
  const manifestPath = options.manifestPath || path.join(baseDir, 'manifest.json');
  const payloadPath = options.payloadPath || path.join(baseDir, 'payload.enc');

  const rawKey = options.releaseKey || options.key || process.env.DEVGUARD_RELEASE_KEY;
  if (!rawKey) {
    throw new Error('bootSync requires local releaseKey or DEVGUARD_RELEASE_KEY env var');
  }
  const keyBuffer = normalizeKeyBuffer(rawKey);

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const payloadBuffer = fs.readFileSync(payloadPath);

  verifyManifestIntegrity(payloadBuffer, manifest, options.publicKey);
  const decrypted = decryptPayload(payloadBuffer, manifest, keyBuffer);

  return executeInMemory(decrypted, {
    dirname: baseDir,
    filename: path.join(baseDir, manifest.entry || 'entry.js'),
    require: options.require || require,
    entry: manifest.entry,
    ...options.context,
  });
}

module.exports = {
  boot,
  bootSync,
  computeCanonicalSignableString,
  verifyManifestIntegrity,
  resolveDecryptionKey,
  decryptPayload,
  executeInMemory,
  normalizeKeyBuffer,
};
