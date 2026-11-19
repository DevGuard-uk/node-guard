/**
 * DevGuard Secured-Export CLI & Packaging Engine
 *
 * Encrypts server-side Node.js / Express / Next.js server targets with AES-256-GCM,
 * generates Ed25519-signed manifest, and creates an isolated dist-secured/ artifact
 * with an in-memory runtime bootloader.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { computeCanonicalSignableString } = require('./bootloader');

/**
 * Encrypts a source file or buffer into a secured export bundle.
 *
 * @param {object} options
 * @param {string} [options.entry] Path to entrypoint file
 * @param {string|Buffer} [options.code] Raw source code buffer/string if entry is omitted
 * @param {string} [options.outDir='dist-secured'] Target output directory
 * @param {string} options.projectId DevGuard Project ID
 * @param {string|Buffer} [options.key] 32-byte AES-256 key (hex or Buffer). Generated if omitted.
 * @param {'per-boot'|'permanent-key'|'dual'} [options.mode='per-boot'] Key custody mode
 * @param {string|crypto.KeyObject} [options.signingPrivateKey] Ed25519 private key (PEM/KeyObject)
 * @param {string|crypto.KeyObject} [options.signingPublicKey] Ed25519 public key (PEM/KeyObject)
 * @param {boolean} [options.copyBootloader=true] Whether to include standalone bootloader in bundle
 * @param {string} [options.apiUrl] DevGuard API URL
 * @param {string} [options.apiKey] DevGuard API Key
 * @param {boolean} [options.registerKeyWithApi=false] Register key with DevGuard API
 * @param {object} [options.metadata] Additional metadata to record in manifest
 * @returns {Promise<object>} Export manifest, keys, and paths
 */
async function exportSecure(options = {}) {
  if (!options.projectId) {
    throw new Error('exportSecure: `projectId` is required');
  }

  // 1. Read source code
  let sourceBuffer;
  let entryFileName = 'server.js';

  if (options.code != null) {
    sourceBuffer = Buffer.isBuffer(options.code) ? options.code : Buffer.from(String(options.code), 'utf8');
    if (options.entry) {
      entryFileName = path.basename(options.entry);
    }
  } else if (options.entry) {
    const resolvedPath = path.resolve(options.entry);
    if (!fs.existsSync(resolvedPath)) {
      throw new Error(`exportSecure: Entry file not found at ${resolvedPath}`);
    }
    sourceBuffer = fs.readFileSync(resolvedPath);
    entryFileName = path.basename(resolvedPath);
  } else {
    throw new Error('exportSecure: Either `entry` file path or `code` must be provided');
  }

  // 2. Resolve AES-256 Key (32 bytes)
  let keyBuffer;
  if (options.key) {
    if (Buffer.isBuffer(options.key)) {
      if (options.key.length !== 32) {
        throw new Error(`exportSecure: Key Buffer must be exactly 32 bytes (got ${options.key.length})`);
      }
      keyBuffer = options.key;
    } else if (typeof options.key === 'string') {
      const trimmed = options.key.trim();
      if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
        keyBuffer = Buffer.from(trimmed, 'hex');
      } else if (Buffer.byteLength(trimmed, 'utf8') === 32) {
        keyBuffer = Buffer.from(trimmed, 'utf8');
      } else {
        throw new Error('exportSecure: Key string must be 64-character hex or 32-byte UTF-8 string');
      }
    } else {
      throw new Error('exportSecure: Invalid key option type');
    }
  } else {
    keyBuffer = crypto.randomBytes(32);
  }

  // 3. Generate random 12-byte IV for AES-256-GCM
  const ivBuffer = crypto.randomBytes(12);

  // 4. Encrypt source with AES-256-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, ivBuffer);
  const ciphertext = Buffer.concat([cipher.update(sourceBuffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // 5. Payload hash
  const payloadHash = 'sha256:' + crypto.createHash('sha256').update(ciphertext).digest('hex');

  // 6. Ed25519 Keypair for integrity signing
  let privateKeyObj = options.signingPrivateKey;
  let publicKeyPem = options.signingPublicKey;
  let generatedKeypair = null;

  if (!privateKeyObj) {
    generatedKeypair = crypto.generateKeyPairSync('ed25519');
    privateKeyObj = generatedKeypair.privateKey;
    publicKeyPem = generatedKeypair.publicKey.export({ type: 'spki', format: 'pem' });
  } else {
    if (typeof publicKeyPem !== 'string' && publicKeyPem && typeof publicKeyPem.export === 'function') {
      publicKeyPem = publicKeyPem.export({ type: 'spki', format: 'pem' });
    }
  }

  const mode = options.mode || 'per-boot';
  const target = (options.target || 'node').toLowerCase();

  // 7. Sign canonical manifest
  const canonicalData = computeCanonicalSignableString({
    projectId: options.projectId,
    payloadHash,
    iv: ivBuffer.toString('hex'),
    authTag: authTag.toString('hex'),
    mode,
  });

  const signature = crypto.sign(null, Buffer.from(canonicalData, 'utf8'), privateKeyObj).toString('hex');

  // 8. Build manifest
  const manifest = {
    format: 'devguard-secured-export',
    version: '1.0.0',
    target,
    projectId: options.projectId,
    entry: entryFileName,
    algorithm: 'aes-256-gcm',
    payloadHash,
    iv: ivBuffer.toString('hex'),
    authTag: authTag.toString('hex'),
    mode,
    publicKey: publicKeyPem,
    signature,
    createdAt: new Date().toISOString(),
    ...(options.metadata && typeof options.metadata === 'object' ? options.metadata : {}),
  };

  // 9. Write outputs to outDir
  const outDir = path.resolve(options.outDir || 'dist-secured');
  fs.mkdirSync(outDir, { recursive: true });

  const payloadPath = path.join(outDir, 'payload.enc');
  const manifestPath = path.join(outDir, 'manifest.json');
  fs.writeFileSync(payloadPath, ciphertext);
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

  if (target === 'node') {
    if (options.copyBootloader !== false) {
      const bootloaderSrc = fs.readFileSync(path.join(__dirname, 'bootloader.js'), 'utf8');
      fs.writeFileSync(path.join(outDir, 'bootloader.js'), bootloaderSrc, 'utf8');

      const indexSrc = `'use strict';
const { boot } = require('./bootloader');

// Automatic boot on module load
module.exports = boot();
`;
      fs.writeFileSync(path.join(outDir, 'index.js'), indexSrc, 'utf8');

      const pkgJsonPath = path.join(outDir, 'package.json');
      if (!fs.existsSync(pkgJsonPath)) {
        const minimalPkg = {
          name: 'secured-application',
          version: '1.0.0',
          private: true,
          main: 'index.js',
          scripts: {
            start: 'node index.js',
          },
        };
        fs.writeFileSync(pkgJsonPath, JSON.stringify(minimalPkg, null, 2), 'utf8');
      }
    }
  } else if (target === 'laravel') {
    // Scaffold Laravel Secured Bundle
    const configDir = path.join(outDir, 'config');
    fs.mkdirSync(configDir, { recursive: true });

    const laravelConfigSrc = `<?php
return [
    'enabled' => env('DEVGUARD_ENABLED', true),
    'project_id' => env('DEVGUARD_PROJECT_ID', ${JSON.stringify(options.projectId)}),
    'api_url' => env('DEVGUARD_API_URL', 'https://api.devguard.uk'),
    'api_key' => env('DEVGUARD_API_KEY', null),
    'allowed_domains' => env('DEVGUARD_ALLOWED_DOMAINS')
        ? array_map('trim', explode(',', env('DEVGUARD_ALLOWED_DOMAINS')))
        : null,
    'fail_safe' => env('DEVGUARD_FAIL_SAFE', 'open'),
    'cache_ttl' => (int) env('DEVGUARD_CACHE_TTL', 300),
    'trust_proxy' => (bool) env('DEVGUARD_TRUST_PROXY', false),
    'allowed_paths' => [
        '/health',
        '/api/health',
        '/robots.txt',
        '/favicon.ico',
        '/.well-known',
    ],
];
`;
    fs.writeFileSync(path.join(configDir, 'devguard.php'), laravelConfigSrc, 'utf8');

    const bootstrapSrc = `<?php
/**
 * DevGuard Secured Laravel Bootstrap
 *
 * Generated by DevGuard Secured-Export CLI for Project: ${options.projectId}
 */
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}
`;
    fs.writeFileSync(path.join(outDir, 'devguard_bootstrap.php'), bootstrapSrc, 'utf8');

    const pkgJsonPath = path.join(outDir, 'composer.json');
    if (!fs.existsSync(pkgJsonPath)) {
      const composerPkg = {
        name: 'secured-laravel-bundle',
        description: `DevGuard secured Laravel bundle for project ${options.projectId}`,
        require: {
          'php': '>=7.4 || >=8.0',
          'devguard/devguard-laravel': '^1.0',
        },
      };
      fs.writeFileSync(pkgJsonPath, JSON.stringify(composerPkg, null, 2), 'utf8');
    }
  } else if (target === 'python') {
    // Scaffold Python Secured WSGI/ASGI Bundle
    const wsgiSrc = `"""DevGuard Secured WSGI Application Wrapper.
Generated by DevGuard Secured-Export CLI for Project: ${options.projectId}
"""
import os
from devguard_python_guard import DevGuardWSGIMiddleware

def wrap_wsgi(app):
    return DevGuardWSGIMiddleware(
        app,
        project_id=os.getenv("DEVGUARD_PROJECT_ID", ${JSON.stringify(options.projectId)}),
        api_url=os.getenv("DEVGUARD_API_URL", "https://api.devguard.uk"),
        fail_safe=True,
    )
`;
    fs.writeFileSync(path.join(outDir, 'wsgi.py'), wsgiSrc, 'utf8');

    const asgiSrc = `"""DevGuard Secured ASGI Application Wrapper (FastAPI / Starlette).
Generated by DevGuard Secured-Export CLI for Project: ${options.projectId}
"""
import os
from devguard_python_guard import DevGuardASGIMiddleware

def wrap_asgi(app):
    return DevGuardASGIMiddleware(
        app,
        project_id=os.getenv("DEVGUARD_PROJECT_ID", ${JSON.stringify(options.projectId)}),
        api_url=os.getenv("DEVGUARD_API_URL", "https://api.devguard.uk"),
        fail_safe=True,
    )
`;
    fs.writeFileSync(path.join(outDir, 'asgi.py'), asgiSrc, 'utf8');

    const reqPath = path.join(outDir, 'requirements.txt');
    if (!fs.existsSync(reqPath)) {
      fs.writeFileSync(reqPath, 'devguard-python-guard>=1.0.0\n', 'utf8');
    }
  }

  // 10. Optional API key registration
  if (options.registerKeyWithApi && options.apiKey) {
    const apiUrl = (options.apiUrl || process.env.DEVGUARD_API_URL || 'https://api.devguard.uk').replace(/\/+$/, '');
    const endpoint = `${apiUrl}/api/v1/projects/${encodeURIComponent(options.projectId)}/secured-export/key`;

    if (typeof globalThis.fetch === 'function') {
      const res = await globalThis.fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${options.apiKey}`,
          'X-DevGuard-Key': options.apiKey,
        },
        body: JSON.stringify({
          key: keyBuffer.toString('hex'),
          mode,
          payloadHash,
        }),
      });
      if (!res.ok) {
        console.warn(`[exportSecure] Warning: Failed to register secured-export key with API (HTTP ${res.status})`);
      }
    }
  }

  return {
    outDir,
    payloadPath,
    manifestPath,
    key: keyBuffer.toString('hex'),
    keyBuffer,
    iv: ivBuffer.toString('hex'),
    authTag: authTag.toString('hex'),
    payloadHash,
    manifest,
    publicKey: publicKeyPem,
    privateKey: generatedKeypair ? generatedKeypair.privateKey.export({ type: 'pkcs8', format: 'pem' }) : null,
  };
}

module.exports = {
  exportSecure,
};
