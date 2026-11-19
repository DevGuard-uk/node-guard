#!/usr/bin/env node
/**
 * DevGuard Web Telemetry Source Maps CLI
 *
 * Usage:
 *   devguard-sourcemaps upload --project <projectId> --release <release> --path <dirOrFile> --apiKey <key> [--endpoint <url>]
 *   npx devguard-sourcemaps upload -p <projectId> -r <release> --path <dirOrFile> -k <key>
 */

'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

function printUsage() {
  console.log(`
DevGuard Source Maps CLI (Web Telemetry Symbolication Pipeline)

Usage:
  devguard-sourcemaps upload [options]

Required Options for upload:
  -p, --project <id>     DevGuard Project ID
  -r, --release <tag>    Release version tag (e.g. 1.4.2 or commit SHA)
      --path <dirOrFile> Path to directory containing .map files, or a single .map file
  -k, --apiKey <key>     Developer Public API Key (dg_sk_*) or Project API Key

Optional:
      --endpoint <url>   DevGuard API endpoint URL (default: https://api.devguard.uk)
      --stripSources     Strip sourcesContent before uploading to protect raw source code
  -v, --version          Display version
  -h, --help             Show this help message

Example:
  npx devguard-sourcemaps upload --project dg-proj-12345 --release 1.4.2 --path ./dist --apiKey dg_sk_abc123
`);
}

/**
 * Recursively find all .map files in a directory or validate single file.
 */
function findMapFiles(targetPath) {
  const resolved = path.resolve(targetPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Target path does not exist: ${resolved}`);
  }

  const stat = fs.statSync(resolved);
  if (stat.isFile()) {
    if (!resolved.endsWith('.map')) {
      throw new Error(`File is not a source map (.map): ${resolved}`);
    }
    return [resolved];
  }

  const results = [];
  function walk(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules' && entry.name !== '.git') {
          walk(full);
        }
      } else if (entry.isFile() && entry.name.endsWith('.map')) {
        results.push(full);
      }
    }
  }

  walk(resolved);
  return results;
}

/**
 * Perform HTTP/HTTPS POST request with JSON payload.
 */
function postJson(urlStr, headers, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;

    const data = JSON.stringify(body);
    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        ...headers,
      },
    };

    const req = client.request(options, (res) => {
      let responseBody = '';
      res.on('data', (chunk) => {
        responseBody += chunk;
      });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(responseBody);
          resolve({ status: res.statusCode, data: parsed });
        } catch (_) {
          resolve({ status: res.statusCode, data: responseBody });
        }
      });
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.write(data);
    req.end();
  });
}

/**
 * Programmatic API for uploading source maps.
 */
async function uploadSourceMaps({
  projectId,
  release,
  targetPath,
  apiKey,
  endpoint = 'https://api.devguard.uk',
  stripSources = false,
}) {
  if (!projectId) throw new Error('Missing required parameter: projectId');
  if (!release) throw new Error('Missing required parameter: release');
  if (!targetPath) throw new Error('Missing required parameter: targetPath');
  if (!apiKey) throw new Error('Missing required parameter: apiKey');

  const files = findMapFiles(targetPath);
  if (files.length === 0) {
    console.log(`[devguard-sourcemaps] No .map files found in ${targetPath}`);
    return { ok: true, uploaded: 0, files: [] };
  }

  console.log(`[devguard-sourcemaps] Found ${files.length} source map(s) in ${targetPath}`);
  const cleanEndpoint = endpoint.replace(/\/+$/, '');
  const uploadUrl = `${cleanEndpoint}/api/v1/projects/${encodeURIComponent(projectId)}/sourcemaps`;

  const results = [];
  for (const filePath of files) {
    const filename = path.basename(filePath);
    const rawContent = fs.readFileSync(filePath, 'utf8');

    let mapObj;
    try {
      mapObj = JSON.parse(rawContent);
    } catch (err) {
      console.warn(`[devguard-sourcemaps] Skipping ${filename}: Invalid JSON (${err.message})`);
      continue;
    }

    if (!mapObj || Number(mapObj.version) !== 3) {
      console.warn(`[devguard-sourcemaps] Skipping ${filename}: Not a Source Map v3`);
      continue;
    }

    const payload = {
      release,
      filename,
      minifiedUrl: mapObj.file || filename.replace(/\.map$/, ''),
      mapContent: rawContent,
      stripSources,
    };

    const headers = {
      Authorization: `Bearer ${apiKey}`,
      'x-api-key': apiKey,
    };

    console.log(`[devguard-sourcemaps] Uploading ${filename} to ${uploadUrl}...`);
    const res = await postJson(uploadUrl, headers, payload);

    if (res.status >= 200 && res.status < 300) {
      console.log(`[devguard-sourcemaps]   ✓ ${filename} uploaded successfully (${res.data?.size || 0} bytes)`);
      results.push({ filename, status: 'uploaded', data: res.data });
    } else {
      console.error(
        `[devguard-sourcemaps]   ✗ Failed to upload ${filename} (${res.status}):`,
        res.data?.error || res.data
      );
      results.push({ filename, status: 'failed', error: res.data });
    }
  }

  const successCount = results.filter((r) => r.status === 'uploaded').length;
  return {
    ok: successCount === files.length,
    uploaded: successCount,
    total: files.length,
    results,
  };
}

async function runCli(argv = process.argv.slice(2)) {
  if (argv.includes('-h') || argv.includes('--help')) {
    printUsage();
    return 0;
  }

  if (argv.includes('-v') || argv.includes('--version')) {
    const pkg = require('../package.json');
    console.log(`devguard-sourcemaps v${pkg.version}`);
    return 0;
  }

  let command = 'upload';
  const filteredArgs = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === 'upload') {
      command = 'upload';
      continue;
    }
    filteredArgs.push(arg);
  }

  const options = {
    endpoint: process.env.DEVGUARD_ENDPOINT || 'https://api.devguard.uk',
    stripSources: false,
  };

  for (let i = 0; i < filteredArgs.length; i++) {
    const arg = filteredArgs[i];
    if (arg === '-p' || arg === '--project') {
      options.projectId = filteredArgs[++i];
    } else if (arg === '-r' || arg === '--release') {
      options.release = filteredArgs[++i];
    } else if (arg === '--path') {
      options.targetPath = filteredArgs[++i];
    } else if (arg === '-k' || arg === '--apiKey' || arg === '--api-key') {
      options.apiKey = filteredArgs[++i];
    } else if (arg === '--endpoint') {
      options.endpoint = filteredArgs[++i];
    } else if (arg === '--stripSources' || arg === '--strip-sources') {
      options.stripSources = true;
    }
  }

  if (command === 'upload') {
    if (!options.projectId || !options.release || !options.targetPath || !options.apiKey) {
      console.error(
        'Error: Missing required arguments: --project, --release, --path, and --apiKey are required.\n'
      );
      printUsage();
      return 1;
    }

    try {
      const summary = await uploadSourceMaps(options);
      if (!summary.ok) {
        console.error(`\nUpload finished with ${summary.total - summary.uploaded} error(s).`);
        return 1;
      }
      console.log(`\n✓ All ${summary.uploaded} source maps uploaded successfully for release ${options.release}.`);
      return 0;
    } catch (err) {
      console.error(`\nError during upload: ${err.message}`);
      return 1;
    }
  }

  console.error(`Unknown command: ${command}`);
  printUsage();
  return 1;
}

if (require.main === module) {
  runCli().then((code) => {
    if (code !== 0) process.exit(code);
  });
}

module.exports = {
  findMapFiles,
  uploadSourceMaps,
  runCli,
};
