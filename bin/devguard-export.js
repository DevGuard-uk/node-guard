#!/usr/bin/env node
/**
 * DevGuard Secured-Export CLI
 *
 * Usage:
 *   devguard export --secure [options]
 *   devguard-export [options]
 *
 * Example:
 *   npx devguard export --secure --entry server.js --project proj_123 --out dist-secured
 */

'use strict';

const path = require('path');
const fs = require('fs');
const { exportSecure } = require('../exportSecure');

function printUsage() {
  console.log(`
DevGuard Secured-Export CLI (AES Server-Side Asset Protection)

Usage:
  devguard export --secure [options]
  devguard-export [options]

Options:
  -e, --entry <file>     Path to the server entry file (e.g. server.js, index.js)
  -o, --out <dir>        Output directory for secured bundle (default: dist-secured)
  -t, --target <target>  Target framework: node | laravel | python (default: node)
  -p, --project <id>     DevGuard Project ID (or env DEVGUARD_PROJECT_ID)
  -k, --key <hex>        32-byte AES-256 key (hex). Generated if omitted
  -m, --mode <mode>      Key custody mode: per-boot | permanent-key (default: per-boot)
      --api-key <key>    DevGuard API Key for registering export key
      --api-url <url>    DevGuard API Base URL
      --register         Auto-register generated key with DevGuard API
  -v, --version          Display version
  -h, --help             Show this help message

Documentation & Threat Model:
  docs/DEVGUARD_SECURED_EXPORT_THREAT_MODEL.md
`);
}

async function runCli(argv = process.argv.slice(2)) {
  if (argv.includes('-h') || argv.includes('--help')) {
    printUsage();
    return 0;
  }

  if (argv.includes('-v') || argv.includes('--version')) {
    const pkg = require('../package.json');
    console.log(`devguard-export v${pkg.version}`);
    return 0;
  }

  // Filter out subcommand verbs if called as: `devguard export --secure ...`
  const filteredArgs = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === 'export' || arg === '--secure') {
      continue;
    }
    filteredArgs.push(arg);
  }

  const options = {
    outDir: 'dist-secured',
    mode: 'per-boot',
    target: 'node',
  };

  for (let i = 0; i < filteredArgs.length; i++) {
    const arg = filteredArgs[i];
    if (arg === '-e' || arg === '--entry') {
      options.entry = filteredArgs[++i];
    } else if (arg === '-o' || arg === '--out') {
      options.outDir = filteredArgs[++i];
    } else if (arg === '-t' || arg === '--target') {
      options.target = filteredArgs[++i];
    } else if (arg === '-p' || arg === '--project') {
      options.projectId = filteredArgs[++i];
    } else if (arg === '-k' || arg === '--key') {
      options.key = filteredArgs[++i];
    } else if (arg === '-m' || arg === '--mode') {
      options.mode = filteredArgs[++i];
    } else if (arg === '--api-key') {
      options.apiKey = filteredArgs[++i];
    } else if (arg === '--api-url') {
      options.apiUrl = filteredArgs[++i];
    } else if (arg === '--register') {
      options.registerKeyWithApi = true;
    } else if (!arg.startsWith('-') && !options.entry) {
      options.entry = arg;
    }
  }

  options.projectId = options.projectId || process.env.DEVGUARD_PROJECT_ID;
  options.apiKey = options.apiKey || process.env.DEVGUARD_API_KEY;

  if (!options.entry) {
    if (fs.existsSync('server.js')) {
      options.entry = 'server.js';
    } else if (fs.existsSync('index.js')) {
      options.entry = 'index.js';
    } else {
      console.error('Error: Missing required entry file. Specify with --entry <file>');
      printUsage();
      return 1;
    }
  }

  if (!options.projectId) {
    console.error('Error: Missing required Project ID. Specify with --project <id> or set DEVGUARD_PROJECT_ID.');
    printUsage();
    return 1;
  }

  console.log(`[devguard-export] Securing entry "${options.entry}" for project "${options.projectId}"...`);

  try {
    const result = await exportSecure(options);
    console.log(`\n✅ Secured export packaged successfully in: ${result.outDir}`);
    console.log(`   - Payload:     ${result.payloadPath}`);
    console.log(`   - Manifest:    ${result.manifestPath}`);
    console.log(`   - PayloadHash: ${result.payloadHash}`);
    console.log(`   - Mode:        ${result.manifest.mode}`);
    console.log(`   - Release Key: ${result.key}`);
    console.log(`\n🔒 Security Notice: Save the Release Key securely. Under Option B (permanent unlock),`);
    console.log(`   deliver this key to client upon invoice completion: DEVGUARD_RELEASE_KEY="${result.key}"`);
    return 0;
  } catch (err) {
    console.error(`\n❌ Secured export failed: ${err.message}`);
    return 1;
  }
}

if (require.main === module) {
  runCli().then((code) => {
    if (code !== 0) process.exit(code);
  });
}

module.exports = {
  runCli,
};
