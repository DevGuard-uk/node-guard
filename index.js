'use strict';

const {
  createWebGuardMiddleware,
  createNextGuardMiddleware,
  StatusCache,
} = require('./guardMiddleware');
const {
  isDomainAllowed,
  normalizeHost,
  isValidDomainPattern,
  extractRequestHost,
} = require('./domainMatcher');
const {
  isPathAllowed,
  sendLockResponse,
  generateLockHtml,
  getLockHeaders,
  DEFAULT_ALLOWED_PATHS,
} = require('./lockResponse');
const { exportSecure } = require('./exportSecure');
const {
  boot,
  bootSync,
  computeCanonicalSignableString,
  verifyManifestIntegrity,
  decryptPayload,
  resolveDecryptionKey,
  executeInMemory,
} = require('./bootloader');
const {
  generateWebTelemetryScriptSnippet,
} = require('./telemetrySnippet');

module.exports = {
  createWebGuardMiddleware,
  createNextGuardMiddleware,
  StatusCache,
  isDomainAllowed,
  normalizeHost,
  isValidDomainPattern,
  extractRequestHost,
  isPathAllowed,
  sendLockResponse,
  generateLockHtml,
  getLockHeaders,
  DEFAULT_ALLOWED_PATHS,
  exportSecure,
  boot,
  bootSync,
  computeCanonicalSignableString,
  verifyManifestIntegrity,
  decryptPayload,
  resolveDecryptionKey,
  executeInMemory,
  generateWebTelemetryScriptSnippet,
};

