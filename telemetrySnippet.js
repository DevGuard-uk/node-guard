'use strict';

/**
 * Generate lightweight HTML script snippet or tag for embedding DevGuard web telemetry into web pages.
 */
function generateWebTelemetryScriptSnippet(options = {}) {
  const {
    projectId,
    apiKey,
    endpoint = '/api/v1/telemetry',
    sampleRate = 1.0,
    enableBreadcrumbs = true,
    appVersion = '1.0.0',
    cdnUrl = 'https://cdn.devguard.uk/telemetry/devguard-web-telemetry.min.js',
  } = options;

  if (!projectId) {
    throw new Error('projectId is required to generate web telemetry snippet');
  }

  const configJson = JSON.stringify({
    projectId,
    ...(apiKey ? { apiKey } : {}),
    endpoint,
    sampleRate,
    enableBreadcrumbs,
    appVersion,
  });

  return `<!-- DevGuard Web Telemetry -->\n<script src="${cdnUrl}" async></script>\n<script>\nwindow.addEventListener('DOMContentLoaded',function(){if(window.DevGuardWebTelemetry){window.DevGuardWebTelemetry.init(${configJson});}});\n</script>`;
}

module.exports = {
  generateWebTelemetryScriptSnippet,
};
