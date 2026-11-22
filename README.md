# @devguard-uk/node-guard

> DevGuard Web & Node Guard Middleware with Domain Lock, Fail-Safe Open, and SEO-Safe HTTP 503 Lockout Pages.

## Features

- **Domain Locking**: Enforce deployment host allowlists with wildcard support (`*.example.com`).
- **Fail-Safe Open**: Network blips or API latency never disrupt your live website.
- **SEO-Safe 503**: Locked states return HTTP 503 with `Retry-After: 3600` and `X-Robots-Tag: noindex, nofollow` to prevent search engine deindexing.
- **Path Allowlist**: Operations paths (`/health`, `/.well-known/*`) remain reachable during locks.
- **Dual Framework**: Native Express middleware and Next.js middleware support.

## Usage (Express)

```js
const express = require('express');
const { createWebGuardMiddleware } = require('@devguard-uk/node-guard');

const app = express();

app.use(createWebGuardMiddleware({
  projectId: 'proj_abc123',
  // Prefer project SDK key (Portal → Project SDK key). Falls back to DEVGUARD_API_KEY.
  sdkKey: process.env.DEVGUARD_SDK_KEY,
  failSafe: 'open', // Default
  allowedDomains: ['example.com', '*.example.com'],
}));
```

## Usage (Next.js)

```js
// middleware.js
import { createNextGuardMiddleware } from '@devguard-uk/node-guard';

const guard = createNextGuardMiddleware({
  projectId: process.env.DEVGUARD_PROJECT_ID,
  allowedDomains: ['example.com', '*.example.com'],
  failSafe: 'open',
});

export async function middleware(request) {
  const lockResult = await guard(request);
  if (lockResult) {
    return new Response(lockResult.body, {
      status: lockResult.status,
      headers: lockResult.headers,
    });
  }
  return NextResponse.next();
}
```

