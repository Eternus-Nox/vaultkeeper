// ────────────────────────────────────────────────────────────────────────
// vk-sw.js — VaultKeeper Service Worker.
//
// Caches the static app shell so the app loads with zero network. API
// calls are NOT cached here (the app handles offline API responses via
// IndexedDB in vk-offline.js).
//
// Strategy:
//   • Static assets  →  cache-first, fall back to network
//   • API calls      →  network-only (caller handles offline)
//   • Navigation     →  serve cached index.html (so / works offline)
// ────────────────────────────────────────────────────────────────────────

'use strict';

// Bump this on every release to invalidate old shells.
// Keep in sync with the version we set on .js?v= query params in index.html.
const SHELL_VERSION = 'v3.4.8';
const SHELL_CACHE = 'vk-shell-' + SHELL_VERSION;

// Files that make up the offline-capable app shell. We pre-cache these
// so the app launches even on a totally cold offline start.
const SHELL_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/vk-app.js?v=3.4.8',
  '/vk-crypto.js?v=3.4.8',
  '/vk-crypto-worker.js?v=3.4.8',
  '/vk-import.js?v=3.4.8',
  '/vk-webauthn-client.js?v=3.4.8',
  '/vk-webauthn-integration.js?v=3.4.8',
  '/vk-offline.js?v=3.4.8',
  '/vk-offline-sync.js?v=3.4.8',
  '/vk-offline-conflicts.js?v=3.4.8',
  '/vendor/hash-wasm.umd.min.js?v=3.4.8',
  '/vendor/lucide.js',
  '/icon-192.png',
  '/icon-512.png',
  '/apple-touch-icon.png',
];

// Paths we should NEVER serve from the cache. API calls hit the network
// or fail (caller handles fallback). Auth endpoints likewise.
const NETWORK_ONLY = [
  /^\/api\//,
  /^\/healthz$/,
];


// ──── INSTALL ─────────────────────────────────────────────────────────

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(SHELL_CACHE);

    // Pre-cache the navigation shell explicitly under BOTH '/' and
    // '/index.html' keys. The browser's navigation requests can come in
    // as either, so we store the same response under both keys to
    // guarantee a hit on cold offline launch. Without this, a cold-PWA
    // launch with no network can show a black screen because the
    // navigation lookup falls through to the offline placeholder.
    try {
      const shellResp = await fetch('/index.html', { cache: 'reload' });
      if (shellResp.ok) {
        await cache.put('/', shellResp.clone());
        await cache.put('/index.html', shellResp.clone());
      }
    } catch (e) {
      console.warn('[sw] could not pre-cache shell:', e.message);
    }

    // Pre-cache the rest of the assets one-by-one. addAll fails the
    // whole install if any URL 404s, so we go individually and ignore
    // failures (vendor files may not be populated yet).
    for (const url of SHELL_ASSETS) {
      if (url === '/' || url === '/index.html') continue; // already done
      try {
        await cache.add(new Request(url, { cache: 'reload' }));
      } catch (e) {
        console.warn('[sw] could not pre-cache', url, e.message);
      }
    }

    // Skip the waiting phase so the new SW takes over immediately.
    self.skipWaiting();
  })());
});


// ──── ACTIVATE ────────────────────────────────────────────────────────

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    // Drop any old shell caches from prior versions
    const keys = await caches.keys();
    await Promise.all(keys
      .filter(k => k.startsWith('vk-shell-') && k !== SHELL_CACHE)
      .map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});


// ──── FETCH ────────────────────────────────────────────────────────────

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // Same-origin only — don't try to cache cross-origin (fonts, etc.)
  if (url.origin !== self.location.origin) return;

  // Network-only paths (API calls)
  if (NETWORK_ONLY.some(p => p.test(url.pathname))) return;

  // The /tests/ folder is for development test pages (e.g. crypto-test.html).
  // Bypass the SW entirely so they always run fresh and don't get aliased
  // to the cached app shell.
  if (url.pathname.startsWith('/tests/')) return;

  // Navigation requests → serve cached index.html if offline
  if (req.mode === 'navigate') {
    event.respondWith(handleNav(req));
    return;
  }

  // Everything else → cache-first
  event.respondWith(handleAsset(req));
});


async function handleNav(req) {
  // Strategy: race the network against a 2s timeout. If network wins,
  // serve fresh and update cache. If network is slow or fails, serve
  // the cached shell. This makes offline cold launches instant — no
  // black screen waiting for the network to time out at the OS level.
  const cache = await caches.open(SHELL_CACHE);

  const networkP = fetch(req).then(res => {
    // Update the cached shell in the background. We DON'T await this
    // before returning; just keep it fresh for next time.
    if (res.ok) {
      const clone = res.clone();
      cache.put('/index.html', clone).catch(() => {});
    }
    return res;
  });

  // Try network with a short timeout
  let networkRes;
  try {
    networkRes = await Promise.race([
      networkP,
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 2500)),
    ]);
    if (networkRes && networkRes.ok) return networkRes;
    // Network responded but error — fall through to cache
  } catch {
    // Network failed (offline) or timed out — fall through to cache
  }

  // Serve from cache. ignoreSearch handles the case where the navigation
  // URL has query parameters or hash that the cached version doesn't.
  const cached = await cache.match('/index.html', { ignoreSearch: true })
    || await cache.match('/', { ignoreSearch: true })
    || await cache.match(req, { ignoreSearch: true });
  if (cached) return cached;

  // If we got a network response (even an error), return it now —
  // better than the offline placeholder.
  if (networkRes) return networkRes;

  // Last resort: simple offline message
  return new Response(
    '<!DOCTYPE html><meta charset="utf-8"><title>Offline</title>' +
    '<style>body{font-family:system-ui;background:#0a0a09;color:#e8e6df;' +
    'display:flex;align-items:center;justify-content:center;height:100vh;' +
    'margin:0;text-align:center;padding:20px}h1{font-weight:400}</style>' +
    '<div><h1>VaultKeeper is offline</h1>' +
    '<p>Reconnect to load the app for the first time.</p></div>',
    { status: 200, headers: { 'Content-Type': 'text/html' } }
  );
}


async function handleAsset(req) {
  const cache = await caches.open(SHELL_CACHE);

  // Cache-first with exact match
  let cached = await cache.match(req, { ignoreSearch: false });
  if (cached) {
    // Refresh in the background so we pick up new versions naturally
    fetch(req).then(fresh => {
      if (fresh.ok) cache.put(req, fresh.clone());
    }).catch(() => {});
    return cached;
  }

  // Loose match — handles ?v=3.2.0 → ?v=3.4.8 cache-buster mismatches
  // when a SW update has bumped the version but the user's still loading
  // an older URL (or vice versa). Critical for offline reload of the
  // shell across deploys.
  cached = await cache.match(req, { ignoreSearch: true });
  if (cached) {
    fetch(req).then(fresh => {
      if (fresh.ok) cache.put(req, fresh.clone());
    }).catch(() => {});
    return cached;
  }

  // Not cached at all → try network and cache the response
  try {
    const fresh = await fetch(req);
    if (fresh.ok) cache.put(req, fresh.clone());
    return fresh;
  } catch (err) {
    // Network completely failed and asset isn't cached. Return a
    // 504 with a helpful body — the page will likely break but at
    // least we're not silently throwing.
    return new Response('Offline and not cached: ' + req.url, {
      status: 504,
      headers: { 'Content-Type': 'text/plain' },
    });
  }
}


// ──── MESSAGES (for in-app cache control) ────────────────────────────

self.addEventListener('message', (event) => {
  const msg = event.data || {};
  if (msg.type === 'skip-waiting') self.skipWaiting();
  if (msg.type === 'cache-version') {
    event.ports?.[0]?.postMessage({ version: SHELL_VERSION });
  }
});
