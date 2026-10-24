// SentinelFlow AI - Progressive Web App (PWA) Service Worker
// Version: sentinelflow-pwa-v1.4.0
// Multi-Platform PWA Cache Engine for PC, Laptops, Mobile, and Tablet

const CACHE_NAME = 'sentinelflow-pwa-v1.4.0';
const FONT_CACHE_NAME = 'sentinelflow-fonts-v1';

const STATIC_ASSETS = [
  '/app/static/manifest.json',
  '/manifest.json',
  '/app/static/favicon.svg',
  '/favicon.svg',
  '/app/static/icon-192.png',
  '/app/static/icon-512.png',
  '/app/static/icon-192.svg',
  '/app/static/icon-512.svg',
  '/app/static/screenshot-wide.png',
  '/app/static/screenshot-narrow.png',
  '/app/static/og_preview.svg',
  '/app/static/offline.html'
];

// Install: Pre-cache core static assets resiliently
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      // Use individual caching to prevent one 404 from breaking the entire cache
      const promises = STATIC_ASSETS.map((asset) =>
        fetch(asset)
          .then((response) => {
            if (response && response.status === 200) {
              return cache.put(asset, response);
            }
          })
          .catch((err) => {
            console.warn('[PWA ServiceWorker] Skipping non-critical pre-cache item:', asset, err);
          })
      );
      await Promise.allSettled(promises);
    }).then(() => self.skipWaiting())
  );
});

// Activate: Clean up obsolete stale caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((name) => {
          if (name !== CACHE_NAME && name !== FONT_CACHE_NAME) {
            console.log('[PWA ServiceWorker] Purging stale cache:', name);
            return caches.delete(name);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch: Strategy based on request type
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);

  // 1. Google Fonts Cache-First Strategy
  if (url.origin === 'https://fonts.googleapis.com' || url.origin === 'https://fonts.gstatic.com') {
    event.respondWith(
      caches.open(FONT_CACHE_NAME).then((cache) => {
        return cache.match(event.request).then((cachedResponse) => {
          if (cachedResponse) return cachedResponse;
          return fetch(event.request).then((networkResponse) => {
            if (networkResponse && networkResponse.status === 200) {
              cache.put(event.request, networkResponse.clone());
            }
            return networkResponse;
          }).catch(() => cachedResponse);
        });
      })
    );
    return;
  }

  // 2. Static PWA Assets: Cache-first with network fallback
  if (url.pathname.startsWith('/app/static/') || url.pathname.endsWith('.png') || url.pathname.endsWith('.svg') || url.pathname.endsWith('.json')) {
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        if (cachedResponse) return cachedResponse;
        return fetch(event.request).then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const clone = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return networkResponse;
        });
      })
    );
    return;
  }

  // 3. Navigation requests: Network-first with offline.html fallback
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() => {
        return caches.match('/app/static/offline.html');
      })
    );
    return;
  }

  // 4. Default network fetch with cache fallback
  event.respondWith(
    fetch(event.request).catch(() => {
      return caches.match(event.request);
    })
  );
});
