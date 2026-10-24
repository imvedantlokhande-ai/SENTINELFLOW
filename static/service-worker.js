// SentinelFlow AI - Progressive Web App (PWA) Service Worker
// Version: sentinelflow-pwa-v1.2.0

const CACHE_NAME = 'sentinelflow-pwa-v1.2.0';
const STATIC_ASSETS = [
  '/app/static/manifest.json',
  '/app/static/favicon.svg',
  '/app/static/icon-192.svg',
  '/app/static/icon-512.svg',
  '/app/static/og_preview.svg',
  '/app/static/offline.html'
];

// Install: Cache core static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn('[PWA ServiceWorker] Pre-caching asset failed:', err);
      });
    }).then(() => self.skipWaiting())
  );
});

// Activate: Clean up old stale caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((name) => {
          if (name !== CACHE_NAME) {
            console.log('[PWA ServiceWorker] Purging stale cache:', name);
            return caches.delete(name);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch: Network-first with cache and offline fallback
self.addEventListener('fetch', (event) => {
  // Only handle GET requests
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);

  // For static assets, try cache first then network
  if (url.pathname.startsWith('/app/static/')) {
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

  // For navigation requests, network first with offline.html fallback
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() => {
        return caches.match('/app/static/offline.html');
      })
    );
    return;
  }

  // Standard network fetch
  event.respondWith(
    fetch(event.request).catch(() => {
      return caches.match(event.request);
    })
  );
});
