// SentinelFlow AI - Progressive Web App (PWA) Service Worker
// Version: sentinelflow-pwa-v1.3.0
// Multi-Platform PWA Cache Engine for PC, Laptops, Mobile, and Tablet

const CACHE_NAME = 'sentinelflow-pwa-v1.3.0';
const FONT_CACHE_NAME = 'sentinelflow-fonts-v1';

const STATIC_ASSETS = [
  '/app/static/manifest.json',
  '/app/static/favicon.svg',
  '/app/static/icon-192.png',
  '/app/static/icon-512.png',
  '/app/static/icon-192.svg',
  '/app/static/icon-512.svg',
  '/app/static/og_preview.svg',
  '/app/static/offline.html'
];

// Install: Pre-cache core static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn('[PWA ServiceWorker] Pre-caching asset failed:', err);
      });
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
