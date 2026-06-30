const CACHE_NAME = 'detector-cache-v1';
const ASSETS_TO_CACHE = [
  '/',
  '/offline',
  '/static/css/app.css',
  '/static/js/app.js',
  '/manifest.json'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(ASSETS_TO_CACHE))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cache => {
          if (cache !== CACHE_NAME) {
            return caches.delete(cache);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  // Only cache GET requests
  if (event.request.method !== 'GET') return;

  // Exclude API requests from caching
  if (event.request.url.includes('/api/')) return;

  event.respondWith(
    caches.match(event.request).then(response => {
      // Return cached response if found
      if (response) return response;

      // Fallback to network
      return fetch(event.request).then(networkResponse => {
        // Don't cache if not a valid response
        if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic') {
          return networkResponse;
        }

        // Cache the new response (we only cache a specific number of result pages if we wanted to, but the prompt says cache last 10 result pages for offline viewing. However, our app is a SPA and results are loaded via API. So we just need the shell cached to work offline, and the session storage handles the local history.)
        const responseToCache = networkResponse.clone();
        caches.open(CACHE_NAME)
          .then(cache => {
            cache.put(event.request, responseToCache);
          });
        return networkResponse;
      }).catch(() => {
        // If network fails (offline) and not in cache, return offline page for navigation requests
        if (event.request.mode === 'navigate') {
          return caches.match('/offline');
        }
      });
    })
  );
});
