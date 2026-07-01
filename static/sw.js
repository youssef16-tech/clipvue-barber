const CACHE_NAME = 'clipvue-shell-v3';
const CACHED_API_GETS = ['/api/bookings', '/api/user/bookings', '/api/barbers'];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(['/', '/index.html', '/manifest.json', '/sw.js'])));
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  if (url.pathname.startsWith('/api/')) {
    const cacheable = event.request.method === 'GET' && CACHED_API_GETS.some(p => url.pathname.startsWith(p));
    event.respondWith(
      fetch(event.request).then(resp => {
        if (cacheable && resp.ok) {
          const copy = resp.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, copy));
        }
        return resp;
      }).catch(() => (cacheable ? caches.match(event.request) : undefined))
    );
    return;
  }
  if (event.request.method !== 'GET') return;

  if (event.request.mode === 'navigate' || event.request.headers.get('accept')?.includes('text/html')) {
    event.respondWith(fetch(event.request).then(resp => {
      const copy = resp.clone();
      caches.open(CACHE_NAME).then(cache => cache.put('/index.html', copy));
      return resp;
    }).catch(() => caches.match('/index.html')));
    return;
  }

  event.respondWith(caches.match(event.request).then(cached => cached || fetch(event.request).then(resp => {
    const copy = resp.clone();
    caches.open(CACHE_NAME).then(cache => cache.put(event.request, copy));
    return resp;
  })));
});

self.addEventListener('push', event => {
  let data = { title: 'ClipVue', body: 'You have a new notification' };
  try { if (event.data) data = event.data.json(); } catch (e) { /* non-JSON payload, use default */ }
  event.waitUntil(self.registration.showNotification(data.title || 'ClipVue', {
    body: data.body || '',
    icon: data.icon || '/manifest.json',
    badge: '/manifest.json',
  }));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(self.clients.matchAll({ type: 'window' }).then(list => {
    for (const c of list) { if ('focus' in c) return c.focus(); }
    if (self.clients.openWindow) return self.clients.openWindow('/');
  }));
});
