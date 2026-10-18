/* Perimeter Notes service worker: makes the app open and run with no connection.
   Pages: network-first (so updates arrive) with a short timeout, falling back to cache.
   Other same-origin files: stale-while-revalidate. Bump VERSION to drop old caches.
   Cross-origin requests (OSM street tiles, geocoding) are never touched or cached here; they
   use only the browser HTTP cache, as the OSM tile usage policy expects. */
const VERSION = "b86810673e";
const CACHE = "perimeter-notes-" + VERSION;
const CORE = ["./", "./index.html", "./manifest.webmanifest", "./icon-192.png", "./icon-512.png", "./apple-touch-icon.png"];
const NET_TIMEOUT = 4000;

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) =>
    Promise.all(CORE.map((u) => c.add(new Request(u, { cache: "reload" })).catch(() => {})))
  ).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(
    keys.filter((k) => k.startsWith("perimeter-notes-") && k !== CACHE).map((k) => caches.delete(k))
  )).then(() => self.clients.claim()));
});

// The page asks us to cache its own URL (covers any file name it was opened under).
self.addEventListener("message", (event) => {
  const d = event.data || {};
  if (d.type === "cache-page" && typeof d.url === "string" && d.url.startsWith(self.location.origin)) {
    event.waitUntil(caches.open(CACHE).then((c) => c.add(new Request(d.url, { cache: "reload" }))).catch(() => {}));
  }
});

function networkFirst(req) {
  return caches.open(CACHE).then((cache) => new Promise((resolve) => {
    let settled = false;
    const fromCache = () => cache.match(req, { ignoreSearch: true })
      .then((r) => r || cache.match("./index.html"))
      .then((r) => r || cache.match("./"));
    const timer = setTimeout(() => {
      fromCache().then((r) => { if (r && !settled) { settled = true; resolve(r); } });
    }, NET_TIMEOUT);
    fetch(req).then((res) => {
      clearTimeout(timer);
      if (res && res.ok) cache.put(req, res.clone()).catch(() => {});
      if (!settled) { settled = true; resolve(res); }
    }).catch(() => {
      clearTimeout(timer);
      fromCache().then((r) => {
        if (settled) return;
        settled = true;
        resolve(r || new Response("<h1>Offline</h1><p>Open Perimeter Notes once while online so it can work offline.</p>",
          { status: 503, headers: { "Content-Type": "text/html; charset=utf-8" } }));
      });
    });
  }));
}

function staleWhileRevalidate(req) {
  return caches.open(CACHE).then((cache) => cache.match(req).then((hit) => {
    const net = fetch(req).then((res) => {
      if (res && res.ok) cache.put(req, res.clone()).catch(() => {});
      return res;
    }).catch(() => hit || new Response("", { status: 504 }));
    return hit || net;
  }));
}

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;           // e.g. Apple Maps links: not ours
  const isPage = req.mode === "navigate" || (req.headers.get("accept") || "").includes("text/html");
  event.respondWith(isPage ? networkFirst(req) : staleWhileRevalidate(req));
});
