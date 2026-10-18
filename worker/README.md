# Perimeter Notes – groups backend

Cloudflare Worker + SQLite Durable Objects (Workers **Free** plan) that syncs the walks people choose to share to a group.
Live at `https://perimeter-notes-groups.dowdyrichard.workers.dev` (CORS: only `https://richdow.github.io`).

* `Group` Durable Object: one per group (random 128-bit id). Members, salted PIN hash, shared walks, change log. All merges for a group run single-threaded here.
* `Directory` Durable Object: short join code → group id; per-IP failed-PIN counters and group-creation limits (IPs are stored only as keyed hashes).

API (`/v1`): `POST /groups` create · `POST /join` (code + PIN → token) · `GET /groups/:gid/pull?since=` · `POST /groups/:gid/push` (upserts + deletes) · `POST /groups/:gid/leave` · `POST /groups/:gid/pin` (creator; revokes all other tokens) · `DELETE /groups/:gid` (creator).

Security: PIN = PBKDF2-SHA256 over an HMAC with the `PIN_PEPPER` secret, per-group random salt; constant-time compare; per-group lockout (5 free tries, then 30 s doubling to 1 h) and per-IP lockout (10 bad tries/hour); bearer tokens are random and stored only as SHA-256; payload validation and size caps (300 walks / 4 MB per group, 8,000 points and 300 pins per walk, 50 members). No request or walk content is logged; observability is off.

```
npm install
printf 'PIN_PEPPER=local-dev-pepper-not-secret\nLOCK_BASE_MS=1500\nTRUST_TEST_IP=1\n' > .dev.vars   # local only, git-ignored
npx wrangler dev --port 8787 --ip 127.0.0.1 --var ALLOWED_ORIGINS:http://127.0.0.1:8765
npm test                                   # integration tests against the dev server
openssl rand -base64 48 | npx wrangler secret put PIN_PEPPER   # once, production (never commit it)
npx wrangler deploy
```

Never delete or change `PIN_PEPPER` in production: every group's PIN would stop working.
