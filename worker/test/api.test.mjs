// Integration tests for the groups API against `wrangler dev` (local workerd + SQLite Durable Objects).
// Run: npx wrangler dev --port 8787 --var ALLOWED_ORIGINS:http://127.0.0.1:8765   then   node --test test/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const API = process.env.API || "http://127.0.0.1:8787";
const ORIGIN = "http://127.0.0.1:8765";
let ipn = 0;
const freshIp = () => "10.0." + Math.floor(Math.random() * 250) + "." + (++ipn);
async function req(method, path, { body, token, origin = ORIGIN, ip, raw } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (origin) headers.Origin = origin;
  if (token) headers.Authorization = "Bearer " + token;
  headers["X-Test-IP"] = ip || "10.9.9.9";
  const r = await fetch(API + path, { method, headers, body: raw != null ? raw : body ? JSON.stringify(body) : undefined });
  let j = null; try { j = await r.json(); } catch (_) {}
  return { status: r.status, body: j, headers: r.headers };
}
const create = (name = "Casino crew", pin = "4821", nick = "Rich", ip) => req("POST", "/v1/groups", { body: { name, pin, nick }, ip: ip || freshIp() });
const join = (code, pin, nick = "Sam", ip) => req("POST", "/v1/join", { body: { code, pin, nick }, ip: ip || freshIp() });
const t0 = 1_700_000_000_000;
const walk = (id, over = {}) => Object.assign({
  id, label: "Palladio floor", startedAt: t0, stoppedAt: t0 + 6e5, demo: false, keywords: ["Casino"],
  address: { city: "Folsom", state: "California", stateCode: "CA", country: "United States", countryCode: "us", source: "nominatim" },
  points: [{ lat: 38.6436, lng: -121.1887, acc: 6, t: t0 }, { lat: 38.644, lng: -121.1887, acc: 6, t: t0 + 3e5 }], pauses: [],
  pins: [{ id: "p1", lat: 38.6437, lng: -121.1887, acc: 6, t: t0, text: "Bar", u: t0 }],
  ft: { label: t0, startedAt: t0, stoppedAt: t0, demo: t0, keywords: t0, address: t0, points: t0, pauses: t0 }
}, over);

test("health + CORS", async () => {
  assert.equal((await req("GET", "/v1/health", { origin: null })).status, 200);
  const pre = await fetch(API + "/v1/groups", { method: "OPTIONS", headers: { Origin: ORIGIN, "Access-Control-Request-Method": "POST" } });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get("access-control-allow-origin"), ORIGIN);
  const evil = await req("POST", "/v1/groups", { body: { name: "x", pin: "1234", nick: "x" }, origin: "https://evil.example" });
  assert.equal(evil.status, 403);
  assert.equal(evil.headers.get("access-control-allow-origin"), null);
  const ok = await req("GET", "/v1/health");
  assert.equal(ok.headers.get("access-control-allow-origin"), ORIGIN);
});

test("create validates name, nickname and PIN strength", async () => {
  assert.equal((await create("Crew", "123")).body.error, "bad_pin");          // 3 digits
  assert.equal((await create("Crew", "abcde")).body.error, "bad_pin");        // 5-char passphrase
  assert.equal((await create("", "1234")).body.error, "bad_name");
  assert.equal((await create("Crew", "1234", "")).body.error, "bad_nickname");
  const r = await create("Crew", "correct horse");
  assert.equal(r.status, 200);
  assert.match(r.body.code, /^[2-9A-HJKMNP-Z]{8}$/);
  assert.match(r.body.gid, /^[\w-]{22}$/);
  assert.match(r.body.token, /^[\w-]{22}\.[\w-]{43}$/);
  assert.equal(r.body.me.role, "owner");
});

test("join with code + PIN, code is forgiving about case/dashes", async () => {
  const g = (await create()).body;
  const pretty = g.code.slice(0, 4).toLowerCase() + "-" + g.code.slice(4);
  const j = await join(pretty, "4821", "Sam");
  assert.equal(j.status, 200);
  assert.equal(j.body.gid, g.gid);
  assert.equal(j.body.me.role, "member");
  assert.deepEqual(j.body.members.map((m) => m.nick), ["Rich", "Sam"]);
  assert.notEqual(j.body.token, g.token);
});

test("wrong PIN → per-group lockout with backoff, then recovers", async () => {
  const g = (await create()).body;
  for (let i = 0; i < 5; i++) {
    const r = await join(g.code, "0000");
    assert.equal(r.status, 403); assert.equal(r.body.error, "wrong_pin");
  }
  const locked = await join(g.code, "4821");                    // right PIN, but locked
  assert.equal(locked.status, 429); assert.equal(locked.body.error, "group_locked");
  assert.ok(locked.headers.get("retry-after"));
  await new Promise((r) => setTimeout(r, 1700));                // LOCK_BASE_MS=1500 in dev
  assert.equal((await join(g.code, "0000")).status, 403);       // 6th wrong → locked for 2× longer
  const again = await join(g.code, "4821");
  assert.equal(again.status, 429);
  await new Promise((r) => setTimeout(r, 3200));
  assert.equal((await join(g.code, "4821")).status, 200);       // success resets the counter
  assert.equal((await join(g.code, "0000")).body.remaining, 4);
});

test("per-IP lockout covers unknown codes and wrong PINs across groups", async () => {
  const ip = freshIp();
  const g = (await create()).body;
  for (let i = 0; i < 6; i++) assert.equal((await join("ZZZZZZZZ", "1234", "x", ip)).body.error, "wrong_pin");   // same answer as a wrong PIN: no code enumeration
  for (let i = 0; i < 4; i++) await join(g.code, "9999", "x", ip);
  const r = await join(g.code, "4821", "x", ip);
  assert.equal(r.status, 429); assert.equal(r.body.error, "ip_locked");
  assert.equal((await join(g.code, "4821", "x", freshIp())).status, 200);                                      // others unaffected
});

test("push + pull with author, cursor and pagination", async () => {
  const g = (await create()).body, m = (await join(g.code, "4821", "Sam")).body;
  const p = await req("POST", "/v1/groups/" + g.gid + "/push", { token: g.token, body: { upserts: [walk("w1"), walk("w2", { label: "Second" })] } });
  assert.equal(p.status, 200);
  assert.equal(p.body.results.length, 2);
  assert.equal(p.body.results[0].walk.author.nick, "Rich");
  const pull = await req("GET", "/v1/groups/" + g.gid + "/pull?since=0", { token: m.token });
  assert.equal(pull.status, 200);
  assert.deepEqual(pull.body.walks.map((w) => w.id), ["w1", "w2"]);
  assert.equal(pull.body.walks[0].author.nick, "Rich");
  assert.equal(pull.body.walks[0].pins[0].text, "Bar");
  assert.equal(pull.body.group.walkCount, 2);
  const again = await req("GET", "/v1/groups/" + g.gid + "/pull?since=" + pull.body.cursor, { token: m.token });
  assert.equal(again.body.walks.length, 0);
  assert.equal(again.body.cursor, pull.body.cursor);
  // member edits → owner sees it with editor name
  await req("POST", "/v1/groups/" + g.gid + "/push", { token: m.token, body: { upserts: [walk("w1", { label: "Renamed", ft: { label: t0 + 10 } })] } });
  const p2 = await req("GET", "/v1/groups/" + g.gid + "/pull?since=" + pull.body.cursor, { token: g.token });
  assert.equal(p2.body.walks[0].label, "Renamed");
  assert.equal(p2.body.walks[0].editor, "Sam");
  assert.equal(p2.body.walks[0].author.nick, "Rich");
  // bad token / token for another group
  assert.equal((await req("GET", "/v1/groups/" + g.gid + "/pull", { token: g.gid + ".nottherealsecretxxxxxxxxxxxxxx" })).status, 401);
  const other = (await create()).body;
  assert.equal((await req("GET", "/v1/groups/" + g.gid + "/pull", { token: other.token })).status, 401);
});

test("conflicts: last writer wins per field, pins merge by id with deletion markers", async () => {
  const g = (await create()).body, m = (await join(g.code, "4821", "Sam")).body;
  const push = (tok, w) => req("POST", "/v1/groups/" + g.gid + "/push", { token: tok, body: { upserts: [w] } });
  await push(g.token, walk("c1"));
  // A renames (newer label), B (offline, stale label) adds a keyword later
  await push(g.token, walk("c1", { label: "A label", ft: { label: t0 + 100 } }));
  const r = await push(m.token, walk("c1", { label: "stale", keywords: ["Casino", "Friday"], ft: { label: t0, keywords: t0 + 110 } }));
  let w = r.body.results[0].walk;
  assert.equal(w.label, "A label");
  assert.deepEqual(w.keywords, ["Casino", "Friday"]);
  // both add pins → union
  await push(g.token, walk("c1", { pins: [{ id: "pA", lat: 38.64, lng: -121.18, t: t0, text: "A pin", u: t0 + 200 }], ft: {} }));
  w = (await push(m.token, walk("c1", { pins: [{ id: "pB", lat: 38.64, lng: -121.18, t: t0, text: "B pin", u: t0 + 201 }], ft: {} }))).body.results[0].walk;
  assert.deepEqual(w.pins.filter((p) => !p.del).map((p) => p.id).sort(), ["p1", "pA", "pB"]);
  // A deletes pA; B's stale copy of pA must not bring it back; B's newer edit of pB wins
  await push(g.token, walk("c1", { pins: [{ id: "pA", del: true, u: t0 + 300 }], ft: {} }));
  w = (await push(m.token, walk("c1", { pins: [{ id: "pA", lat: 1, lng: 1, t: t0, text: "A pin", u: t0 + 200 }, { id: "pB", lat: 38.64, lng: -121.18, t: t0, text: "B pin edited", u: t0 + 400 }], ft: {} }))).body.results[0].walk;
  assert.ok(w.pins.find((p) => p.id === "pA").del);
  assert.equal(w.pins.find((p) => p.id === "pB").text, "B pin edited");
});

test("delete walk: marker in pull, stale edits don't resurrect, newer edits do", async () => {
  const g = (await create()).body, m = (await join(g.code, "4821", "Sam")).body;
  const base = "/v1/groups/" + g.gid;
  await req("POST", base + "/push", { token: g.token, body: { upserts: [walk("d1")] } });
  const c = (await req("GET", base + "/pull?since=0", { token: m.token })).body.cursor;
  const del = await req("POST", base + "/push", { token: m.token, body: { deletes: ["d1"] } });
  assert.equal(del.body.results[0].deleted, true);
  const pull = await req("GET", base + "/pull?since=" + c, { token: g.token });
  assert.deepEqual(pull.body.deleted, ["d1"]);
  assert.equal(pull.body.group.walkCount, 0);
  const stale = await req("POST", base + "/push", { token: g.token, body: { upserts: [walk("d1")] } });
  assert.equal(stale.body.results[0].deleted, true);
  const fresh = await req("POST", base + "/push", { token: g.token, body: { upserts: [walk("d1", { label: "Back", ft: { label: Date.now() + 1000 } })] } });
  assert.equal(fresh.body.results[0].walk.label, "Back");
});

test("limits: payload size, points, pins, walk shape, batch size", async () => {
  const g = (await create()).body;
  const base = "/v1/groups/" + g.gid + "/push";
  const big = await req("POST", base, { token: g.token, raw: JSON.stringify({ upserts: [walk("b1", { label: "x".repeat(800000) })] }) });
  assert.equal(big.status, 413);
  const pts = Array.from({ length: 8001 }, (_, i) => ({ lat: 38.6, lng: -121.1, t: t0 + i }));
  const r = await req("POST", base, { token: g.token, body: { upserts: [walk("b2", { points: pts }), walk("ok1")] } });
  assert.equal(r.body.results[0].error, "too_many_points");
  assert.ok(r.body.results[1].walk, "other walks in the batch still saved");
  const pins = Array.from({ length: 301 }, (_, i) => ({ id: "p" + i, lat: 38.6, lng: -121.1, t: t0, text: "x", u: t0 }));
  assert.equal((await req("POST", base, { token: g.token, body: { upserts: [walk("b3", { pins })] } })).body.results[0].error, "too_many_pins");
  assert.equal((await req("POST", base, { token: g.token, body: { upserts: [walk("bad id!")] } })).body.results[0].error, "bad_walk");
  assert.equal((await req("POST", base, { token: g.token, body: { upserts: [walk("b4", { points: [{ lat: 200, lng: 0, t: 1 }] })] } })).body.results[0].error, "bad_walk");
  const many = Array.from({ length: 21 }, (_, i) => walk("m" + i));
  assert.equal((await req("POST", base, { token: g.token, body: { upserts: many } })).status, 413);
  const pull = (await req("GET", "/v1/groups/" + g.gid + "/pull", { token: g.token })).body;
  assert.ok(pull.walks[0].label.length <= 120 && pull.group.limits.walks === 300);
});

test("change PIN (owner only) revokes everyone else's access", async () => {
  const g = (await create()).body, m = (await join(g.code, "4821", "Sam")).body;
  assert.equal((await req("POST", "/v1/groups/" + g.gid + "/pin", { token: m.token, body: { pin: "5555" } })).status, 403);
  const c = await req("POST", "/v1/groups/" + g.gid + "/pin", { token: g.token, body: { pin: "7777" } });
  assert.equal(c.body.revoked, 1);
  assert.equal((await req("GET", "/v1/groups/" + g.gid + "/pull", { token: m.token })).status, 401);
  assert.equal((await req("GET", "/v1/groups/" + g.gid + "/pull", { token: g.token })).status, 200);
  assert.equal((await join(g.code, "4821")).status, 403);
  assert.equal((await join(g.code, "7777")).status, 200);
});

test("leave revokes the token", async () => {
  const g = (await create()).body, m = (await join(g.code, "4821", "Sam")).body;
  assert.equal((await req("POST", "/v1/groups/" + g.gid + "/leave", { token: m.token })).status, 200);
  assert.equal((await req("GET", "/v1/groups/" + g.gid + "/pull", { token: m.token })).status, 401);
  const info = (await req("GET", "/v1/groups/" + g.gid + "/pull", { token: g.token })).body.group;
  assert.deepEqual(info.members.map((x) => x.nick), ["Rich"]);
});

test("delete group (owner only) removes all data and the join code", async () => {
  const g = (await create()).body, m = (await join(g.code, "4821", "Sam")).body;
  await req("POST", "/v1/groups/" + g.gid + "/push", { token: g.token, body: { upserts: [walk("x1")] } });
  assert.equal((await req("DELETE", "/v1/groups/" + g.gid, { token: m.token })).status, 403);
  assert.equal((await req("DELETE", "/v1/groups/" + g.gid, { token: g.token })).status, 200);
  assert.equal((await req("GET", "/v1/groups/" + g.gid + "/pull", { token: g.token })).status, 404);
  assert.equal((await req("GET", "/v1/groups/" + g.gid + "/pull", { token: m.token })).status, 404);
  assert.equal((await join(g.code, "4821")).body.error, "wrong_pin");
});

test("source never logs request contents", () => {
  const src = readFileSync(new URL("../src/index.js", import.meta.url), "utf8");
  assert.equal(/console\.(log|info|warn|error|debug)/.test(src), false);
  assert.match(readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8"), /\[observability\]\s*\nenabled = false/);
});
