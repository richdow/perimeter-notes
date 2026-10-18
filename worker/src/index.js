/* Perimeter Notes: groups API (Cloudflare Worker + SQLite-backed Durable Objects, Free plan).
 *
 * One Durable Object per group (class Group) holds that group's members, PIN hash and shared walks
 * in its own SQLite database, so every merge for a group runs single-threaded and consistent.
 * One Directory object maps short join codes to random group IDs and keeps per-IP rate limits.
 *
 * Privacy: request bodies and walk contents are never logged (observability is off and nothing is
 * written to the console). IP addresses are only kept as salted hashes for rate limits.
 */
import { DurableObject } from "cloudflare:workers";

const LIMITS = {
  BODY_BYTES: 700_000,       // per request
  WALK_BYTES: 450_000,       // one stored walk (JSON)
  GROUP_BYTES: 4_000_000,    // all live walks in a group
  WALKS: 300,                // live walks per group
  POINTS: 8000,              // GPS points per walk
  PINS: 300,                 // live pins per walk (+ the same again in deletion markers)
  MEMBERS: 50,
  PUSH_ITEMS: 20,            // walks per push request
  PULL_WALKS: 40, PULL_BYTES: 1_500_000,
  NAME: 60, NICK: 32, LABEL: 120, TEXT: 500, KEYWORDS: 30, KEYWORD: 40,
  GROUPS_PER_IP_DAY: 10
};
const LOCK = {
  GROUP_FREE_FAILS: 5,       // wrong PINs allowed per group before lockout
  GROUP_BASE_MS: 30_000,     // then 30 s, 60 s, 2 min … up to 1 h
  GROUP_MAX_MS: 3_600_000,
  IP_FAILS: 10,              // wrong PIN / unknown code per IP per hour → locked for an hour
  IP_WINDOW_MS: 3_600_000,
  IP_LOCK_MS: 3_600_000
};
const SYNC_FIELDS = ["label", "startedAt", "stoppedAt", "demo", "keywords", "address", "points", "pauses"];
const CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";   // no 0/O, 1/I/L
const enc = new TextEncoder();

/* ---------------- helpers ---------------- */
class ApiError extends Error {
  constructor(status, code, message, extra) { super(message || code); this.status = status; this.code = code; this.extra = extra; }
}
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const randomB64 = (n) => b64url(crypto.getRandomValues(new Uint8Array(n)));
async function sha256(str) { return b64url(await crypto.subtle.digest("SHA-256", enc.encode(str))); }
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
function randomCode() {
  const r = crypto.getRandomValues(new Uint8Array(8));
  return Array.from(r, (x) => CODE_ALPHABET[x % CODE_ALPHABET.length]).join("");
}
export function normCode(c) { return String(c || "").toUpperCase().replace(/[^0-9A-Z]/g, "").replace(/[O]/g, "0").replace(/[IL]/g, "1").slice(0, 12); }
function checkPin(pin) {
  if (typeof pin !== "string") throw new ApiError(400, "bad_pin", "PIN is required");
  const p = pin.normalize("NFKC");
  if (p.length > 64) throw new ApiError(400, "bad_pin", "PIN is too long (64 max)");
  if (/^\d+$/.test(p) ? p.length < 4 : p.length < 6) throw new ApiError(400, "bad_pin", "Use at least 4 digits, or a passphrase of 6+ characters");
  return p;
}
function cleanStr(v, max, field, required) {
  if (v == null || v === "") { if (required) throw new ApiError(400, "bad_" + field, field + " is required"); return ""; }
  if (typeof v !== "string") throw new ApiError(400, "bad_" + field, field + " must be text");
  const s = v.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();
  if (required && !s) throw new ApiError(400, "bad_" + field, field + " is required");
  if (s.length > max) throw new ApiError(400, "bad_" + field, field + " is too long (" + max + " max)");
  return s;
}
// PIN hash: HMAC with a server-side secret ("pepper", a Worker secret) then PBKDF2-SHA256.
// A leaked database alone is not enough to brute-force short PINs offline.
async function hashPin(pin, salt, iterations, pepper) {
  if (!pepper || pepper.length < 16) throw new ApiError(503, "not_configured", "Server isn't configured yet");
  const hk = await crypto.subtle.importKey("raw", enc.encode(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const peppered = await crypto.subtle.sign("HMAC", hk, enc.encode(pin));
  const base = await crypto.subtle.importKey("raw", peppered, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations }, base, 256);
  return b64url(bits);
}
const iterOf = (env) => Math.min(100_000, Math.max(1000, parseInt(env.PBKDF2_ITER || "60000", 10)));
const lockBase = (env) => parseInt(env.LOCK_BASE_MS || LOCK.GROUP_BASE_MS, 10);

/* ---------------- walk validation + merge ---------------- */
const num = (v, f) => { if (typeof v !== "number" || !isFinite(v)) throw new ApiError(400, "bad_walk", f + " must be a number"); return v; };
const optNum = (v, f) => (v == null ? null : num(v, f));
function cleanPoint(p) {
  if (!p || typeof p !== "object") throw new ApiError(400, "bad_walk", "bad point");
  const lat = num(p.lat, "lat"), lng = num(p.lng, "lng");
  if (Math.abs(lat) > 90 || Math.abs(lng) > 180) throw new ApiError(400, "bad_walk", "point out of range");
  const o = { lat, lng, t: optNum(p.t, "t") };
  if (p.acc != null) o.acc = num(p.acc, "acc");
  if (p.heading != null) o.heading = num(p.heading, "heading");
  if (p.gap) o.gap = true;
  return o;
}
function cleanAddress(a) {
  if (a == null) return null;
  if (typeof a !== "object") throw new ApiError(400, "bad_walk", "bad address");
  const o = {};
  for (const k of ["line", "city", "state", "stateCode", "postcode", "country", "countryCode", "source"]) if (a[k] != null) o[k] = cleanStr(a[k], 160, "address");
  for (const k of ["at", "lat", "lng"]) if (a[k] != null) o[k] = num(a[k], "address." + k);
  return o;
}
function cleanPin(p) {
  if (!p || typeof p !== "object" || typeof p.id !== "string" || !/^[\w-]{1,48}$/.test(p.id)) throw new ApiError(400, "bad_walk", "bad pin id");
  const u = optNum(p.u, "pin.u") || 0;
  if (p.del) return { id: p.id, del: true, u };
  const lat = num(p.lat, "pin.lat"), lng = num(p.lng, "pin.lng");
  if (Math.abs(lat) > 90 || Math.abs(lng) > 180) throw new ApiError(400, "bad_walk", "pin out of range");
  const o = { id: p.id, lat, lng, t: optNum(p.t, "pin.t"), text: cleanStr(p.text == null ? "" : p.text, LIMITS.TEXT, "pin text"), u };
  if (p.acc != null) o.acc = num(p.acc, "pin.acc");
  if (p.n != null) o.n = num(p.n, "pin.n");
  return o;
}
export function cleanWalk(w) {
  if (!w || typeof w !== "object") throw new ApiError(400, "bad_walk", "walk must be an object");
  if (typeof w.id !== "string" || !/^[\w-]{1,48}$/.test(w.id)) throw new ApiError(400, "bad_walk", "bad walk id");
  const ft = {};
  if (w.ft && typeof w.ft === "object") for (const f of SYNC_FIELDS) if (w.ft[f] != null) ft[f] = num(w.ft[f], "ft." + f);
  const o = { id: w.id, ft };
  if ("label" in w) o.label = cleanStr(w.label, LIMITS.LABEL, "label");
  if ("startedAt" in w) o.startedAt = optNum(w.startedAt, "startedAt");
  if ("stoppedAt" in w) o.stoppedAt = optNum(w.stoppedAt, "stoppedAt");
  if ("demo" in w) o.demo = !!w.demo;
  if ("keywords" in w) {
    if (!Array.isArray(w.keywords) || w.keywords.length > LIMITS.KEYWORDS) throw new ApiError(400, "bad_walk", "too many keywords");
    o.keywords = w.keywords.map((k) => cleanStr(k, LIMITS.KEYWORD, "keyword")).filter(Boolean);
  }
  if ("address" in w) o.address = cleanAddress(w.address);
  if ("points" in w) {
    if (!Array.isArray(w.points)) throw new ApiError(400, "bad_walk", "points must be a list");
    if (w.points.length > LIMITS.POINTS) throw new ApiError(413, "too_many_points", "A walk can have at most " + LIMITS.POINTS + " GPS points");
    o.points = w.points.map(cleanPoint);
  }
  if ("pauses" in w) {
    if (!Array.isArray(w.pauses) || w.pauses.length > 1000) throw new ApiError(400, "bad_walk", "bad pauses");
    o.pauses = w.pauses.map((p) => ({ from: num(p && p.from, "pause"), to: num(p && p.to, "pause") }));
  }
  const pins = Array.isArray(w.pins) ? w.pins : [];
  if (pins.length > LIMITS.PINS * 2) throw new ApiError(413, "too_many_pins", "Too many pins on one walk");
  o.pins = pins.map(cleanPin);
  return o;
}
// Field-level last-writer-wins (newest edit time per field) + pins merged by id (newest wins,
// deletions kept as small markers so they spread to everyone).
export function mergeWalk(stored, inc) {
  const out = stored ? { ...stored, ft: { ...(stored.ft || {}) } } : { id: inc.id, ft: {} };
  for (const f of SYNC_FIELDS) {
    if (!(f in inc)) continue;
    const ti = inc.ft[f] || 0, ts = out.ft[f] || 0;
    if (!stored || !(f in out) || ti > ts) { out[f] = inc[f]; out.ft[f] = ti; }
  }
  const pins = new Map((out.pins || []).map((p) => [p.id, p]));
  for (const p of inc.pins || []) {
    const cur = pins.get(p.id);
    if (!cur || (p.u || 0) > (cur.u || 0)) pins.set(p.id, p);
  }
  out.pins = [...pins.values()];
  if (out.pins.filter((p) => !p.del).length > LIMITS.PINS) throw new ApiError(413, "too_many_pins", "A walk can have at most " + LIMITS.PINS + " pins");
  if (out.pins.length > LIMITS.PINS * 2) {   // drop the oldest deletion markers first
    const dels = out.pins.filter((p) => p.del).sort((a, b) => a.u - b.u);
    const drop = new Set(dels.slice(0, out.pins.length - LIMITS.PINS * 2).map((p) => p.id));
    out.pins = out.pins.filter((p) => !drop.has(p.id));
  }
  return out;
}
const maxFt = (w) => Math.max(0, ...Object.values(w.ft || {}), ...(w.pins || []).map((p) => p.u || 0));

/* ---------------- Group Durable Object ---------------- */
export class Group extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
  }
  // Tables are created only when a group is created, so requests that reach a deleted group's
  // object don't recreate storage for it.
  ensureTables() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
      CREATE TABLE IF NOT EXISTS members (id TEXT PRIMARY KEY, nick TEXT, token_hash TEXT UNIQUE, role TEXT, created INTEGER, last_seen INTEGER);
      CREATE TABLE IF NOT EXISTS walks (id TEXT PRIMARY KEY, seq INTEGER, data TEXT, author_id TEXT, author_nick TEXT,
        editor_nick TEXT, updated INTEGER, deleted INTEGER DEFAULT 0, deleted_at INTEGER, bytes INTEGER DEFAULT 0);
      CREATE INDEX IF NOT EXISTS walks_seq ON walks(seq);`);
  }
  m(k) {
    let r;
    try { r = this.sql.exec("SELECT v FROM meta WHERE k = ?", k).toArray()[0]; }
    catch (e) { if (/no such table/.test(String(e && e.message))) return undefined; throw e; }
    return r ? JSON.parse(r.v) : undefined;
  }
  setM(k, v) { this.sql.exec("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", k, JSON.stringify(v)); }
  nextSeq() { const s = (this.m("seq") || 0) + 1; this.setM("seq", s); return s; }
  requireLive() { if (!this.m("gid")) throw new ApiError(404, "no_group", "This group doesn't exist (it may have been deleted)"); }

  async newMember(nick, role) {
    if (this.sql.exec("SELECT COUNT(*) AS n FROM members").one().n >= LIMITS.MEMBERS) throw new ApiError(403, "group_full", "This group already has " + LIMITS.MEMBERS + " members");
    const id = "m_" + randomB64(9), secret = randomB64(32);
    this.sql.exec("INSERT INTO members (id, nick, token_hash, role, created, last_seen) VALUES (?, ?, ?, ?, ?, ?)", id, nick, await sha256(secret), role, Date.now(), Date.now());
    return { memberId: id, token: this.m("gid") + "." + secret };
  }
  async auth(secret) {
    this.requireLive();
    if (typeof secret !== "string" || secret.length < 20) throw new ApiError(401, "bad_token", "Please join the group again");
    const row = this.sql.exec("SELECT * FROM members WHERE token_hash = ?", await sha256(secret)).toArray()[0];
    if (!row) throw new ApiError(401, "bad_token", "Your access to this group ended (the PIN changed, you left, or the group was deleted). Join again.");
    if (Date.now() - row.last_seen > 600_000) this.sql.exec("UPDATE members SET last_seen = ? WHERE id = ?", Date.now(), row.id);
    return row;
  }
  info(me) {
    const members = this.sql.exec("SELECT id, nick, role FROM members ORDER BY created").toArray();
    const walks = this.sql.exec("SELECT COUNT(*) AS n, COALESCE(SUM(bytes), 0) AS b FROM walks WHERE deleted = 0").one();
    return { gid: this.m("gid"), name: this.m("name"), code: this.m("code"), members, walkCount: walks.n, bytes: walks.b,
      limits: { walks: LIMITS.WALKS, bytes: LIMITS.GROUP_BYTES, points: LIMITS.POINTS }, me: me && { id: me.id, nick: me.nick, role: me.role } };
  }

  async init({ gid, name, code, pin, nick }) {
    if (this.m("gid")) throw new ApiError(409, "exists", "Group already exists");
    this.ensureTables();
    const salt = randomB64(16), iter = iterOf(this.env);
    this.setM("gid", gid); this.setM("name", name); this.setM("code", code); this.setM("created", Date.now());
    this.setM("pin", { salt, iter, hash: await hashPin(pin, salt, iter, this.env.PIN_PEPPER) });
    this.setM("fails", { n: 0, until: 0 });
    const mem = await this.newMember(nick, "owner");
    return { ...mem, ...this.info({ id: mem.memberId, nick, role: "owner" }) };
  }
  async join({ pin, nick }) {
    this.requireLive();
    const now = Date.now(), f = this.m("fails") || { n: 0, until: 0 };
    if (f.until > now) throw new ApiError(429, "group_locked", "Too many wrong PINs for this group. Try again in " + Math.ceil((f.until - now) / 1000) + " s.", { retryAfter: Math.ceil((f.until - now) / 1000) });
    const p = this.m("pin");
    const ok = safeEqual(await hashPin(pin, p.salt, p.iter, this.env.PIN_PEPPER), p.hash);
    if (!ok) {
      const n = f.n + 1;
      const until = n >= LOCK.GROUP_FREE_FAILS ? now + Math.min(LOCK.GROUP_MAX_MS, lockBase(this.env) * Math.pow(2, n - LOCK.GROUP_FREE_FAILS)) : 0;
      this.setM("fails", { n, until });
      throw new ApiError(403, "wrong_pin", "Wrong group code or PIN", { remaining: Math.max(0, LOCK.GROUP_FREE_FAILS - n) });
    }
    if (f.n) this.setM("fails", { n: 0, until: 0 });
    const mem = await this.newMember(nick, "member");
    return { ...mem, ...this.info({ id: mem.memberId, nick, role: "member" }) };
  }
  async pull({ secret, since }) {
    const me = await this.auth(secret);
    const rows = this.sql.exec("SELECT id, seq, data, author_id, author_nick, editor_nick, updated, deleted FROM walks WHERE seq > ? ORDER BY seq LIMIT ?",
      Math.max(0, since | 0), LIMITS.PULL_WALKS + 1).toArray();
    const walks = [], deleted = [];
    let bytes = 0, cursor = since | 0, more = false;
    for (const [i, r] of rows.entries()) {
      if (i >= LIMITS.PULL_WALKS || (bytes > 0 && bytes + (r.data ? r.data.length : 0) > LIMITS.PULL_BYTES)) { more = true; break; }
      cursor = r.seq;
      if (r.deleted) { deleted.push(r.id); continue; }
      bytes += r.data.length;
      walks.push({ ...JSON.parse(r.data), seq: r.seq, author: { id: r.author_id, nick: r.author_nick }, editor: r.editor_nick, updated: r.updated });
    }
    return { cursor, more, walks, deleted, group: this.info(me) };
  }
  async push({ secret, upserts, deletes }) {
    const me = await this.auth(secret);
    upserts = Array.isArray(upserts) ? upserts : []; deletes = Array.isArray(deletes) ? deletes : [];
    if (upserts.length + deletes.length > LIMITS.PUSH_ITEMS) throw new ApiError(413, "too_many_items", "Send at most " + LIMITS.PUSH_ITEMS + " walks at a time");
    const results = [];
    for (const raw of upserts) {
      try {
        const inc = cleanWalk(raw);
        const row = this.sql.exec("SELECT * FROM walks WHERE id = ?", inc.id).toArray()[0];
        // a walk deleted from the group comes back only if edited after the deletion
        if (row && row.deleted && maxFt(inc) <= row.deleted_at) { results.push({ id: inc.id, deleted: true, seq: row.seq }); continue; }
        const stored = row && !row.deleted ? JSON.parse(row.data) : null;
        const merged = mergeWalk(stored, inc);
        const data = JSON.stringify(merged);
        if (data.length > LIMITS.WALK_BYTES) throw new ApiError(413, "walk_too_big", "This walk is too large to share (" + Math.round(data.length / 1000) + " KB, limit " + LIMITS.WALK_BYTES / 1000 + " KB)");
        const tot = this.sql.exec("SELECT COUNT(*) AS n, COALESCE(SUM(bytes), 0) AS b FROM walks WHERE deleted = 0 AND id != ?", inc.id).one();
        if (!stored && tot.n >= LIMITS.WALKS) throw new ApiError(413, "group_walk_limit", "This group already has " + LIMITS.WALKS + " walks");
        if (tot.b + data.length > LIMITS.GROUP_BYTES) throw new ApiError(413, "group_full", "This group is out of space (" + LIMITS.GROUP_BYTES / 1e6 + " MB). Remove some walks first.");
        const seq = this.nextSeq(), now = Date.now();
        if (row) this.sql.exec("UPDATE walks SET seq = ?, data = ?, editor_nick = ?, updated = ?, deleted = 0, deleted_at = NULL, bytes = ?" + (row.deleted ? ", author_id = ?, author_nick = ?" : "") + " WHERE id = ?",
          ...[seq, data, me.nick, now, data.length].concat(row.deleted ? [me.id, me.nick] : []), inc.id);
        else this.sql.exec("INSERT INTO walks (id, seq, data, author_id, author_nick, editor_nick, updated, deleted, bytes) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
          inc.id, seq, data, me.id, me.nick, me.nick, now, data.length);
        const r2 = row && !row.deleted ? row : { author_id: me.id, author_nick: me.nick };
        results.push({ id: inc.id, seq, walk: { ...merged, seq, author: { id: r2.author_id, nick: r2.author_nick }, editor: me.nick, updated: now } });
      } catch (e) {
        if (!(e instanceof ApiError)) throw e;
        results.push({ id: raw && typeof raw.id === "string" ? raw.id.slice(0, 48) : null, error: e.code, message: e.message });
      }
    }
    for (const id of deletes) {
      if (typeof id !== "string" || !/^[\w-]{1,48}$/.test(id)) { results.push({ id: null, error: "bad_walk" }); continue; }
      const row = this.sql.exec("SELECT deleted FROM walks WHERE id = ?", id).toArray()[0];
      if (!row) { results.push({ id, deleted: true }); continue; }
      const seq = this.nextSeq();
      this.sql.exec("UPDATE walks SET seq = ?, data = NULL, bytes = 0, deleted = 1, deleted_at = ?, editor_nick = ? WHERE id = ?", seq, Date.now(), me.nick, id);
      results.push({ id, deleted: true, seq });
    }
    return { results, seq: this.m("seq") || 0 };
  }
  async leave({ secret }) {
    const me = await this.auth(secret);
    this.sql.exec("DELETE FROM members WHERE id = ?", me.id);
    return { ok: true, wasOwner: me.role === "owner" };
  }
  async changePin({ secret, pin }) {
    const me = await this.auth(secret);
    if (me.role !== "owner") throw new ApiError(403, "not_owner", "Only the group's creator can change the PIN");
    const salt = randomB64(16), iter = iterOf(this.env);
    this.setM("pin", { salt, iter, hash: await hashPin(pin, salt, iter, this.env.PIN_PEPPER) });
    this.setM("fails", { n: 0, until: 0 });
    const n = this.sql.exec("SELECT COUNT(*) AS n FROM members WHERE id != ?", me.id).one().n;
    this.sql.exec("DELETE FROM members WHERE id != ?", me.id);   // everyone else must rejoin with the new PIN
    return { ok: true, revoked: n };
  }
  async destroy({ secret }) {
    const me = await this.auth(secret);
    if (me.role !== "owner") throw new ApiError(403, "not_owner", "Only the group's creator can delete the group");
    const code = this.m("code");
    await this.ctx.storage.deleteAll();
    return { ok: true, code };
  }
  async peekCode() { return this.m("code") || null; }
}

/* ---------------- Directory Durable Object (join codes + per-IP limits) ---------------- */
export class Directory extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS codes (code TEXT PRIMARY KEY, gid TEXT, created INTEGER);
      CREATE TABLE IF NOT EXISTS ips (ip TEXT PRIMARY KEY, fails INTEGER, win INTEGER, locked_until INTEGER, creates INTEGER, day INTEGER);`);
  }
  ipRow(ip, now) {
    let r = this.sql.exec("SELECT * FROM ips WHERE ip = ?", ip).toArray()[0];
    if (!r) { r = { ip, fails: 0, win: now, locked_until: 0, creates: 0, day: Math.floor(now / 864e5) }; this.sql.exec("INSERT INTO ips VALUES (?, 0, ?, 0, 0, ?)", ip, now, r.day); }
    if (now - r.win > LOCK.IP_WINDOW_MS) { r.fails = 0; r.win = now; }
    if (Math.floor(now / 864e5) !== r.day) { r.creates = 0; r.day = Math.floor(now / 864e5); }
    return r;
  }
  saveIp(r) { this.sql.exec("UPDATE ips SET fails = ?, win = ?, locked_until = ?, creates = ?, day = ? WHERE ip = ?", r.fails, r.win, r.locked_until, r.creates, r.day, r.ip); }
  sweep(now) { if (Math.random() < 0.02) this.sql.exec("DELETE FROM ips WHERE win < ? AND locked_until < ?", now - 2 * 864e5, now); }
  async reserve({ ip, gid }) {
    const now = Date.now(), r = this.ipRow(ip, now);
    if (r.creates >= LIMITS.GROUPS_PER_IP_DAY) throw new ApiError(429, "create_limit", "Too many new groups from this network today");
    r.creates++; this.saveIp(r); this.sweep(now);
    for (let i = 0; i < 10; i++) {
      const code = randomCode();
      if (!this.sql.exec("SELECT 1 FROM codes WHERE code = ?", code).toArray().length) {
        this.sql.exec("INSERT INTO codes VALUES (?, ?, ?)", code, gid, now);
        return { code };
      }
    }
    throw new ApiError(500, "code_space", "Couldn't make a join code, try again");
  }
  async lookup({ ip, code }) {
    const now = Date.now(), r = this.ipRow(ip, now);
    if (r.locked_until > now) throw new ApiError(429, "ip_locked", "Too many wrong attempts from this network. Try again in " + Math.ceil((r.locked_until - now) / 60000) + " min.", { retryAfter: Math.ceil((r.locked_until - now) / 1000) });
    const row = this.sql.exec("SELECT gid FROM codes WHERE code = ?", code).toArray()[0];
    if (!row) { this.failIp(r, now); throw new ApiError(403, "wrong_pin", "Wrong group code or PIN"); }
    return { gid: row.gid };
  }
  failIp(r, now) {
    r.fails++;
    if (r.fails >= LOCK.IP_FAILS) r.locked_until = now + LOCK.IP_LOCK_MS;
    this.saveIp(r);
  }
  async fail({ ip }) { const now = Date.now(); this.failIp(this.ipRow(ip, now), now); return { ok: true }; }
  async remove({ code }) { this.sql.exec("DELETE FROM codes WHERE code = ?", code); return { ok: true }; }
}

/* ---------------- HTTP front door ---------------- */
function corsHeaders(env, origin) {
  const allowed = String(env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
  const h = { "Vary": "Origin", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
  if (origin && allowed.includes(origin)) Object.assign(h, {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400"
  });
  return { h, ok: !origin || allowed.includes(origin) };
}
const json = (status, body, headers) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json; charset=utf-8", ...headers } });
async function readJson(req) {
  const len = parseInt(req.headers.get("Content-Length") || "0", 10);
  if (len > LIMITS.BODY_BYTES) throw new ApiError(413, "too_large", "Request too large");
  const text = await req.text();
  if (text.length > LIMITS.BODY_BYTES) throw new ApiError(413, "too_large", "Request too large");
  try { return text ? JSON.parse(text) : {}; } catch (_) { throw new ApiError(400, "bad_json", "Body must be JSON"); }
}
function bearer(req) {
  const m = /^Bearer\s+([\w-]{8,64})\.([\w-]{20,80})$/.exec(req.headers.get("Authorization") || "");
  if (!m) throw new ApiError(401, "bad_token", "Please join the group again");
  return { gid: m[1], secret: m[2] };
}
// DO errors arrive as plain Errors over RPC; carry our status/code in the message.
async function call(fn) {
  try { return await fn(); }
  catch (e) {
    if (e instanceof ApiError) throw e;
    const m = /^APIERR (\d{3}) (\w+) (.*)$/s.exec(e && e.message || "");
    if (m) { let extra; let msg = m[3]; const j = msg.lastIndexOf(" |X|"); if (j >= 0) { try { extra = JSON.parse(msg.slice(j + 4)); } catch (_) {} msg = msg.slice(0, j); } throw new ApiError(+m[1], m[2], msg, extra); }
    throw e;
  }
}
// wrap DO methods so ApiError survives the RPC boundary
for (const C of [Group, Directory]) {
  for (const name of Object.getOwnPropertyNames(C.prototype)) {
    if (["constructor", "ensureTables", "m", "setM", "nextSeq", "requireLive", "newMember", "auth", "info", "ipRow", "saveIp", "sweep", "failIp"].includes(name)) continue;
    const orig = C.prototype[name];
    if (typeof orig !== "function") continue;
    C.prototype[name] = async function (...a) {
      try { return await orig.apply(this, a); }
      catch (e) { if (e instanceof ApiError) throw new Error("APIERR " + e.status + " " + e.code + " " + e.message + (e.extra ? " |X|" + JSON.stringify(e.extra) : "")); throw e; }
    };
  }
}
const groupStub = (env, gid) => env.GROUP.get(env.GROUP.idFromName("g:" + gid));
const dirStub = (env) => env.DIRECTORY.get(env.DIRECTORY.idFromName("directory"));
async function ipKey(req, env) {
  // TRUST_TEST_IP is only set in local tests (.dev.vars) to simulate different networks
  const ip = (env.TRUST_TEST_IP === "1" && req.headers.get("X-Test-IP")) || req.headers.get("CF-Connecting-IP") || "local";
  return (await sha256((env.PIN_PEPPER || "") + "|ip|" + ip)).slice(0, 22);
}

async function route(req, env) {
  const url = new URL(req.url);
  const p = url.pathname.replace(/\/+$/, "");
  if (p === "/v1/health" && req.method === "GET") return { ok: true, service: "perimeter-notes-groups" };
  if (p === "/v1/groups" && req.method === "POST") {
    const b = await readJson(req);
    const name = cleanStr(b.name, LIMITS.NAME, "name", true), nick = cleanStr(b.nick, LIMITS.NICK, "nickname", true), pin = checkPin(b.pin);
    const gid = randomB64(16);   // 128-bit, unguessable
    const ip = await ipKey(req, env);
    const { code } = await call(() => dirStub(env).reserve({ ip, gid }));
    return await call(() => groupStub(env, gid).init({ gid, name, code, pin, nick }));
  }
  if (p === "/v1/join" && req.method === "POST") {
    const b = await readJson(req);
    const code = normCode(b.code), nick = cleanStr(b.nick, LIMITS.NICK, "nickname", true);
    if (code.length < 6) throw new ApiError(400, "bad_code", "Enter the group code");
    if (typeof b.pin !== "string" || !b.pin || b.pin.length > 64) throw new ApiError(400, "bad_pin", "Enter the PIN");
    const ip = await ipKey(req, env), dir = dirStub(env);
    const { gid } = await call(() => dir.lookup({ ip, code }));
    try { return await call(() => groupStub(env, gid).join({ pin: b.pin.normalize("NFKC"), nick })); }
    catch (e) { if (e.code === "wrong_pin") await dir.fail({ ip }); throw e; }
  }
  const m = /^\/v1\/groups\/([\w-]{8,64})(?:\/(pull|push|leave|pin))?$/.exec(p);
  if (m) {
    const t = bearer(req);
    if (t.gid !== m[1]) throw new ApiError(401, "bad_token", "Token doesn't match this group");
    const g = groupStub(env, t.gid);
    const action = m[2];
    if (action === "pull" && req.method === "GET") return await call(() => g.pull({ secret: t.secret, since: parseInt(url.searchParams.get("since") || "0", 10) || 0 }));
    if (action === "push" && req.method === "POST") { const b = await readJson(req); return await call(() => g.push({ secret: t.secret, upserts: b.upserts, deletes: b.deletes })); }
    if (action === "leave" && req.method === "POST") return await call(() => g.leave({ secret: t.secret }));
    if (action === "pin" && req.method === "POST") { const b = await readJson(req); return await call(() => g.changePin({ secret: t.secret, pin: checkPin(b.pin) })); }
    if (!action && req.method === "DELETE") {
      const r = await call(() => g.destroy({ secret: t.secret }));
      if (r.code) await dirStub(env).remove({ code: r.code });
      return { ok: true };
    }
  }
  throw new ApiError(404, "not_found", "Not found");
}

export default {
  async fetch(req, env) {
    const { h, ok } = corsHeaders(env, req.headers.get("Origin"));
    if (!ok) return json(403, { error: "origin_not_allowed", message: "This API only serves the Perimeter Notes app" }, { "Vary": "Origin" });
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: h });
    try {
      return json(200, await route(req, env), h);
    } catch (e) {
      if (e instanceof ApiError) {
        const extra = e.extra || {};
        const hh = { ...h };
        if (extra.retryAfter) hh["Retry-After"] = String(extra.retryAfter);
        return json(e.status, { error: e.code, message: e.message, ...extra }, hh);
      }
      return json(500, { error: "server_error", message: "Something went wrong on the server" }, h);
    }
  }
};
