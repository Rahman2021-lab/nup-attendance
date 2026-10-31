// Online sync for the attendance app. Stores everything in a Redis database
// (Upstash Redis from the Vercel Marketplace / Vercel KV). No other packages needed.
const crypto = require("crypto");

const RURL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL || "";
const RTOK = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN || "";

let cachedHash = null;
let cachedOwner = null;
// block guessing: too many wrong owner codes / sync keys within 15 minutes
async function tooMany(name, max) {
  const [n] = await rd([["GET", "nup:fail:" + name]]);
  return Number(n || 0) >= max;
}
async function noteFail(name) { await rd([["INCR", "nup:fail:" + name], ["EXPIRE", "nup:fail:" + name, 900]]); }
async function clearFail(name) { await rd([["DEL", "nup:fail:" + name]]); } // the key hash never changes once set, so remember it between calls

async function rd(cmds) {
  const r = await fetch(RURL.replace(/\/+$/, "") + "/pipeline", {
    method: "POST",
    headers: { Authorization: "Bearer " + RTOK, "Content-Type": "application/json" },
    body: JSON.stringify(cmds),
  });
  if (!r.ok) throw new Error("storage_http_" + r.status);
  const j = await r.json();
  return j.map((x) => { if (x && x.error) throw new Error(x.error); return x.result; });
}

const own = (c) => crypto.createHash("sha256").update("nup-owner:" + c).digest("hex");
const rand = (n) => crypto.randomBytes(n).toString("hex");
const CODE_CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
function makeCode() { let o = ""; for (let i = 0; i < 10; i++) { o += CODE_CHARS[crypto.randomInt(CODE_CHARS.length)]; if (i === 4) o += "-"; } return o; }
const normCode = (c) => String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
const clientIp = (req) => String((req.headers && (req.headers["x-forwarded-for"] || req.headers["x-real-ip"])) || (req.socket && req.socket.remoteAddress) || "").split(",")[0].trim().slice(0, 60);
const str = (v, n) => (typeof v === "string" ? v : "").trim().slice(0, n);
const devCache = new Map(); // token hash -> { dev, at } (re-checked every 30 s so removal takes effect quickly)
function parse(x) { try { return x ? JSON.parse(x) : null; } catch (_) { return null; } }
function pairs(flat) { const o = {}; for (let i = 0; i + 1 < (flat || []).length; i += 2) o[flat[i]] = flat[i + 1]; return o; }
async function deviceFor(token, req) {
  const th = sha("tok:" + token), now = Date.now(), ip = clientIp(req);
  let c = devCache.get(th);
  if (!c || now - c.at > 30000) {
    const [id] = await rd([["HGET", "nup:tok", th]]);
    if (!id) { devCache.delete(th); return null; }
    const [raw] = await rd([["HGET", "nup:devices", id]]);
    const dev = parse(raw);
    if (!dev || dev.revoked) { devCache.delete(th); return null; }
    c = { dev, at: now }; devCache.set(th, c);
  }
  if (now - (c.dev.last || 0) > 300000 || (ip && ip !== c.dev.lastIp)) {
    c.dev.last = now; if (ip) c.dev.lastIp = ip;
    await rd([["HSET", "nup:devices", c.dev.id, JSON.stringify(c.dev)]]);
  }
  return c.dev;
}
const sha = (k) => crypto.createHash("sha256").update("nup-attendance:" + k).digest("hex");
const same = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") { try { return JSON.parse(req.body); } catch (e) { return null; } }
  const chunks = []; let n = 0;
  for await (const c of req) { n += c.length; if (n > 4e6) throw new Error("too_big"); chunks.push(c); }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch (e) { return null; }
}

function send(res, code, obj) {
  res.statusCode = code;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(obj));
}

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") { res.statusCode = 204; return res.end(); }
  if (req.method === "GET") {
    // Open  https://YOUR-SITE/api/sync  in a browser to check that the service and database work.
    const info = { ok: true, service: "nup-attendance-sync", storage_connected: !!(RURL && RTOK) };
    if (info.storage_connected) {
      try { const [pong] = await rd([["PING"]]); info.redis = pong === "PONG" ? "ok" : "unexpected answer"; }
      catch (e) { info.redis = "error: " + String((e && e.message) || e).slice(0, 100); }
    } else {
      info.hint = "Connect an Upstash Redis database to this Vercel project (Storage tab), then redeploy.";
    }
    return send(res, 200, info);
  }
  if (req.method !== "POST") return send(res, 405, { error: "post_only" });
  if (!RURL || !RTOK) return send(res, 503, { error: "storage_missing" });

  let b;
  try { b = await readBody(req); } catch (e) { return send(res, 413, { error: "too_big" }); }
  if (!b || typeof b !== "object") return send(res, 400, { error: "bad_json" });

  try {
    let stored = cachedHash;
    if (!stored) { [stored] = await rd([["GET", "nup:keyhash"]]); if (stored) cachedHash = stored; }

    if (b.action === "status") return send(res, 200, { ok: true, claimed: !!stored });

    let ownerHash = cachedOwner;
    if (!ownerHash) { [ownerHash] = await rd([["GET", "nup:ownerhash"]]); if (ownerHash) cachedOwner = ownerHash; }

    if (b.action === "owner_status") return send(res, 200, { ok: true, set: !!ownerHash });

    if (b.action === "owner_set") {
      if (ownerHash) return send(res, 409, { error: "owner_already_set" });
      if (typeof b.code !== "string" || b.code.length < 8) return send(res, 400, { error: "short_owner" });
      const [r] = await rd([["SET", "nup:ownerhash", own(b.code), "NX"]]);
      if (r === "OK") { cachedOwner = own(b.code); return send(res, 200, { ok: true }); }
      return send(res, 409, { error: "owner_already_set" });
    }

    if (b.action === "owner_check") {
      if (!ownerHash) return send(res, 409, { error: "owner_not_set" });
      if (await tooMany("owner", 10)) return send(res, 429, { error: "too_many" });
      if (typeof b.code === "string" && same(ownerHash, own(b.code))) { await clearFail("owner"); return send(res, 200, { ok: true }); }
      await noteFail("owner");
      return send(res, 403, { error: "bad_owner" });
    }

    const ownerGate = async () => {
      if (!ownerHash) return [409, "owner_not_set"];
      if (await tooMany("owner", 10)) return [429, "too_many"];
      if (typeof b.owner === "string" && same(ownerHash, own(b.owner))) return null;
      await noteFail("owner"); return [403, "owner_required"];
    };

    if (["access_create", "access_list", "access_cancel", "device_revoke", "device_delete"].includes(b.action)) {
      const bad = await ownerGate(); if (bad) return send(res, bad[0], { error: bad[1] });
      const now = Date.now();
      if (b.action === "access_create") {
        const label = str(b.label, 60); if (!label) return send(res, 400, { error: "label_required" });
        const hours = Math.max(1, Math.min(720, Number(b.hours) || 24));
        const code = makeCode(), exp = now + hours * 3600000;
        await rd([["HSET", "nup:codes", sha("code:" + normCode(code)), JSON.stringify({ label, exp, created: now })]]);
        return send(res, 200, { ok: true, code, exp });
      }
      if (b.action === "access_list") {
        const [cf, df] = await rd([["HGETALL", "nup:codes"], ["HGETALL", "nup:devices"]]);
        const codes = [], devices = [], stale = [];
        const co = pairs(cf), dv = pairs(df);
        Object.keys(co).forEach((h) => { const c = parse(co[h]); if (!c) return; if (c.exp < now) stale.push(["HDEL", "nup:codes", h]); else codes.push({ id: h.slice(0, 12), label: c.label, exp: c.exp, created: c.created }); });
        Object.keys(dv).forEach((id) => { const d = parse(dv[id]); if (d) devices.push({ id: d.id, label: d.label, dname: d.dname, device: d.device, ip: d.ip, lastIp: d.lastIp, created: d.created, last: d.last, revoked: !!d.revoked }); });
        if (stale.length) await rd(stale);
        return send(res, 200, { ok: true, codes, devices });
      }
      if (b.action === "access_cancel") {
        const [cf] = await rd([["HGETALL", "nup:codes"]]);
        const h = Object.keys(pairs(cf)).find((k) => k.slice(0, 12) === String(b.id || ""));
        if (h) await rd([["HDEL", "nup:codes", h]]);
        return send(res, 200, { ok: true });
      }
      const [raw] = await rd([["HGET", "nup:devices", String(b.id || "")]]);
      const dev = parse(raw);
      if (!dev) return send(res, 404, { error: "no_such_device" });
      if (b.action === "device_revoke") {
        dev.revoked = true; dev.rev = now;
        await rd([["HSET", "nup:devices", dev.id, JSON.stringify(dev)], ["HDEL", "nup:tok", dev.th]]);
        devCache.delete(dev.th);
        return send(res, 200, { ok: true });
      }
      if (!dev.revoked) return send(res, 409, { error: "remove_access_first" });
      await rd([["HDEL", "nup:devices", dev.id]]);
      return send(res, 200, { ok: true });
    }

    if (b.action === "device_login") {
      if (await tooMany("code", 10)) return send(res, 429, { error: "too_many" });
      const norm = normCode(b.code);
      if (norm.length < 8) { await noteFail("code"); return send(res, 403, { error: "bad_code" }); }
      const h = sha("code:" + norm);
      const [raw] = await rd([["HGET", "nup:codes", h]]);
      const c = parse(raw);
      if (!c || c.exp < Date.now()) { await noteFail("code"); return send(res, 403, { error: "bad_code" }); }
      const [gone] = await rd([["HDEL", "nup:codes", h]]);
      if (Number(gone) !== 1) { await noteFail("code"); return send(res, 403, { error: "bad_code" }); }
      const id = rand(6), token = rand(24), th = sha("tok:" + token), now = Date.now(), ip = clientIp(req);
      const dev = { id, label: c.label, dname: str(b.device && b.device.label, 60), device: str(b.device && b.device.name, 80), ip, lastIp: ip, created: now, last: now, revoked: false, th };
      await rd([["HSET", "nup:devices", id, JSON.stringify(dev)], ["HSET", "nup:tok", th, id]]);
      await clearFail("code");
      return send(res, 200, { ok: true, token, id, name: c.label });
    }

    if (b.action === "claim") {
      if (!ownerHash) return send(res, 409, { error: "owner_not_set" });
      if (await tooMany("owner", 10)) return send(res, 429, { error: "too_many" });
      if (typeof b.owner !== "string" || !same(ownerHash, own(b.owner))) { await noteFail("owner"); return send(res, 403, { error: "owner_required" }); }
      if (stored) return send(res, 409, { error: "already_claimed" });
      if (typeof b.key !== "string" || b.key.length < 8) return send(res, 400, { error: "short_key" });
      const [r] = await rd([["SET", "nup:keyhash", sha(b.key), "NX"]]);
      if (r === "OK") cachedHash = sha(b.key);
      return r === "OK" ? send(res, 200, { ok: true }) : send(res, 409, { error: "already_claimed" });
    }

    if (typeof b.token === "string" && b.token) {
      const dev = await deviceFor(b.token, req);
      if (!dev) return send(res, 401, { error: "revoked" });
    } else {
      if (await tooMany("key", 30)) return send(res, 429, { error: "too_many" });
      if (!stored || typeof b.key !== "string" || !same(stored, sha(b.key))) { await noteFail("key"); return send(res, 401, { error: "bad_key" }); }
    }

    const cid = String(b.cid || "").slice(0, 40);
    const rejected = [];
    const push = (Array.isArray(b.push) ? b.push : []).slice(0, 300)
      .filter((x) => x && typeof x.k === "string" && x.k.length > 0 && x.k.length <= 240 && typeof x.t === "number");

    if (push.length) {
      const [old] = await rd([["HMGET", "nup:data", ...push.map((x) => x.k)]]);
      const accepted = [];
      push.forEach((x, i) => {
        let e = null;
        try { e = old[i] ? JSON.parse(old[i]) : null; } catch (_) { e = null; }
        if (e && x.t < e.t) rejected.push(x.k); else accepted.push(x);
      });
      if (accepted.length) {
        const [last] = await rd([["INCRBY", "nup:seq", accepted.length]]);
        const cmds = [];
        accepted.forEach((x, i) => {
          const st = last - accepted.length + 1 + i;
          cmds.push(["HSET", "nup:data", x.k, JSON.stringify({ t: x.t, v: x.v === undefined ? null : x.v, st, c: cid })]);
          cmds.push(["ZADD", "nup:idx", st, x.k]);
        });
        await rd(cmds);
      }
    }

    const items = [];
    let cursor = Number(b.since) || 0, more = false;
    if (b.pull !== false) {
      const [keys] = await rd([["ZRANGEBYSCORE", "nup:idx", "(" + cursor, "+inf", "LIMIT", 0, 300]]);
      if (keys && keys.length) {
        const [vals] = await rd([["HMGET", "nup:data", ...keys]]);
        let size = 0;
        for (let i = 0; i < keys.length; i++) {
          let e = null;
          try { e = vals[i] ? JSON.parse(vals[i]) : null; } catch (_) { e = null; }
          if (!e) continue;
          if (size > 2500000) { more = true; break; }
          size += vals[i].length;
          cursor = e.st;
          if (e.c !== cid) items.push({ k: keys[i], t: e.t, v: e.v });
        }
        if (keys.length === 300) more = true;
      }
    }
    return send(res, 200, { ok: true, cursor, items, more, rejected });
  } catch (e) {
    return send(res, 500, { error: "server_error", detail: String(e && e.message || e).slice(0, 120) });
  }
};
