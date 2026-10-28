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

    if (await tooMany("key", 30)) return send(res, 429, { error: "too_many" });
    if (!stored || typeof b.key !== "string" || !same(stored, sha(b.key))) { await noteFail("key"); return send(res, 401, { error: "bad_key" }); }

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
