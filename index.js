import { Database } from "bun:sqlite";
import { existsSync, readFileSync, writeFileSync, mkdirSync, unlinkSync } from "fs";
import { fileURLToPath } from "url";
import { join, dirname } from "path";

const __dir = dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.env.PORT || "3000");
const UPLOADS_DIR = join(__dir, "uploads");
mkdirSync(UPLOADS_DIR, { recursive: true });
const PASSPHRASE = process.env.PASSPHRASE;

if (!PASSPHRASE) {
  console.error("Error: PASSPHRASE env var is required");
  console.error("Usage: PASSPHRASE=my-secret PORT=3000 bun run index.js");
  process.exit(1);
}

// ── State ─────────────────────────────────────────────────────────────────────
const STATE_FILE = join(__dir, "state.json");

function loadState() {
  if (!existsSync(STATE_FILE)) return { passwordHash: null, routes: [], crons: [] };
  try {
    const s = JSON.parse(readFileSync(STATE_FILE, "utf8"));
    s.crons = s.crons || [];
    return s;
  } catch {
    return { passwordHash: null, routes: [], crons: [] };
  }
}

let state = loadState();

function saveState() {
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

// ── SQLite ─────────────────────────────────────────────────────────────────────
const db = new Database(join(__dir, "logs.db"));
db.run(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    route_id TEXT NOT NULL,
    method TEXT,
    path TEXT,
    status INTEGER,
    request_headers TEXT,
    request_body TEXT,
    response_body TEXT,
    timestamp TEXT DEFAULT (datetime('now'))
  )
`);

const insertLog = db.prepare(`
  INSERT INTO logs (route_id, method, path, status, request_headers, request_body, response_body)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);
const getLogs = db.prepare(`SELECT * FROM logs WHERE route_id = ? ORDER BY id DESC LIMIT 200`);
const clearLogs = db.prepare(`DELETE FROM logs WHERE route_id = ?`);

// ── Store ──────────────────────────────────────────────────────────────────────
db.run(`
  CREATE TABLE IF NOT EXISTS store (
    collection TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (collection, key)
  )
`);

const _sGet    = db.prepare(`SELECT value FROM store WHERE collection = ? AND key = ?`);
const _sSet    = db.prepare(`INSERT INTO store (collection, key, value, updated_at) VALUES (?, ?, ?, datetime('now')) ON CONFLICT(collection, key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`);
const _sAll    = db.prepare(`SELECT key, value, updated_at FROM store WHERE collection = ? ORDER BY updated_at DESC`);
const _sDel    = db.prepare(`DELETE FROM store WHERE collection = ? AND key = ?`);
const _sDrop   = db.prepare(`DELETE FROM store WHERE collection = ?`);
const _sCols   = db.prepare(`SELECT collection, COUNT(*) as count FROM store GROUP BY collection ORDER BY collection`);

const store = {
  get(collection, key) {
    const row = _sGet.get(collection, key);
    return row ? JSON.parse(row.value) : null;
  },
  set(collection, key, value) {
    _sSet.run(collection, key, JSON.stringify(value));
  },
  all(collection) {
    return _sAll.all(collection).map(r => ({ key: r.key, value: JSON.parse(r.value), updatedAt: r.updated_at }));
  },
  delete(collection, key) {
    _sDel.run(collection, key);
  },
  drop(collection) {
    _sDrop.run(collection);
  },
  find(collection, fn) {
    return this.all(collection).filter(r => fn(r.value));
  },
};

// ── Files ──────────────────────────────────────────────────────────────────────
db.run(`
  CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    mimetype TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

const _fInsert = db.prepare(`INSERT INTO files (id, filename, mimetype, size) VALUES (?, ?, ?, ?)`);
const _fAll    = db.prepare(`SELECT * FROM files ORDER BY created_at DESC`);
const _fGet    = db.prepare(`SELECT * FROM files WHERE id = ?`);
const _fDel    = db.prepare(`DELETE FROM files WHERE id = ?`);

function fileId() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  return Array.from(crypto.getRandomValues(new Uint8Array(13)))
    .map(b => chars[b % chars.length]).join("");
}

// ── Rate limiting ──────────────────────────────────────────────────────────────
const rlMap = new Map();

function windowMs(w) {
  const m = String(w).match(/^(\d+)(s|m|h|d)$/);
  if (!m) return 60_000;
  return parseInt(m[1]) * { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2]];
}

function isRateLimited(route, req, server) {
  if (!route.rateLimit?.enabled) return false;
  const { requests, window: win, perIp } = route.rateLimit;

  let key = route.id;
  if (perIp) {
    const forwarded = req.headers.get("x-forwarded-for");
    const ip = forwarded
      ? forwarded.split(",")[0].trim()
      : (server.requestIP(req)?.address || "unknown");
    key = `${route.id}:${ip}`;
  }

  const now = Date.now();
  let e = rlMap.get(key);
  if (!e || now > e.resetAt) e = { count: 0, resetAt: now + windowMs(win) };
  e.count++;
  rlMap.set(key, e);
  return e.count > requests;
}

// ── Crons ──────────────────────────────────────────────────────────────────────
const cronTimers = new Map();
const cronLastRun = new Map();

async function runCron(cron) {
  cronLastRun.set(cron.id, new Date().toISOString());
  try {
    const fn = new Function("store", `return (async () => { ${cron.code} })()`);
    const result = await fn(store);
    if (cron.logging) {
      insertLog.run(cron.id, "CRON", cron.name || cron.id, 200, null, null,
        JSON.stringify(result ?? null));
    }
  } catch (err) {
    console.error(`[cron] "${cron.name}" failed:`, err.message);
    if (cron.logging) {
      insertLog.run(cron.id, "CRON", cron.name || cron.id, 500, null, null,
        JSON.stringify({ error: err.message, stack: err.stack }));
    }
  }
}

function scheduleCrons() {
  for (const timer of cronTimers.values()) clearInterval(timer);
  cronTimers.clear();

  for (const cron of state.crons) {
    if (!cron.enabled) continue;
    const id = cron.id;
    const ms = windowMs(cron.schedule);
    const timer = setInterval(() => {
      const current = state.crons.find((c) => c.id === id);
      if (current?.enabled) runCron(current);
    }, ms);
    cronTimers.set(id, timer);
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────────
function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...extra },
  });
}

function corsHeaders(route) {
  if (!route.corsOrigin) return {};
  return {
    "Access-Control-Allow-Origin": route.corsOrigin,
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
  };
}

async function parseBody(req) {
  try {
    const ct = req.headers.get("content-type") || "";
    if (ct.includes("application/json")) return await req.json();
    const text = await req.text();
    return text || null;
  } catch {
    return null;
  }
}

// ── Path matching ──────────────────────────────────────────────────────────────
function matchPath(routePath, reqPath) {
  const rp = routePath.split("/");
  const qp = reqPath.split("/");
  if (rp.length !== qp.length) return null;
  const params = {};
  for (let i = 0; i < rp.length; i++) {
    if (rp[i].startsWith(":")) {
      params[rp[i].slice(1)] = decodeURIComponent(qp[i]);
    } else if (rp[i] !== qp[i]) {
      return null;
    }
  }
  return params;
}

// ── Code execution ─────────────────────────────────────────────────────────────
async function runRoute(route, req, url, params) {
  const body = await parseBody(req);
  const headers = Object.fromEntries(req.headers.entries());
  const query = Object.fromEntries(url.searchParams.entries());

  let result, status;
  try {
    const fn = new Function(
      "req", "body", "headers", "query", "params", "store",
      `return (async () => { ${route.code} })()`
    );
    result = await fn(req, body, headers, query, params, store);
    status = 200;
  } catch (err) {
    result = { error: err.message, stack: err.stack };
    status = 500;
  }

  if (result instanceof Response) {
    if (route.logging) {
      const clone = result.clone();
      const text = await clone.text();
      insertLog.run(route.id, req.method, url.pathname, result.status,
        JSON.stringify(headers), JSON.stringify(body), text);
    }
    const newHeaders = new Headers(result.headers);
    for (const [k, v] of Object.entries(corsHeaders(route))) newHeaders.set(k, v);
    return new Response(result.body, { status: result.status, headers: newHeaders });
  }

  const responseBody = JSON.stringify(result ?? null);
  if (route.logging) {
    insertLog.run(route.id, req.method, url.pathname, status,
      JSON.stringify(headers), JSON.stringify(body), responseBody);
  }
  return new Response(responseBody, {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(route) },
  });
}

// ── Auth ───────────────────────────────────────────────────────────────────────
async function verifyAuth(req) {
  const pw = req.headers.get("x-password");
  if (!pw || !state.passwordHash) return false;
  return Bun.password.verify(pw, state.passwordHash);
}

// ── Dashboard ──────────────────────────────────────────────────────────────────
const dashboardHTML = readFileSync(join(__dir, "dashboard.html"), "utf8");

async function handleDashboard(req, url) {
  const sub = url.pathname.slice("/__dashboard".length) || "/";
  const method = req.method;

  if (sub === "/" && method === "GET")
    return new Response(dashboardHTML, { headers: { "Content-Type": "text/html" } });

  if (sub === "/status" && method === "GET")
    return json({ setup: !!state.passwordHash });

  if (sub === "/setup" && method === "POST") {
    if (state.passwordHash) return json({ error: "Already set up" }, 400);
    const { password } = await req.json();
    if (!password || password.length < 4) return json({ error: "Minimum 4 characters" }, 400);
    state.passwordHash = await Bun.password.hash(password);
    saveState();
    return json({ ok: true });
  }

  if (sub === "/login" && method === "POST") {
    if (!state.passwordHash) return json({ setup: false });
    const { password } = await req.json();
    const ok = await Bun.password.verify(password, state.passwordHash);
    return json({ ok });
  }

  if (sub === "/forgot" && method === "POST") {
    const { passphrase, password } = await req.json();
    if (passphrase !== PASSPHRASE) return json({ error: "Wrong passphrase" }, 401);
    if (!password || password.length < 4) return json({ error: "Minimum 4 characters" }, 400);
    state.passwordHash = await Bun.password.hash(password);
    saveState();
    return json({ ok: true });
  }

  if (!(await verifyAuth(req))) return json({ error: "Unauthorized" }, 401);

  // ── Routes ────────────────────────────────────────────────────────────────
  if (sub === "/routes" && method === "GET") return json(state.routes);

  if (sub === "/routes" && method === "POST") {
    const r = await req.json();
    const route = {
      id: crypto.randomUUID(),
      path: r.path,
      method: r.method || "GET",
      code: r.code || "",
      corsOrigin: r.corsOrigin || "",
      logging: r.logging ?? false,
      rateLimit: r.rateLimit || null,
      enabled: r.enabled ?? true,
    };
    state.routes.push(route);
    saveState();
    return json(route, 201);
  }

  const routeLogsMatch = sub.match(/^\/routes\/([^/]+)\/logs$/);
  if (routeLogsMatch) {
    const id = routeLogsMatch[1];
    if (method === "GET") return json(getLogs.all(id));
    if (method === "DELETE") { clearLogs.run(id); return json({ ok: true }); }
  }

  const routeMatch = sub.match(/^\/routes\/([^/]+)$/);
  if (routeMatch) {
    const id = routeMatch[1];
    const idx = state.routes.findIndex((r) => r.id === id);
    if (method === "PUT" || method === "PATCH") {
      if (idx === -1) return json({ error: "Not found" }, 404);
      const updates = await req.json();
      state.routes[idx] = { ...state.routes[idx], ...updates, id };
      saveState();
      return json(state.routes[idx]);
    }
    if (method === "DELETE") {
      if (idx === -1) return json({ error: "Not found" }, 404);
      state.routes.splice(idx, 1);
      clearLogs.run(id);
      saveState();
      return json({ ok: true });
    }
  }

  // ── Crons ─────────────────────────────────────────────────────────────────
  if (sub === "/crons" && method === "GET") {
    return json(state.crons.map((c) => ({ ...c, lastRun: cronLastRun.get(c.id) || null })));
  }

  if (sub === "/crons" && method === "POST") {
    const c = await req.json();
    const cron = {
      id: crypto.randomUUID(),
      name: c.name || "unnamed",
      schedule: c.schedule || "1h",
      code: c.code || "",
      enabled: c.enabled ?? true,
      logging: c.logging ?? false,
    };
    state.crons.push(cron);
    saveState();
    scheduleCrons();
    return json({ ...cron, lastRun: null }, 201);
  }

  const cronLogsMatch = sub.match(/^\/crons\/([^/]+)\/logs$/);
  if (cronLogsMatch) {
    const id = cronLogsMatch[1];
    if (method === "GET") return json(getLogs.all(id));
    if (method === "DELETE") { clearLogs.run(id); return json({ ok: true }); }
  }

  const cronRunMatch = sub.match(/^\/crons\/([^/]+)\/run$/);
  if (cronRunMatch && method === "POST") {
    const cron = state.crons.find((c) => c.id === cronRunMatch[1]);
    if (!cron) return json({ error: "Not found" }, 404);
    runCron(cron);
    return json({ ok: true });
  }

  const cronMatch = sub.match(/^\/crons\/([^/]+)$/);
  if (cronMatch) {
    const id = cronMatch[1];
    const idx = state.crons.findIndex((c) => c.id === id);
    if (method === "PUT" || method === "PATCH") {
      if (idx === -1) return json({ error: "Not found" }, 404);
      const updates = await req.json();
      state.crons[idx] = { ...state.crons[idx], ...updates, id };
      saveState();
      scheduleCrons();
      return json(state.crons[idx]);
    }
    if (method === "DELETE") {
      if (idx === -1) return json({ error: "Not found" }, 404);
      state.crons.splice(idx, 1);
      clearLogs.run(id);
      saveState();
      scheduleCrons();
      return json({ ok: true });
    }
  }

  // ── Store browse (dashboard only) ─────────────────────────────────────────
  if (sub === "/store" && method === "GET") {
    return json(_sCols.all());
  }

  const storeColMatch = sub.match(/^\/store\/([^/]+)$/);
  if (storeColMatch) {
    const col = decodeURIComponent(storeColMatch[1]);
    if (method === "GET") {
      return json(_sAll.all(col).map(r => ({ key: r.key, value: JSON.parse(r.value), updated_at: r.updated_at })));
    }
    if (method === "DELETE") { _sDrop.run(col); return json({ ok: true }); }
  }

  const storeEntryMatch = sub.match(/^\/store\/([^/]+)\/([^/]+)$/);
  if (storeEntryMatch && method === "DELETE") {
    _sDel.run(decodeURIComponent(storeEntryMatch[1]), decodeURIComponent(storeEntryMatch[2]));
    return json({ ok: true });
  }

  // ── Files ─────────────────────────────────────────────────────────────────
  if (sub === "/files" && method === "GET") {
    return json(_fAll.all());
  }

  if (sub === "/files" && method === "POST") {
    const formData = await req.formData();
    const file = formData.get("file");
    if (!file || typeof file === "string") return json({ error: "No file" }, 400);
    const id = fileId();
    const filename = file.name;
    const mimetype = file.type || "application/octet-stream";
    const bytes = await file.arrayBuffer();
    await Bun.write(join(UPLOADS_DIR, id), bytes);
    _fInsert.run(id, filename, mimetype, bytes.byteLength);
    return json({ id, filename, mimetype, size: bytes.byteLength }, 201);
  }

  const fileMatch = sub.match(/^\/files\/([^/]+)$/);
  if (fileMatch && method === "DELETE") {
    const id = fileMatch[1];
    const row = _fGet.get(id);
    if (!row) return json({ error: "Not found" }, 404);
    try { unlinkSync(join(UPLOADS_DIR, id)); } catch {}
    _fDel.run(id);
    return json({ ok: true });
  }

  return json({ error: "Not found" }, 404);
}

// ── Server ─────────────────────────────────────────────────────────────────────
const server = Bun.serve({
  port: PORT,
  async fetch(req, server) {
    const url = new URL(req.url);

    if (url.pathname.startsWith("/__u/")) {
      const id = url.pathname.slice("/__u/".length);
      const row = _fGet.get(id);
      if (!row) return json({ error: "Not found" }, 404);
      return new Response(Bun.file(join(UPLOADS_DIR, id)), {
        headers: {
          "Content-Type": row.mimetype,
          "Content-Disposition": `inline; filename="${row.filename}"`,
        },
      });
    }

    if (url.pathname.startsWith("/__dashboard"))
      return handleDashboard(req, url);

    if (req.method === "OPTIONS") {
      for (const route of state.routes) {
        if (!route.enabled) continue;
        if (matchPath(route.path, url.pathname) !== null)
          return new Response(null, { status: 204, headers: corsHeaders(route) });
      }
      return new Response(null, { status: 204 });
    }

    for (const route of state.routes) {
      if (!route.enabled || route.method !== req.method) continue;
      const params = matchPath(route.path, url.pathname);
      if (params === null) continue;
      if (isRateLimited(route, req, server))
        return json({ error: "Rate limit exceeded" }, 429, corsHeaders(route));
      return runRoute(route, req, url, params);
    }

    return json({ error: "Not found" }, 404);
  },
});

scheduleCrons();

console.log(`\nbleh running on :${PORT}`);
console.log(`Dashboard → http://localhost:${PORT}/__dashboard\n`);
