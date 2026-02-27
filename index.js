import { Database } from "bun:sqlite";
import { existsSync, readFileSync, writeFileSync } from "fs";
import { fileURLToPath } from "url";
import { join, dirname } from "path";

const __dir = dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.env.PORT || "3000");
const PASSPHRASE = process.env.PASSPHRASE;

if (!PASSPHRASE) {
  console.error("Error: PASSPHRASE env var is required");
  console.error("Usage: PASSPHRASE=my-secret PORT=3000 bun run index.js");
  process.exit(1);
}

// ── State ────────────────────────────────────────────────────────────────────
const STATE_FILE = join(__dir, "state.json");

function loadState() {
  if (!existsSync(STATE_FILE)) return { passwordHash: null, routes: [] };
  try {
    return JSON.parse(readFileSync(STATE_FILE, "utf8"));
  } catch {
    return { passwordHash: null, routes: [] };
  }
}

let state = loadState();

function saveState() {
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

// ── SQLite ───────────────────────────────────────────────────────────────────
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
const getLogs = db.prepare(
  `SELECT * FROM logs WHERE route_id = ? ORDER BY id DESC LIMIT 200`
);
const clearLogs = db.prepare(`DELETE FROM logs WHERE route_id = ?`);

// ── Rate limiting ─────────────────────────────────────────────────────────────
const rlMap = new Map(); // routeId -> { count, resetAt }

function windowMs(w) {
  const m = String(w).match(/^(\d+)(s|m|h|d)$/);
  if (!m) return 60_000;
  return parseInt(m[1]) * { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2]];
}

function isRateLimited(route) {
  if (!route.rateLimit?.enabled) return false;
  const { requests, window } = route.rateLimit;
  const now = Date.now();
  let e = rlMap.get(route.id);
  if (!e || now > e.resetAt) e = { count: 0, resetAt: now + windowMs(window) };
  e.count++;
  rlMap.set(route.id, e);
  return e.count > requests;
}

// ── Helpers ──────────────────────────────────────────────────────────────────
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

// ── Path matching ─────────────────────────────────────────────────────────────
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

// ── Code execution ────────────────────────────────────────────────────────────
async function runRoute(route, req, url, params) {
  const body = await parseBody(req);
  const headers = Object.fromEntries(req.headers.entries());
  const query = Object.fromEntries(url.searchParams.entries());

  let result, status;

  try {
    // eslint-disable-next-line no-new-func
    const fn = new Function(
      "req", "body", "headers", "query", "params",
      `return (async () => { ${route.code} })()`
    );
    result = await fn(req, body, headers, query, params);
    status = 200;
  } catch (err) {
    result = { error: err.message, stack: err.stack };
    status = 500;
  }

  // User returned a raw Response
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

// ── Auth ──────────────────────────────────────────────────────────────────────
async function verifyAuth(req) {
  const pw = req.headers.get("x-password");
  if (!pw || !state.passwordHash) return false;
  return Bun.password.verify(pw, state.passwordHash);
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
const dashboardHTML = readFileSync(join(__dir, "dashboard.html"), "utf8");

async function handleDashboard(req, url) {
  const sub = url.pathname.slice("/__dashboard".length) || "/";
  const method = req.method;

  // Serve UI
  if (sub === "/" && method === "GET") {
    return new Response(dashboardHTML, { headers: { "Content-Type": "text/html" } });
  }

  // Public endpoints
  if (sub === "/status" && method === "GET") {
    return json({ setup: !!state.passwordHash });
  }

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

  // Auth required below
  if (!(await verifyAuth(req))) return json({ error: "Unauthorized" }, 401);

  // Routes list
  if (sub === "/routes" && method === "GET") {
    return json(state.routes);
  }

  // Create route
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

  // Logs endpoints (must check before /routes/:id)
  const logsMatch = sub.match(/^\/routes\/([^/]+)\/logs$/);
  if (logsMatch) {
    const id = logsMatch[1];
    if (method === "GET") return json(getLogs.all(id));
    if (method === "DELETE") {
      clearLogs.run(id);
      return json({ ok: true });
    }
  }

  // Single route CRUD
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

  return json({ error: "Not found" }, 404);
}

// ── Server ────────────────────────────────────────────────────────────────────
Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);

    // Dashboard
    if (url.pathname.startsWith("/__dashboard")) {
      return handleDashboard(req, url);
    }

    // CORS preflight for user routes
    if (req.method === "OPTIONS") {
      for (const route of state.routes) {
        if (!route.enabled) continue;
        if (matchPath(route.path, url.pathname) !== null) {
          return new Response(null, { status: 204, headers: corsHeaders(route) });
        }
      }
      return new Response(null, { status: 204 });
    }

    // Match user routes
    for (const route of state.routes) {
      if (!route.enabled || route.method !== req.method) continue;
      const params = matchPath(route.path, url.pathname);
      if (params === null) continue;

      if (isRateLimited(route)) {
        return json({ error: "Rate limit exceeded" }, 429, corsHeaders(route));
      }

      return runRoute(route, req, url, params);
    }

    return json({ error: "Not found" }, 404);
  },
});

console.log(`\nbleh running on :${PORT}`);
console.log(`Dashboard → http://localhost:${PORT}/__dashboard\n`);
