// Custom Next.js server for the Ghost Node Dashboard.
//
// Why this file exists
// --------------------
// App-Router route handlers cannot upgrade a connection to a WebSocket, so
// there is no way to authenticate a WS purely inside `src/app`. The browser
// used to open a raw socket straight to the backend (`ws://<host>:8080/ws`),
// bypassing the JWT that gates every REST call — anyone who could reach the
// node's :8080 got the live event/log stream unauthenticated.
//
// This server wraps Next.js and takes over the HTTP `upgrade` event. Upgrades
// to the same-origin path `/api/ws` are authenticated with the SAME
// `ghost-session` JWT the middleware/REST proxy use; only after the token
// verifies do we open a socket to the loopback backend and pipe frames
// through. An unauthenticated upgrade is answered with `401` and never becomes
// a socket. Everything else is served by Next unchanged.
//
// The WS relay is a transparent TCP tunnel: once auth passes we forward the
// client's original upgrade request (with the path rewritten to `/ws` and the
// cookie stripped) to the backend and pipe the two sockets. The backend
// computes `Sec-WebSocket-Accept` from the client's key and its `101` flows
// straight back, so no frame parsing (and no `ws` dependency) is needed.

"use strict";

const http = require("http");
const net = require("net");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const WS_PATH = "/api/ws";

// ---------------------------------------------------------------------------
// Embedded mempool.space frontend.
//
// Each node runs a self-serving, Core-only mempool.space backend bound to
// 127.0.0.1:8999 (pointed at the node's own ghostd). We ship the built
// mempool.space SPA under `public/mempool-app/` and serve it SAME-ORIGIN at
// the subpath `/mempool-app/`, proxying its API + WebSocket to that loopback
// backend. Because everything is same-origin and loopback-proxied there is no
// certificate, DNS, or mixed-content problem, and it works unchanged on any
// node (the proxy target is always 127.0.0.1:8999).
//
// The SPA's compiled bundles were patched to prefix every API/WS path with
// `/mempool-app` (it hard-codes `apiBaseUrl = ""` in the browser and ignores
// window.__env), so all of its traffic lands under `/mempool-app/api/...` and
// never collides with the dashboard's own `/api/*` routes.
//
// Both the static assets and the API/WS proxy are gated behind the SAME
// `ghost-session` JWT as the rest of the dashboard — this is an operator tool,
// not a public explorer.
// ---------------------------------------------------------------------------

const MEMPOOL_PREFIX = "/mempool-app";
const MEMPOOL_STATIC_ROOT = path.join(__dirname, "public", "mempool-app");

const MEMPOOL_MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".webmanifest": "application/manifest+json",
  ".map": "application/json; charset=utf-8",
  ".ico": "image/x-icon",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".webp": "image/webp",
  ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".wasm": "application/wasm",
};

// ---------------------------------------------------------------------------
// JWT verification — a plain-Node mirror of `src/lib/jwt.ts`.
//
// This deliberately re-implements the verifier instead of importing the TS
// module: this file is a hand-written entry point that runs before/outside the
// Next bundle (and inside the standalone output, where `src/` is not present),
// so it can only depend on Node built-ins. `tests/ws-auth.test.js` pins the two
// implementations together — a token minted by `jwt.ts` MUST verify here, and
// vice versa — so they cannot silently drift.
// ---------------------------------------------------------------------------

const JWT_HEADER_B64U = Buffer.from(
  JSON.stringify({ alg: "HS256", typ: "JWT" }),
).toString("base64url");

/** Derive a stable signing secret from the dashboard password (matches jwt.ts). */
function deriveJwtSecret(password) {
  return crypto
    .createHmac("sha256", Buffer.from(password, "utf8"))
    .update("ghost-dashboard-jwt-v1")
    .digest("base64url");
}

/** Resolve the signing secret from env, deriving from DASHBOARD_PASSWORD as a fallback. */
function resolveJwtSecret() {
  const explicit = process.env.DASHBOARD_JWT_SECRET;
  if (explicit && explicit.length >= 32) return explicit;
  const password = process.env.DASHBOARD_PASSWORD;
  if (!password) return null;
  return deriveJwtSecret(password);
}

/** Verify an HS256 JWT. Returns the payload on success, else null. */
function verifySession(token, secret) {
  if (!token || !secret) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  if (h !== JWT_HEADER_B64U) return null; // reject non-HS256 / mis-typed
  const signingInput = `${h}.${p}`;
  const expected = crypto
    .createHmac("sha256", Buffer.from(secret, "utf8"))
    .update(signingInput)
    .digest();
  let got;
  try {
    got = Buffer.from(s, "base64url");
  } catch {
    return null;
  }
  if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) {
    return null;
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (
    typeof payload.exp !== "number" ||
    payload.exp < Math.floor(Date.now() / 1000)
  ) {
    return null;
  }
  return payload;
}

/** Extract a named cookie value from a raw Cookie header. */
function readCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) {
      return part.slice(eq + 1).trim();
    }
  }
  return null;
}

/**
 * Decide whether an upgrade request is allowed to reach the backend stream.
 * Pure and synchronous so it is trivially testable.
 */
function authorizeUpgrade(req) {
  const token = readCookie(req.headers.cookie, "ghost-session");
  const secret = resolveJwtSecret();
  return verifySession(token, secret) !== null;
}

// ---------------------------------------------------------------------------
// Backend target (loopback by default).
// ---------------------------------------------------------------------------

/** Parse NEXT_PUBLIC_API_URL into {host, port}, defaulting to loopback:8080. */
function backendTarget() {
  const raw = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8080";
  try {
    const u = new URL(raw);
    return {
      host: u.hostname || "127.0.0.1",
      port: Number(u.port) || (u.protocol === "https:" ? 443 : 80),
    };
  } catch {
    return { host: "127.0.0.1", port: 8080 };
  }
}

/** Answer a rejected upgrade with a real HTTP status, then close the socket. */
function rejectUpgrade(socket, status, message) {
  if (socket.writable) {
    socket.write(
      `HTTP/1.1 ${status} ${message}\r\n` +
        "Connection: close\r\n" +
        "Content-Length: 0\r\n" +
        "\r\n",
    );
  }
  socket.destroy();
}

/**
 * Serialise the (rewritten) upgrade request line + headers for the backend.
 * `backendPath` is the absolute request-target to send upstream; when omitted
 * it defaults to `/ws` (preserving the original query), which is the dashboard
 * event/log stream. The mempool WS proxy passes its own rewritten path.
 */
function buildBackendRequest(req, target, backendPath) {
  if (backendPath === undefined) {
    const qIndex = (req.url || "").indexOf("?");
    const search = qIndex === -1 ? "" : req.url.slice(qIndex);
    backendPath = `/ws${search}`;
  }
  const headers = { ...req.headers };
  // Never leak the operator's session cookie to the backend, and rewrite Host.
  delete headers.cookie;
  headers.host = `${target.host}:${target.port}`;

  let raw = `GET ${backendPath} HTTP/1.1\r\n`;
  for (const [k, v] of Object.entries(headers)) {
    if (Array.isArray(v)) {
      for (const item of v) raw += `${k}: ${item}\r\n`;
    } else if (v !== undefined) {
      raw += `${k}: ${v}\r\n`;
    }
  }
  raw += "\r\n";
  return raw;
}

/**
 * Authenticate an `upgrade` event and, if allowed, transparently proxy it to
 * the backend `/ws`. Returns true if this handler owns the request (i.e. it was
 * for WS_PATH), false to let the caller delegate (e.g. dev HMR).
 */
function handleUpgrade(req, socket, head, target = backendTarget()) {
  const pathname = (req.url || "").split("?")[0];
  if (pathname !== WS_PATH) return false;

  socket.on("error", () => socket.destroy());

  if (!authorizeUpgrade(req)) {
    rejectUpgrade(socket, 401, "Unauthorized");
    return true;
  }

  const backend = net.connect(target.port, target.host);
  backend.on("connect", () => {
    backend.write(buildBackendRequest(req, target));
    if (head && head.length) backend.write(head);
    // Transparent byte pipe in both directions from here on.
    socket.pipe(backend);
    backend.pipe(socket);
  });
  backend.on("error", () => {
    rejectUpgrade(socket, 502, "Bad Gateway");
  });
  socket.on("close", () => backend.destroy());
  return true;
}

// ---------------------------------------------------------------------------
// Embedded mempool.space frontend — static serving + API/WS proxy.
// ---------------------------------------------------------------------------

/** Parse MEMPOOL_BACKEND_URL into {host, port}, defaulting to loopback:8999. */
function mempoolBackendTarget() {
  const raw = process.env.MEMPOOL_BACKEND_URL || "http://127.0.0.1:8999";
  try {
    const u = new URL(raw);
    return {
      host: u.hostname || "127.0.0.1",
      port: Number(u.port) || (u.protocol === "https:" ? 443 : 80),
    };
  } catch {
    return { host: "127.0.0.1", port: 8999 };
  }
}

/**
 * Send a file from the mempool static root. Resolves true once the response is
 * committed, false if the file does not exist (so the caller can fall back).
 */
function sendMempoolFile(res, filePath) {
  return new Promise((resolve) => {
    fs.stat(filePath, (err, stat) => {
      if (err || !stat.isFile()) return resolve(false);
      const type =
        MEMPOOL_MIME[path.extname(filePath).toLowerCase()] ||
        "application/octet-stream";
      const isHtml = type.startsWith("text/html");
      res.writeHead(200, {
        "Content-Type": type,
        "Content-Length": stat.size,
        // index.html must never be cached (it is the SPA shell); the hashed
        // asset filenames make everything else safely immutable.
        "Cache-Control": isHtml
          ? "no-cache"
          : "public, max-age=31536000, immutable",
      });
      const stream = fs.createReadStream(filePath);
      stream.on("error", () => {
        res.destroy();
        resolve(true);
      });
      stream.pipe(res);
      resolve(true);
    });
  });
}

/**
 * Serve the mempool.space SPA from `public/mempool-app`. Real files are served
 * directly; unknown non-asset paths fall back to `index.html` so Angular's
 * client-side routing works on deep-link/reload.
 */
async function serveMempoolStatic(req, res) {
  const rawPath = (req.url || "").split("?")[0];

  // Redirect the bare prefix to the trailing-slash form so the SPA's relative
  // asset URLs (and its <base href="/mempool-app/">) resolve correctly.
  if (rawPath === MEMPOOL_PREFIX) {
    res.writeHead(308, { Location: `${MEMPOOL_PREFIX}/` });
    res.end();
    return;
  }

  let rel;
  try {
    rel = decodeURIComponent(rawPath.slice(MEMPOOL_PREFIX.length));
  } catch {
    res.writeHead(400);
    res.end("Bad Request");
    return;
  }
  if (rel === "" || rel === "/") rel = "/index.html";

  const candidate = path.normalize(path.join(MEMPOOL_STATIC_ROOT, rel));
  // Path-traversal guard: never serve anything outside the static root.
  if (
    candidate !== MEMPOOL_STATIC_ROOT &&
    !candidate.startsWith(MEMPOOL_STATIC_ROOT + path.sep)
  ) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  if (await sendMempoolFile(res, candidate)) return;

  // Not a real file. A path with a file extension is a genuine missing asset
  // (404); an extension-less path is a client route → serve the SPA shell.
  const lastSeg = rel.split("/").pop() || "";
  if (lastSeg.includes(".")) {
    res.writeHead(404);
    res.end("Not Found");
    return;
  }
  if (!(await sendMempoolFile(res, path.join(MEMPOOL_STATIC_ROOT, "index.html")))) {
    res.writeHead(404);
    res.end("Not Found");
  }
}

/** Transparently proxy a mempool `/mempool-app/api/...` HTTP request to :8999. */
function proxyMempoolHttp(req, res, target) {
  // Strip the `/mempool-app` prefix: `/mempool-app/api/v1/x` -> `/api/v1/x`.
  const backendPath = (req.url || "").slice(MEMPOOL_PREFIX.length);
  const headers = { ...req.headers };
  delete headers.cookie; // don't leak the operator's session to the backend
  headers.host = `${target.host}:${target.port}`;

  const upstream = http.request(
    {
      host: target.host,
      port: target.port,
      method: req.method,
      path: backendPath,
      headers,
    },
    (up) => {
      res.writeHead(up.statusCode || 502, up.headers);
      up.pipe(res);
    },
  );
  upstream.on("error", () => {
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "application/json" });
    }
    res.end('{"error":"mempool backend unavailable"}');
  });
  req.pipe(upstream);
}

/**
 * Own every `/mempool-app` HTTP request: gate on the dashboard session, then
 * either proxy `/mempool-app/api/*` to the node-local backend or serve the
 * static SPA. Returns true if this handler owned the request.
 */
function handleMempoolHttp(req, res, target = mempoolBackendTarget()) {
  const pathname = (req.url || "").split("?")[0];
  if (pathname !== MEMPOOL_PREFIX && !pathname.startsWith(`${MEMPOOL_PREFIX}/`)) {
    return false;
  }

  // Same JWT gate as the rest of the dashboard.
  if (!authorizeUpgrade(req)) {
    if (pathname.startsWith(`${MEMPOOL_PREFIX}/api/`)) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end('{"error":"unauthorized"}');
    } else {
      res.writeHead(302, { Location: "/login" });
      res.end();
    }
    return true;
  }

  if (pathname.startsWith(`${MEMPOOL_PREFIX}/api/`)) {
    proxyMempoolHttp(req, res, target);
  } else {
    serveMempoolStatic(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  }
  return true;
}

/**
 * Authenticate and proxy the mempool WebSocket upgrade
 * (`/mempool-app/api/v1/ws`) to the node-local backend. Returns true if this
 * handler owns the request.
 */
function handleMempoolUpgrade(req, socket, head, target = mempoolBackendTarget()) {
  const pathname = (req.url || "").split("?")[0];
  if (!pathname.startsWith(`${MEMPOOL_PREFIX}/api/`)) return false;

  socket.on("error", () => socket.destroy());

  if (!authorizeUpgrade(req)) {
    rejectUpgrade(socket, 401, "Unauthorized");
    return true;
  }

  const backendPath = (req.url || "").slice(MEMPOOL_PREFIX.length);
  const backend = net.connect(target.port, target.host);
  backend.on("connect", () => {
    backend.write(buildBackendRequest(req, target, backendPath));
    if (head && head.length) backend.write(head);
    socket.pipe(backend);
    backend.pipe(socket);
  });
  backend.on("error", () => {
    rejectUpgrade(socket, 502, "Bad Gateway");
  });
  socket.on("close", () => backend.destroy());
  return true;
}

module.exports = {
  WS_PATH,
  JWT_HEADER_B64U,
  MEMPOOL_PREFIX,
  deriveJwtSecret,
  resolveJwtSecret,
  verifySession,
  readCookie,
  authorizeUpgrade,
  backendTarget,
  handleUpgrade,
  mempoolBackendTarget,
  handleMempoolHttp,
  handleMempoolUpgrade,
};

// ---------------------------------------------------------------------------
// Entry point — only runs when executed directly (`node server.js`), so tests
// can require the helpers above without booting Next.
// ---------------------------------------------------------------------------

if (require.main === module) {
  // Standalone-config hydration. Next's `output: 'standalone'` build strips the
  // build toolchain (swc / browserslist / the webpack config hook) from the
  // minimal `node_modules`. The generated standalone entrypoint copes by handing
  // Next its pre-serialised config via `__NEXT_PRIVATE_STANDALONE_CONFIG` BEFORE
  // requiring `next`, so `next()` never re-loads (and, for a TypeScript
  // `next.config.ts`, re-transpiles) the config at runtime. This custom server
  // replaces that generated entrypoint, so it must do the same — otherwise
  // `app.prepare()` reaches for modules that aren't in the standalone bundle and
  // crashes on boot. The config is read from `.next/required-server-files.json`
  // (the build writes it as the single source of truth). Gated on production +
  // file presence, so `npm run dev` (no standalone build) is completely
  // unaffected and falls back to Next's normal config load.
  if (
    process.env.NODE_ENV === "production" &&
    !process.env.__NEXT_PRIVATE_STANDALONE_CONFIG
  ) {
    try {
      const rsfPath = require("path").join(
        __dirname,
        ".next",
        "required-server-files.json",
      );
      const rsf = require(rsfPath);
      if (rsf && rsf.config) {
        process.env.__NEXT_PRIVATE_STANDALONE_CONFIG = JSON.stringify(rsf.config);
      }
    } catch {
      // No standalone build alongside this server (e.g. a full production
      // build) — leave the env var unset and let Next load the config normally.
    }
  }

  const next = require("next");
  const dev = process.env.NODE_ENV !== "production";
  const hostname = process.env.HOSTNAME || "127.0.0.1";
  const port = Number(process.env.PORT) || 3000;

  const app = next({ dev, dir: __dirname, hostname, port });
  const handle = app.getRequestHandler();

  app.prepare().then(() => {
    // Must be fetched after prepare(); used to hand dev HMR upgrades back to Next.
    const upgradeHandle =
      typeof app.getUpgradeHandler === "function"
        ? app.getUpgradeHandler()
        : null;
    const server = http.createServer((req, res) => {
      // Stamp the REAL TCP peer address as a trusted header. Next does not
      // populate `request.ip` under a custom server, so downstream routes (the
      // login rate-limiter) have no other way to see the true source. We delete
      // any client-supplied value first, then set it from the socket, so a
      // remote client cannot forge it to dodge (or frame another IP for) the
      // per-source login throttle.
      delete req.headers["x-ghost-peer-addr"];
      const peerAddr = req.socket && req.socket.remoteAddress;
      if (peerAddr) req.headers["x-ghost-peer-addr"] = peerAddr;

      // The embedded mempool app (static assets + its API/WS proxy) is served
      // here, ahead of Next, so it can be gated on the session and proxied to
      // the node-local backend without colliding with the dashboard's own
      // routes. Everything else falls through to Next unchanged.
      try {
        if (handleMempoolHttp(req, res)) return;
      } catch {
        if (!res.headersSent) res.writeHead(500);
        res.end();
        return;
      }
      handle(req, res);
    });

    server.on("upgrade", (req, socket, head) => {
      let owned = false;
      try {
        owned = handleUpgrade(req, socket, head) || handleMempoolUpgrade(req, socket, head);
      } catch {
        rejectUpgrade(socket, 500, "Internal Server Error");
        return;
      }
      if (owned) return;
      // Not our endpoint: let Next handle its own upgrades (HMR in dev);
      // reject anything else so no other unauthenticated upgrade slips by.
      if (upgradeHandle) upgradeHandle(req, socket, head);
      else socket.destroy();
    });

    server.listen(port, hostname, () => {
      console.log(`> Dashboard ready on http://${hostname}:${port}`);
    });
  });
}
