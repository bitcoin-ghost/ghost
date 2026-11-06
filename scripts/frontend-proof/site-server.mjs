#!/usr/bin/env node
// The website as the browser proof serves it: ghost-web/ as static files, plus the two API paths
// the pages read, both forwarded to live node pool nodes.
//
//   /node-list.json            the merged list (`ghost-audit merge` output), from --node-list
//   /api/pool/<host>/<path>    the per-node proxy miner.js asks: forwarded to that host's API port
//                              ONLY if <host> is listed in the current node list and <path> is
//                              one of the node pool's read routes (the rule PORTING_NOTES sets
//                              for the real website's proxy); anything else is 404
//   /api/v1/<path>             the same-origin API index.html and pool.html read: one node's
//
// A node's API port comes from --api-port-map (host=port,...): on a real network it is 8080 on
// every host; on a regtest run every node is on loopback with a port of its own.
//
//   node site-server.mjs --root ghost-web --port 43900 --node-list merged.json \
//        --api-port-map 127.0.0.10=43010,127.0.0.11=43110 --same-origin-api http://127.0.0.1:43010
//
// No packages. Logs one line per request to stdout.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";

function args() {
  const a = {};
  const v = process.argv.slice(2);
  for (let i = 0; i < v.length; i += 2) a[v[i].replace(/^--/, "")] = v[i + 1];
  for (const k of ["root", "port", "node-list", "api-port-map", "same-origin-api"])
    if (!a[k]) throw new Error(`missing --${k}`);
  return a;
}

const A = args();
const ROOT = path.resolve(A.root);
const PORTS = Object.fromEntries(
  A["api-port-map"].split(",").filter(Boolean).map((kv) => kv.split("=")),
);
const TYPES = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".json": "application/json", ".png": "image/png",
  ".svg": "image/svg+xml", ".md": "text/markdown; charset=utf-8", ".txt": "text/plain",
  ".xml": "application/xml", ".ico": "image/x-icon", ".sh": "text/plain",
};
// The read routes a miner page may ask a listed node for.
const ALLOWED = [
  /^\/api\/v1\/ledger\/[A-Za-z0-9]{1,100}$/,
  /^\/api\/v1\/miner\/[A-Za-z0-9]{1,100}$/,
  /^\/api\/v1\/miner\/[A-Za-z0-9]{1,100}\/history$/,
  /^\/api\/v1\/node-pool\/status$/,
];

function listedHosts() {
  try {
    const l = JSON.parse(fs.readFileSync(A["node-list"], "utf8"));
    return new Set((l.nodes || []).map((n) => n.host));
  } catch {
    return new Set();
  }
}

function forward(res, target) {
  const req = http.get(target, { timeout: 10_000 }, (up) => {
    res.writeHead(up.statusCode, { "content-type": up.headers["content-type"] || "application/json" });
    up.pipe(res);
  });
  req.on("timeout", () => req.destroy(new Error("timeout")));
  req.on("error", (e) => {
    if (res.headersSent) return res.end();
    res.writeHead(502, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: `node did not answer: ${e.message}` }));
  });
}

function notFound(res) {
  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found");
}

http
  .createServer((req, res) => {
    const u = new URL(req.url, "http://x");
    const log = () => console.log(`${new Date().toISOString()} ${req.method} ${req.url} ${res.statusCode}`);
    res.on("finish", log);
    if (req.method !== "GET" && req.method !== "HEAD") return notFound(res);
    if (u.pathname === "/node-list.json") {
      fs.readFile(A["node-list"], (e, b) => {
        if (e) return notFound(res);
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(b);
      });
      return;
    }
    const m = u.pathname.match(/^\/api\/pool\/([0-9A-Fa-f:.]{2,45})(\/.*)$/);
    if (m) {
      const [, host, rest] = m;
      if (!listedHosts().has(host) || !PORTS[host] || !ALLOWED.some((r) => r.test(rest)))
        return notFound(res);
      const h = host.includes(":") ? `[${host}]` : host;
      return forward(res, `http://${h}:${PORTS[host]}${rest}${u.search}`);
    }
    if (u.pathname.startsWith("/api/")) {
      if (!ALLOWED.some((r) => r.test(u.pathname))) return notFound(res);
      return forward(res, `${A["same-origin-api"]}${u.pathname}${u.search}`);
    }
    let p = path.normalize(path.join(ROOT, decodeURIComponent(u.pathname)));
    if (!p.startsWith(ROOT)) return notFound(res);
    if (fs.existsSync(p) && fs.statSync(p).isDirectory()) p = path.join(p, "index.html");
    fs.readFile(p, (e, b) => {
      if (e) {
        const nf = path.join(ROOT, "404.html");
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        return res.end(fs.existsSync(nf) ? fs.readFileSync(nf) : "not found");
      }
      res.writeHead(200, { "content-type": TYPES[path.extname(p)] || "application/octet-stream" });
      res.end(req.method === "HEAD" ? undefined : b);
    });
  })
  .listen(Number(A.port), "127.0.0.1", () => console.log(`site-server on 127.0.0.1:${A.port}, root ${ROOT}`));
