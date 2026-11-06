#!/usr/bin/env node
// The website as the browser proof serves it: ghost-web/ as static files, as nginx serves the real
// site, plus the paths nginx hands to the website's API proxy, handed to a running one.
//
//   /node-list.json            the merged list (`ghost-audit merge` output), from --node-list
//   /api/pool/<host>/<path>    the per-node proxy miner.js asks, and
//   /api/v1/node-pool/status   the status tiles' same-origin status: both passed, method, path and
//                              query as received and nothing else, to --api-proxy, which is
//                              scripts/website-proxy/ghost-site-proxy.py (the rules live there)
//
//   node site-server.mjs --root ghost-web --port 43900 --node-list merged.json \
//        --api-proxy http://127.0.0.1:43902
//
// No packages. Logs one line per request to stdout.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";

function args() {
  const a = {};
  const v = process.argv.slice(2);
  for (let i = 0; i < v.length; i += 2) a[v[i].replace(/^--/, "")] = v[i + 1];
  for (const k of ["root", "port", "node-list", "api-proxy"])
    if (!a[k]) throw new Error(`missing --${k}`);
  return a;
}

const A = args();
const ROOT = path.resolve(A.root);
const PROXY = new URL(A["api-proxy"]);
const TYPES = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".json": "application/json", ".png": "image/png",
  ".svg": "image/svg+xml", ".md": "text/markdown; charset=utf-8", ".txt": "text/plain",
  ".xml": "application/xml", ".ico": "image/x-icon", ".sh": "text/plain",
};

// As the nginx locations do: the raw path and query, the method, no viewer header, no body.
function toProxy(req, res) {
  const up = http.request(
    { host: PROXY.hostname, port: PROXY.port, method: req.method, path: req.url, timeout: 20_000,
      headers: { host: "bitcoinghost.test" } },
    (r) => {
      const h = { "content-type": r.headers["content-type"] || "application/json" };
      if (r.headers["x-ghost-node"]) h["x-ghost-node"] = r.headers["x-ghost-node"];
      if (r.headers.allow) h.allow = r.headers.allow;
      res.writeHead(r.statusCode, h);
      r.pipe(res);
    },
  );
  up.on("timeout", () => up.destroy(new Error("timeout")));
  up.on("error", (e) => {
    if (res.headersSent) return res.end();
    res.writeHead(502, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: `the API proxy did not answer: ${e.message}` }));
  });
  up.end();
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
    if (u.pathname.startsWith("/api/pool/") || u.pathname === "/api/v1/node-pool/status")
      return toProxy(req, res);
    if (req.method !== "GET" && req.method !== "HEAD") return notFound(res);
    if (u.pathname === "/node-list.json") {
      fs.readFile(A["node-list"], (e, b) => {
        if (e) return notFound(res);
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(b);
      });
      return;
    }
    if (u.pathname.startsWith("/api/")) return notFound(res);
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
