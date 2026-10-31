"use strict";

// #1016: the OPTIONAL off-node backup destination, from the dashboard's side.
//
// Three things are asserted here, against the REAL modules:
//
//   1. auth   — middleware.ts refuses /api/backup-offsite without a valid session (401) and lets
//               a valid one through. The route itself has no auth of its own by design, exactly
//               like /api/auto-update, so this is the gate that matters.
//   2. route  — GET/POST drive the helper only as `sudo -n <helper> <one of five subcommands>`,
//               settings travel on stdin built from validated values, and bad input is a 400 that
//               never reaches the helper at all.
//   3. validation — the client-side whitelist refuses the same hostile strings the helper's own
//               self-test (scripts/test-backup-offsite.sh) throws at it.
//
// The TypeScript route and middleware are loaded with Node's built-in type stripping and a resolve
// hook for the `@/` alias, so nothing here is a re-implementation of what is being tested. A fake
// `sudo` records each call and answers as the helper would.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { pathToFileURL } = require("node:url");
const nodeModule = require("node:module");

const SRC = path.resolve(__dirname, "..", "src");
const { validateOffsiteSetting } = require("../src/lib/backupOffsite.js");

// ---------------------------------------------------------------- loading the real TS modules

let canLoadTs = typeof nodeModule.registerHooks === "function";
if (canLoadTs) {
  nodeModule.registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier.startsWith("@/")) {
        const base = path.join(SRC, specifier.slice(2));
        for (const ext of [".ts", ".tsx", ".js"]) {
          if (fs.existsSync(base + ext)) return nextResolve(pathToFileURL(base + ext).href, context);
        }
      }
      // Next's server entry is CommonJS without static named exports; hand ESM importers the
      // module that actually defines NextRequest/NextResponse.
      if (specifier === "next/server") {
        return nextResolve("next/dist/server/web/exports/index.js", context);
      }
      return nextResolve(specifier, context);
    },
  });
}

const SECRET = "test-secret-abcdefghijklmnopqrstuvwxyz-0123456789";
process.env.DASHBOARD_JWT_SECRET = SECRET;
delete process.env.DASHBOARD_PASSWORD;

// The fake sudo: logs argv and stdin, then answers as the helper would for each subcommand.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "backup-offsite-test-"));
const LOG = path.join(TMP, "calls.jsonl");
const FAKE_SUDO = path.join(TMP, "sudo");
fs.writeFileSync(
  FAKE_SUDO,
  `#!/usr/bin/env node
const fs = require("fs");
const argv = process.argv.slice(2);
let input = "";
try { input = fs.readFileSync(0, "utf8"); } catch {}
fs.appendFileSync(${JSON.stringify(LOG)}, JSON.stringify({ argv, input }) + "\\n");
const sub = argv[2];
const state = { ok: true, enabled: false, kind: null, target: null, port: null, keep: 7,
  conf_error: null, public_key: null, host_key_pinned: false, last_result: null,
  local: { dir: "/var/backups/ghost/db", count: 0, newest: null, newest_time: null, timer: "enabled" } };
if (sub === "show") { console.log(JSON.stringify(state)); process.exit(0); }
if (sub === "set") { console.log(JSON.stringify({ ok: true, message: "set" })); process.exit(0); }
if (sub === "test") { console.log(JSON.stringify({ ok: false, error: "ssh: connect to host nas port 22: Connection refused" })); process.exit(1); }
console.log(JSON.stringify({ ok: true }));
`,
  { mode: 0o755 },
);
process.env.GHOST_SUDO_BIN = FAKE_SUDO;
process.env.GHOST_BACKUP_OFFSITE_BIN = "/opt/ghost/bin/ghost-backup-offsite";

function calls() {
  if (!fs.existsSync(LOG)) return [];
  return fs.readFileSync(LOG, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
}
function resetCalls() {
  fs.rmSync(LOG, { force: true });
}

function mintToken(secret) {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(JSON.stringify({ sub: "operator", iat: now, exp: now + 3600 })).toString(
    "base64url",
  );
  const sig = crypto.createHmac("sha256", Buffer.from(secret, "utf8")).update(`${header}.${payload}`).digest("base64url");
  return `${header}.${payload}.${sig}`;
}

let route;
let middleware;
let NextRequest;
test.before(async () => {
  if (!canLoadTs) return;
  try {
    route = await import(pathToFileURL(path.join(SRC, "app/api/backup-offsite/route.ts")).href);
    ({ middleware } = await import(pathToFileURL(path.join(SRC, "middleware.ts")).href));
    ({ NextRequest } = await import("next/server"));
  } catch (e) {
    canLoadTs = false;
    console.error(`cannot load the TypeScript modules: ${e.message}`);
  }
});
test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));

// A test that cannot load what it tests must FAIL, not skip: a skipped test is green.
function requireTs() {
  assert.ok(canLoadTs, "this Node cannot load the TypeScript route/middleware (needs registerHooks + type stripping)");
}

function post(body, raw) {
  return new NextRequest("http://localhost/api/backup-offsite", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: raw ?? JSON.stringify(body),
  });
}

// ---------------------------------------------------------------- 1. auth

test("middleware: /api/backup-offsite without a session is 401", async () => {
  requireTs();
  for (const method of ["GET", "POST"]) {
    const res = await middleware(new NextRequest("http://localhost/api/backup-offsite", { method }));
    assert.equal(res.status, 401, `${method} must be refused`);
  }
});

test("middleware: a forged session (wrong key) is 401", async () => {
  requireTs();
  const req = new NextRequest("http://localhost/api/backup-offsite", {
    headers: { cookie: `ghost-session=${mintToken("not-the-secret-not-the-secret-not-the-secret")}` },
  });
  assert.equal((await middleware(req)).status, 401);
});

test("middleware: a valid session reaches the route (control)", async () => {
  requireTs();
  const req = new NextRequest("http://localhost/api/backup-offsite", {
    headers: { cookie: `ghost-session=${mintToken(SECRET)}` },
  });
  const res = await middleware(req);
  assert.notEqual(res.status, 401);
  assert.equal(res.headers.get("x-middleware-next"), "1");
});

// ---------------------------------------------------------------- 2. route

test("GET runs exactly `sudo -n <helper> show` and returns its JSON", async () => {
  requireTs();
  resetCalls();
  const res = await route.GET();
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.enabled, false);
  assert.equal(body.local.timer, "enabled");
  assert.deepEqual(calls().map((c) => c.argv), [["-n", "/opt/ghost/bin/ghost-backup-offsite", "show"]]);
});

test("POST set: validated values go on stdin, argv is fixed", async () => {
  requireTs();
  resetCalls();
  const res = await route.POST(
    post({ action: "set", kind: "ssh", target: "bk@nas.example.org:/srv/ghost", keep: 5, port: 2222, extra: "x" }),
  );
  assert.equal(res.status, 200);
  const c = calls();
  assert.deepEqual(c[0].argv, ["-n", "/opt/ghost/bin/ghost-backup-offsite", "set"]);
  assert.equal(c[0].input, "kind=ssh\ntarget=bk@nas.example.org:/srv/ghost\nkeep=5\nport=2222\n");
  assert.ok(!c[0].input.includes("extra"), "unknown fields must not be forwarded");
  assert.deepEqual(c[1].argv.slice(2), ["show"], "the fresh state is re-read after a change");
});

test("POST with invalid input is a 400 and never reaches the helper", async () => {
  requireTs();
  const bad = [
    { action: "set", kind: "local", target: "/mnt/x;rm -rf /" },
    { action: "set", kind: "local", target: "/mnt/$(id)" },
    { action: "set", kind: "local", target: "/mnt/a\nkind=ssh" },
    { action: "set", kind: "ssh", target: "bk@-oProxyCommand=id:/srv" },
    { action: "set", kind: "ssh", target: "bk@nas:/srv", port: "22;id" },
    { action: "set", kind: "ssh", target: "bk@nas:/srv", keep: 0 },
    { action: "set", kind: "nfs", target: "/mnt/x" },
    { action: "show" },
    { action: "push" },
    { action: "rm -rf /" },
    {},
  ];
  for (const body of bad) {
    resetCalls();
    const res = await route.POST(post(body));
    assert.equal(res.status, 400, `must be 400: ${JSON.stringify(body)}`);
    assert.equal(calls().length, 0, `must not run the helper: ${JSON.stringify(body)}`);
  }
  resetCalls();
  for (const raw of ["not json", "[1,2]", "null"]) {
    assert.equal((await route.POST(post(null, raw))).status, 400, `must be 400: ${raw}`);
  }
  assert.equal(calls().length, 0);
});

test("POST test: a failed probe is an answer carrying the server's error verbatim", async () => {
  requireTs();
  resetCalls();
  const res = await route.POST(post({ action: "test" }));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.result.ok, false);
  assert.match(body.result.error, /Connection refused/);
  assert.deepEqual(calls()[0].argv, ["-n", "/opt/ghost/bin/ghost-backup-offsite", "test"]);
});

test("POST disable and keygen map to their own subcommands only", async () => {
  requireTs();
  for (const action of ["disable", "keygen"]) {
    resetCalls();
    const res = await route.POST(post({ action }));
    assert.equal(res.status, 200);
    assert.deepEqual(calls()[0].argv, ["-n", "/opt/ghost/bin/ghost-backup-offsite", action]);
  }
});

// ---------------------------------------------------------------- 3. validation

test("validation accepts the two destination kinds (control)", () => {
  const l = validateOffsiteSetting({ kind: "local", target: "/mnt/usb/ghost", keep: 7 });
  assert.equal(l.ok, true);
  assert.equal(l.input, "kind=local\ntarget=/mnt/usb/ghost\nkeep=7\n");
  const s = validateOffsiteSetting({ kind: "ssh", target: "u123-sub1@backup.example.org:/home/ghost" });
  assert.equal(s.ok, true);
  assert.equal(s.input, "kind=ssh\ntarget=u123-sub1@backup.example.org:/home/ghost\nkeep=7\nport=22\n");
});

test("validation rejects hostile and malformed targets", () => {
  const hostile = [
    ["local", "/tmp/x;rm -rf /"],
    ["local", "/tmp/$(id)"],
    ["local", "/tmp/`id`"],
    ["local", "/tmp/a b"],
    ["local", "/tmp/a\nb"],
    ["local", "/tmp/a\rb"],
    ["local", "/tmp/../etc"],
    ["local", "relative/path"],
    ["local", "/"],
    ["local", "/tmp/x|id"],
    ["local", "/tmp/x'y"],
    ["ssh", "bk@nas:/srv;id"],
    ["ssh", "bk@nas$(id):/srv"],
    ["ssh", "bk@-oProxyCommand=id:/srv"],
    ["ssh", "-oProxyCommand=id@nas:/srv"],
    ["ssh", "bk@nas:/srv/a b"],
    ["ssh", "bk@nas:relative"],
    ["ssh", "nas:/srv"],
    ["ssh", "bk@[::1]:/srv"],
  ];
  for (const [kind, target] of hostile) {
    assert.equal(validateOffsiteSetting({ kind, target }).ok, false, `${kind} ${JSON.stringify(target)}`);
  }
  for (const body of [
    { kind: "ssh", target: "bk@nas:/srv", port: 0 },
    { kind: "ssh", target: "bk@nas:/srv", port: 65536 },
    { kind: "ssh", target: "bk@nas:/srv", port: "22" },
    { kind: "ssh", target: "bk@nas:/srv", keep: 366 },
    { kind: "ssh", target: "bk@nas:/srv", keep: 1.5 },
    { kind: "local", target: "/mnt/x", port: 22 },
    { kind: "local", target: 42 },
    null,
  ]) {
    assert.equal(validateOffsiteSetting(body).ok, false, JSON.stringify(body));
  }
});
