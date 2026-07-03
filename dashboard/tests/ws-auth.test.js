"use strict";

// End-to-end tests for the authenticated WebSocket relay in ../server.js.
//
// These exercise the REAL upgrade handler and REAL JWT verification against a
// mock backend WS server, over real TCP sockets — no mocking of the security
// boundary. Run with: `npm test` (node --test).

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const net = require("node:net");
const crypto = require("node:crypto");

// Deterministic signing secret for the whole suite (>= 32 chars so
// resolveJwtSecret uses it verbatim instead of deriving from a password).
const SECRET = "test-secret-abcdefghijklmnopqrstuvwxyz-0123456789";
process.env.DASHBOARD_JWT_SECRET = SECRET;
delete process.env.DASHBOARD_PASSWORD;

const server = require("../server.js");

// --- helpers ---------------------------------------------------------------

/** Mint an HS256 JWT the same way src/lib/jwt.ts (and server.js) expect. */
function mintToken(secret, { sub = "operator", ttl = 3600, exp } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const payload = { sub, iat: now, exp: exp ?? now + ttl };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signingInput = `${server.JWT_HEADER_B64U}.${payloadB64}`;
  const sig = crypto
    .createHmac("sha256", Buffer.from(secret, "utf8"))
    .update(signingInput)
    .digest("base64url");
  return `${signingInput}.${sig}`;
}

/** Minimal WS backend: completes the handshake and pushes one text frame. */
function startMockBackend() {
  let connections = 0;
  const srv = http.createServer((_req, res) => {
    res.writeHead(426);
    res.end();
  });
  srv.on("upgrade", (req, socket) => {
    connections += 1;
    const key = req.headers["sec-websocket-key"];
    const accept = crypto
      .createHash("sha1")
      .update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
      .digest("base64");
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    const payload = Buffer.from('{"type":"Ping"}');
    // FIN + text opcode, unmasked (server->client), length < 126.
    socket.write(Buffer.concat([Buffer.from([0x81, payload.length]), payload]));
  });
  return new Promise((resolve) => {
    srv.listen(0, "127.0.0.1", () =>
      resolve({
        srv,
        port: srv.address().port,
        get connections() {
          return connections;
        },
      }),
    );
  });
}

/** The relay under test: a bare HTTP server wired to server.handleUpgrade. */
function startRelay(backendPort) {
  const srv = http.createServer((_req, res) => {
    res.writeHead(404);
    res.end();
  });
  srv.on("upgrade", (req, socket, head) => {
    server.handleUpgrade(req, socket, head, {
      host: "127.0.0.1",
      port: backendPort,
    });
  });
  return new Promise((resolve) => {
    srv.listen(0, "127.0.0.1", () =>
      resolve({ srv, port: srv.address().port }),
    );
  });
}

/**
 * Perform a raw WS upgrade against the relay. Resolves with the HTTP status
 * code and, on a 101, the decoded payload of the first text frame received.
 */
function rawUpgrade(port, { cookie } = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, "127.0.0.1");
    const key = crypto.randomBytes(16).toString("base64");
    let buf = Buffer.alloc(0);
    let settled = false;

    const done = (val) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      resolve(val);
    };
    const timer = setTimeout(() => done({ status: 0, timedOut: true }), 2000);

    sock.on("connect", () => {
      let req =
        "GET /api/ws HTTP/1.1\r\n" +
        `Host: 127.0.0.1:${port}\r\n` +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        `Sec-WebSocket-Key: ${key}\r\n` +
        "Sec-WebSocket-Version: 13\r\n";
      if (cookie) req += `Cookie: ${cookie}\r\n`;
      req += "\r\n";
      sock.write(req);
    });

    sock.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const sep = buf.indexOf("\r\n\r\n");
      if (sep === -1) return;
      const head = buf.slice(0, sep).toString("latin1");
      const status = Number(head.split(" ")[1]);
      if (status !== 101) {
        return done({ status });
      }
      // Decode the first (unmasked, short) text frame from the body, if present.
      const body = buf.slice(sep + 4);
      if (body.length < 2) return; // wait for the frame
      const len = body[1] & 0x7f;
      if (body.length < 2 + len) return;
      const message = body.slice(2, 2 + len).toString("utf8");
      done({ status: 101, message });
    });

    sock.on("error", reject);
  });
}

// --- JWT parity / unit checks ---------------------------------------------

test("JWT header encoding matches the HS256/JWT constant", () => {
  const expected = Buffer.from(
    JSON.stringify({ alg: "HS256", typ: "JWT" }),
  ).toString("base64url");
  assert.equal(server.JWT_HEADER_B64U, expected);
});

test("verifySession accepts a valid token and rejects bad ones", () => {
  const good = mintToken(SECRET);
  assert.ok(server.verifySession(good, SECRET), "valid token should verify");

  // Wrong secret.
  assert.equal(server.verifySession(good, "another-secret-x".repeat(3)), null);
  // Tampered signature.
  assert.equal(server.verifySession(good.slice(0, -2) + "xy", SECRET), null);
  // Expired.
  const expired = mintToken(SECRET, { exp: Math.floor(Date.now() / 1000) - 10 });
  assert.equal(server.verifySession(expired, SECRET), null);
  // Malformed.
  assert.equal(server.verifySession("not.a.jwt", SECRET), null);
  assert.equal(server.verifySession("", SECRET), null);
});

test("resolveJwtSecret prefers explicit secret, else derives from password", () => {
  assert.equal(server.resolveJwtSecret(), SECRET);

  const saved = process.env.DASHBOARD_JWT_SECRET;
  delete process.env.DASHBOARD_JWT_SECRET;
  process.env.DASHBOARD_PASSWORD = "hunter2";
  assert.equal(server.resolveJwtSecret(), server.deriveJwtSecret("hunter2"));

  delete process.env.DASHBOARD_PASSWORD;
  assert.equal(server.resolveJwtSecret(), null, "no secret -> locked (null)");

  process.env.DASHBOARD_JWT_SECRET = saved; // restore for later tests
});

test("readCookie extracts the named cookie", () => {
  assert.equal(
    server.readCookie("a=1; ghost-session=TOKEN; b=2", "ghost-session"),
    "TOKEN",
  );
  assert.equal(server.readCookie("", "ghost-session"), null);
  assert.equal(server.readCookie(undefined, "ghost-session"), null);
});

// --- end-to-end relay behaviour -------------------------------------------

test("upgrade WITHOUT a valid session -> 401, no backend socket", async () => {
  const backend = await startMockBackend();
  const relay = await startRelay(backend.port);
  try {
    const noCookie = await rawUpgrade(relay.port);
    assert.equal(noCookie.status, 401, "missing cookie must be rejected");

    const badCookie = await rawUpgrade(relay.port, {
      cookie: "ghost-session=forged.invalid.token",
    });
    assert.equal(badCookie.status, 401, "forged token must be rejected");

    const expired = await rawUpgrade(relay.port, {
      cookie: `ghost-session=${mintToken(SECRET, { exp: Math.floor(Date.now() / 1000) - 10 })}`,
    });
    assert.equal(expired.status, 401, "expired token must be rejected");

    // No unauthorized attempt reached the backend.
    assert.equal(backend.connections, 0, "backend must see zero connections");
  } finally {
    backend.srv.close();
    relay.srv.close();
  }
});

test("upgrade WITH a valid session -> 101 and relays a message", async () => {
  const backend = await startMockBackend();
  const relay = await startRelay(backend.port);
  try {
    const res = await rawUpgrade(relay.port, {
      cookie: `ghost-session=${mintToken(SECRET)}`,
    });
    assert.equal(res.status, 101, "valid session must complete the handshake");
    assert.equal(res.message, '{"type":"Ping"}', "backend frame must relay");
    assert.equal(backend.connections, 1, "exactly one backend connection");
  } finally {
    backend.srv.close();
    relay.srv.close();
  }
});
