#!/usr/bin/env python3
"""The website's API proxy: lets bitcoinghost.org's pages read live node pool nodes, and nothing else.

    ghost-site-proxy.py [--listen 127.0.0.1:8791] [--node-list /var/lib/ghost-merge/node-list.json]
                        [--api-port 8080] [--api-port-map HOST=PORT,...] [--allow-private]
                        [--timeout 8] [--max-bytes 4194304] [--max-inflight 32] [--status-cache 10]

nginx on the website host sends it two paths (scripts/website-proxy/nginx-site-proxy.conf):

  /api/pool/<host>/<route>      what the miner page (ghost-web/miner.js) asks each listed node:
                                forwarded to <host>'s API port, ONLY if <host> is in the CURRENT
                                node-list.json and <route> is one of ROUTES below.
  /api/v1/node-pool/status      what the home and pool pages' tiles read (ghost-web/node-pool.js):
                                the first listed node, in list order, that answers 200. Every node
                                reports the same pool-wide figures; the answer is cached for
                                --status-cache seconds so a crowd of viewers costs one request.

Everything else is 404, and every method but GET is 405. The rule (docs/node-pool-reference/
PORTING_NOTES.md): without it this is an open proxy.

- **Only listed hosts.** `node-list.json` (`ghost-audit merge` output) is re-read whenever its
  mtime, size or inode changes, so a node dropped from the list is refused on the next request. A
  host must be an IP literal written exactly as the list writes it: a name could be pointed
  anywhere after it was listed. Loopback, private, link-local and other non-global addresses are
  refused unless --allow-private (a regtest run). A list that cannot be read or parsed lists
  nobody: the proxy fails closed.
- **Only the read routes the pages use**, matched on the raw request path before any decoding:
  `/api/v1/ledger/<addr>`, `/api/v1/miner/<addr>`, `/api/v1/miner/<addr>/history` and
  `/api/v1/node-pool/status`, `<addr>` 1-100 letters and digits. The only query forwarded is
  `window=24h|7d|30d` on history. No `..`, no `%`, no other characters reach a node.
- **Fixed ports.** node-list.json carries no API port (a node's public API is 8080), so the port
  is --api-port, or the host's entry in --api-port-map (a regtest run, every node on loopback).
  Nothing in the request chooses a port.
- **Nothing of the viewer's is forwarded**: no header, cookie or body. The request to the node
  carries only Host, Accept and a User-Agent. Nothing of the node's is passed back but its status
  code and body: no header, so no Set-Cookie.
- **Bounded.** --timeout seconds for the whole answer (connect, headers and body); a node that
  takes longer is 504. A body over --max-bytes is 502 and nothing of it is sent. A redirect is
  never followed (502). At most --max-inflight requests to nodes at once, then 503.

Logs one line per request to stdout (journald). Python 3.8+, standard library only.
"""

import argparse
import http.client
import http.server
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time

ADDR = r"[A-Za-z0-9]{1,100}"
# The read routes a page may ask a listed node for: (path regex, allowed query keys and values).
ROUTES = [
    (re.compile(r"^/api/v1/ledger/" + ADDR + r"$"), {}),
    (re.compile(r"^/api/v1/miner/" + ADDR + r"$"), {}),
    (re.compile(r"^/api/v1/miner/" + ADDR + r"/history$"), {"window": {"24h", "7d", "30d"}}),
    (re.compile(r"^/api/v1/node-pool/status$"), {}),
]
STATUS_PATH = "/api/v1/node-pool/status"
# /api/pool/<host><route>: an IPv4 or IPv6 literal (hex, digits, dots, colons), then the route.
POOL_PATH = re.compile(r"^/api/pool/([0-9A-Fa-f:.]{2,45})(/.*)$")
USER_AGENT = "ghost-site-proxy/1"


class NodeList:
    """The hosts of the current node-list.json, re-read when the file changes."""

    def __init__(self, path, allow_private):
        self.path = path
        self.allow_private = allow_private
        self.lock = threading.Lock()
        self.sig = None
        self.hosts = []

    def _usable(self, host):
        if not isinstance(host, str):
            return False
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        if str(ip) != host and host.lower() != str(ip):
            return False  # not written in its canonical form: refuse rather than guess
        return self.allow_private or ip.is_global

    def current(self):
        """Listed hosts, in list order. Empty when the list cannot be read."""
        try:
            st = os.stat(self.path)
            sig = (st.st_mtime_ns, st.st_size, st.st_ino)
        except OSError:
            sig = None
        with self.lock:
            if sig != self.sig:
                hosts = []
                if sig is not None:
                    try:
                        with open(self.path, "rb") as f:
                            data = json.loads(f.read(8 * 1024 * 1024))
                        for n in data.get("nodes") or []:
                            h = n.get("host") if isinstance(n, dict) else None
                            if self._usable(h) and h not in hosts:
                                hosts.append(h)
                    except (OSError, ValueError, AttributeError):
                        hosts = []
                self.sig, self.hosts = sig, hosts
            return list(self.hosts)


class Upstream:
    """One bounded GET to a node."""

    class Fail(Exception):
        def __init__(self, code, msg):
            super().__init__(msg)
            self.code, self.msg = code, msg

    def __init__(self, timeout, max_bytes, max_inflight):
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.slots = threading.BoundedSemaphore(max_inflight)

    def get(self, host, port, path_qs):
        if not self.slots.acquire(blocking=False):
            raise Upstream.Fail(503, "too many requests to nodes at once; try again")
        try:
            return self._get(host, port, path_qs)
        finally:
            self.slots.release()

    def _get(self, host, port, path_qs):
        deadline = time.monotonic() + self.timeout

        def left():
            t = deadline - time.monotonic()
            if t <= 0:
                raise socket.timeout("deadline")
            return t

        conn = http.client.HTTPConnection(host, port, timeout=left())
        try:
            hdr_host = "[%s]" % host if ":" in host else host
            conn.putrequest("GET", path_qs, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", "%s:%d" % (hdr_host, port))
            conn.putheader("Accept", "application/json")
            conn.putheader("User-Agent", USER_AGENT)
            conn.putheader("Connection", "close")
            conn.endheaders()
            # Held here: http.client drops conn.sock once a closing response is read.
            sock = conn.sock
            sock.settimeout(left())
            r = conn.getresponse()
            if 300 <= r.status < 400:
                raise Upstream.Fail(502, "the node answered with a redirect, which is not followed")
            length = r.getheader("Content-Length")
            if length is not None and length.isdigit() and int(length) > self.max_bytes:
                raise Upstream.Fail(502, "the node's answer is larger than %d bytes" % self.max_bytes)
            body = bytearray()
            while not r.isclosed():
                sock.settimeout(left())
                # read1: one recv at most, so a node trickling bytes meets the deadline too.
                chunk = r.read1(65536)
                if not chunk:
                    break
                body += chunk
                if len(body) > self.max_bytes:
                    raise Upstream.Fail(502, "the node's answer is larger than %d bytes" % self.max_bytes)
            return r.status, bytes(body)
        except Upstream.Fail:
            raise
        except socket.timeout:
            raise Upstream.Fail(504, "the node did not answer within %g s" % self.timeout)
        except (OSError, http.client.HTTPException) as e:
            raise Upstream.Fail(502, "the node did not answer: %s" % type(e).__name__)
        finally:
            conn.close()


def route_query(path, query):
    """The path and query to forward, or None if this is not an allowed read route."""
    for rx, allowed in ROUTES:
        if rx.match(path):
            break
    else:
        return None
    if not query:
        return path
    parts = query.split("&")
    out = []
    for p in parts:
        k, sep, v = p.partition("=")
        if not sep or k not in allowed or v not in allowed[k] or k in [o[0] for o in out]:
            return None
        out.append((k, v))
    return path + "?" + "&".join("%s=%s" % kv for kv in out)


class Proxy:
    def __init__(self, nodes, upstream, api_port, port_map, status_cache):
        self.nodes = nodes
        self.upstream = upstream
        self.api_port = api_port
        self.port_map = port_map
        self.status_cache = status_cache
        self.cache_lock = threading.Lock()
        self.cached = None  # (expires, status, body, host)

    def port_of(self, host):
        return self.port_map.get(host, self.api_port)

    def handle(self, method, raw):
        """(code, body bytes, extra headers) for one request."""
        if method != "GET":
            return 405, b'{"error":"only GET"}', {"Allow": "GET"}
        path, _, query = raw.partition("?")
        m = POOL_PATH.match(path)
        if m:
            host, rest = m.group(1), m.group(2)
            fwd = route_query(rest, query)
            if fwd is None or host not in self.nodes.current():
                return 404, b'{"error":"not found"}', {}
            try:
                code, body = self.upstream.get(host, self.port_of(host), fwd)
            except Upstream.Fail as f:
                return f.code, json.dumps({"error": f.msg, "node": host}).encode(), {}
            return code, body, {"X-Ghost-Node": host}
        if path == STATUS_PATH and not query:
            return self.status()
        return 404, b'{"error":"not found"}', {}

    def status(self):
        now = time.monotonic()
        with self.cache_lock:
            c = self.cached
            if c and c[0] > now:
                return c[1], c[2], {"X-Ghost-Node": c[3]}
        hosts = self.nodes.current()
        if not hosts:
            return 503, b'{"error":"no node is listed"}', {}
        errors = []
        for host in hosts:
            try:
                code, body = self.upstream.get(host, self.port_of(host), STATUS_PATH)
            except Upstream.Fail as f:
                errors.append("%s: %s" % (host, f.msg))
                if f.code == 503 and "too many" in f.msg:
                    break
                continue
            if code == 200:
                with self.cache_lock:
                    self.cached = (time.monotonic() + self.status_cache, code, body, host)
                return code, body, {"X-Ghost-Node": host}
            errors.append("%s: HTTP %d" % (host, code))
        return 502, json.dumps({"error": "no listed node answered", "nodes": errors[:8]}).encode(), {}


def make_handler(proxy):
    class H(http.server.BaseHTTPRequestHandler):
        server_version = "ghost-site-proxy"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def _serve(self):
            try:
                code, body, extra = proxy.handle(self.command, self.path)
            except Exception as e:  # never leak a traceback to the viewer
                print("ghost-site-proxy: error %r on %s" % (e, self.path), file=sys.stderr, flush=True)
                code, body, extra = 500, b'{"error":"internal error"}', {}
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            for k, v in extra.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        do_GET = _serve
        do_HEAD = _serve
        do_POST = _serve
        do_PUT = _serve
        do_DELETE = _serve
        do_PATCH = _serve
        do_OPTIONS = _serve

        def log_message(self, fmt, *args):
            print("%s %s" % (self.address_string(), fmt % args), flush=True)

    return H


def parse_port_map(s):
    out = {}
    for kv in filter(None, (s or "").split(",")):
        h, sep, p = kv.rpartition("=")
        if not sep or not p.isdigit() or not 0 < int(p) < 65536:
            raise ValueError("bad --api-port-map entry %r (HOST=PORT)" % kv)
        out[h] = int(p)
    return out


def build(args):
    nodes = NodeList(args.node_list, args.allow_private)
    upstream = Upstream(args.timeout, args.max_bytes, args.max_inflight)
    proxy = Proxy(nodes, upstream, args.api_port, parse_port_map(args.api_port_map), args.status_cache)
    host, _, port = args.listen.rpartition(":")
    server = http.server.ThreadingHTTPServer((host.strip("[]"), int(port)), make_handler(proxy))
    server.daemon_threads = True
    return server


def parser():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--listen", default="127.0.0.1:8791")
    p.add_argument("--node-list", default="/var/lib/ghost-merge/node-list.json")
    p.add_argument("--api-port", type=int, default=8080)
    p.add_argument("--api-port-map", default="")
    p.add_argument("--allow-private", action="store_true")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--max-bytes", type=int, default=4 * 1024 * 1024)
    p.add_argument("--max-inflight", type=int, default=32)
    p.add_argument("--status-cache", type=float, default=10.0)
    return p


def main():
    args = parser().parse_args()
    try:
        server = build(args)
    except (ValueError, OSError) as e:
        print("ghost-site-proxy: %s" % e, file=sys.stderr)
        return 2
    print("ghost-site-proxy on %s, node list %s" % (args.listen, args.node_list), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
