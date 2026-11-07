#!/usr/bin/env python3
"""The website's API proxy: lets bitcoinghost.org's pages read the Ghost Pool nodes, and nothing else.

    ghost-site-proxy.py [--listen 127.0.0.1:8791] [--nodes /etc/ghost/site-proxy-nodes.json]
                        [--allow-private] [--timeout 8] [--max-bytes 4194304]
                        [--max-inflight 32] [--status-cache 10]

nginx on the website host sends it one path prefix (scripts/website-proxy/nginx-site-proxy.conf):

  /api/pool/<id>/<route>   forwarded to the node named <id> in the nodes file, ONLY if <route> is
                           one of ROUTES below. The pages (ghost-web/pool.js, ghost-web/miner.js)
                           ask every node in ghost-web/pool-nodes.json this way, by the same ids.

Everything else is 404, and every method but GET is 405. Without these rules this is an open proxy.

- **Only the pool's own nodes.** The nodes file is a static list, read once at start:

      {"nodes": [{"id": "a", "host": "203.0.113.10", "api_port": 8080},
                 {"id": "b", "host": "198.51.100.20"}]}

  `id` is 1-32 lowercase letters, digits and `-`; `host` an IP literal in its canonical form (a
  name could be pointed anywhere later); `api_port` the node's public API port (default 8080).
  Loopback, private, link-local and other non-global addresses are refused unless
  --allow-private (a regtest run). A file that is missing, does not parse, lists no node or lists
  a bad one stops the proxy from starting: it never runs with a guessed list. The request names a
  node only by its id; nothing in it chooses a host or a port.
- **Only the read routes the pages use**, matched on the raw request path before any decoding:
  `/api/v1/pool/status`, `/api/v1/miner/<addr>` and `/api/v1/miner/<addr>/history`, `<addr>`
  1-100 letters and digits. The only query forwarded is `window=24h|7d|30d` on history. No `..`,
  no `%`, no other characters reach a node.
- **Nothing of the viewer's is forwarded**: no header, cookie or body. The request to the node
  carries only Host, Accept and a User-Agent. Nothing of the node's is passed back but its status
  code and body: no header, so no Set-Cookie.
- **Bounded.** --timeout seconds for the whole answer (connect, headers and body); a node that
  takes longer is 504. A body over --max-bytes is 502 and nothing of it is sent. A redirect is
  never followed (502). At most --max-inflight requests to nodes at once, then 503. A node's
  `/api/v1/pool/status` answer (200 only) is cached for --status-cache seconds, so a crowd of
  viewers on the home page costs one request per node.

Logs one line per request to stdout (journald). Python 3.8+, standard library only.
"""

import argparse
import http.client
import http.server
import ipaddress
import json
import re
import socket
import sys
import threading
import time

ADDR = r"[A-Za-z0-9]{1,100}"
STATUS_ROUTE = "/api/v1/pool/status"
# The read routes a page may ask a node for: (path regex, allowed query keys and values).
ROUTES = [
    (re.compile(r"^/api/v1/pool/status$"), {}),
    (re.compile(r"^/api/v1/miner/" + ADDR + r"$"), {}),
    (re.compile(r"^/api/v1/miner/" + ADDR + r"/history$"), {"window": {"24h", "7d", "30d"}}),
]
NODE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
# /api/pool/<id><route>
POOL_PATH = re.compile(r"^/api/pool/([a-z0-9][a-z0-9-]{0,31})(/.*)$")
USER_AGENT = "ghost-site-proxy/2"


class Node:
    __slots__ = ("id", "host", "port")

    def __init__(self, node_id, host, port):
        self.id, self.host, self.port = node_id, host, port


def load_nodes(path, allow_private):
    """The nodes of the nodes file, by id. Raises ValueError on anything wrong with it."""
    try:
        with open(path, "rb") as f:
            data = json.loads(f.read(1024 * 1024))
    except OSError as e:
        raise ValueError("cannot read the nodes file %s: %s" % (path, e.strerror or e))
    except ValueError:
        raise ValueError("the nodes file %s is not JSON" % path)
    entries = data.get("nodes") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError("the nodes file %s lists no node" % path)
    nodes = {}
    for i, n in enumerate(entries):
        if not isinstance(n, dict):
            raise ValueError("node %d is not an object" % i)
        node_id, host, port = n.get("id"), n.get("host"), n.get("api_port", 8080)
        if not isinstance(node_id, str) or not NODE_ID.match(node_id):
            raise ValueError("node %d: bad id %r (1-32 of a-z, 0-9, -)" % (i, node_id))
        if node_id in nodes:
            raise ValueError("node %d: id %r is listed twice" % (i, node_id))
        if not isinstance(host, str):
            raise ValueError("node %r: no host" % node_id)
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            raise ValueError("node %r: host %r is not an IP address" % (node_id, host))
        if str(ip) != host.lower():
            raise ValueError("node %r: write host %r as %s" % (node_id, host, ip))
        if not (allow_private or ip.is_global):
            raise ValueError("node %r: host %s is not a public address (--allow-private for a test)" % (node_id, host))
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
            raise ValueError("node %r: bad api_port %r" % (node_id, port))
        nodes[node_id] = Node(node_id, str(ip), port)
    return nodes


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
    out = []
    for p in query.split("&"):
        k, sep, v = p.partition("=")
        if not sep or k not in allowed or v not in allowed[k] or k in [o[0] for o in out]:
            return None
        out.append((k, v))
    return path + "?" + "&".join("%s=%s" % kv for kv in out)


class Proxy:
    def __init__(self, nodes, upstream, status_cache):
        self.nodes = nodes
        self.upstream = upstream
        self.status_cache = status_cache
        self.cache_lock = threading.Lock()
        self.cached = {}  # node id -> (expires, body)

    def handle(self, method, raw):
        """(code, body bytes, extra headers) for one request."""
        if method != "GET":
            return 405, b'{"error":"only GET"}', {"Allow": "GET"}
        path, _, query = raw.partition("?")
        m = POOL_PATH.match(path)
        if not m:
            return 404, b'{"error":"not found"}', {}
        node = self.nodes.get(m.group(1))
        fwd = route_query(m.group(2), query)
        if node is None or fwd is None:
            return 404, b'{"error":"not found"}', {}
        is_status = fwd == STATUS_ROUTE
        if is_status:
            with self.cache_lock:
                c = self.cached.get(node.id)
                if c and c[0] > time.monotonic():
                    return 200, c[1], {"X-Ghost-Node": node.id}
        try:
            code, body = self.upstream.get(node.host, node.port, fwd)
        except Upstream.Fail as f:
            return f.code, json.dumps({"error": f.msg, "node": node.id}).encode(), {}
        if is_status and code == 200 and self.status_cache > 0:
            with self.cache_lock:
                self.cached[node.id] = (time.monotonic() + self.status_cache, body)
        return code, body, {"X-Ghost-Node": node.id}


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


def build(args):
    nodes = load_nodes(args.nodes, args.allow_private)
    upstream = Upstream(args.timeout, args.max_bytes, args.max_inflight)
    proxy = Proxy(nodes, upstream, args.status_cache)
    host, _, port = args.listen.rpartition(":")
    server = http.server.ThreadingHTTPServer((host.strip("[]"), int(port)), make_handler(proxy))
    server.daemon_threads = True
    server.proxy = proxy
    return server


def parser():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--listen", default="127.0.0.1:8791")
    p.add_argument("--nodes", default="/etc/ghost/site-proxy-nodes.json")
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
    print("ghost-site-proxy on %s, nodes %s" % (args.listen, ", ".join(sorted(server.proxy.nodes))), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
