#!/usr/bin/env python3
"""Tests for ghost-site-proxy.py against fake nodes on loopback. No real node is asked.

    python3 -I scripts/website-proxy/test_ghost_site_proxy.py

Each fake node is an HTTP server on 127.0.0.1 that records every request it gets (path and
headers) and answers by path: a normal JSON answer, or a slow one, an oversized one, a redirect.
The proxy runs in this process on its own port, with --allow-private (the fakes are on loopback)
and a nodes file naming each fake's host and port. Ports are chosen by the OS, never in
41000-41999.
"""

import http.client
import http.server
import importlib.util
import json
import os
import socket
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("site_proxy", os.path.join(HERE, "ghost-site-proxy.py"))
sp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sp)

ADDR = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"


def free_port(host="127.0.0.1"):
    """An OS-chosen free port outside 41000-41999 (reserved on this machine)."""
    for _ in range(50):
        s = socket.socket()
        s.bind((host, 0))
        p = s.getsockname()[1]
        s.close()
        if not 41000 <= p <= 41999:
            return p
    raise RuntimeError("no free port")


class FakeNode:
    def __init__(self, name, host):
        self.name = name
        self.host = host
        self.requests = []
        self.status_code = 200
        node = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                node.requests.append((self.path, dict(self.headers)))
                if "slowminer" in self.path:
                    time.sleep(3)
                if "bigminer" in self.path:
                    body = b"[" + b"0," * 600_000 + b"0]"
                elif "redirect" in self.path:
                    self.send_response(302)
                    self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                elif "trickle" in self.path:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    for _ in range(40):
                        try:
                            self.wfile.write(b" ")
                            self.wfile.flush()
                        except OSError:
                            return
                        time.sleep(0.1)
                    return
                else:
                    body = json.dumps({"node": node.name, "path": self.path}).encode()
                code = node.status_code if self.path == "/api/v1/pool/status" else 200
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "session=node-secret")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.port = free_port(host)
        self.server = http.server.ThreadingHTTPServer((host, self.port), H)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class ProxyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Two configured nodes on loopback hosts of their own, one never configured, one down.
        cls.a = FakeNode("a", "127.0.0.10")
        cls.b = FakeNode("b", "127.0.0.11")
        cls.c = FakeNode("c", "127.0.0.12")
        cls.closed = free_port("127.0.0.13")  # nothing listens there: a node that is down
        cls.tmp = tempfile.TemporaryDirectory()
        cls.nodes_path = cls.write_nodes("nodes.json", [
            {"id": "a", "host": "127.0.0.10", "api_port": cls.a.port},
            {"id": "b", "host": "127.0.0.11", "api_port": cls.b.port},
            {"id": "down", "host": "127.0.0.13", "api_port": cls.closed},
        ])
        cls.port = free_port()
        args = sp.parser().parse_args([
            "--listen", "127.0.0.1:%d" % cls.port, "--nodes", cls.nodes_path,
            "--allow-private", "--timeout", "1.5", "--max-bytes", "100000", "--status-cache", "0",
        ])
        cls.server = sp.build(args)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        for n in (cls.a, cls.b, cls.c):
            n.stop()
        cls.tmp.cleanup()

    @classmethod
    def write_nodes(cls, name, nodes, raw=None):
        path = os.path.join(cls.tmp.name, name)
        with open(path, "w") as f:
            f.write(raw if raw is not None else json.dumps({"nodes": nodes}))
        return path

    def setUp(self):
        for n in (self.a, self.b, self.c):
            n.requests.clear()
            n.status_code = 200

    def req(self, method, path, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.putrequest(method, path, skip_accept_encoding=True)
        for k, v in (headers or {}).items():
            c.putheader(k, v)
        if body is not None:
            c.putheader("Content-Length", str(len(body)))
        c.endheaders()
        if body is not None:
            c.send(body)
        r = c.getresponse()
        data = r.read()
        hdrs = dict(r.getheaders())
        c.close()
        return r.status, data, hdrs

    # ---- allowed

    def test_a_configured_node_and_read_route_is_forwarded(self):
        for route in ["/api/v1/pool/status", "/api/v1/miner/" + ADDR,
                      "/api/v1/miner/" + ADDR + "/history", "/api/v1/miner/" + ADDR + "/history?window=7d"]:
            code, body, hdrs = self.req("GET", "/api/pool/b" + route)
            self.assertEqual(code, 200, route)
            self.assertEqual(json.loads(body), {"node": "b", "path": route})
            self.assertEqual(hdrs.get("X-Ghost-Node"), "b")
            self.assertEqual(hdrs.get("Content-Type"), "application/json")
        self.assertEqual(len(self.b.requests), 4)
        self.assertEqual(self.a.requests, [])

    def test_each_node_is_asked_at_its_own_configured_port(self):
        self.assertEqual(json.loads(self.req("GET", "/api/pool/a/api/v1/pool/status")[1])["node"], "a")
        self.assertEqual(json.loads(self.req("GET", "/api/pool/b/api/v1/pool/status")[1])["node"], "b")

    def test_nothing_of_the_viewers_request_reaches_the_node_and_nothing_of_the_nodes_comes_back(self):
        code, _, hdrs = self.req("GET", "/api/pool/a/api/v1/miner/" + ADDR, {
            "Cookie": "dashboard_session=viewer-secret", "Authorization": "Bearer x",
            "X-Forwarded-For": "1.2.3.4", "X-Ghost-Signature": "forged", "Origin": "https://evil.example",
        })
        self.assertEqual(code, 200)
        _, sent = self.a.requests[0]
        self.assertEqual(sorted(k.lower() for k in sent), ["accept", "connection", "host", "user-agent"])
        self.assertNotIn("viewer-secret", json.dumps(sent))
        self.assertNotIn("Set-Cookie", hdrs)
        self.assertEqual(hdrs.get("Cache-Control"), "no-store")

    def test_a_nodes_status_is_cached_for_a_crowd_but_a_failure_is_not(self):
        nodes = sp.load_nodes(self.nodes_path, True)
        proxy = sp.Proxy(nodes, sp.Upstream(2, 100000, 4), 60)
        self.a.status_code = 503
        self.assertEqual(proxy.handle("GET", "/api/pool/a/api/v1/pool/status")[0], 503)
        self.a.status_code = 200
        for _ in range(5):
            code, body, hdrs = proxy.handle("GET", "/api/pool/a/api/v1/pool/status")
            self.assertEqual((code, json.loads(body)["node"], hdrs["X-Ghost-Node"]), (200, "a", "a"))
        self.assertEqual(len(self.a.requests), 2, "one failed, then one cached answer for five")
        # A miner's answer is never cached.
        for _ in range(3):
            proxy.handle("GET", "/api/pool/a/api/v1/miner/" + ADDR)
        self.assertEqual(len(self.a.requests), 5)
        # Each node has its own cache entry.
        proxy.handle("GET", "/api/pool/b/api/v1/pool/status")
        self.assertEqual(len(self.b.requests), 1)

    # ---- refused

    def test_a_node_not_in_the_file_is_refused_and_nothing_is_asked(self):
        for name in ["c", "127.0.0.12", "127.0.0.10", "10.0.0.1", "169.254.169.254", "localhost", "A", "a.b",
                     "x" * 33]:
            code, _, _ = self.req("GET", "/api/pool/%s/api/v1/pool/status" % name)
            self.assertEqual(code, 404, name)
        self.assertEqual(self.c.requests, [])
        self.assertEqual(self.a.requests, [])

    def test_every_method_but_get_is_refused(self):
        path = "/api/pool/a/api/v1/pool/status"
        for m in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
            code, _, hdrs = self.req(m, path, body=b"{}" if m in ("POST", "PUT", "PATCH") else None)
            self.assertEqual(code, 405, m)
            self.assertEqual(hdrs.get("Allow"), "GET")
        self.assertEqual(self.a.requests, [])

    def test_routes_outside_the_read_list_and_path_tricks_are_refused(self):
        bad = [
            "/api/pool/a/api/v1/pool/../../admin",
            "/api/pool/a/api/v1/miner/../../api/internal/config",
            "/api/pool/a/api/v1/miner/%2e%2e%2fapi%2finternal",
            "/api/pool/a/api/v1/miner/" + ADDR + "/../../../internal",
            "/api/pool/a/api/internal/config/update",
            "/api/pool/a/api/v1/ledger/" + ADDR,
            "/api/pool/a/api/v1/node-pool/status",
            "/api/pool/a/api/v1/node-pool/node-list",
            "/api/pool/a/admin/restart",
            "/api/pool/a//api/v1/pool/status",
            "/api/pool/a/api/v1/miner/" + "a" * 101,
            "/api/pool/a/api/v1/miner/" + ADDR + "?x=1",
            "/api/pool/a/api/v1/miner/" + ADDR + "/history?window=1y",
            "/api/pool/a/api/v1/miner/" + ADDR + "/history?window=7d&window=24h",
            "/api/pool/a/api/v1/miner/" + ADDR + "/history?window",
            "/api/pool/a/api/v1/pool/status?debug=1",
            "/api/pool/a:22/api/v1/pool/status",
            "/api/pool/a@127.0.0.12/api/v1/pool/status",
            "/api/pool/a",
            "/api/v1/pool/status",
            "/api/v1/node-pool/status",
            "/api/pool/",
            "/",
        ]
        for p in bad:
            code, _, _ = self.req("GET", p)
            self.assertEqual(code, 404, p)
        self.assertEqual(self.a.requests, [], "no node was asked")

    # ---- the nodes file

    def test_a_bad_nodes_file_stops_the_proxy_from_starting(self):
        cases = {
            "missing": None,
            "not json": "{not json",
            "no nodes": json.dumps({"nodes": []}),
            "not a list": json.dumps({"nodes": {"a": "8.8.8.8"}}),
            "a name": json.dumps({"nodes": [{"id": "a", "host": "pool.example.org"}]}),
            "no host": json.dumps({"nodes": [{"id": "a"}]}),
            "bad id": json.dumps({"nodes": [{"id": "A/../b", "host": "8.8.8.8"}]}),
            "twice": json.dumps({"nodes": [{"id": "a", "host": "8.8.8.8"}, {"id": "a", "host": "8.8.4.4"}]}),
            "bad port": json.dumps({"nodes": [{"id": "a", "host": "8.8.8.8", "api_port": 70000}]}),
            "port as text": json.dumps({"nodes": [{"id": "a", "host": "8.8.8.8", "api_port": "8080"}]}),
            "non-canonical v6": json.dumps({"nodes": [{"id": "a", "host": "2001:4860:4860:0::8888"}]}),
            "private": json.dumps({"nodes": [{"id": "a", "host": "10.1.2.3"}]}),
            "loopback": json.dumps({"nodes": [{"id": "a", "host": "127.0.0.1"}]}),
            "documentation range": json.dumps({"nodes": [{"id": "a", "host": "203.0.113.5"}]}),
        }
        for what, raw in cases.items():
            path = os.path.join(self.tmp.name, "missing.json") if raw is None else self.write_nodes("bad.json", None, raw)
            with self.assertRaises(ValueError, msg=what):
                sp.load_nodes(path, False)
            args = sp.parser().parse_args(["--listen", "127.0.0.1:%d" % free_port(), "--nodes", path])
            with self.assertRaises(ValueError, msg=what):
                sp.build(args)

    def test_a_good_nodes_file_is_read_with_the_default_port(self):
        path = self.write_nodes("good.json", [
            {"id": "a", "host": "8.8.8.8"},
            {"id": "node-b", "host": "2001:4860:4860::8888", "api_port": 9080},
        ])
        nodes = sp.load_nodes(path, False)
        self.assertEqual(sorted(nodes), ["a", "node-b"])
        self.assertEqual((nodes["a"].host, nodes["a"].port), ("8.8.8.8", 8080))
        self.assertEqual((nodes["node-b"].host, nodes["node-b"].port), ("2001:4860:4860::8888", 9080))

    def test_the_shipped_example_nodes_file_is_well_formed(self):
        path = os.path.join(HERE, "site-proxy-nodes.example.json")
        nodes = sp.load_nodes(path, True)
        self.assertGreaterEqual(len(nodes), 2)
        site = json.load(open(os.path.join(HERE, "..", "..", "ghost-web", "pool-nodes.json")))
        self.assertEqual(sorted(nodes), sorted(n["id"] for n in site["nodes"]),
                         "the website's pool-nodes.json and the proxy's example name the same node ids")

    # ---- bounded

    def test_an_oversized_answer_is_not_passed_on(self):
        code, body, _ = self.req("GET", "/api/pool/a/api/v1/miner/bigminer")
        self.assertEqual(code, 502)
        self.assertIn("larger than 100000 bytes", json.loads(body)["error"])

    def test_a_slow_node_is_cut_off(self):
        t0 = time.monotonic()
        code, body, _ = self.req("GET", "/api/pool/a/api/v1/miner/slowminer")
        self.assertEqual(code, 504)
        self.assertLess(time.monotonic() - t0, 2.9)
        self.assertIn("did not answer within", json.loads(body)["error"])

    def test_a_node_trickling_bytes_is_cut_off_at_the_deadline(self):
        t0 = time.monotonic()
        code, _, _ = self.req("GET", "/api/pool/a/api/v1/miner/trickle")
        self.assertEqual(code, 504)
        self.assertLess(time.monotonic() - t0, 2.9, "the deadline covers the whole answer")

    def test_a_redirect_is_not_followed(self):
        code, body, _ = self.req("GET", "/api/pool/a/api/v1/miner/redirect")
        self.assertEqual(code, 502)
        self.assertIn("redirect", json.loads(body)["error"])
        self.assertEqual(len(self.a.requests), 1, "only the first request was made")

    def test_a_node_that_is_down_is_a_502_naming_it(self):
        code, body, _ = self.req("GET", "/api/pool/down/api/v1/pool/status")
        self.assertEqual(code, 502)
        self.assertEqual(json.loads(body)["node"], "down")

    def test_requests_to_nodes_are_capped(self):
        up = sp.Upstream(5, 1000, 1)
        self.assertTrue(up.slots.acquire(blocking=False))
        try:
            with self.assertRaises(sp.Upstream.Fail) as e:
                up.get("127.0.0.10", self.a.port, "/api/v1/pool/status")
            self.assertEqual(e.exception.code, 503)
        finally:
            up.slots.release()


if __name__ == "__main__":
    unittest.main(verbosity=2)
