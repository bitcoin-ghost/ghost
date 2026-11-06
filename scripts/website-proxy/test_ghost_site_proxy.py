#!/usr/bin/env python3
"""Tests for ghost-site-proxy.py against fake nodes on loopback. No real node is asked.

    python3 -I scripts/website-proxy/test_ghost_site_proxy.py

Each fake node is an HTTP server on 127.0.0.1 that records every request it gets (path and
headers) and answers by path: a normal JSON answer, or a slow one, an oversized one, a redirect.
The proxy runs in this process on its own port, with --allow-private (the fakes are on loopback)
and an --api-port-map naming each fake's port. Ports are chosen by the OS, never in 41000-41999.
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
                if self.path.endswith("/slow") or "slowledger" in self.path:
                    time.sleep(3)
                if "bigledger" in self.path:
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
                code = node.status_code if self.path == "/api/v1/node-pool/status" else 200
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
        # Two listed nodes on loopback hosts of their own, and one never listed.
        cls.a = FakeNode("a", "127.0.0.10")
        cls.b = FakeNode("b", "127.0.0.11")
        cls.c = FakeNode("c", "127.0.0.12")
        closed = free_port("127.0.0.13")  # nothing listens there: a node that is down
        cls.tmp = tempfile.TemporaryDirectory()
        cls.list_path = os.path.join(cls.tmp.name, "node-list.json")
        cls.write_list(["127.0.0.10", "127.0.0.11"])
        cls.port = free_port()
        args = sp.parser().parse_args([
            "--listen", "127.0.0.1:%d" % cls.port,
            "--node-list", cls.list_path,
            "--api-port-map", "127.0.0.10=%d,127.0.0.11=%d,127.0.0.12=%d,127.0.0.13=%d"
            % (cls.a.port, cls.b.port, cls.c.port, closed),
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
    def write_list(cls, hosts):
        tmp = cls.list_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"schema": "ghost-audit/node-list/v1", "nodes": [{"host": h} for h in hosts]}, f)
        os.replace(tmp, cls.list_path)
        # The proxy notices a change by mtime, size or inode; a rename gives a new inode.

    def setUp(self):
        for n in (self.a, self.b, self.c):
            n.requests.clear()
            n.status_code = 200
        self.write_list(["127.0.0.10", "127.0.0.11"])

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

    def test_a_listed_host_and_read_route_is_forwarded(self):
        for route in ["/api/v1/ledger/" + ADDR, "/api/v1/miner/" + ADDR,
                      "/api/v1/miner/" + ADDR + "/history?window=7d", "/api/v1/node-pool/status"]:
            code, body, hdrs = self.req("GET", "/api/pool/127.0.0.11" + route)
            self.assertEqual(code, 200, route)
            self.assertEqual(json.loads(body), {"node": "b", "path": route})
            self.assertEqual(hdrs.get("X-Ghost-Node"), "127.0.0.11")
            self.assertEqual(hdrs.get("Content-Type"), "application/json")
        self.assertEqual(len(self.b.requests), 4)
        self.assertEqual(self.a.requests, [])

    def test_nothing_of_the_viewers_request_reaches_the_node_and_nothing_of_the_nodes_comes_back(self):
        code, _, hdrs = self.req("GET", "/api/pool/127.0.0.10/api/v1/ledger/" + ADDR, {
            "Cookie": "dashboard_session=viewer-secret", "Authorization": "Bearer x",
            "X-Forwarded-For": "1.2.3.4", "X-Ghost-Signature": "forged", "Origin": "https://evil.example",
        })
        self.assertEqual(code, 200)
        _, sent = self.a.requests[0]
        self.assertEqual(sorted(k.lower() for k in sent), ["accept", "connection", "host", "user-agent"])
        self.assertNotIn("viewer-secret", json.dumps(sent))
        self.assertNotIn("Set-Cookie", hdrs)
        self.assertEqual(hdrs.get("Cache-Control"), "no-store")

    def test_the_status_is_the_first_listed_node_that_answers(self):
        code, body, hdrs = self.req("GET", "/api/v1/node-pool/status")
        self.assertEqual((code, json.loads(body)["node"]), (200, "a"))
        self.a.status_code = 503
        code, body, hdrs = self.req("GET", "/api/v1/node-pool/status")
        self.assertEqual((code, json.loads(body)["node"], hdrs.get("X-Ghost-Node")), (200, "b", "127.0.0.11"))
        self.b.status_code = 500
        code, body, _ = self.req("GET", "/api/v1/node-pool/status")
        self.assertEqual(code, 502)
        self.assertIn("no listed node answered", json.loads(body)["error"])
        self.write_list([])
        code, body, _ = self.req("GET", "/api/v1/node-pool/status")
        self.assertEqual(code, 503)

    def test_the_status_is_cached_for_a_crowd(self):
        proxy = sp.Proxy(sp.NodeList(self.list_path, True), sp.Upstream(2, 100000, 4), 1,
                         {"127.0.0.10": self.a.port}, 60)
        for _ in range(5):
            self.assertEqual(proxy.status()[0], 200)
        self.assertEqual(len(self.a.requests), 1)

    # ---- refused

    def test_an_unlisted_host_is_refused_and_asked_nothing(self):
        for host in ["127.0.0.12", "127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "localhost"]:
            code, _, _ = self.req("GET", "/api/pool/%s/api/v1/node-pool/status" % host)
            self.assertEqual(code, 404, host)
        self.assertEqual(self.c.requests, [])

    def test_a_host_dropped_from_the_list_is_refused_on_the_next_request(self):
        self.assertEqual(self.req("GET", "/api/pool/127.0.0.11/api/v1/node-pool/status")[0], 200)
        self.write_list(["127.0.0.10"])
        self.assertEqual(self.req("GET", "/api/pool/127.0.0.11/api/v1/node-pool/status")[0], 404)
        self.write_list(["127.0.0.10", "127.0.0.12"])
        self.assertEqual(self.req("GET", "/api/pool/127.0.0.12/api/v1/node-pool/status")[0], 200)

    def test_an_unreadable_list_lists_nobody(self):
        with open(self.list_path, "w") as f:
            f.write("{not json")
        self.assertEqual(self.req("GET", "/api/pool/127.0.0.10/api/v1/node-pool/status")[0], 404)
        os.remove(self.list_path)
        self.assertEqual(self.req("GET", "/api/pool/127.0.0.10/api/v1/node-pool/status")[0], 404)
        self.assertEqual(self.a.requests, [])

    def test_private_hosts_are_refused_without_allow_private(self):
        nl = sp.NodeList(self.list_path, False)
        self.write_list(["127.0.0.10", "10.1.2.3", "192.168.1.1", "203.0.113.5", "8.8.8.8", "2001:4860:4860::8888",
                         "2001:4860:4860:0::8888", "pool.example.org"])
        # 203.0.113.0/24 is documentation space (not global); a name or a non-canonical IPv6 is refused.
        self.assertEqual(nl.current(), ["8.8.8.8", "2001:4860:4860::8888"])

    def test_every_method_but_get_is_refused(self):
        path = "/api/pool/127.0.0.10/api/v1/node-pool/status"
        for m in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
            code, _, hdrs = self.req(m, path, body=b"{}" if m in ("POST", "PUT", "PATCH") else None)
            self.assertEqual(code, 405, m)
            self.assertEqual(hdrs.get("Allow"), "GET")
        self.assertEqual(self.req("POST", "/api/v1/node-pool/status", body=b"x")[0], 405)
        self.assertEqual(self.a.requests, [])

    def test_routes_outside_the_read_list_and_path_tricks_are_refused(self):
        bad = [
            "/api/pool/127.0.0.10/api/v1/node-pool/../../admin",
            "/api/pool/127.0.0.10/api/v1/ledger/../../api/internal/config",
            "/api/pool/127.0.0.10/api/v1/ledger/%2e%2e%2fapi%2finternal",
            "/api/pool/127.0.0.10/api/v1/ledger/" + ADDR + "/../../../internal",
            "/api/pool/127.0.0.10/api/internal/config/update",
            "/api/pool/127.0.0.10/api/v1/node-pool/node-list",
            "/api/pool/127.0.0.10/admin/restart",
            "/api/pool/127.0.0.10//api/v1/node-pool/status",
            "/api/pool/127.0.0.10/api/v1/ledger/" + "a" * 101,
            "/api/pool/127.0.0.10/api/v1/ledger/" + ADDR + "?x=1",
            "/api/pool/127.0.0.10/api/v1/miner/" + ADDR + "/history?window=1y",
            "/api/pool/127.0.0.10/api/v1/miner/" + ADDR + "/history?window=7d&window=24h",
            "/api/pool/127.0.0.10/api/v1/node-pool/status?debug=1",
            "/api/pool/127.0.0.10:22/api/v1/node-pool/status",
            "/api/pool/127.0.0.10@127.0.0.12/api/v1/node-pool/status",
            "/api/pool/127.0.0.10",
            "/api/v1/node-pool/status?x=1",
            "/api/v1/ledger/" + ADDR,
            "/api/pool/",
            "/",
        ]
        for p in bad:
            code, _, _ = self.req("GET", p)
            self.assertEqual(code, 404, p)
        self.assertEqual(self.a.requests, [], "no node was asked")

    # ---- bounded

    def test_an_oversized_answer_is_not_passed_on(self):
        code, body, _ = self.req("GET", "/api/pool/127.0.0.10/api/v1/ledger/bigledger")
        self.assertEqual(code, 502)
        self.assertIn("larger than 100000 bytes", json.loads(body)["error"])

    def test_a_slow_node_is_cut_off(self):
        t0 = time.monotonic()
        code, body, _ = self.req("GET", "/api/pool/127.0.0.10/api/v1/ledger/slowledger")
        self.assertEqual(code, 504)
        self.assertLess(time.monotonic() - t0, 2.9)
        self.assertIn("did not answer within", json.loads(body)["error"])

    def test_a_node_trickling_bytes_is_cut_off_at_the_deadline(self):
        t0 = time.monotonic()
        code, _, _ = self.req("GET", "/api/pool/127.0.0.10/api/v1/ledger/trickle")
        self.assertEqual(code, 504)
        self.assertLess(time.monotonic() - t0, 2.9, "the deadline covers the whole answer")

    def test_a_redirect_is_not_followed(self):
        code, body, _ = self.req("GET", "/api/pool/127.0.0.10/api/v1/ledger/redirect")
        self.assertEqual(code, 502)
        self.assertIn("redirect", json.loads(body)["error"])
        self.assertEqual(len(self.a.requests), 1, "only the first request was made")

    def test_a_node_that_is_down_is_a_502_naming_it(self):
        self.write_list(["127.0.0.10", "127.0.0.13"])
        code, body, _ = self.req("GET", "/api/pool/127.0.0.13/api/v1/node-pool/status")
        self.assertEqual(code, 502)
        self.assertEqual(json.loads(body)["node"], "127.0.0.13")

    def test_requests_to_nodes_are_capped(self):
        up = sp.Upstream(5, 1000, 1)
        self.assertTrue(up.slots.acquire(blocking=False))
        try:
            with self.assertRaises(sp.Upstream.Fail) as e:
                up.get("127.0.0.10", self.a.port, "/api/v1/node-pool/status")
            self.assertEqual(e.exception.code, 503)
        finally:
            up.slots.release()

    def test_bad_port_maps_are_refused(self):
        for m in ["127.0.0.1", "127.0.0.1=0", "127.0.0.1=70000", "127.0.0.1=x"]:
            with self.assertRaises(ValueError):
                sp.parse_port_map(m)
        self.assertEqual(sp.parse_port_map("::1=8080,127.0.0.1=9"), {"::1": 8080, "127.0.0.1": 9})


if __name__ == "__main__":
    unittest.main(verbosity=2)
