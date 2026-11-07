#!/usr/bin/env python3
"""Tests for namecheap-hook.py against a local fake Namecheap API. No real API call is made.

    python3 -I scripts/dns-hooks/test_namecheap_hook.py

The fake serves namecheap.domains.dns.getHosts and setHosts over HTTP on 127.0.0.1 (an OS-chosen
port), with setHosts REPLACING the whole host set as the real one does, and records every call.
Each case runs the hook as `ghost-audit merge` does (a subprocess with the fragment's path) and
checks what the fake now holds, what was sent, the exit code, and that no credential appears in
anything printed.
"""

import http.server
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from xml.sax.saxutils import quoteattr

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.path.join(HERE, "namecheap-hook.py")
NS = "http://api.namecheap.com/xml.response"

API_USER = "ghostapiuser"
API_KEY = "0123456789abcdef0123456789abcdef"
USERNAME = "ghostaccount"
CLIENT_IP = "203.0.113.10"

# The domain's records apart from the pool's, with values that must survive byte for byte.
OTHERS = [
    {"Name": "@", "Type": "A", "Address": "198.51.100.7", "MXPref": "10", "TTL": "1800"},
    {"Name": "www", "Type": "CNAME", "Address": "bitcoinghost.org.", "MXPref": "10", "TTL": "1800"},
    {"Name": "@", "Type": "TXT", "Address": 'v=spf1 include:_spf.example.net ~all "q" & <x>',
     "MXPref": "10", "TTL": "3600"},
    {"Name": "@", "Type": "MX", "Address": "mx1.example.net.", "MXPref": "5", "TTL": "1800"},
    {"Name": "get", "Type": "A", "Address": "198.51.100.8", "MXPref": "10", "TTL": "300"},
    {"Name": "pool-old", "Type": "AAAA", "Address": "2001:db8::9", "MXPref": "10", "TTL": "60"},
]
POOL = [
    {"Name": "pool", "Type": "A", "Address": "192.0.2.1", "MXPref": "10", "TTL": "300"},
    {"Name": "pool", "Type": "A", "Address": "192.0.2.2", "MXPref": "10", "TTL": "300"},
]


class Fake:
    def __init__(self):
        self.hosts = []
        self.email_type = "MX"
        self.using_our_dns = "true"
        self.get_error = None
        self.set_error = None
        self.calls = []
        self.drop_on_set = False


def xml_hosts(fake):
    hosts = "".join(
        "<host HostId=\"%d\" %s IsActive=\"true\" IsDDNSEnabled=\"false\" />" % (
            i + 1, " ".join(f"{k}={quoteattr(v)}" for k, v in h.items()))
        for i, h in enumerate(fake.hosts))
    return (f'<ApiResponse Status="OK" xmlns="{NS}"><Errors /><RequestedCommand>'
            f'namecheap.domains.dns.getHosts</RequestedCommand><CommandResponse '
            f'Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="bitcoinghost.org" '
            f'EmailType="{fake.email_type}" IsUsingOurDNS="{fake.using_our_dns}">{hosts}'
            f'</DomainDNSGetHostsResult></CommandResponse></ApiResponse>')


def xml_error(number, text):
    return (f'<ApiResponse Status="ERROR" xmlns="{NS}"><Errors><Error Number="{number}">{text}'
            f'</Error></Errors><CommandResponse /></ApiResponse>')


def make_handler(fake):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, body):
            b = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            fake.calls.append(("GET", self.path, {}))
            self.send_response(405)
            self.end_headers()

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            p = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode(), keep_blank_values=True))
            fake.calls.append(("POST", self.path, p))
            creds = (p.get("ApiUser"), p.get("ApiKey"), p.get("UserName"), p.get("ClientIp"))
            if creds != (API_USER, API_KEY, USERNAME, CLIENT_IP):
                return self.reply(xml_error(1011102, "API Key is invalid or API access has not been enabled"))
            if (p.get("SLD"), p.get("TLD")) != ("bitcoinghost", "org"):
                return self.reply(xml_error(2019166, "Domain not found"))
            cmd = p.get("Command")
            if cmd == "namecheap.domains.dns.getHosts":
                if fake.get_error:
                    return self.reply(xml_error(*fake.get_error))
                return self.reply(xml_hosts(fake))
            if cmd == "namecheap.domains.dns.setHosts":
                if fake.set_error:
                    return self.reply(xml_error(*fake.set_error))
                hosts, i = [], 1
                while f"HostName{i}" in p:
                    hosts.append({"Name": p[f"HostName{i}"], "Type": p[f"RecordType{i}"],
                                  "Address": p[f"Address{i}"], "MXPref": p.get(f"MXPref{i}", "10"),
                                  "TTL": p.get(f"TTL{i}", "1800")})
                    i += 1
                # setHosts replaces the whole set, as the real one does.
                fake.hosts = hosts[:-1] if fake.drop_on_set else hosts
                if "EmailType" in p:
                    fake.email_type = p["EmailType"]
                return self.reply(
                    f'<ApiResponse Status="OK" xmlns="{NS}"><Errors /><CommandResponse '
                    f'Type="namecheap.domains.dns.setHosts"><DomainDNSSetHostsResult '
                    f'Domain="bitcoinghost.org" IsSuccess="true" /></CommandResponse></ApiResponse>')
            return self.reply(xml_error(1010101, "unknown command"))

    return H


class HookTest(unittest.TestCase):
    def setUp(self):
        self.fake = Fake()
        self.fake.hosts = [dict(h) for h in OTHERS + POOL]
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.fake))
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.dir = tempfile.TemporaryDirectory()
        self.env_file = self.write_env()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.dir.cleanup()

    def write_env(self, **over):
        env = {
            "NAMECHEAP_API_USER": API_USER,
            "NAMECHEAP_API_KEY": API_KEY,
            "NAMECHEAP_USERNAME": USERNAME,
            "NAMECHEAP_CLIENT_IP": CLIENT_IP,
            "NAMECHEAP_DOMAIN": "bitcoinghost.org",
            "NAMECHEAP_HOST": "pool",
            "NAMECHEAP_API_URL": f"http://127.0.0.1:{self.port}/xml.response",
            "NAMECHEAP_TIMEOUT": "5",
        }
        env.update(over)
        path = os.path.join(self.dir.name, "namecheap.env")
        with open(path, "w") as f:
            f.write("# test\n")
            for k, v in env.items():
                if v is not None:
                    f.write(f"{k}={v}\n")
        os.chmod(path, 0o600)
        return path

    def fragment(self, records, name="pool"):
        path = os.path.join(self.dir.name, "pool.zone")
        with open(path, "w") as f:
            f.write("; ghost-audit/dns/v1: generated by ghost-audit merge at 2026-11-06T00:00:00Z.\n")
            for t, ip in records:
                f.write(f"{name} 300 IN {t} {ip}\n")
        return path

    def run_hook(self, frag, *extra):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GHOST_DNS_FRAGMENT": frag}
        r = subprocess.run([sys.executable, "-I", HOOK, "--env-file", self.env_file, *extra, frag],
                           capture_output=True, text=True, env=env, timeout=60)
        out = r.stdout + r.stderr
        for secret in (API_KEY, API_USER, USERNAME):
            self.assertNotIn(secret, out, "a credential was printed")
        return r.returncode, out

    def sets(self):
        return [c for c in self.fake.calls if c[2].get("Command") == "namecheap.domains.dns.setHosts"]

    def pool_now(self):
        return sorted((h["Type"], h["Address"]) for h in self.fake.hosts if h["Name"] == "pool")

    def others_now(self):
        return [h for h in self.fake.hosts if h["Name"] != "pool"]

    def test_replaces_only_the_pool_records_and_keeps_every_other_exactly(self):
        code, out = self.run_hook(self.fragment([("A", "192.0.2.2"), ("A", "192.0.2.3"),
                                                 ("AAAA", "2001:db8::1")]))
        self.assertEqual(code, 0, out)
        self.assertEqual(self.pool_now(), [("A", "192.0.2.2"), ("A", "192.0.2.3"), ("AAAA", "2001:db8::1")])
        self.assertEqual(self.others_now(), OTHERS)
        self.assertEqual(self.fake.email_type, "MX")
        s = self.sets()
        self.assertEqual(len(s), 1)
        self.assertEqual(s[0][2]["EmailType"], "MX")
        self.assertIn("- pool A 192.0.2.1 TTL 300", out)
        self.assertIn("+ pool A 192.0.2.3 TTL 300", out)
        self.assertIn("pushed:", out)
        # Every call was a POST, and no credential went into a URL.
        for method, path, _ in self.fake.calls:
            self.assertEqual(method, "POST")
            self.assertNotIn(API_KEY, path)
        # getHosts, setHosts, then getHosts to check what Namecheap now holds.
        self.assertEqual([c[2]["Command"].rsplit(".", 1)[1] for c in self.fake.calls],
                         ["getHosts", "setHosts", "getHosts"])

    def test_dry_run_prints_the_diff_and_writes_nothing(self):
        code, out = self.run_hook(self.fragment([("A", "192.0.2.9")]), "--dry-run")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.sets(), [])
        self.assertEqual(self.fake.hosts, OTHERS + POOL)
        self.assertIn("- pool A 192.0.2.1 TTL 300", out)
        self.assertIn("- pool A 192.0.2.2 TTL 300", out)
        self.assertIn("+ pool A 192.0.2.9 TTL 300", out)
        self.assertIn("6 other record(s) of bitcoinghost.org kept exactly", out)
        self.assertIn("dry run: nothing written", out)

    def test_unchanged_records_are_not_written(self):
        code, out = self.run_hook(self.fragment([("A", "192.0.2.1"), ("A", "192.0.2.2")]))
        self.assertEqual(code, 0, out)
        self.assertEqual(self.sets(), [])
        self.assertIn("no change", out)

    def test_a_failed_get_hosts_writes_nothing(self):
        self.fake.get_error = (1011150, "Parameter RequestIP is invalid")
        code, out = self.run_hook(self.fragment([("A", "192.0.2.9")]))
        self.assertEqual(code, 1, out)
        self.assertEqual(self.sets(), [])
        self.assertIn("whitelisted", out)

    def test_an_unreachable_api_writes_nothing(self):
        self.server.shutdown()
        self.server.server_close()
        code, out = self.run_hook(self.fragment([("A", "192.0.2.9")]))
        self.assertEqual(code, 1, out)
        self.assertIn("getHosts", out)
        self.assertEqual(self.sets(), [])
        # A running server again, for tearDown to shut down.
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.fake))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def test_wrong_credentials_are_an_api_error_and_are_not_printed(self):
        self.env_file = self.write_env(NAMECHEAP_API_KEY="f" * 32)
        code, out = self.run_hook(self.fragment([("A", "192.0.2.9")]))
        self.assertEqual(code, 1, out)
        self.assertNotIn("f" * 32, out)
        self.assertEqual(self.sets(), [])

    def test_no_records_from_get_hosts_is_refused(self):
        self.fake.hosts = []
        code, out = self.run_hook(self.fragment([("A", "192.0.2.9")]))
        self.assertEqual(code, 3, out)
        self.assertIn("returned no records", out)
        self.assertEqual(self.sets(), [])

    def test_a_domain_off_namecheap_dns_is_refused(self):
        self.fake.using_our_dns = "false"
        code, out = self.run_hook(self.fragment([("A", "192.0.2.9")]))
        self.assertEqual(code, 3, out)
        self.assertEqual(self.sets(), [])

    def test_an_empty_fragment_is_refused_unless_allowed(self):
        code, out = self.run_hook(self.fragment([]))
        self.assertEqual(code, 3, out)
        self.assertIn("NAMECHEAP_ALLOW_EMPTY", out)
        self.assertEqual(self.fake.calls, [])
        self.env_file = self.write_env(NAMECHEAP_ALLOW_EMPTY="1")
        code, out = self.run_hook(self.fragment([]))
        self.assertEqual(code, 0, out)
        self.assertEqual(self.pool_now(), [])
        self.assertEqual(self.others_now(), OTHERS)

    def test_a_record_it_cannot_give_back_exactly_stops_it(self):
        self.fake.hosts.append({"Name": "@", "Type": "CAA", "Address": '0 issue "letsencrypt.org"',
                                "MXPref": "10", "TTL": "1800"})
        code, out = self.run_hook(self.fragment([("A", "192.0.2.9")]))
        self.assertEqual(code, 3, out)
        self.assertIn("CAA", out)
        self.assertEqual(self.sets(), [])

    def test_another_record_type_on_the_pool_name_stops_it(self):
        self.fake.hosts = [h for h in self.fake.hosts if h["Name"] != "pool"]
        self.fake.hosts.append({"Name": "pool", "Type": "CNAME", "Address": "elsewhere.example.",
                                "MXPref": "10", "TTL": "300"})
        code, out = self.run_hook(self.fragment([("A", "192.0.2.9")]))
        self.assertEqual(code, 3, out)
        self.assertIn("CNAME", out)
        self.assertEqual(self.sets(), [])

    def test_a_fragment_for_another_name_is_refused(self):
        code, out = self.run_hook(self.fragment([("A", "192.0.2.9")], name="www"))
        self.assertEqual(code, 3, out)
        self.assertEqual(self.fake.calls, [])
        # An absolute name in the domain is the same name.
        code, out = self.run_hook(self.fragment([("A", "192.0.2.9")], name="pool.bitcoinghost.org."))
        self.assertEqual(code, 0, out)
        self.assertEqual(self.pool_now(), [("A", "192.0.2.9")])

    def test_a_readable_env_file_is_refused(self):
        os.chmod(self.env_file, 0o644)
        code, out = self.run_hook(self.fragment([("A", "192.0.2.9")]))
        self.assertEqual(code, 2, out)
        self.assertIn("chmod 600", out)
        self.assertEqual(self.fake.calls, [])

    def test_the_apex_and_wildcard_cannot_be_owned(self):
        for host in ("@", "*"):
            self.env_file = self.write_env(NAMECHEAP_HOST=host)
            code, out = self.run_hook(self.fragment([("A", "192.0.2.9")], name=host))
            self.assertEqual(code, 2, out)
        self.assertEqual(self.fake.calls, [])

    def test_a_mismatch_after_set_hosts_is_a_failure(self):
        self.fake.drop_on_set = True
        code, out = self.run_hook(self.fragment([("A", "192.0.2.9")]))
        self.assertEqual(code, 1, out)
        self.assertIn("does not return the record set sent", out)

    def test_a_refused_set_hosts_is_a_failure(self):
        self.fake.set_error = (2030166, "Edit permission for domain is not supported")
        code, out = self.run_hook(self.fragment([("A", "192.0.2.9")]))
        self.assertEqual(code, 1, out)
        self.assertEqual(self.fake.hosts, OTHERS + POOL)

    def test_bad_fragment_lines_are_refused(self):
        path = os.path.join(self.dir.name, "bad.zone")
        for bad in ["pool 300 IN CNAME x.example.", "pool 300 IN A 2001:db8::1", "pool 5 IN A 192.0.2.1",
                    "pool 300 IN A not-an-ip", "pool IN A 192.0.2.1"]:
            with open(path, "w") as f:
                f.write(bad + "\n")
            code, out = self.run_hook(path)
            self.assertEqual(code, 2, f"{bad}: {out}")
        self.assertEqual(self.fake.calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
