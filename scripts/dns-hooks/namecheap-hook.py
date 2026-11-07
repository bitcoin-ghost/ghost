#!/usr/bin/env python3
"""Push the node pool's DNS records to Namecheap: the `ghost-audit merge --dns-hook` for
bitcoinghost.org.

    namecheap-hook.py [--env-file /etc/ghost/namecheap.env] [--dry-run] <fragment>

`ghost-audit merge` runs this with the path of the merged DNS fragment (zone-file lines
`<name> <ttl> IN A|AAAA <ip>`) when its records changed since the last successful push. It
records the push only when this exits 0, so a failure here is retried on the next merge.

Namecheap's `namecheap.domains.dns.setHosts` REPLACES the domain's whole host record set, so this
never writes blind:

1. `getHosts` first. If it fails, answers anything but Status="OK", returns no records at all, or
   says the domain is not on Namecheap's DNS, nothing is written.
2. Only the A and AAAA records of ONE dedicated name (NAMECHEAP_HOST, for example `pool`) are
   replaced. Every other record is sent back exactly as getHosts returned it: name, type, address,
   MX preference and TTL, and the domain's EmailType. A record this cannot send back exactly (CAA,
   whose flag and tag setHosts takes separately), or a record of another type on the dedicated
   name (a CNAME there), stops it before writing.
3. An empty fragment (no listed node) would delete the name's addresses. It is refused unless
   NAMECHEAP_ALLOW_EMPTY=1.
4. After setHosts, getHosts again: the push succeeds only if Namecheap now holds exactly the set
   sent.

--dry-run does step 1 and prints the record diff; it writes nothing.

Credentials come from a root-only env file (KEY=VALUE lines; mode 0600, owned by the user running
this), never from the command line, and are sent in POST bodies, never in URLs. Nothing printed
contains them:

    NAMECHEAP_API_USER=...       API user
    NAMECHEAP_API_KEY=...        API key (Profile > Tools > API Access)
    NAMECHEAP_USERNAME=...       account user name (default: NAMECHEAP_API_USER)
    NAMECHEAP_CLIENT_IP=...      this machine's public IPv4, WHITELISTED in API Access
    NAMECHEAP_DOMAIN=bitcoinghost.org
    NAMECHEAP_HOST=pool          the one name this owns (no `@`, no `*`)
    NAMECHEAP_SLD= / NAMECHEAP_TLD=   only for a domain whose TLD has a dot (example.co.uk)
    NAMECHEAP_API_URL=           default https://api.namecheap.com/xml.response
                                 (sandbox: https://api.sandbox.namecheap.com/xml.response)
    NAMECHEAP_ALLOW_EMPTY=0      1 lets an empty fragment remove the name's addresses
    NAMECHEAP_TIMEOUT=30         seconds per API call

Exit 0: pushed, or nothing to change (or a dry run). 1: the API refused or failed. 2: bad
configuration or input. 3: refused to write (see the message); nothing was changed.
"""

import argparse
import ipaddress
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

DEFAULT_ENV_FILE = "/etc/ghost/namecheap.env"
DEFAULT_API_URL = "https://api.namecheap.com/xml.response"
# Record types setHosts takes back exactly from what getHosts returns.
ROUND_TRIP_TYPES = {"A", "AAAA", "ALIAS", "CNAME", "MX", "MXE", "NS", "TXT", "URL", "URL301", "FRAME"}
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


class Refused(Exception):
    """Nothing was written, on purpose."""


class ApiError(Exception):
    """The API failed or said no."""


class ConfigError(Exception):
    """Bad configuration or input."""


SECRETS = []


def redact(text):
    s = str(text)
    for secret in SECRETS:
        if secret:
            s = s.replace(secret, "<redacted>")
    return s


def say(msg, err=False):
    print(redact(msg), file=sys.stderr if err else sys.stdout, flush=True)


def read_env_file(path):
    try:
        st = os.stat(path)
    except OSError as e:
        raise ConfigError(f"{path}: {e.strerror}")
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"{path} is not a file")
    if st.st_mode & 0o077:
        raise ConfigError(f"{path} is readable by others (mode {stat.S_IMODE(st.st_mode):04o}): "
                          f"chmod 600 it, it holds the API key")
    if st.st_uid != os.geteuid():
        raise ConfigError(f"{path} is not owned by the user running this hook")
    env = {}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ConfigError(f"{path} line {n} is not KEY=VALUE")
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            env[k] = v
    return env


class Config:
    def __init__(self, env):
        def need(k):
            v = env.get(k, "")
            if not v:
                raise ConfigError(f"{k} is not set in the env file")
            return v

        self.api_user = need("NAMECHEAP_API_USER")
        self.api_key = need("NAMECHEAP_API_KEY")
        self.username = env.get("NAMECHEAP_USERNAME") or self.api_user
        SECRETS.extend([self.api_key, self.api_user, self.username])
        self.client_ip = need("NAMECHEAP_CLIENT_IP")
        try:
            if ipaddress.ip_address(self.client_ip).version != 4:
                raise ValueError
        except ValueError:
            raise ConfigError("NAMECHEAP_CLIENT_IP must be this machine's public IPv4 address")
        self.domain = need("NAMECHEAP_DOMAIN").lower().rstrip(".")
        if not HOST_RE.match(self.domain) or "." not in self.domain:
            raise ConfigError(f"NAMECHEAP_DOMAIN {self.domain!r} is not a domain name")
        self.sld = env.get("NAMECHEAP_SLD") or self.domain.split(".", 1)[0]
        self.tld = env.get("NAMECHEAP_TLD") or self.domain.split(".", 1)[1]
        if f"{self.sld}.{self.tld}" != self.domain:
            raise ConfigError("NAMECHEAP_SLD.NAMECHEAP_TLD is not NAMECHEAP_DOMAIN")
        self.host = need("NAMECHEAP_HOST").lower()
        if self.host in ("@", "*") or not HOST_RE.match(self.host):
            raise ConfigError(f"NAMECHEAP_HOST {self.host!r} must be one dedicated name such as "
                              f"'pool' (not '@' or '*')")
        self.api_url = env.get("NAMECHEAP_API_URL") or DEFAULT_API_URL
        if not self.api_url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise ConfigError("NAMECHEAP_API_URL must be https:// (plain http only to localhost)")
        self.allow_empty = env.get("NAMECHEAP_ALLOW_EMPTY", "0") == "1"
        try:
            self.timeout = float(env.get("NAMECHEAP_TIMEOUT", "30"))
        except ValueError:
            raise ConfigError("NAMECHEAP_TIMEOUT is not a number")


def read_fragment(path, cfg):
    """The fragment's records, as a set of (type, address, ttl), all on cfg.host."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise ConfigError(f"{path}: {e.strerror}")
    records = set()
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        f = line.split()
        if len(f) != 5 or f[2] != "IN" or f[3] not in ("A", "AAAA"):
            raise ConfigError(f"{path} line {n} is not '<name> <ttl> IN A|AAAA <ip>'")
        name, ttl, _, rtype, addr = f
        name = name.lower()
        if name.endswith("."):
            name = name[:-1]
            if name == cfg.domain:
                name = "@"
            elif name.endswith("." + cfg.domain):
                name = name[: -len(cfg.domain) - 1]
            else:
                raise Refused(f"{path} line {n}: {name}. is not in {cfg.domain}")
        if name != cfg.host:
            raise Refused(f"{path} line {n}: the record is for {name!r}, but this hook owns only "
                          f"{cfg.host!r} (NAMECHEAP_HOST); match --dns-name to it")
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            raise ConfigError(f"{path} line {n}: {addr!r} is not an IP address")
        if (ip.version == 4) != (rtype == "A"):
            raise ConfigError(f"{path} line {n}: {rtype} record with address {addr}")
        if not ttl.isdigit() or not 60 <= int(ttl) <= 60000:
            raise ConfigError(f"{path} line {n}: TTL {ttl} is outside Namecheap's 60 to 60000")
        records.add((rtype, ip.compressed, ttl))
    return records


def local(tag):
    return tag.rsplit("}", 1)[-1]


def find(root, name):
    for e in root.iter():
        if local(e.tag) == name:
            return e
    return None


def call(cfg, command, params):
    body = {
        "ApiUser": cfg.api_user,
        "ApiKey": cfg.api_key,
        "UserName": cfg.username,
        "ClientIp": cfg.client_ip,
        "Command": command,
        "SLD": cfg.sld,
        "TLD": cfg.tld,
    }
    body.update(params)
    req = urllib.request.Request(
        cfg.api_url,
        data=urllib.parse.urlencode(body).encode(),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout) as r:
            raw = r.read(4 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as e:
        raise ApiError(f"{command}: HTTP {e.code}")
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        raise ApiError(f"{command}: {type(e).__name__}: {reason}")
    if len(raw) > 4 * 1024 * 1024:
        raise ApiError(f"{command}: the answer is too large")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise ApiError(f"{command}: the answer is not XML ({e})")
    if local(root.tag) != "ApiResponse":
        raise ApiError(f"{command}: the answer is not an ApiResponse")
    if root.get("Status") != "OK":
        errors = [f"{e.get('Number', '?')}: {(e.text or '').strip()}"
                  for e in root.iter() if local(e.tag) == "Error"]
        hint = ""
        if any("IP" in x or "1011150" in x for x in errors):
            hint = " (is NAMECHEAP_CLIENT_IP whitelisted under Profile > Tools > API Access?)"
        raise ApiError(f"{command}: Status={root.get('Status')!r}: {'; '.join(errors) or 'no error given'}{hint}")
    return root


class Host:
    FIELDS = ("Name", "Type", "Address", "MXPref", "TTL")

    def __init__(self, e):
        self.attrs = {k: e.get(k) for k in self.FIELDS}
        if any(self.attrs[k] is None for k in ("Name", "Type", "Address")):
            raise ApiError("getHosts: a host has no Name, Type or Address")

    @property
    def name(self):
        return self.attrs["Name"]

    @property
    def type(self):
        return self.attrs["Type"]

    def key(self):
        return tuple(self.attrs[k] or "" for k in self.FIELDS)

    def show(self):
        a = self.attrs
        return f"{a['Name']} {a['Type']} {a['Address']} TTL {a['TTL']}" + (
            f" MXPref {a['MXPref']}" if a["Type"] in ("MX", "MXE") else "")


def get_hosts(cfg):
    root = call(cfg, "namecheap.domains.dns.getHosts", {})
    result = find(root, "DomainDNSGetHostsResult")
    if result is None:
        raise Refused("getHosts returned no DomainDNSGetHostsResult: nothing written")
    if (result.get("IsUsingOurDNS") or "").lower() != "true":
        raise Refused(f"{cfg.domain} is not on Namecheap's DNS (IsUsingOurDNS="
                      f"{result.get('IsUsingOurDNS')!r}): nothing written")
    hosts = [Host(e) for e in result if local(e.tag).lower() == "host"]
    if not hosts:
        raise Refused(f"getHosts returned no records for {cfg.domain}: refusing to replace the "
                      f"record set with only the pool's")
    return hosts, result.get("EmailType")


def plan(cfg, hosts, email_type):
    """The full host set to send, and the pool's old records."""
    kept, old = [], set()
    for h in hosts:
        if h.name.lower() == cfg.host:
            if h.type not in ("A", "AAAA"):
                raise Refused(f"{cfg.host} has a {h.type} record ({h.show()}); this hook owns "
                              f"only its A and AAAA records. Remove it by hand first")
            old.add((h.type, ipaddress.ip_address(h.attrs["Address"]).compressed, h.attrs["TTL"] or ""))
            continue
        if h.type not in ROUND_TRIP_TYPES:
            raise Refused(f"the record {h.show()} is a {h.type} record, which setHosts cannot be "
                          f"given back exactly: nothing written")
        kept.append(h)
    if email_type is None and any(h.type in ("MX", "MXE") for h in kept):
        raise Refused("getHosts gave no EmailType but the domain has MX records: nothing written")
    return kept, old


def set_params(cfg, kept, new, email_type):
    p = {}
    i = 0
    for h in kept:
        i += 1
        p[f"HostName{i}"] = h.attrs["Name"]
        p[f"RecordType{i}"] = h.attrs["Type"]
        p[f"Address{i}"] = h.attrs["Address"]
        if h.attrs["MXPref"] is not None:
            p[f"MXPref{i}"] = h.attrs["MXPref"]
        if h.attrs["TTL"] is not None:
            p[f"TTL{i}"] = h.attrs["TTL"]
    for rtype, addr, ttl in sorted(new):
        i += 1
        p[f"HostName{i}"] = cfg.host
        p[f"RecordType{i}"] = rtype
        p[f"Address{i}"] = addr
        p[f"TTL{i}"] = ttl
    if email_type is not None:
        p["EmailType"] = email_type
    return p


def show_diff(cfg, old, new, kept):
    for r in sorted(old - new):
        say(f"  - {cfg.host} {r[0]} {r[1]} TTL {r[2]}")
    for r in sorted(new - old):
        say(f"  + {cfg.host} {r[0]} {r[1]} TTL {r[2]}")
    for r in sorted(old & new):
        say(f"    {cfg.host} {r[0]} {r[1]} TTL {r[2]}")
    say(f"  {len(kept)} other record(s) of {cfg.domain} kept exactly as they are")


def main(argv):
    ap = argparse.ArgumentParser(description="Push the pool's DNS records to Namecheap.")
    ap.add_argument("--env-file", default=DEFAULT_ENV_FILE)
    ap.add_argument("--dry-run", action="store_true", help="print the record diff; write nothing")
    ap.add_argument("fragment", nargs="?", default=os.environ.get("GHOST_DNS_FRAGMENT"))
    a = ap.parse_args(argv)
    if not a.fragment:
        raise ConfigError("no fragment: pass its path (ghost-audit merge does)")
    cfg = Config(read_env_file(a.env_file))
    new = read_fragment(a.fragment, cfg)
    if not new and not cfg.allow_empty:
        raise Refused(f"the fragment has no records: pushing it would leave {cfg.host}.{cfg.domain} "
                      f"with no address. Set NAMECHEAP_ALLOW_EMPTY=1 to allow that")
    hosts, email_type = get_hosts(cfg)
    kept, old = plan(cfg, hosts, email_type)
    say(f"{cfg.host}.{cfg.domain}: {len(old)} record(s) now, {len(new)} wanted")
    show_diff(cfg, old, new, kept)
    if old == new:
        say("no change: nothing written")
        return 0
    if a.dry_run:
        say("dry run: nothing written")
        return 0
    root = call(cfg, "namecheap.domains.dns.setHosts", set_params(cfg, kept, new, email_type))
    result = find(root, "DomainDNSSetHostsResult")
    if result is None or (result.get("IsSuccess") or "").lower() != "true":
        raise ApiError("setHosts did not report IsSuccess=\"true\"")
    after, _ = get_hosts(cfg)
    want = sorted([h.key() for h in kept] +
                  [(cfg.host, t, addr, None, ttl) for t, addr, ttl in new], key=_cmp_key)
    got = sorted([h.key() for h in after], key=_cmp_key)
    if [_cmp_key(k) for k in want] != [_cmp_key(k) for k in got]:
        raise ApiError("after setHosts, getHosts does not return the record set sent")
    say(f"pushed: {cfg.host}.{cfg.domain} now has {len(new)} record(s)")
    return 0


def _cmp_key(k):
    # Name, Type, Address, TTL. MXPref is compared for MX/MXE only: Namecheap reports one (10) on
    # every record, whatever was sent for the others.
    name, rtype, addr, mxpref, ttl = k
    if rtype in ("A", "AAAA"):
        try:
            addr = ipaddress.ip_address(addr).compressed
        except ValueError:
            pass
    return (name.lower(), rtype, addr, ttl or "", (mxpref or "") if rtype in ("MX", "MXE") else "")


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ConfigError as e:
        say(f"namecheap-hook: {e}", err=True)
        sys.exit(2)
    except Refused as e:
        say(f"namecheap-hook: REFUSED, nothing written: {e}", err=True)
        sys.exit(3)
    except ApiError as e:
        say(f"namecheap-hook: Namecheap API: {e}", err=True)
        sys.exit(1)
