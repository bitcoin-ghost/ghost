#!/usr/bin/env python3
"""Ghost Pool solo end-to-end harness, on regtest.

Native processes on loopback, one temp directory, no Docker. Two nodes, each:

  ghostd (regtest, peered with the other) -> ghost-mining (TDP template provider + API)
    -> pool_sv2 ([solo], submit_rpc = the other node's ghostd) -> translator_sv2 (SV1 3333, 4444)

and three miners with payout addresses of their own: cpu_miner.py on 3333, cpu_miner.py on 4444
(the farm tier) and the SV2 mining_device on 34255. Node i serves miners on 127.0.0.<10+i>, so
both nodes use the real ports. The miners take turns (SIGSTOP / SIGCONT), so every port of every
node finds blocks and the run is short; the chain starts at BOOTSTRAP_HEIGHT plain blocks, so the
pool's blocks cross regtest's first halving (150).

Every scenario prints PASS, FAIL or UNMEASURED with its evidence; only a positive reading passes.
Exit status 1 if any FAIL. Run: scripts/regtest-solo/run.sh --help
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

RPC_USER, RPC_PASS = "solo", "solopass"
# One SV2 authority keypair for both pools (regtest only).
POOL_PUB = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
POOL_SEC = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
# The treasury, the same on every network: P2WPKH of bc1qgxg5ywk835c9fp6arz6d6x50xpk6y0ualt900k
# (ghost_common::solo::TREASURY_SCRIPT).
TREASURY_SCRIPT = "00144191423ac78d3054875d18b4dd1a8f306da23f9d"
# The hostile build's skim script (pool_sv2 feature solo-fault-injection, solo.rs `fault`).
SKIM_SCRIPT = "0014" + "5c" * 20
WITNESS_PREFIX = "6a24aa21a9ed"
COIN = 100_000_000
# Regtest's subsidy schedule: it halves every 150 blocks.
HALVING = 150
# The ports a Ghost Pool node serves miners on.
SV1_SMALL, SV1_FARM, SV2_PORT = 3333, 4444, 34255

RESULTS = []


def say(*a):
    print(*a, flush=True)


def result(name, verdict, evidence):
    RESULTS.append((name, verdict, evidence))
    say(f"\n[{verdict}] {name}")
    for line in evidence if isinstance(evidence, list) else [evidence]:
        say(f"    {line}")


# ---------------------------------------------------------------------------------------------
# bech32 / bech32m (BIP 173 / 350), for payee addresses.
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _convertbits(data, frombits, tobits):
    acc, bits, ret = 0, 0, []
    for v in data:
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & ((1 << tobits) - 1))
    if bits:
        ret.append((acc << (tobits - bits)) & ((1 << tobits) - 1))
    return ret


def segwit_address(hrp, version, program):
    data = [version] + _convertbits(program, 8, 5)
    const = 1 if version == 0 else 0x2BC830A3
    hrpx = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    pm = _polymod(hrpx + data + [0] * 6) ^ const
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + chk)


def payee(tag, kind="wpkh"):
    """(address, script hex) for a deterministic regtest payee: P2WPKH, P2WSH or P2TR."""
    h = hashlib.sha256(tag.encode()).digest()
    if kind == "tr":
        return segwit_address("bcrt", 1, h), "5120" + h.hex()
    if kind == "wsh":
        return segwit_address("bcrt", 0, h), "0020" + h.hex()
    return segwit_address("bcrt", 0, h[:20]), "0014" + h[:20].hex()


# ---------------------------------------------------------------------------------------------
def http(url, body=None, auth=None, headers=None, timeout=30):
    """(status, parsed JSON or None) of a request; never raises on an HTTP error status."""
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    if auth:
        hdrs["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
    data = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data, hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            code = r.status
    except urllib.error.HTTPError as e:
        raw, code = e.read(), e.code
    try:
        return code, json.loads(raw)
    except ValueError:
        return code, None


def get_json(url, timeout=20):
    code, v = http(url, timeout=timeout)
    if code != 200 or v is None:
        raise RuntimeError(f"{url}: HTTP {code} {v}")
    return v


def port_open(port, host="127.0.0.1"):
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


def wait_for(cond, timeout, step=0.5, what="condition"):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            v = cond()
            if v:
                return v
        except Exception as e:  # noqa: BLE001 - polled until it holds
            last = e
        time.sleep(step)
    raise TimeoutError(f"timed out waiting for {what}" + (f" (last error: {last})" if last else ""))


def strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def subsidy(h):
    return 0 if h // HALVING >= 64 else (50 * COIN) >> (h // HALVING)


class Proc:
    def __init__(self, name, argv, log, cwd=None, env=None):
        self.name, self.log, self.argv = name, log, argv
        out = open(log, "ab")
        self.p = subprocess.Popen(argv, stdout=out, stderr=out, cwd=cwd, start_new_session=True,
                                  env={**os.environ, **(env or {})})
        out.close()

    def alive(self):
        return self.p.poll() is None

    def terminate(self):
        if self.p.poll() is None:
            try:
                os.killpg(self.p.pid, signal.SIGCONT)
                os.killpg(self.p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def stop(self, grace=15):
        if self.p.poll() is not None:
            return
        self.terminate()
        try:
            self.p.wait(grace)
        except subprocess.TimeoutExpired:
            say(f"  {self.name}: no exit {grace}s after SIGTERM; SIGKILL")
            self.kill()

    def kill(self):
        try:
            os.killpg(self.p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.p.wait(10)

    def signal(self, sig):
        if self.alive():
            try:
                os.killpg(self.p.pid, sig)
            except ProcessLookupError:
                pass


class Miner:
    """One miner: a payout address on one port of one node."""

    def __init__(self, node, kind, address, script, worker):
        self.node, self.kind, self.address, self.script, self.worker = node, kind, address, script, worker
        self.name = f"node{node.i}/{kind}"

    @property
    def proc(self):
        return self.node.procs.get(self.kind)

    @property
    def port(self):
        return {"sv1-3333": SV1_SMALL, "sv1-4444": SV1_FARM, "sv2": SV2_PORT}[self.kind]


class Node:
    def __init__(self, h, idx):
        self.h, self.i = h, idx
        self.dir = os.path.join(h.work, f"node{idx}")
        os.makedirs(self.dir, exist_ok=True)
        b = h.args.base_port + 100 * idx
        self.p2p, self.rpc_port, self.zmq_block, self.zmq_tx = b, b + 1, b + 2, b + 3
        self.http, self.tdp, self.pool_mon, self.tr_mon = b + 10, b + 11, b + 21, b + 31
        # Each node serves miners on a loopback address of its own, on the real ports.
        self.ip = f"127.0.0.{10 + idx}"
        self.procs = {}
        self.miners = []
        self.api_secret = hashlib.sha256(f"secret{idx}".encode()).hexdigest()
        self.reward_addr = payee(f"node{idx}/operator")[0]

    def log(self, name):
        return os.path.join(self.dir, name + ".log")

    def read_log(self, name):
        try:
            with open(self.log(name), errors="replace") as f:
                return strip_ansi(f.read())
        except FileNotFoundError:
            return ""

    # -- bitcoin ---------------------------------------------------------------------------
    def rpc(self, method, *params, timeout=60, wallet=None):
        url = f"http://127.0.0.1:{self.rpc_port}/" + (f"wallet/{wallet}" if wallet else "")
        code, out = http(url, {"jsonrpc": "1.0", "id": "h", "method": method, "params": list(params)},
                         auth=f"{RPC_USER}:{RPC_PASS}", timeout=timeout)
        if out is None:
            raise RuntimeError(f"{method}: HTTP {code}")
        if out.get("error"):
            raise RuntimeError(f"{method}: {out['error']}")
        return out["result"]

    def start_bitcoind(self, peers):
        d = os.path.join(self.dir, "bitcoin")
        os.makedirs(d, exist_ok=True)
        conf = ["regtest=1", "server=1", "[regtest]",
                f"rpcuser={RPC_USER}", f"rpcpassword={RPC_PASS}",
                f"rpcport={self.rpc_port}", "rpcbind=127.0.0.1", "rpcallowip=127.0.0.1",
                f"port={self.p2p}", "bind=127.0.0.1", "listen=1", "discover=0", "dnsseed=0",
                "fixedseeds=0", "listenonion=0", "fallbackfee=0.0002", "txindex=0",
                f"zmqpubhashblock=tcp://127.0.0.1:{self.zmq_block}",
                f"zmqpubhashtx=tcp://127.0.0.1:{self.zmq_tx}",
                # ghost_common::solo::BLOCK_RESERVED_WEIGHT, as the installer writes it.
                "blockreservedweight=8000", "dbcache=16", "maxmempool=50", "rpcworkqueue=64",
                ] + [f"addnode=127.0.0.1:{p}" for p in peers]
        with open(os.path.join(d, "bitcoin.conf"), "w") as f:
            f.write("\n".join(conf) + "\n")
        self.procs["bitcoind"] = Proc("bitcoind", [self.h.args.bitcoind, f"-datadir={d}"],
                                      self.log("bitcoind"))
        wait_for(lambda: self.rpc("getblockcount") is not None, 90, what=f"node{self.i} ghostd RPC")

    # -- ghost-mining ----------------------------------------------------------------------
    def start_ghost_mining(self):
        d = os.path.join(self.dir, "ghost")
        os.makedirs(os.path.join(d, "data"), exist_ok=True)
        cfg = f"""[identity]
key_path = "{d}/node.key"
display_name = "regtest-solo-node{self.i}"

[bitcoin]
rpc_host = "127.0.0.1"
rpc_port = {self.rpc_port}
rpc_user = "{RPC_USER}"
rpc_password = "{RPC_PASS}"
network = "regtest"
zmq_hashblock = "tcp://127.0.0.1:{self.zmq_block}"
zmq_hashtx = "tcp://127.0.0.1:{self.zmq_tx}"

[network]
internal_api_secret = "{self.api_secret}"
signing_key = "{hashlib.sha256(f"sign{self.i}".encode()).hexdigest()}"
public_address = "{self.ip}"
sv2_port = {SV2_PORT}
sv1_port = {SV1_SMALL}
farm_port = {SV1_FARM}
http_port = {self.http}
verification_https_port = {self.http + 2}
sv2_authority_public_key = "{POOL_PUB}"
max_miners = 100

[policy]
profile = "full_open"

[storage]
db_path = "{d}/data"
wal_mode = true
archive_mode = false
prune_height = 0

[pool]
# pool_sv2's monitoring listener, which this node's API forwards the pool routes to.
node_pool_api = "http://127.0.0.1:{self.pool_mon}"

[reaper]
enabled = false
"""
        with open(os.path.join(d, "pool.toml"), "w") as f:
            f.write(cfg)
        self.procs["ghost-mining"] = Proc(
            "ghost-mining",
            [self.h.bin("ghost-mining"), "--config", os.path.join(d, "pool.toml"), "--data-dir", d,
             "--tdp-enabled", "--tdp-port", str(self.tdp), "--no-stratum"],
            self.log("ghost-mining"), cwd=d, env={"RUST_LOG": "info", "NO_COLOR": "1"})

        def ready():
            m = re.search(r"TDP authority public key: (\w+)", self.read_log("ghost-mining"))
            return m and port_open(self.tdp) and port_open(self.http) and m.group(1)
        self.tdp_key = wait_for(ready, 180, what=f"node{self.i} ghost-mining TDP")

    # -- pool_sv2 ----------------------------------------------------------------------------
    def write_pool_config(self, submit_to):
        d = os.path.join(self.dir, "pool")
        os.makedirs(os.path.join(d, "state"), exist_ok=True)
        auth = os.path.join(d, "submit-rpc.auth")
        with open(auth, "w") as f:
            f.write("# the other node's RPC credentials\n" + "".join(
                f"http://127.0.0.1:{n.rpc_port} {RPC_USER}:{RPC_PASS}\n" for n in submit_to))
        os.chmod(auth, 0o600)
        urls = ", ".join(f'"http://127.0.0.1:{n.rpc_port}"' for n in submit_to)
        cfg = f"""authority_public_key = "{POOL_PUB}"
authority_secret_key = "{POOL_SEC}"
cert_validity_sec = 3600
listen_address = "{self.ip}:{SV2_PORT}"
coinbase_reward_script = "addr({self.reward_addr})"
server_id = 1
pool_signature = "- G H O S T -"
shares_per_minute = 6.0
share_batch_size = 1
supported_extensions = [0x0002, 0x4748]
required_extensions = []
monitoring_address = "127.0.0.1:{self.pool_mon}"

[share_webhook]
url = "http://127.0.0.1:{self.http}/api/internal/shares"
secret = "{self.api_secret}"
batch_size = 1
batch_timeout_ms = 2000
max_retries = 3

[solo]
network = "regtest"
state_dir = "{d}/state"
submit_rpc = [{urls}]
submit_rpc_auth_file = "{auth}"
sv1_ports = [{SV1_SMALL}, {SV1_FARM}]

[template_provider_type.Sv2Tp]
address = "127.0.0.1:{self.tdp}"
public_key = "{self.tdp_key}"
"""
        with open(os.path.join(d, "pool-config.toml"), "w") as f:
            f.write(cfg)
        self.pool_dir = d

    def start_pool(self, binary=None, env=None):
        name = "pool_sv2"
        self.procs[name] = Proc(
            name, [binary or self.h.bin("pool_sv2"), "-c", os.path.join(self.pool_dir, "pool-config.toml")],
            self.log(name), cwd=self.pool_dir, env={"RUST_LOG": "info", "NO_COLOR": "1", **(env or {})})
        wait_for(lambda: port_open(SV2_PORT, self.ip) and port_open(self.pool_mon), 120,
                 what=f"node{self.i} pool_sv2 listening")

    def start_translator(self):
        d = os.path.join(self.dir, "translator")
        os.makedirs(d, exist_ok=True)
        # As the installer writes it (scripts/install-node.sh), on this node's address, except the
        # hobby floor: a CPU's hashrate, so the 3333 difficulty stays tiny (the CPU miners aim at
        # the block target anyway). The farm tier keeps the installer's floor.
        cfg = f"""downstream_address = "{self.ip}"
downstream_port = {SV1_SMALL}
max_supported_version = 2
min_supported_version = 2
downstream_extranonce2_size = 8
user_identity = "ghost_miner"
aggregate_channels = false
open_channel_on_subscribe = true
supported_extensions = []
required_extensions = [0x0002, 0x4748]
monitoring_address = "127.0.0.1:{self.tr_mon}"

[downstream_difficulty_config]
min_individual_miner_hashrate = 50.0
shares_per_minute = 6.0
enable_vardiff = false
job_keepalive_interval_secs = 60
quantise_to_tiers = false

[farm_tier]
port = {SV1_FARM}
min_individual_miner_hashrate = 100_000_000_000_000.0
hobby_max_individual_miner_hashrate = 50_000_000_000_000.0

[[upstreams]]
address = "{self.ip}"
port = {SV2_PORT}
authority_pubkey = "{POOL_PUB}"
"""
        with open(os.path.join(d, "translator.toml"), "w") as f:
            f.write(cfg)
        self.procs["translator"] = Proc(
            "translator", [self.h.bin("translator_sv2"), "-c", os.path.join(d, "translator.toml")],
            self.log("translator"), cwd=d, env={"RUST_LOG": "info", "NO_COLOR": "1"})
        wait_for(lambda: port_open(SV1_SMALL, self.ip) and port_open(SV1_FARM, self.ip), 90,
                 what=f"node{self.i} translator SV1 ports")

    # -- miners ------------------------------------------------------------------------------
    def add_miners(self):
        """This node's three miners (not started): 3333 P2WPKH, 4444 P2TR, SV2 P2WSH."""
        for kind, cls, worker, agent in [("sv1-3333", "wpkh", "bitaxe", "bitaxe/v2.10.0"),
                                         ("sv1-4444", "tr", "s21", "Antminer S21/Thu Jan 1"),
                                         ("sv2", "wsh", "dev", None)]:
            addr, script = payee(f"node{self.i}/{kind}", cls)
            m = Miner(self, kind, addr, script, worker)
            m.agent = agent
            self.miners.append(m)

    def start_miner(self, m):
        a = self.h.args
        user = f"{m.address}.{m.worker}"
        if m.kind == "sv2":
            argv = [self.h.bin("mining_device"), "-a", f"{self.ip}:{SV2_PORT}", "--cores", "1",
                    "--handicap", str(a.sv2_handicap_us), "--id-user", user, "--pubkey-pool", POOL_PUB]
            env = {"RUST_LOG": "info", "NO_COLOR": "1"}
        else:
            argv = [sys.executable, os.path.join(HERE, "cpu_miner.py"), self.ip, str(m.port),
                    "--events", os.path.join(self.dir, f"{m.kind}-events.jsonl"),
                    "--pace", str(a.pace), "--seed", str(100 * self.i + self.miners.index(m)),
                    "--miner", f"{user}@{m.agent}"]
            env = None
        self.procs[m.kind] = Proc(m.kind, argv, self.log(m.kind), env=env)

    def pause(self, miners, paused):
        for m in miners:
            if m.proc:
                m.proc.signal(signal.SIGSTOP if paused else signal.SIGCONT)

    def stop(self):
        for n in [m.kind for m in self.miners] + ["translator", "pool_sv2", "ghost-mining", "bitcoind"]:
            if n in self.procs:
                self.procs[n].stop()

    # -- readings --------------------------------------------------------------------------
    def status(self):
        return get_json(f"http://127.0.0.1:{self.pool_mon}/api/v1/pool/status")

    def miner_view(self, address):
        return get_json(f"http://127.0.0.1:{self.pool_mon}/api/v1/miner/{address}")

    def miner_list(self):
        return get_json(f"http://127.0.0.1:{self.pool_mon}/api/v1/pool/miners")

    def signed_get(self, path):
        """GET `path` on ghost-mining's API signed as the dashboard signs (HMAC-SHA256 over the
        timestamp's 8 little-endian bytes and the empty body)."""
        ts = int(time.time())
        sig = hmac.new(bytes.fromhex(self.api_secret), ts.to_bytes(8, "little"), hashlib.sha256).hexdigest()
        return http(f"http://127.0.0.1:{self.http}{path}",
                    headers={"X-Ghost-Signature": sig, "X-Ghost-Timestamp": str(ts)})


class Harness:
    def __init__(self, args):
        self.args = args
        if args.workdir and os.path.isdir(args.workdir) and os.listdir(args.workdir):
            raise SystemExit(f"work dir {args.workdir} is not empty; pass a new one")
        self.work = args.workdir or tempfile.mkdtemp(prefix="solo-regtest-")
        os.makedirs(self.work, exist_ok=True)
        self.nodes = []
        self.t0 = time.time()
        out = subprocess.run([args.bitcoind, "-version"], capture_output=True, text=True).stdout
        self.node_version = (out.splitlines() or ["unknown version"])[0]
        self.state = {}

    def bin(self, name):
        p = os.path.join(self.args.bin_dir, name)
        if not os.access(p, os.X_OK):
            raise SystemExit(f"missing binary {p}; build it first (see run.sh --help)")
        return p

    def miners(self):
        return [m for n in self.nodes for m in n.miners]

    def teardown(self):
        miners = [m.proc for m in self.miners() if m.proc]
        procs = miners + [p for n in self.nodes for p in n.procs.values() if p not in miners]
        for p in procs:
            p.terminate()
        for p in procs:
            p.stop()

    def leftovers(self):
        left = []
        for n in self.nodes:
            for name, p in n.procs.items():
                try:
                    os.killpg(p.p.pid, 0)
                    left.append(f"process group {p.p.pid} node{n.i}/{name}")
                except ProcessLookupError:
                    pass
        return left

    # -- chain readings ------------------------------------------------------------------------
    def pool_blocks(self, node, start=1):
        """Every block on node's best chain whose coinbase pays the treasury first (or the hostile
        build's skim script): (height, hash, coinbase vouts, fees of its transactions)."""
        tip = node.rpc("getblockcount")
        out = []
        for h in range(start, tip + 1):
            bh = node.rpc("getblockhash", h)
            blk = node.rpc("getblock", bh, 2)
            cb = blk["tx"][0]
            vouts = [(round(v["value"] * COIN), v["scriptPubKey"]["hex"]) for v in cb["vout"]]
            if vouts and vouts[0][1] in (TREASURY_SCRIPT, SKIM_SCRIPT):
                fees = sum(round(t.get("fee", 0) * COIN) for t in blk["tx"][1:])
                out.append((h, bh, vouts, fees, len(blk["tx"]) - 1))
        return out


def check_coinbase(h, vouts, fees, payees):
    """Problems with one pool block's coinbase against the solo rule, [] when exact: the treasury
    exactly subsidy/200, then the finder (a known miner) subsidy - subsidy/200 + fees, then nothing
    but the witness commitment."""
    s = subsidy(h)
    errs = []
    if len(vouts) not in (2, 3):
        errs.append(f"{len(vouts)} outputs, want treasury, miner and at most the witness commitment")
    if not vouts or vouts[0] != (s // 200, TREASURY_SCRIPT):
        errs.append(f"output 0 is {vouts[0] if vouts else None}, want ({s // 200}, treasury)")
    if len(vouts) >= 2:
        v, sc = vouts[1]
        if sc not in payees:
            errs.append(f"output 1 pays {sc}, not a miner of this run")
        if v != s - s // 200 + fees:
            errs.append(f"output 1 pays {v}, want subsidy {s} - {s // 200} + fees {fees} = {s - s // 200 + fees}")
    if len(vouts) == 3 and not (vouts[2][0] == 0 and vouts[2][1].startswith(WITNESS_PREFIX)):
        errs.append(f"output 2 is {vouts[2]}, not the witness commitment")
    return errs


def audit(h, node, proto, address, extra=None):
    """ghost-audit check against node's `proto` (sv1-3333, sv1-4444 or sv2): (exit code, output)."""
    argv = [h.bin("ghost-audit"), "check", "--network", "regtest", "--address", address,
            "--jobs", str(h.args.audit_jobs), "--timeout-secs", "90", "--worker", "audit"]
    if proto == "sv2":
        argv += ["--sv2", f"{node.ip}:{SV2_PORT}", "--authority-key", POOL_PUB]
    else:
        argv += ["--sv1", f"{node.ip}:{SV1_SMALL if proto == 'sv1-3333' else SV1_FARM}"]
    argv += extra or []
    r = subprocess.run(argv, capture_output=True, text=True, timeout=300, env={**os.environ, "NO_COLOR": "1"})
    out = strip_ansi(r.stdout + r.stderr)
    with open(os.path.join(h.work, "ghost-audit.log"), "a") as f:
        f.write(f"$ {' '.join(argv)}\n{out}\nexit {r.returncode}\n\n")
    return r.returncode, out


# ---------------------------------------------------------------------------------------------
# Scenarios. Each records its own result; one that cannot run records why.

def bringup(h):
    a = h.args
    n0 = Node(h, 0)
    n1 = Node(h, 1)
    h.nodes = [n0, n1]
    n0.start_bitcoind([])
    # The bootstrap: plain blocks to a wallet of node0's (their coinbases mature, so the run can
    # send fee-paying transactions), and the chain close enough to regtest's first halving that
    # the pool's blocks cross it.
    try:
        n0.rpc("createwallet", "h")
        h.wallet = "h"
        to = n0.rpc("getnewaddress", wallet="h")
    except RuntimeError as e:
        say(f"  no wallet on this ghostd ({e}); no fee-paying transactions")
        h.wallet = None
        to = payee("bootstrap")[0]
    n0.rpc("generatetoaddress", a.bootstrap_height, to, timeout=300)
    n1.start_bitcoind([n0.p2p])
    tip = n0.rpc("getbestblockhash")
    wait_for(lambda: n1.rpc("getbestblockhash") == tip, 120, what="node1 to sync node0's chain")
    for n in h.nodes:
        n.start_ghost_mining()
    n0.write_pool_config([n1])
    n1.write_pool_config([n0])
    for n in h.nodes:
        n.start_pool()
        n.start_translator()
        n.add_miners()
    ev = []
    # One miner at a time: started, connected (its address has an open channel on its node), then
    # paused, so at most one mines at once and the bring-up adds few blocks.
    ok = True
    for m in h.miners():
        m.node.start_miner(m)
        try:
            wait_for(lambda: any(e["address"] == m.address and e["connected"]
                                 for e in m.node.miner_list()["miners"]), 90, step=0.5,
                     what=f"{m.name}'s channel")
        except TimeoutError as e:
            ok = False
            ev.append(str(e))
        m.node.pause([m], True)
    for n in h.nodes:
        peers = n.rpc("getconnectioncount")
        ev.append(f"node{n.i}: ghostd :{n.rpc_port} ({peers} peer), ghost-mining tdp :{n.tdp} api :{n.http}, "
                  f"pool_sv2 {n.ip}:{SV2_PORT} (api :{n.pool_mon}), translator {n.ip}:{SV1_SMALL},{SV1_FARM}; "
                  f"submit_rpc -> the other node's ghostd")
    h.state["after_bringup"] = n0.rpc("getblockcount")
    ev.append(f"height {h.state['after_bringup']} after the bring-up ({a.bootstrap_height} plain blocks)")
    for m in h.miners():
        ev.append(f"{m.name}: {m.address}.{m.worker}")
    result("bring-up: two peered nodes, each with ghostd, ghost-mining, pool_sv2 [solo] submitting to the "
           "other, the translator on 3333 and 4444, and a miner on each of 3333, 4444 and SV2 34255",
           "PASS" if ok and all(n.rpc("getconnectioncount") >= 1 for n in h.nodes) else "FAIL", ev)


def send_fee_transactions(h, count):
    """Fee-paying transactions from node0's wallet into both mempools."""
    if not h.wallet:
        return 0
    sent = 0
    for k in range(count):
        try:
            h.nodes[0].rpc("sendtoaddress", payee(f"spend/{time.time()}/{k}")[0], 0.5, wallet=h.wallet)
            sent += 1
        except RuntimeError as e:
            say(f"  sendtoaddress: {e}")
            break
    return sent


def mine_rounds(h):
    """The miners take turns: each in turn mines alone until its node records a block it found,
    then pauses. Fee-paying transactions go into the mempools before some rounds."""
    a = h.args
    ev, ok = [], True
    sent = 0
    start_height = h.nodes[0].rpc("getblockcount")
    found = {m.name: 0 for m in h.miners()}
    for r in range(a.rounds):
        if r in (1, 2):
            sent += send_fee_transactions(h, 4)
            time.sleep(3)  # into the templates
        for m in h.miners():
            before = len(m.node.miner_view(m.address)["blocks_found"])
            m.node.pause([m], False)
            try:
                wait_for(lambda: len(m.node.miner_view(m.address)["blocks_found"]) > before,
                         a.turn_timeout, step=0.5, what=f"{m.name} to find a block")
                found[m.name] += 1
            except TimeoutError as e:
                ok = False
                ev.append(f"round {r}: {e}")
            m.node.pause([m], True)
            # Both nodes on the new tip before the next turn.
            try:
                wait_for(lambda: len({n.rpc("getbestblockhash") for n in h.nodes}) == 1, 60,
                         what="both nodes on one tip")
            except TimeoutError as e:
                ok = False
                ev.append(str(e))
    end_height = h.nodes[0].rpc("getblockcount")
    blocks = h.pool_blocks(h.nodes[0], start_height + 1)
    h.state["sent_txs"] = sent
    ev.append(f"heights {start_height + 1}..{end_height}: {len(blocks)} pool blocks; "
              f"{sent} fee-paying transactions sent")
    ev += [f"{name}: {k} block(s)" for name, k in found.items()]
    need = a.rounds
    ok = ok and len(blocks) >= a.min_blocks and all(k >= need for k in found.values())
    result(f"mining: at least {a.min_blocks} pool blocks, every miner (3333, 4444 and SV2 on both nodes) "
           f"finding {need}", "PASS" if ok else "FAIL", ev)


def coinbase_rule(h):
    payees = {m.script for m in h.miners()}
    blocks = h.pool_blocks(h.nodes[0], h.args.bootstrap_height + 1)
    h.state["blocks"] = blocks
    bad, ev = [], []
    with_fees = [b for b in blocks if b[3] > 0]
    for hgt, bh, vouts, fees, ntx in blocks:
        errs = check_coinbase(hgt, vouts, fees, payees)
        if errs:
            bad.append(f"height {hgt} {bh[:16]}: " + "; ".join(errs))
    ev.append(f"{len(blocks)} pool blocks checked, {len(bad)} wrong; {len(with_fees)} carried fees "
              f"({sum(b[3] for b in with_fees)} sats in all)")
    for hgt, bh, vouts, fees, ntx in blocks[:2] + with_fees[:2]:
        ev.append(f"  height {hgt}: " + ", ".join(f"{v} -> {s[:16]}.." for v, s in vouts) + f"; fees {fees}, {ntx} tx")
    ev += bad[:10]
    result("coinbase: every pool block pays the treasury exactly subsidy/200 and its finder "
           "subsidy - subsidy/200 + fees, and nothing else but the witness commitment",
           "PASS" if blocks and not bad else "FAIL", ev)
    if h.state.get("sent_txs"):
        result("fees: the transactions' fees all went to the finder",
               "PASS" if with_fees and not bad else "UNMEASURED",
               f"{len(with_fees)} pool block(s) with fees; each finder output checked = subsidy - "
               f"subsidy/200 + its block's fees")


def halving(h):
    blocks = h.state.get("blocks", [])
    before = [b for b in blocks if b[0] < HALVING]
    after = [b for b in blocks if b[0] >= HALVING]
    ev = [f"{len(before)} pool blocks below {HALVING}, {len(after)} at or above"]
    ok = bool(after) and bool(before)
    for label, group, s in (("before", before, 50 * COIN), ("after", after, 25 * COIN)):
        for b in group:
            if b[2][0][0] != s // 200 or b[2][1][0] != s - s // 200 + b[3]:
                ok = False
                ev.append(f"height {b[0]}: {b[2][:2]} with subsidy {s}")
        if group:
            ev.append(f"{label}: treasury {group[0][2][0][0]} sats, finder {group[0][2][1][0]} sats + fees "
                      f"(subsidy {s})")
    result(f"halving: past regtest's halving ({HALVING}) the treasury is exactly 12,500,000 sats and the "
           "finder 2,487,500,000 + fees", "PASS" if ok else "FAIL", ev)


def submitted_to_both(h):
    """Every block a pool found: sent to the other node (accepted or duplicate), on both chains."""
    ev, ok, n_blocks = [], True, 0
    for n in h.nodes:
        other = h.nodes[1 - n.i]
        label = f"http://127.0.0.1:{other.rpc_port}"

        def all_answered():
            bl = n.status()["blocks_found"]
            return all(b["submitted"] for b in bl) and bl
        try:
            found = wait_for(all_answered, 60, step=2, what=f"node{n.i}'s submissions")
        except TimeoutError as e:
            ok = False
            ev.append(str(e))
            continue
        for b in found:
            n_blocks += 1
            res = {s["node"]: s["result"] for s in b["submitted"]}
            if res.get(label) not in ("accepted", "duplicate"):
                ok = False
                ev.append(f"node{n.i} block {b['height']}: the other node said {res}")
            for m in h.nodes:
                try:
                    have = m.rpc("getblockhash", b["height"]) == b["hash"]
                except RuntimeError:
                    have = False
                if not have:
                    ok = False
                    ev.append(f"block {b['height']} {b['hash'][:16]} found by node{n.i}: not on node{m.i}'s chain")
            if b["check"] != "ok":
                ok = False
                ev.append(f"node{n.i} block {b['height']}: post-submit check {b['check']}")
        answers = {}
        for b in found:
            for s in b["submitted"]:
                answers[s["result"]] = answers.get(s["result"], 0) + 1
        ev.append(f"node{n.i}: {len(found)} found; {label} answered {answers}")
        log = n.read_log("pool_sv2")
        if "SOLO_COINBASE_MISMATCH" in log:
            ok = False
            ev.append(f"node{n.i}'s pool_sv2 logged SOLO_COINBASE_MISMATCH")
    result("submission: every found block was sent to the other node (accepted or duplicate), is on "
           "both nodes' chains and passed the post-submit check",
           "PASS" if ok and n_blocks else "FAIL", ev)


def api(h):
    ev, ok = [], True
    for n in h.nodes:
        st = n.status()
        chain = [b for b in h.state["blocks"] if any(b[2][1][1] == m.script for m in n.miners)]
        bf = st["blocks_found"]
        if len(bf) != len(chain):
            ok = False
            ev.append(f"node{n.i}: status lists {len(bf)} blocks found, the chain has {len(chain)} of its miners'")
        hr = st["pool_hashrate_hs"]
        if not any(isinstance(hr.get(k), (int, float)) and hr[k] > 0 for k in ("15m", "1h")):
            ok = False
            ev.append(f"node{n.i}: pool hashrate {hr}")
        if not st["best_share"]["ever"] > 0:
            ok = False
            ev.append(f"node{n.i}: best share {st['best_share']}")
        if st["ports"] != {"sv1": [SV1_SMALL, SV1_FARM], "sv2": SV2_PORT, "sv2_authority_public_key": POOL_PUB}:
            ok = False
            ev.append(f"node{n.i}: ports {st['ports']}")
        sn = st["submit_nodes"]
        other = h.nodes[1 - n.i]
        if not (len(sn) == 1 and sn[0]["node"] == f"http://127.0.0.1:{other.rpc_port}" and sn[0]["reachable"]
                and isinstance(sn[0]["height"], int) and sn[0]["height"] >= h.args.bootstrap_height):
            ok = False
            ev.append(f"node{n.i}: submit_nodes {sn}")
        if RPC_PASS in json.dumps(st):
            ok = False
            ev.append(f"node{n.i}: the status carries the RPC password")
        ev.append(f"node{n.i} status: {len(bf)} blocks, hashrate 15m {hr.get('15m')}, best share "
                  f"{st['best_share']['ever']:.3g}, miners {st['miners']}, submit node {sn[0] if sn else None}")
        for m in n.miners:
            v = n.miner_view(m.address)
            mine = [b for b in chain if b[2][1][1] == m.script]
            rates = v["summary"]["hashrate_hs"]
            names = [w["name"] for w in v["workers"]]
            good = (len(v["blocks_found"]) == len(mine) and v["summary"]["best_share"]["ever"] > 0
                    and any(isinstance(rates.get(k), (int, float)) and rates[k] > 0 for k in ("15m", "1h"))
                    and m.worker in names and v["summary"]["shares_24h"]["accepted"] >= len(mine)
                    and all(b["reward_sats"] == b2[2][1][0] for b, b2 in zip(v["blocks_found"], mine)))
            if not good:
                ok = False
            ev.append(f"  {m.name} /api/v1/miner: {len(v['blocks_found'])} blocks (chain {len(mine)}), "
                      f"accepted {v['summary']['shares_24h']['accepted']}, hashrate 15m {rates.get('15m')}, "
                      f"best {v['summary']['best_share']['ever']:.3g}, workers {names}"
                      + ("" if good else "  <-- WRONG"))
        # The operator list: every miner of this node, by address, with its workers.
        lst = {e["address"]: e for e in n.miner_list()["miners"]}
        missing = [m.name for m in n.miners if m.address not in lst or lst[m.address]["workers"] < 1]
        if missing:
            ok = False
            ev.append(f"node{n.i} /api/v1/pool/miners misses {missing}")
        # Forwarded by ghost-mining: the public routes to anyone, the miner list to signed requests only.
        code_pub, body = http(f"http://127.0.0.1:{n.http}/api/v1/pool/status")
        code_unsigned, _ = http(f"http://127.0.0.1:{n.http}/api/v1/pool/miners")
        code_signed, signed = n.signed_get("/api/v1/pool/miners")
        code_miner, _ = http(f"http://127.0.0.1:{n.http}/api/v1/miner/{n.miners[0].address}")
        fwd_ok = (code_pub == 200 and body and body.get("network") == "regtest" and code_miner == 200
                  and code_unsigned == 401 and code_signed == 200
                  and {e["address"] for e in signed["miners"]} == set(lst))
        if not fwd_ok:
            ok = False
        ev.append(f"node{n.i} ghost-mining :{n.http}: /pool/status {code_pub}, /miner {code_miner}, "
                  f"/pool/miners unsigned {code_unsigned}, signed {code_signed} ({len(lst)} addresses)"
                  + ("" if fwd_ok else "  <-- WRONG"))
    result("API: /api/v1/pool/status, /api/v1/miner/<addr> and /api/v1/pool/miners report the blocks, best "
           "share, hashrate, workers, the SV2 key and the other node's reachability; ghost-mining serves the "
           "miner list to signed requests only", "PASS" if ok else "FAIL", ev)


def audit_honest(h):
    n = h.nodes[0]
    # The miners mine meanwhile, so new jobs come.
    n.pause(n.miners, False)
    ev, ok = [], True
    try:
        for proto in ("sv1-3333", "sv1-4444", "sv2"):
            addr = payee(f"audit/{proto}", "tr")[0]
            code, out = audit(h, n, proto, addr)
            passes = len(re.findall(r"^PASS", out, re.M))
            if code != 0 or passes < 1:
                ok = False
            ev.append(f"{proto}: exit {code}, {passes} job(s) PASS" + ("" if code == 0 else ": " + out.strip()[-300:]))
    finally:
        n.pause(n.miners, True)
    result("ghost-audit check passes against an honest node on 3333, 4444 and SV2",
           "PASS" if ok else "FAIL", ev)


def failover(h):
    """node1's pool_sv2 is killed: node0 keeps mining, and its blocks still reach node1."""
    n0, n1 = h.nodes
    n1.procs["pool_sv2"].kill()
    for m in n1.miners:
        if m.proc:
            m.proc.stop()
    n1.procs["translator"].stop()
    before = len(n0.status()["blocks_found"])
    h0 = n0.rpc("getblockcount")
    n0.pause(n0.miners, False)
    ev, ok = [], True
    try:
        wait_for(lambda: len(n0.status()["blocks_found"]) >= before + 3, 180, step=1,
                 what="node0 to find 3 more blocks")
    except TimeoutError as e:
        ok = False
        ev.append(str(e))
    finally:
        n0.pause(n0.miners, True)
    h1 = n0.rpc("getblockcount")
    try:
        wait_for(lambda: n1.rpc("getbestblockhash") == n0.rpc("getbestblockhash"), 60, what="node1 on node0's tip")
    except TimeoutError as e:
        ok = False
        ev.append(str(e))
    time.sleep(3)
    new = n0.status()["blocks_found"][before:]
    for b in new:
        res = [s["result"] for s in b["submitted"]]
        if not res or res[0] not in ("accepted", "duplicate"):
            ok = False
            ev.append(f"block {b['height']}: node1's ghostd said {res}")
    ev.append(f"node1's pool_sv2 killed (alive: {n1.procs['pool_sv2'].alive()}); node0 mined {h0 + 1}..{h1}, "
              f"{len(new)} found, node1's ghostd answered {[s['result'] for b in new for s in b['submitted']]}")
    result("failover: with one node's pool_sv2 killed, the other keeps mining and still sends its blocks "
           "to the first node's ghostd", "PASS" if ok and len(new) >= 3 else "FAIL", ev)


def hostile(h):
    """node1 runs the hostile build: its jobs pay the treasury's share to the operator. ghost-audit
    must refuse it."""
    a = h.args
    if not a.hostile_binary:
        result("hostile: ghost-audit refuses a pool that skims the treasury", "UNMEASURED",
               "no --hostile-binary (pool_sv2 built with --features solo-fault-injection)")
        return
    n1 = h.nodes[1]
    n1.start_pool(binary=a.hostile_binary, env={"GHOST_SOLO_FAULT": "skim-treasury"})
    addr = payee("audit/hostile", "wpkh")[0]
    code, out = audit(h, n1, "sv2", addr)
    fails = len(re.findall(r"^FAIL", out, re.M))
    ok = code == 1 and fails >= 1
    result("hostile: ghost-audit refuses a pool that skims the treasury (pool_sv2 feature "
           "solo-fault-injection, GHOST_SOLO_FAULT=skim-treasury)",
           "PASS" if ok else "FAIL", [f"sv2 on node1: exit {code}, {fails} job(s) FAIL"] +
           [l for l in out.splitlines() if l.startswith("FAIL")][:2])
    n1.procs["pool_sv2"].stop()


def reachability(h):
    """node1's ghostd stops: node0's status says the submit node is unreachable, and why."""
    n0, n1 = h.nodes
    n1.procs["bitcoind"].stop()
    ev = []
    try:
        sn = wait_for(lambda: (lambda s: s if s and s[0]["reachable"] is False else None)(n0.status()["submit_nodes"]),
                      150, step=3, what="node0 to report node1's ghostd unreachable")
        ok = bool(sn[0]["error"]) and sn[0]["last_ok_at"] is not None and RPC_PASS not in json.dumps(sn)
        ev.append(f"node0 submit_nodes: {sn[0]}")
    except TimeoutError as e:
        ok = False
        ev.append(str(e))
    result("reachability: a submit node that stops answering is reported unreachable (with the error and "
           "its last good answer) within the 60 s check", "PASS" if ok else "FAIL", ev)


ALL = [bringup, mine_rounds, coinbase_rule, halving, submitted_to_both, api, audit_honest, failover,
       hostile, reachability]


def run(args):
    h = Harness(args)
    say(f"work dir: {h.work}")
    say(f"bitcoin node: {args.bitcoind} ({h.node_version})")
    interrupted = False

    def on_signal(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")
    signal.signal(signal.SIGTERM, on_signal)
    try:
        for sc in ALL:
            if args.only and sc.__name__ not in args.only and sc is not bringup:
                continue
            say(f"\n== {sc.__name__}  ({time.time() - h.t0:.0f}s)")
            sc(h)
            if sc is bringup and RESULTS[-1][1] == "FAIL":
                break
    except KeyboardInterrupt as e:
        interrupted = True
        result("harness", "FAIL", f"interrupted: {e}")
    except Exception:  # noqa: BLE001 - a crash is a FAIL with its evidence
        import traceback
        result("harness", "FAIL", traceback.format_exc().splitlines()[-8:])
    finally:
        say("\n== teardown")
        t = time.time()
        h.teardown()
        left = h.leftovers()
        busy = [p for n in h.nodes for p in (n.p2p, n.rpc_port, n.tdp, n.http, n.pool_mon) if port_open(p)] + \
            [f"{n.ip}:{p}" for n in h.nodes for p in (SV1_SMALL, SV1_FARM, SV2_PORT) if port_open(p, n.ip)]
        if left or busy:
            result("teardown", "FAIL", [f"left running: {l}" for l in left] + [f"port still open: {p}" for p in busy])
        else:
            result("teardown", "PASS", f"{sum(len(n.procs) for n in h.nodes)} processes stopped in "
                   f"{time.time() - t:.1f}s; every port closed")
    say("\n== summary")
    for name, verdict, _ in RESULTS:
        say(f"  {verdict:10} {name}")
    say(f"runtime {time.time() - h.t0:.0f}s")
    failed = any(v == "FAIL" for _, v, _ in RESULTS)
    if args.logs_to:
        shutil.copytree(h.work, args.logs_to, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("blocks", "chainstate", "*.dat", "data"))
    if not args.keep and not interrupted and not failed:
        shutil.rmtree(h.work, ignore_errors=True)
    else:
        say(f"logs kept in {h.work}")
    return 1 if failed else 0


def find_ghostd(cache):
    if cache and os.path.isdir(cache):
        def version(d):
            return tuple(int(x) for x in re.findall(r"\d+", d))
        for d in sorted((d for d in os.listdir(cache) if d.startswith("ghostd-v")), key=version, reverse=True):
            p = os.path.join(cache, d, "ghostd")
            if os.access(p, os.X_OK):
                return p
    for p in (shutil.which("ghostd"), "/opt/ghost/bin/ghostd"):
        if p and os.access(p, os.X_OK):
            return p
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bitcoind", default=os.environ.get("GHOSTD") or os.environ.get("BITCOIND"),
                    help="the Bitcoin node binary (default: the newest cached release ghostd, see run.sh)")
    ap.add_argument("--ghostd-cache", help="where run.sh --fetch-ghostd keeps released ghostds")
    ap.add_argument("--bin-dir", default=os.path.join(REPO, "target", "debug"),
                    help="ghost-mining, pool_sv2, translator_sv2, ghost-audit and mining_device")
    ap.add_argument("--hostile-binary", default=os.environ.get("HOSTILE_POOL_SV2"),
                    help="pool_sv2 built with --features solo-fault-injection (optional)")
    ap.add_argument("--workdir")
    ap.add_argument("--keep", action="store_true", help="keep the work dir even on success")
    ap.add_argument("--logs-to", help="copy the run's logs and configs here at the end (for CI)")
    ap.add_argument("--base-port", type=int, default=21000)
    ap.add_argument("--bootstrap-height", type=int, default=138,
                    help="plain blocks before the pool mines (the pool's blocks then cross 150)")
    ap.add_argument("--rounds", type=int, default=3,
                    help="turns each of the six miners takes (each turn: one block)")
    ap.add_argument("--min-blocks", type=int, default=10)
    ap.add_argument("--pace", type=float, default=1.0, help="seconds an SV1 miner sleeps after a share")
    ap.add_argument("--sv2-handicap-us", type=int, default=500_000,
                    help="microseconds the SV2 mining_device waits between hash batches")
    ap.add_argument("--turn-timeout", type=float, default=90)
    ap.add_argument("--audit-jobs", type=int, default=1)
    ap.add_argument("--only", nargs="*", help="scenario function names to run (bring-up always runs)")
    args = ap.parse_args()
    args.bitcoind = args.bitcoind or find_ghostd(args.ghostd_cache)
    if not args.bitcoind:
        raise SystemExit("no ghostd: run `run.sh --fetch-ghostd`, put ghostd on PATH, or pass --bitcoind")
    sys.exit(run(args))


if __name__ == "__main__":
    main()
