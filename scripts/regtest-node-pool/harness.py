#!/usr/bin/env python3
"""Node pool end-to-end harness (plan, Phase 3): regtest, and our own signet (--network signet).

Native processes on loopback, one temp directory, no Docker. Per node:

  ghostd (regtest or signet, peered) -> ghost-mining (TDP template provider) -> pool_sv2
  ([node_pool] + [node_pool.relay], relays peered) -> translator_sv2 (SV1) -> cpu_miner.py

Signet is a custom signet of the run's own (-signetchallenge, a fresh network id every run, so its
message start and genesis are nobody else's), mined by ghostd's own generatetoaddress for plain
blocks and by the pool's miners for pool blocks; see SIGNET_* below and scenarios_signet.py.

The Bitcoin node is ghostd, as on every node pool node, run as the installer runs it (Reaper on;
--no-reaper turns it off). --bitcoind (or BITCOIND=) runs any other binary that speaks Core's RPC
and ZMQ on regtest instead. Every scenario prints PASS, FAIL or UNMEASURED with its evidence;
only a positive reading passes. Run: scripts/regtest-node-pool/run.sh --help
"""
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

RPC_USER, RPC_PASS = "np", "nppass"
# One SV2 authority keypair for every node's pool_sv2 (regtest only; a node's identity is its
# ghost-mining node key, which is generated per node).
POOL_PUB = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
POOL_SEC = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
# Installer regtest defaults (scripts/install-node.sh, np_network_defaults).
REGTEST_GENESIS = "8d8cd561340ff83e99410e115619d64ad94516264d3e5cd6a991109c69f1229c"
REGTEST_TIER_BASE = "7fffff" + "00" * 29
TREASURY_SCRIPT = "51209925167815d1202e985dc607bceab162cb70c98d292da3592c087b44a3fefb2f"
LEDGER_MAGIC = b"GHNP".hex()
WITNESS_PREFIX = "6a24aa21a9ed"
COIN = 100_000_000
# Regtest's subsidy schedule (Halving::REGTEST): it halves every 150 blocks.
HALVING = 150
# The network the run is on, and what follows from it. configure_network() sets these for
# --network before the scenarios import them; the defaults are regtest's.
NETWORK = "regtest"
HRP = "bcrt"
TIER_BASE = REGTEST_TIER_BASE
GENESIS_ANCHOR = "UNSET"  # regtest's default anchor (REGTEST_GENESIS), as the installer writes it
GENESIS_HEIGHT = 0
SIGNET_CHALLENGE = None
# Signet: the proof-of-work limit (chainparams, SigNetParams), the minimum difficulty, about 4.8M
# hashes a block. Blocks stay there below the first retarget at 2,016.
SIGNET_POW_LIMIT = 0x377AE << 216
# Signet tier base: 2^17 x the limit. The network tier (floor 10) is then 2^7 easier than a block
# and the anchor tier (+8) half a block's target, so every block is a network share and half are
# anchors; a share that is not a block is below pool_sv2's channel floor (difficulty 2^10,
# 2^42 hashes) and never reaches the relay, as on regtest. tier_base is configuration on signet.
SIGNET_TIER_BASE = f"{SIGNET_POW_LIMIT << 17:064x}"
# Agents chosen to land in each class of the ceiling table (slot_class_sensing.rs).
AGENTS = [
    ("cpuminer/2.5", 3),              # unknown -> smallest class
    ("bmminer/2.0.0", 9),             # stock Antminer, 730 B
    ("Antminer S21/Thu Jan 1", 44),   # S21, 2,250 B
    ("whatsminer/v1.1", 143),         # 6,500 B
    ("bosminer/1.0", 364),            # Braiins, 16 KB
    ("bitaxe/v2.10.0", 500),          # ESP-Miner <= 2.15, 22 KB
]
SLOT_CLASSES = [3, 9, 44, 143, 364, 500]
# The serialising miner's agent: cgminer with no model, so an unknown agent (smallest class).
SERIAL_AGENT = "cgminer/4.10"
# Plain blocks mined before any pool job: one, so the Bitcoin node leaves initial block download
# (regtest's genesis is from 2011). Pool blocks then start at height 2, through the OP_1..OP_16
# BIP34 heights, and through the first 20 blocks after the genesis anchor, whose shares are void
# (cut(H) is at or below genesis, so rule 6 has no snapshot anchor): jobs are still served there,
# and pool_sv2 says they earn nothing (NODE_POOL_VOID_WORK).
BOOTSTRAP_HEIGHT = 1
# The height the synthetic ledger export is taken at (its rows' queue_since).
EXPORT_HEIGHT = 1
# The first job height whose shares earn: genesis btc_height (0) + SNAPSHOT_CUT_LAG + 1.
FIRST_EARNING_HEIGHT = 21
# The snapshot cut lag, cut(H) = H - 20.
CUT_LAG = 20
# The installer's Reaper flags for ghostd (scripts/install-node.sh, REAPER_FLAGS).
REAPER_FLAGS = ["-ghostreaper=enabled", "-ghostreaper-rejectinscription=1",
                "-ghostreaper-rejectdropstuffing=1", "-ghostreaper-rejectfakepubkey=1",
                "-ghostreaper-rejectannex=1", "-ghostreaper-rejectopreturn=1",
                "-ghostreaper-rejectrunestone=1", "-ghostreaper-maxopreturn=82",
                "-ghostreaper-mindropsize=76"]

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


def b58check(version, payload):
    raw = bytes([version]) + payload
    raw += hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    n = int.from_bytes(raw, "big")
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def p2pkh_address(tag):
    """A regtest P2PKH address: a valid address the node pool refuses as a payee."""
    return b58check(0x6F, hashlib.sha256(tag.encode()).digest()[:20])


def payee(tag, taproot=False):
    """(address, script hex) for a deterministic payee on the run's network."""
    h = hashlib.sha256(tag.encode()).digest()
    if taproot:
        return segwit_address(HRP, 1, h), "5120" + h.hex()
    return segwit_address(HRP, 0, h[:20]), "0014" + h[:20].hex()


def configure_network(args):
    """Set the module's network values for --network (before scenarios import them)."""
    global NETWORK, HRP, TIER_BASE, GENESIS_ANCHOR, GENESIS_HEIGHT, SIGNET_CHALLENGE, HALVING
    global BOOTSTRAP_HEIGHT, FIRST_EARNING_HEIGHT, EXPORT_HEIGHT
    NETWORK = args.network
    if NETWORK == "regtest":
        return
    HRP = "tb"
    HALVING = 210_000
    TIER_BASE = SIGNET_TIER_BASE
    # The run's own signet: <32-byte network id> OP_DROP OP_TRUE. An empty block solution
    # satisfies it (signet.cpp: no solution, "to support OP_TRUE as trivial block challenge"), so
    # pool miners can find blocks: a challenge needing a signature cannot be pool-mined, since the
    # signature commits to the merkle root and so to every extranonce a miner rolls. The id makes
    # the network's message start, and so the network, the run's alone.
    net_id = hashlib.sha256(b"GhostNodePool/signet-harness/" + os.urandom(16)).digest()
    SIGNET_CHALLENGE = "20" + net_id.hex() + "7551"
    GENESIS_ANCHOR = hashlib.sha256(b"GhostNodePool/genesis/signet/" + net_id).hexdigest()
    GENESIS_HEIGHT = args.signet_genesis_height
    # The export is taken at the genesis anchor's height (the freeze), and plain blocks run 20
    # past it before any pool job, so the first pool job is at the first earning height: the
    # operational rule of plan Phase 4 (genesis anchor at least 20 blocks before miners are
    # repointed), rehearsed. No work is void.
    EXPORT_HEIGHT = GENESIS_HEIGHT
    BOOTSTRAP_HEIGHT = GENESIS_HEIGHT + CUT_LAG
    FIRST_EARNING_HEIGHT = GENESIS_HEIGHT + CUT_LAG + 1


def audit_chain_args():
    """ghost-audit's share-chain arguments for the run's network (its start and tier base)."""
    if NETWORK == "regtest":
        return ["--network", "regtest"]
    return ["--network", NETWORK, "--genesis-anchor", GENESIS_ANCHOR, "--genesis-height",
            str(GENESIS_HEIGHT), "--tier-base", TIER_BASE]


# ---------------------------------------------------------------------------------------------
def http_json(url, body=None, auth=None, timeout=30):
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
    req = urllib.request.Request(url, json.dumps(body).encode() if body is not None else None, headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except Exception:
            raise RuntimeError(f"{url}: HTTP {e.code}")


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


def logged(log, block_hash, phrase):
    """A line of `log` names both `block_hash` and `phrase`: a positive marker for that block."""
    return any(block_hash in line and phrase in line for line in log.splitlines())


def strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


class Proc:
    def __init__(self, name, argv, log, cwd=None, env=None):
        self.name, self.log = name, log
        out = open(log, "ab")
        self.p = subprocess.Popen(argv, stdout=out, stderr=out, cwd=cwd, start_new_session=True,
                                  env={**os.environ, **(env or {})})
        out.close()

    def alive(self):
        return self.p.poll() is None

    def terminate(self):
        """SIGTERM without waiting (a resumed group, so a paused miner can exit)."""
        if self.p.poll() is None:
            try:
                os.killpg(self.p.pid, signal.SIGCONT)
                os.killpg(self.p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def stop(self, grace=15):
        if self.p.poll() is not None:
            return
        try:
            os.killpg(self.p.pid, signal.SIGCONT)
            os.killpg(self.p.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            self.p.wait(grace)
        except subprocess.TimeoutExpired:
            say(f"  {self.name}: no exit {grace}s after SIGTERM; SIGKILL")
            try:
                os.killpg(self.p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.p.wait(10)

    def signal(self, sig):
        if self.alive():
            os.killpg(self.p.pid, sig)


class Node:
    """One node pool node: its own Bitcoin node, template provider, pool, translator, miners."""

    def __init__(self, h, idx):
        self.h, self.i = h, idx
        self.dir = os.path.join(h.work, f"node{idx}")
        os.makedirs(self.dir, exist_ok=True)
        b = h.args.base_port + 100 * idx
        self.p2p, self.rpc_port, self.zmq_block, self.zmq_tx = b, b + 1, b + 2, b + 3
        self.http, self.tdp = b + 10, b + 11
        self.pool, self.pool_mon, self.relay = b + 20, b + 21, b + 22
        self.sv1, self.tr_mon = b + 30, b + 31
        self.procs = {}
        self.fee_addr, self.fee_script = payee(f"node{idx}/fee")
        self.miners = []  # (user, address, script, agent, class)
        self.tdp_key = None
        self.node_id = None
        self.fault = None  # GHOST_NP_FAULT for a hostile node's pool_sv2
        self.sync_fault = None  # GHOST_NP_SYNC_FAULT for a lying sync peer's relay
        # The relay listens here: a loopback address of its own for a node whose relay must be
        # told apart by IP (a ban is per IP, and every node else shares 127.0.0.1).
        self.relay_ip = "127.0.0.1"
        self.relay_peers = []
        self.restarts = 0  # pool_sv2 restarts: its in-memory counters start again from 0
        self.miner_argv = {}  # miner process name -> argv, to start it again

    def log(self, name):
        return os.path.join(self.dir, name + ".log")

    def read_log(self, name):
        try:
            with open(self.log(name), errors="replace") as f:
                return strip_ansi(f.read())
        except FileNotFoundError:
            return ""

    # -- bitcoin ---------------------------------------------------------------------------
    def rpc(self, method, *params, timeout=60):
        out = http_json(f"http://127.0.0.1:{self.rpc_port}/",
                        {"jsonrpc": "1.0", "id": "h", "method": method, "params": list(params)},
                        auth=f"{RPC_USER}:{RPC_PASS}", timeout=timeout)
        if out.get("error"):
            raise RuntimeError(f"{method}: {out['error']}")
        return out["result"]

    def start_bitcoind(self, peers):
        d = os.path.join(self.dir, "bitcoin")
        os.makedirs(d, exist_ok=True)
        chain = ["regtest=1", "server=1", "[regtest]"] if NETWORK == "regtest" else [
            "signet=1", "server=1", "[signet]", f"signetchallenge={SIGNET_CHALLENGE}"]
        conf = chain + [
            f"rpcuser={RPC_USER}", f"rpcpassword={RPC_PASS}",
            f"rpcport={self.rpc_port}", "rpcbind=127.0.0.1", "rpcallowip=127.0.0.1",
            f"port={self.p2p}", "bind=127.0.0.1", "listen=1", "discover=0", "dnsseed=0",
            "fixedseeds=0", "listenonion=0", "fallbackfee=0.0002", "txindex=0",
            f"zmqpubhashblock=tcp://127.0.0.1:{self.zmq_block}",
            f"zmqpubhashtx=tcp://127.0.0.1:{self.zmq_tx}",
            # Must match NODE_POOL_BLOCK_RESERVED_WEIGHT, as the installer writes it.
            "blockreservedweight=90000", "dbcache=16", "maxmempool=50", "rpcworkqueue=64",
        ] + [f"addnode=127.0.0.1:{p}" for p in peers]
        with open(os.path.join(d, "bitcoin.conf"), "w") as f:
            f.write("\n".join(conf) + "\n")
        argv = [self.h.args.bitcoind, f"-datadir={d}"]
        if self.h.is_ghostd and self.h.args.reaper:
            argv += REAPER_FLAGS
        self.procs["bitcoind"] = Proc("bitcoind", argv, self.log("bitcoind"))
        wait_for(lambda: self.rpc("getblockcount") is not None, 60, what=f"node{self.i} bitcoind RPC")

    # -- ghost-mining ----------------------------------------------------------------------
    def start_ghost_mining(self):
        d = os.path.join(self.dir, "ghost")
        os.makedirs(os.path.join(d, "data"), exist_ok=True)
        # --seed-ghost-db / --seed-node-key: start this node on an old node's migrated database
        # and its node key (the flag-day rehearsal), once; a restart keeps what it has.
        seeds = [(self.h.args.seed_ghost_db, "ghost.db"), (self.h.args.seed_node_key, "node.key")]
        for files, name in seeds:
            if files and self.i < len(files) and not os.path.exists(os.path.join(d, name)):
                shutil.copy2(files[self.i], os.path.join(d, name))
                os.chmod(os.path.join(d, name), 0o600)
        self.api_secret = hashlib.sha256(f"secret{self.i}".encode()).hexdigest()
        cfg = f"""[identity]
key_path = "{d}/node.key"
display_name = "regtest-node{self.i}"

[bitcoin]
rpc_host = "127.0.0.1"
rpc_port = {self.rpc_port}
rpc_user = "{RPC_USER}"
rpc_password = "{RPC_PASS}"
network = "{NETWORK}"
zmq_hashblock = "tcp://127.0.0.1:{self.zmq_block}"
zmq_hashtx = "tcp://127.0.0.1:{self.zmq_tx}"

[network]
internal_api_secret = "{self.api_secret}"
signing_key = "{hashlib.sha256(f"sign{self.i}".encode()).hexdigest()}"
public_address = "127.0.0.1"
sv2_port = {self.pool}
sv1_port = {self.sv1}
http_port = {self.http}
max_miners = 100
farm_port = {self.sv1 + 5}

[policy]
profile = "full_open"

[storage]
db_path = "{d}/data"
wal_mode = true
archive_mode = false
prune_height = 0

[pool]

[reaper]
enabled = {"true" if self.h.is_ghostd and self.h.args.reaper else "false"}
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
    def relay_addr(self):
        return f"{self.relay_ip}:{self.relay}"

    def write_pool_config(self, relay_peers, pin=None):
        """relay_peers: relay addresses, `ip:port` (or bare ports on 127.0.0.1)."""
        d = os.path.join(self.dir, "pool")
        os.makedirs(d, exist_ok=True)
        self.relay_peers = [p if isinstance(p, str) else f"127.0.0.1:{p}" for p in relay_peers]
        peers = ", ".join(f'"{p}"' for p in self.relay_peers)
        a = self.h.args
        pin = f'genesis_table_digest = "{pin}"\n' if pin else ""
        cfg = f"""authority_public_key = "{POOL_PUB}"
authority_secret_key = "{POOL_SEC}"
cert_validity_sec = 3600
listen_address = "127.0.0.1:{self.pool}"
coinbase_reward_script = "addr({self.fee_addr})"
server_id = 1
pool_signature = "- G H O S T -"
shares_per_minute = 6.0
share_batch_size = 1
supported_extensions = [0x0002]
required_extensions = []
monitoring_address = "127.0.0.1:{self.pool_mon}"

[share_webhook]
url = "http://127.0.0.1:{self.http}/api/internal/shares"
secret = "{self.api_secret}"
batch_size = 1
batch_timeout_ms = 2000
max_retries = 3

[node_pool]
fee_address = "{self.fee_addr}"
ghost_pool_health_url = "http://127.0.0.1:{self.http}/health"
sensing_min_shares = {a.sensing_min_shares}

[node_pool.relay]
network = "{NETWORK}"
listen = "{self.relay_ip}:{self.relay}"
advertise_sv1_port = {self.sv1}
peers = [{peers}]
db_path = "{d}/node-pool.db"
genesis_anchor = "{GENESIS_ANCHOR}"
genesis_btc_height = {GENESIS_HEIGHT}
{pin}tier_base = "{TIER_BASE}"
rpc_host = "127.0.0.1"
rpc_port = {self.rpc_port}
rpc_user = "{RPC_USER}"
rpc_password = "{RPC_PASS}"

[template_provider_type.Sv2Tp]
address = "127.0.0.1:{self.tdp}"
public_key = "{self.tdp_key}"
"""
        with open(os.path.join(d, "pool-config.toml"), "w") as f:
            f.write(cfg)
        return d

    def import_genesis(self, relay_peers):
        """Import the run's genesis export into this node's store, verify it, and pin its root."""
        d = self.write_pool_config(relay_peers)
        exe = self.h.bin(self.h.args.pool_binary)
        base = [exe, "-c", os.path.join(d, "pool-config.toml"), "--np-import-genesis",
                self.h.export_dir, "--np-export-digest", self.h.export_digest]
        lines = []
        for extra in ([], ["--np-verify-genesis"]):
            out = subprocess.run(base + extra, capture_output=True, text=True, cwd=d, timeout=120,
                                 env={**os.environ, "NO_COLOR": "1"})
            text = strip_ansi(out.stdout + out.stderr)
            with open(self.log("genesis-import"), "a") as f:
                f.write(f"$ {' '.join(base + extra)}\n{text}\nexit {out.returncode}\n")
            line = next((l for l in text.splitlines() if "NODE_POOL_GENESIS_" in l), None)
            if out.returncode != 0 or not line:
                raise RuntimeError(f"node{self.i} genesis import failed (exit {out.returncode}): "
                                   + text.strip()[-300:])
            lines.append(line[line.index("NODE_POOL_GENESIS_"):])
        self.genesis_lines = lines
        root = re.search(r"table_root=([0-9a-f]{64})", lines[0]).group(1)
        self.write_pool_config(relay_peers, pin=root)
        return root

    def start_pool(self, relay_peers):
        if self.h.export_dir:
            self.genesis_root = self.import_genesis(relay_peers)
        else:
            self.write_pool_config(relay_peers)
        self.run_pool()

    def run_pool(self):
        """Start pool_sv2 on the config written last."""
        a = self.h.args
        d = os.path.join(self.dir, "pool")
        hostile = self.fault or self.sync_fault
        if hostile and not a.hostile_binary:
            raise RuntimeError("a hostile node needs --hostile-binary (np-fault-injection build)")
        binary = a.hostile_binary if hostile else self.h.bin(a.pool_binary)
        env = {"RUST_LOG": "info", "NO_COLOR": "1"}
        if self.fault:
            env["GHOST_NP_FAULT"] = self.fault
        if self.sync_fault:
            env["GHOST_NP_SYNC_FAULT"] = self.sync_fault
        self.procs["pool_sv2"] = Proc(
            "pool_sv2", [binary, "-c", os.path.join(d, "pool-config.toml")],
            self.log("pool_sv2"), cwd=d, env=env)
        wait_for(lambda: port_open(self.pool) and port_open(self.relay, self.relay_ip)
                 and port_open(self.pool_mon), 120, what=f"node{self.i} pool_sv2 listening")

    def restart_pool(self, relay_peers=None, wipe=False):
        """Stop pool_sv2 and start it again, on new relay peers if given. `wipe` deletes its
        share-chain store first and imports the genesis table again: a fresh node on the same
        Bitcoin node."""
        # The translator drops every SV1 miner when it loses its upstream, and cpu_miner.py does
        # not reconnect: the translator and the miners are started again too, paused.
        miners = [k for k in self.miner_procs() if k in self.miner_argv]
        for k in miners + ["translator", "pool_sv2"]:
            if k in self.procs:
                self.procs[k].stop()
        self.restarts += 1
        peers = self.relay_peers if relay_peers is None else relay_peers
        d = os.path.join(self.dir, "pool")
        if wipe:
            for f in os.listdir(d):
                if f.startswith("node-pool.db") or f == "miner-stats.json":
                    os.remove(os.path.join(d, f))
            if self.h.export_dir:
                self.genesis_root = self.import_genesis(peers)
            else:
                self.write_pool_config(peers)
        else:
            self.write_pool_config(peers, pin=getattr(self, "genesis_root", None))
        self.run_pool()
        if "translator" in self.procs:
            self.start_translator()
        for k in miners:
            self.procs[k] = Proc(k, self.miner_argv[k], self.log(k))
        self.pause_miners(True, only=miners)

    def start_translator(self):
        d = os.path.join(self.dir, "translator")
        os.makedirs(d, exist_ok=True)
        # As the installer writes it, except the difficulty floor: quantise_to_tiers floors SV1
        # difficulty at 2^10 (difficulty-1 units, about 2^42 hashes a share), out of a CPU's
        # reach, so regtest runs a fixed, tiny difficulty and the miner aims at the network tier.
        cfg = f"""downstream_address = "127.0.0.1"
downstream_port = {self.sv1}
max_supported_version = 2
min_supported_version = 2
downstream_extranonce2_size = 8
user_identity = "{self.fee_addr}"
aggregate_channels = false
open_channel_on_subscribe = {self.h.args.open_channel_on_subscribe}
supported_extensions = {self.h.args.translator_supported}
required_extensions = {self.h.args.translator_required}
monitoring_address = "127.0.0.1:{self.tr_mon}"

[downstream_difficulty_config]
min_individual_miner_hashrate = 50.0
shares_per_minute = 6.0
enable_vardiff = false
job_keepalive_interval_secs = 60
quantise_to_tiers = false

[[upstreams]]
address = "127.0.0.1"
port = {self.pool}
authority_pubkey = "{POOL_PUB}"
"""
        with open(os.path.join(d, "translator.toml"), "w") as f:
            f.write(cfg)
        self.procs["translator"] = Proc(
            "translator", [self.h.bin("translator_sv2"), "-c", os.path.join(d, "translator.toml")],
            self.log("translator"), cwd=d, env={"RUST_LOG": "info", "NO_COLOR": "1"})
        wait_for(lambda: port_open(self.sv1), 60, what=f"node{self.i} translator SV1 port")

    def start_miners(self, specs, pace, anchor_odds, name="miner"):
        """One cpu_miner.py process (`name`) mining for `specs`, (user, agent) pairs. A node
        may run several, paused and resumed apart (pause_miners)."""
        argv = [sys.executable, os.path.join(HERE, "cpu_miner.py"), "127.0.0.1", str(self.sv1),
                "--events", os.path.join(self.dir, "miner-events.jsonl"), "--pace", str(pace),
                "--anchor-odds", str(anchor_odds), "--tier-base", TIER_BASE,
                "--seed", str(1000 + 10 * self.i + len(self.miner_procs()))]
        if self.h.grinder:
            argv += ["--grinder", self.h.grinder]
        for user, agent in specs:
            argv += ["--miner", f"{user}@{agent}"]
        self.miner_argv[name] = argv
        self.procs[name] = Proc(name, argv, self.log(name))

    def miner_procs(self):
        return [n for n in self.procs if n.startswith("miner")]

    def start_sv2_device(self, user):
        dev = self.h.args.mining_device
        if not dev:
            return False
        self.procs["sv2-device"] = Proc(
            "sv2-device", [dev, "-a", f"127.0.0.1:{self.pool}", "--cores", "1", "--handicap",
                           str(self.h.args.sv2_handicap), "--id-user", user,
                           "--pubkey-pool", POOL_PUB],
            self.log("sv2-device"), env={"RUST_LOG": "info", "NO_COLOR": "1"})
        return True

    def pause_miners(self, paused, only=None):
        """Pause (SIGSTOP) or resume every miner process of this node, or only those named."""
        for n in self.miner_procs() + ["sv2-device"]:
            if n in self.procs and (only is None or n in only):
                self.procs[n].signal(signal.SIGSTOP if paused else signal.SIGCONT)

    def stop(self):
        for n in ["sv2-device"] + self.miner_procs() + ["translator", "pool_sv2", "ghost-mining",
                                                         "bitcoind"]:
            if n in self.procs:
                self.procs[n].stop()

    # -- readings --------------------------------------------------------------------------
    def status(self):
        return http_json(f"http://127.0.0.1:{self.pool_mon}/api/v1/node-pool/status", timeout=20)

    def ledger(self, address):
        return http_json(f"http://127.0.0.1:{self.pool_mon}/api/v1/node-pool/ledger/{address}",
                         timeout=20)

    def db(self):
        path = os.path.join(self.dir, "pool", "node-pool.db")
        return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)

    def digests(self):
        """Store readings every honest node must agree on once quiet."""
        c = self.db()
        try:
            ledger = sorted(c.execute("SELECT hex(script), hex(owed) FROM np_ledger"))
            retired = sorted(c.execute(
                "SELECT hex(block_hash), position, height, hex(script), hex(amount) FROM np_retirements"))
            blocks = sorted(c.execute(
                "SELECT height, hex(event_key) FROM np_ledger_events WHERE kind = 1"))
            # The best share chain only: a node that synced later never fetched dead-fork
            # anchors it did not need, and that is not a disagreement.
            parent = dict(c.execute("SELECT hex(hash), hex(parent) FROM np_anchors"))
            tip = self.status()["share_chain"]["tip"].upper()
            best = []
            while tip in parent:
                best.append(tip)
                tip = parent[tip]
            counts = dict(c.execute("SELECT hex(anchor_hash), share_count FROM np_batches"))
            anchors = len(best)
            batches = [(a, counts.get(a)) for a in best]
        finally:
            c.close()

        def d(x):
            return hashlib.sha256(json.dumps(x).encode()).hexdigest()[:16]
        return {"ledger": d(ledger), "ledger_rows": len(ledger), "retirements": d(retired),
                "retirement_rows": len(retired), "settled_blocks": d(blocks),
                "settled_block_count": len(blocks), "anchors": anchors, "batches": d(batches)}


class Harness:
    def __init__(self, args):
        self.args = args
        # A run's stores (and its genesis import, which runs once) belong to that run: a reused
        # work dir would start every node on the last run's state. Refuse one that is not empty.
        if args.workdir and os.path.isdir(args.workdir) and os.listdir(args.workdir):
            raise SystemExit(f"work dir {args.workdir} is not empty (a previous run's?); pass a new "
                             "one, or none for a fresh temporary dir")
        self.work = args.workdir or tempfile.mkdtemp(prefix="np-regtest-")
        os.makedirs(self.work, exist_ok=True)
        self.nodes = []
        self.retired = []  # nodes stopped and taken out of the run (retire())
        self.next_index = 0
        self.t0 = time.time()
        self.peak_rss = 0
        self.export_dir = self.export_digest = None
        out = subprocess.run([args.bitcoind, "-version"], capture_output=True, text=True).stdout
        self.node_version = (out.splitlines() or ["unknown version"])[0]
        self.is_ghostd = "Ghost Core" in out
        self.genesis = {}  # script hex -> whole sats owed at genesis (payable part)
        self.genesis_face = {}  # script hex -> face units (2^-32 sat) owed at genesis, exact
        self.genesis_addr = {}  # script hex -> address
        self.grinder = self.build_grinder() if args.network != "regtest" else None
        if args.genesis_export:
            self.use_export(args.genesis_export, args.genesis_export_digest)
        elif args.genesis_rows:
            self.make_export(args.genesis_rows)

    def use_export(self, src, digest):
        """A real ledger export (`ghost-mining --np-export` on the old release) instead of the
        synthetic one: copied into the work dir as published, read for the reference's balances
        (face units, so fractional sats are kept), and imported by every node with `digest`."""
        self.export_dir = os.path.join(self.work, "export")
        os.makedirs(self.export_dir, exist_ok=True)
        for name in os.listdir(src):
            shutil.copy2(os.path.join(src, name), self.export_dir)
        with open(os.path.join(self.export_dir, "ledger-export.json")) as f:
            j = json.load(f)
        if j["network"] != NETWORK:
            raise SystemExit(f"--genesis-export is a {j['network']} export; this run is {NETWORK}")
        if j["checkpoint"]["height"] != EXPORT_HEIGHT:
            raise SystemExit(f"--genesis-export is at height {j['checkpoint']['height']}, the run's "
                             f"export height is {EXPORT_HEIGHT}")
        for row in j["genesis_table"]:
            face = int(row["face_units"])
            self.genesis_face[row["script_hex"]] = face
            self.genesis[row["script_hex"]] = face >> 32
        for m in j.get("miners", []):
            self.genesis_addr.setdefault(m["script_hex"], m["address"])
        missing = [s for s in self.genesis if s not in self.genesis_addr]
        if missing:
            raise SystemExit(f"--genesis-export: {len(missing)} genesis rows have no address in "
                             "`miners`")
        self.export_digest = digest
        say(f"genesis export {src}: {len(self.genesis)} rows, digest {self.export_digest[:16]}.., "
            f"height {EXPORT_HEIGHT}")

    def build_grinder(self):
        """grind.c built into the work dir for the miners (signet's blocks need ~4.8M hashes).
        None, and a pure-Python search, if it does not build."""
        out = os.path.join(self.work, "grind.so")
        r = subprocess.run(["cc", "-O2", "-shared", "-fPIC", os.path.join(HERE, "grind.c"),
                            "-lcrypto", "-o", out], capture_output=True, text=True)
        if r.returncode != 0:
            say(f"  grind.c did not build ({r.stderr.strip()[-200:]}); the miners search in Python")
            return None
        return out

    def make_export(self, rows):
        """A synthetic ledger export in GhostLedgerExport/v1, the format `pool_sv2
        --np-import-genesis` reads (the real exporter is ghost-mining --np-export on main):
        `rows` balances, the last 40 below the 1,000-sat floor."""
        table = {}
        for i in range(rows):
            sats = 400 if i >= rows - 40 else 1_000 + (i * 7_919) % 99_000
            addr, script = payee(f"genesis/{i}", taproot=i % 2 == 1)
            table[script] = sats
            self.genesis_addr[script] = addr
        self.genesis = table
        self.genesis_face = {s: v << 32 for s, v in table.items()}
        ordered = sorted(table.items(), key=lambda kv: bytes.fromhex(kv[0]))
        net = NETWORK.encode()
        body = b"GhostLedgerExport/v1" + len(net).to_bytes(2, "big") + net
        body += EXPORT_HEIGHT.to_bytes(8, "big")
        body += len(ordered).to_bytes(4, "big")
        for script, sats in ordered:
            sb = bytes.fromhex(script)
            body += len(sb).to_bytes(2, "big") + sb + (sats << 32).to_bytes(16, "big")
        body += bytes(96)  # the totals block; the import reads the rows before it, not it
        digest = hashlib.sha256(body).hexdigest()
        self.export_dir = os.path.join(self.work, "export")
        os.makedirs(self.export_dir, exist_ok=True)
        with open(os.path.join(self.export_dir, "ledger-export.bin"), "wb") as f:
            f.write(body)
        with open(os.path.join(self.export_dir, "ledger-export.json"), "w") as f:
            json.dump({"digest_sha256": digest, "network": NETWORK,
                       "genesis_table": [{"script_hex": s, "face_units": str(v << 32)}
                                         for s, v in ordered]}, f)
        self.export_digest = digest

    def bin(self, name):
        p = os.path.join(self.args.bin_dir, name)
        if not os.access(p, os.X_OK):
            raise SystemExit(f"missing binary {p}; build it first (see run.sh --help)")
        return p

    def rss_mb(self):
        total = 0
        for n in self.all_nodes():
            for p in n.procs.values():
                if not p.alive():
                    continue
                for pid in [p.p.pid] + self.children(p.p.pid):
                    try:
                        with open(f"/proc/{pid}/status") as f:
                            m = re.search(r"VmRSS:\s+(\d+)", f.read())
                            total += int(m.group(1)) if m else 0
                    except OSError:
                        pass
        self.peak_rss = max(self.peak_rss, total // 1024)
        return total // 1024

    def rss_by_process(self):
        """Resident set size in KB of every live process of the run, with its children, keyed
        `node<i>/<name>`."""
        out = {}
        for n in self.all_nodes():
            for name, p in n.procs.items():
                if not p.alive():
                    continue
                kb = 0
                for pid in [p.p.pid] + self.children(p.p.pid):
                    try:
                        with open(f"/proc/{pid}/status") as f:
                            m = re.search(r"VmRSS:\s+(\d+)", f.read())
                            kb += int(m.group(1)) if m else 0
                    except OSError:
                        pass
                out[f"node{n.i}/{name}"] = kb
        return out

    @staticmethod
    def children(pid):
        try:
            out = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout
            return [int(x) for x in out.split()]
        except Exception:
            return []

    # -- bring-up --------------------------------------------------------------------------
    def honest(self):
        return [n for n in self.nodes if not n.fault and not n.sync_fault and "pool_sv2" in n.procs
                and n.procs["pool_sv2"].alive()]

    def retire(self, n):
        """Stop node n and take it out of the run's node list (its ports and directory are
        never reused); teardown still checks it."""
        n.stop()
        if n in self.nodes:
            self.nodes.remove(n)
            self.retired.append(n)

    def all_nodes(self):
        return self.nodes + self.retired

    def add_node(self, mine=True, fault=None, agents=None, anchor_odds=None, sync_fault=None,
                 relay_ip="127.0.0.1", peers=None):
        """A node peered with every node so far (or only with `peers`, nodes, for its relay)."""
        i = self.next_index
        self.next_index += 1
        n = Node(self, i)
        n.fault = fault
        n.sync_fault = sync_fault
        n.relay_ip = relay_ip
        others = [m for m in self.nodes]
        n.start_bitcoind([m.p2p for m in others])
        self.nodes.append(n)
        if i == 0 and n.rpc("getblockcount") == 0:
            # Leave initial block download (regtest's genesis is from 2011, signet's from 2020);
            # see BOOTSTRAP_HEIGHT. On signet these are the plain blocks below the genesis anchor.
            self.generate(n, BOOTSTRAP_HEIGHT)
        # Synced to node0's tip as it was, or past it: earlier nodes' miners keep mining.
        h0 = self.nodes[0].rpc("getblockcount")
        tip = self.nodes[0].rpc("getblockhash", h0)
        wait_for(lambda: n.rpc("getblockcount") >= h0 and n.rpc("getblockhash", h0) == tip, 120,
                 what=f"node{i} Bitcoin sync")
        n.start_ghost_mining()
        n.start_pool([m.relay_addr() for m in (others if peers is None else peers)])
        n.start_translator()
        if mine:
            specs = []
            picks = agents or [AGENTS[(i * self.args.miners_per_node + k) % len(AGENTS)]
                               for k in range(self.args.miners_per_node)]
            for k, (agent, cls) in enumerate(picks):
                taproot = k % 2 == 1
                addr, script = payee(f"node{i}/miner{k}", taproot)
                user = f"{addr}.w{k}"
                n.miners.append((user, addr, script, agent, cls))
                specs.append((user, agent))
            if i == 0 and not agents and self.args.serial_miner:
                # A cgminer-style miner: authorize only after its subscribe is answered, so the
                # translator opens its channel on subscribe and binds the payee on authorize.
                # It authorises as its bare payout address (finding G).
                addr, script = payee("node0/serial", False)
                n.miners.append((f"{addr}.default", addr, script, SERIAL_AGENT, 3))
                specs.append((addr, SERIAL_AGENT + "@serial"))
            n.start_miners(specs, self.args.pace,
                           self.args.anchor_odds if anchor_odds is None else anchor_odds)
        say(f"  node{i}: bitcoind :{n.rpc_port}  ghost-mining tdp :{n.tdp}  pool_sv2 :{n.pool} "
            f"relay :{n.relay} api :{n.pool_mon}  sv1 :{n.sv1}  miners {len(n.miners)}")
        return n

    def generate(self, n, count, tag="bootstrap"):
        """Plain (non-pool) blocks from n's own ghostd, one call each. Signet's minimum
        difficulty takes a few million hashes, past generatetoaddress's default of 1M tries."""
        addr = payee(tag)[0]
        out = []
        for _ in range(count):
            got = []
            while not got:
                got = n.rpc("generatetoaddress", 1, addr, 1 << 30, timeout=600)
            out += got
        return out

    def teardown(self):
        # Miners and proxies first, so nothing reconnects; then everything else at once.
        first = [p for n in self.all_nodes() for k, p in n.procs.items()
                 if k == "sv2-device" or k.startswith("miner")]
        procs = first + [p for n in self.all_nodes() for p in n.procs.values() if p not in first]
        for p in procs:
            p.terminate()
        for p in procs:
            p.stop()

    def leftovers(self):
        """Processes still running from this run's work dir, other than the harness itself."""
        me, mine = os.getpid(), set()
        p = me
        while p > 1:
            mine.add(p)
            try:
                with open(f"/proc/{p}/stat") as f:
                    p = int(f.read().rsplit(")", 1)[1].split()[1])
            except OSError:
                break
        out = subprocess.run(["pgrep", "-af", self.work], capture_output=True, text=True).stdout
        # Inside the work dir only: a path that merely starts with its name (a log beside it,
        # say) is someone else's.
        left = [l for l in out.splitlines()
                if l.strip() and int(l.split()[0]) not in mine and "pgrep" not in l
                and re.search(re.escape(self.work) + r"(/|\s|$)", l)]
        # And every process started, by pid (the SV2 device's command line names no path here).
        for n in self.all_nodes():
            for name, p in n.procs.items():
                try:
                    os.killpg(p.p.pid, 0)  # its process group still has a member
                    left.append(f"process group {p.p.pid} node{n.i}/{name}")
                except ProcessLookupError:
                    pass
        return left

    # -- chain readings --------------------------------------------------------------------
    def pool_blocks(self, node):
        """Every pool block on node's best chain: (height, hash, coinbase vouts)."""
        tip = node.rpc("getblockcount")
        out = []
        for h in range(1, tip + 1):
            bh = node.rpc("getblockhash", h)
            blk = node.rpc("getblock", bh, 2)
            cb = blk["tx"][0]
            vouts = [(round(v["value"] * COIN), v["scriptPubKey"]["hex"]) for v in cb["vout"]]
            if any(s.startswith("6a24" + LEDGER_MAGIC) for _, s in vouts):
                out.append((h, bh, vouts))
        return out

    def quiesce(self, timeout=180, nodes=None):
        """Wait until every node (every honest node, or `nodes`) sees the same Bitcoin tip, the
        same share-chain tip, and settlement has caught up to it."""
        nodes = self.honest() if nodes is None else nodes

        def same():
            tips = {n.rpc("getbestblockhash") for n in nodes}
            if len(tips) != 1:
                return False
            height = nodes[0].rpc("getblockcount")
            st = [n.status() for n in nodes]
            anchors = {s["share_chain"]["tip"] for s in st}
            settled = all(s["settlement"]["caught_up"] and s["settlement"]["synced_height"] == height
                          for s in st)
            unseen = sum(s["share_chain"]["unseen_anchors"] for s in st)
            return len(anchors) == 1 and settled and unseen == 0 and (height, anchors.pop()[:16])
        return wait_for(same, timeout, step=2, what="nodes to agree")


# ---------------------------------------------------------------------------------------------
def subsidy(h):
    """The run's network's block subsidy at height h."""
    return 0 if h // HALVING >= 64 else (50 * COIN) >> (h // HALVING)


def check_coinbase(h, vouts, payee_scripts, fee_scripts):
    """Problems with one pool block's coinbase against the layout rule, [] when exact."""
    errs = []
    s = subsidy(h)
    if not vouts or vouts[0][1] != TREASURY_SCRIPT:
        errs.append("first output is not the treasury")
        return errs
    if vouts[-1][1][:12] != WITNESS_PREFIX:
        errs.append("last output is not the witness commitment")
    if not vouts[-2][1].startswith("6a24" + LEDGER_MAGIC):
        errs.append("second-to-last output is not the GHNP ledger commitment")
    body = vouts[1:-2]
    finder = 0
    if body and body[-1][1] in fee_scripts and body[-1][1] not in payee_scripts:
        finder = body[-1][0]
        body = body[:-1]
    treasury = vouts[0][0]
    miners = sum(v for v, _ in body)
    total = sum(v for v, _ in vouts)
    if treasury + miners != s:
        errs.append(f"treasury {treasury} + miners {miners} != subsidy {s}")
    if treasury < s // 200:
        errs.append(f"treasury {treasury} below S/200 {s // 200}")
    if finder != total - s:
        errs.append(f"finder {finder} != fees {total - s}")
    for v, sc in body:
        if sc not in payee_scripts:
            errs.append(f"miner output to unknown script {sc}")
        if v < 1000:
            errs.append(f"miner output {v} below 1,000 sats")
    return errs


def run(args):
    busy = [p for p in range(args.base_port, args.base_port + 100 * (args.nodes + 1 + len(args.faults)))
            if p % 100 < 40 and port_open(p)]
    if busy:
        raise SystemExit(f"ports already in use (another run?): {busy[:8]}; pass --base-port")
    h = Harness(args)
    say(f"work dir: {h.work}")
    say(f"bitcoin node: {args.bitcoind} ({h.node_version}); Reaper "
        f"{'on' if h.is_ghostd and args.reaper else 'off'}")
    interrupted = False

    def on_signal(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")
    signal.signal(signal.SIGTERM, on_signal)
    try:
        scenarios(h)
    except KeyboardInterrupt as e:
        interrupted = True
        result("harness", "FAIL", f"interrupted: {e}")
    except Exception as e:  # noqa: BLE001 - a crash is a FAIL with its evidence
        import traceback
        result("harness", "FAIL", traceback.format_exc().splitlines()[-6:])
    finally:
        say("\n== teardown")
        t = time.time()
        h.teardown()
        left = h.leftovers()
        busy = [p for n in h.all_nodes() for p in (n.p2p, n.rpc_port, n.pool, n.sv1, n.tdp, n.http)
                if port_open(p)] + [n.relay for n in h.all_nodes() if port_open(n.relay, n.relay_ip)]
        if left or busy:
            result("teardown", "FAIL", [f"left running: {l}" for l in left] + [f"port still open: {p}" for p in busy])
        else:
            result("teardown", "PASS", f"{sum(len(n.procs) for n in h.all_nodes())} processes stopped in "
                   f"{time.time() - t:.1f}s; none left matching {h.work}; every port closed")
    say("\n== summary")
    for name, verdict, _ in RESULTS:
        say(f"  {verdict:10} {name}")
    say(f"runtime {time.time() - h.t0:.0f}s; peak RSS of the harness's processes {h.peak_rss} MB")
    if not args.keep and not interrupted and all(v != "FAIL" for _, v, _ in RESULTS):
        shutil.rmtree(h.work, ignore_errors=True)
    else:
        say(f"logs kept in {h.work}")
    return 1 if any(v == "FAIL" for _, v, _ in RESULTS) else 0


def scenarios(h):
    if h.args.network == "signet":
        from scenarios_signet import ALL, SOAK  # noqa: E402 - kept in its own file
        if h.args.soak_minutes:
            ALL = SOAK
    else:
        from scenarios import ALL  # noqa: E402 - kept in its own file
    for sc in ALL:
        if h.args.only and sc.__name__ not in h.args.only:
            continue
        sc(h)


def find_ghostd(cache):
    """The newest released ghostd run.sh --fetch-ghostd verified and cached, else ghostd on PATH,
    else the installer's /opt/ghost/bin/ghostd."""
    if cache and os.path.isdir(cache):
        def version(d):
            return tuple(int(x) for x in re.findall(r"\d+", d))
        for d in sorted((d for d in os.listdir(cache) if d.startswith("ghostd-v")), key=version,
                        reverse=True):
            p = os.path.join(cache, d, "ghostd")
            if os.access(p, os.X_OK):
                return p
    for p in (shutil.which("ghostd"), "/opt/ghost/bin/ghostd"):
        if p and os.access(p, os.X_OK):
            return p
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--network", choices=["regtest", "signet"], default="regtest",
                    help="regtest, or a custom signet of the run's own (scenarios_signet.py)")
    ap.add_argument("--signet-genesis-height", type=int, default=30,
                    help="signet: plain blocks mined first; the genesis anchor and export height")
    ap.add_argument("--nodes", type=int, default=None, help="default 3 (regtest), 4 (signet)")
    ap.add_argument("--miners-per-node", type=int, default=2)
    ap.add_argument("--bitcoind", default=os.environ.get("BITCOIND") or os.environ.get("GHOSTD"),
                    help="the Bitcoin node binary (default: ghostd; see run.sh)")
    ap.add_argument("--ghostd-cache", help="where run.sh --fetch-ghostd keeps released ghostds")
    ap.add_argument("--no-reaper", dest="reaper", action="store_false",
                    help="run ghostd and ghost-mining without the Reaper (the installer's default is on)")
    ap.add_argument("--bin-dir", default=os.path.join(REPO, "target", "debug"))
    ap.add_argument("--pool-binary", default="pool_sv2")
    ap.add_argument("--mining-device", default=os.environ.get("MINING_DEVICE"),
                    help="SV2 mining_device binary for a standard channel on node 0 (optional)")
    ap.add_argument("--sv2-handicap", type=int, default=20000)
    ap.add_argument("--workdir")
    ap.add_argument("--keep", action="store_true", help="keep the work dir even on success")
    ap.add_argument("--base-port", type=int, default=21000)
    ap.add_argument("--pace", type=float, default=8.0, help="mean seconds between a miner's shares")
    ap.add_argument("--signet-blocks", type=int, default=90,
                    help="signet: Bitcoin blocks to mine in the main mining phase")
    ap.add_argument("--reorg-depth", type=int, default=4,
                    help="signet: blocks the reorg scenario takes off the best chain, at least")
    ap.add_argument("--anchor-odds", type=float, default=0.35)
    ap.add_argument("--sensing-min-shares", type=int, default=None,
                    help="valid shares before a class step; default 2 (regtest), 1 (signet: every "
                         "share is a block, and the climb must fit in genesis-only snapshots)")
    ap.add_argument("--mine-to", type=int, default=110, help="Bitcoin height to mine to first")
    ap.add_argument("--no-serial-miner", dest="serial_miner", action="store_false",
                    help="leave out node0's cgminer-style (serialising) miner")
    ap.add_argument("--translator-required", default="[0x0002, 0x4748]")
    ap.add_argument("--translator-supported", default="[]")
    ap.add_argument("--open-channel-on-subscribe", choices=["true", "false"], default="true",
                    help="translator setting; the installer writes true")
    ap.add_argument("--mine-timeout", type=float, default=900)
    ap.add_argument("--sync-timeout", type=float, default=300)
    ap.add_argument("--audit-jobs", type=int, default=2)
    ap.add_argument("--hostile-binary", default=os.environ.get("HOSTILE_POOL_SV2"),
                    help="pool_sv2 built with --features np-fault-injection, for the hostile node")
    ap.add_argument("--genesis-rows", type=int, default=1200,
                    help="rows of the synthetic genesis export every node imports (0: none)")
    ap.add_argument("--genesis-export", metavar="DIR",
                    help="import this real ledger export (ghost-mining --np-export) instead of the "
                         "synthetic one; signet: its height becomes the genesis height")
    ap.add_argument("--genesis-export-digest", metavar="HEX",
                    help="the export's published digest (sha256 of ledger-export.bin); required "
                         "with --genesis-export")
    ap.add_argument("--seed-ghost-db", nargs="*", metavar="FILE",
                    help="node i starts ghost-mining on a copy of FILE[i] as its ghost.db (an old "
                         "node's database, migrated by v65 on first open)")
    ap.add_argument("--seed-node-key", nargs="*", metavar="FILE",
                    help="node i uses a copy of FILE[i] as its ghost-mining node.key (the old "
                         "node's key, so its database's addresses decrypt)")
    ap.add_argument("--faults", nargs="*", default=None,
                    help="hostile builds (node_pool_fault.rs); default wrong-treasury fee-skim "
                         "(regtest), and payee-order no-root overpay as well (signet)")
    ap.add_argument("--hostile-blocks", type=int, default=3)
    ap.add_argument("--past-halving", action="store_true",
                    help="finally mine past regtest's first halving (150) and report what happens")
    ap.add_argument("--only", nargs="*", help="scenario function names to run")
    ap.add_argument("--stall-wait", type=float, default=600,
                    help="slot classes: seconds to wait, miners paused, for a class to be suspended "
                         "by the no-share timeout before resuming them")
    ap.add_argument("--partition-blocks", type=int, default=30,
                    help="signet: Bitcoin blocks mined while the relay network is split in two "
                         "(more than the 20-block snapshot cut)")
    ap.add_argument("--heal-blocks", type=int, default=16,
                    help="signet: Bitcoin blocks mined after the split heals, so the losing side's "
                         "shares can be re-included")
    ap.add_argument("--sync-faults", nargs="*", default=["balances", "stamps", "truncate"],
                    help="signet: lies the lying sync peer tells (ghost-np-relay fault.rs)")
    ap.add_argument("--liar-alone-secs", type=float, default=75,
                    help="signet: how long a fresh node syncs from the lying peer alone")
    ap.add_argument("--soak-minutes", type=float, default=0,
                    help="signet: run the soak instead of the scenario list: N minutes of mining "
                         "with miners joining, leaving and stalling, then the checks")
    ap.add_argument("--soak-pace", type=float, default=45.0,
                    help="signet soak: mean seconds between one miner's shares")
    ap.add_argument("--soak-stall-secs", type=float, default=1500,
                    help="signet soak: how long a stalled miner stays silent (past its no-share "
                         "timeout at the soak pace)")
    args = ap.parse_args()
    signet = args.network == "signet"
    if args.nodes is None:
        args.nodes = 4 if signet else 3
    if args.sensing_min_shares is None:
        args.sensing_min_shares = 1 if signet else 2
    if args.soak_minutes:
        if not signet:
            raise SystemExit("--soak-minutes runs on --network signet")
        args.pace = args.soak_pace
    if args.faults is None:
        args.faults = ["wrong-treasury", "fee-skim"] + (
            ["payee-order", "no-root", "overpay"] if signet else [])
    if args.genesis_export:
        if not args.genesis_export_digest:
            raise SystemExit("--genesis-export needs --genesis-export-digest (the published digest)")
        with open(os.path.join(args.genesis_export, "ledger-export.json")) as f:
            export_height = json.load(f)["checkpoint"]["height"]
        if signet:
            # The freeze: the export's height is the genesis anchor's (plan Phase 4).
            args.signet_genesis_height = export_height
    configure_network(args)
    args.bitcoind = args.bitcoind or find_ghostd(args.ghostd_cache)
    if not args.bitcoind:
        raise SystemExit("no ghostd: run `run.sh --fetch-ghostd`, put ghostd on PATH, or pass "
                         "--bitcoind (BITCOIND=/GHOSTD=)")
    sys.path.insert(0, HERE)
    # scenarios.py imports this file as `harness`: make that this very module, so its results
    # land in the same RESULTS list.
    sys.modules.setdefault("harness", sys.modules[__name__])
    sys.exit(run(args))


if __name__ == "__main__":
    main()
