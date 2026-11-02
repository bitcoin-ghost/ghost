#!/usr/bin/env python3
"""SV1 CPU miner for the node pool regtest harness.

One process runs several miners (threads), each its own stratum connection with its own
username (payout address + worker) and user agent, so one process per node is enough. A miner
spec ending `@serial` behaves like cgminer: it sends mining.authorize only once its
mining.subscribe has been answered (the translator answers it from a channel opened on
subscribe); every other miner pipelines subscribe and authorize, as AxeOS does.

On regtest every hash below the proof-of-work limit's half is a Bitcoin block, and the node
pool's network tier T_net (tier base = regtest's limit, floor tier 10) sits 2^10 below it, so
any share that reaches T_net is also a block. A miner here therefore submits only hashes that
meet the network tier (or, with probability --anchor-odds, the anchor tier T_net + 8), and then
sleeps --pace seconds, so the block rate is set by the harness and not by the CPU.

On the harness's signet the tier base is set so that the network tier is easier than a block and
the anchor tier harder (harness.py, SIGNET_TIER_BASE): a miner aims at the easier of the network
tier and the job's own block target, so again every share it submits is a Bitcoin block, and
pool_sv2 (whose channel floor, difficulty 2^10, is out of a CPU's reach) accepts it as one.
Signet's minimum difficulty is about 4.8M hashes, so --grinder names grind.so (grind.c, built by
the harness) to search nonces natively; without it the search is pure Python.

Writes one JSON event per line to --events. Pause and resume with SIGSTOP / SIGCONT.

Usage: cpu_miner.py HOST PORT --miner USER@AGENT [--miner ...] --events FILE
                    [--pace S] [--anchor-odds P] [--tier-base HEX] [--t-net N]
"""
import argparse
import binascii
import hashlib
import json
import queue
import random
import socket
import struct
import sys
import threading
import time

ap = argparse.ArgumentParser()
ap.add_argument("host")
ap.add_argument("port", type=int)
ap.add_argument("--miner", action="append", required=True, help="USER@AGENT[@serial]")
ap.add_argument("--events", required=True)
ap.add_argument("--pace", type=float, default=6.0, help="mean seconds between submits, per miner")
ap.add_argument("--anchor-odds", type=float, default=0.3)
ap.add_argument("--tier-base", default="7fffff" + "00" * 29)
ap.add_argument("--t-net", type=int, default=10)
ap.add_argument("--anchor-offset", type=int, default=8)
ap.add_argument("--seed", type=int, default=None)
ap.add_argument("--grinder", help="grind.so (grind.c) for a native nonce search")
ARGS = ap.parse_args()

BASE = int(ARGS.tier_base, 16)
NS_TARGET = BASE >> ARGS.t_net
ANCHOR_TARGET = BASE >> (ARGS.t_net + ARGS.anchor_offset)
LOG = open(ARGS.events, "a", buffering=1)
LOG_LOCK = threading.Lock()
RNG = random.Random(ARGS.seed)
GRIND = None
if ARGS.grinder:
    import ctypes
    GRIND = ctypes.CDLL(ARGS.grinder).grind
    GRIND.restype = ctypes.c_int64
    GRIND.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32]
# Nonces per native call, between checks for a newer job.
GRIND_CHUNK = 1 << 21


def bits_target(nbits):
    """The target a compact nBits encodes."""
    exp, mant = nbits >> 24, nbits & 0x007FFFFF
    return mant << (8 * (exp - 3)) if exp >= 3 else mant >> (8 * (3 - exp))


def emit(miner, kind, **kw):
    with LOG_LOCK:
        LOG.write(json.dumps({"t": time.time(), "miner": miner, "ev": kind, **kw}) + "\n")


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def u32le(x):
    return struct.pack("<I", x)


def varint(b, p):
    f = b[p]
    if f < 0xFD:
        return f, p + 1
    if f == 0xFD:
        return struct.unpack_from("<H", b, p + 1)[0], p + 3
    if f == 0xFE:
        return struct.unpack_from("<I", b, p + 1)[0], p + 5
    return struct.unpack_from("<Q", b, p + 1)[0], p + 9


def count_outputs(coinbase):
    """(outputs, value) of a non-witness coinbase."""
    p = 4
    n, p = varint(coinbase, p)
    p += 36
    sl, p = varint(coinbase, p)
    p += sl + 4
    n, p = varint(coinbase, p)
    total = 0
    for _ in range(n):
        total += struct.unpack_from("<Q", coinbase, p)[0]
        p += 8
        sl, p = varint(coinbase, p)
        p += sl
    return n, total


class Miner(threading.Thread):
    def __init__(self, spec):
        super().__init__(daemon=True)
        self.user, _, self.agent = spec.partition("@")
        self.serial = self.agent.endswith("@serial")
        if self.serial:
            self.agent = self.agent[: -len("@serial")]
        self.subscribed = threading.Event()
        self.name_ = self.user.split(".", 1)[-1]
        self.rid = 1
        self.en1, self.en2sz, self.diff = "", 4, 1.0
        self.jobs = queue.Queue()
        self.sent = {}
        self.sock = None

    def send(self, method, params):
        msg = {"id": self.rid, "method": method, "params": params}
        self.rid += 1
        self.sock.sendall((json.dumps(msg) + "\n").encode())
        return msg["id"]

    def reader(self):
        buf = b""
        while True:
            try:
                data = self.sock.recv(1 << 20)
            except OSError:
                data = b""
            if not data:
                emit(self.user, "disconnect")
                self.jobs.put(None)
                return
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    try:
                        self.on_line(json.loads(line))
                    except Exception as e:  # a bad line is evidence, not a crash
                        emit(self.user, "bad_line", error=str(e))

    def on_line(self, msg):
        method = msg.get("method")
        if msg.get("id") == 1 and msg.get("result"):
            self.en1, self.en2sz = msg["result"][1], msg["result"][2]
            emit(self.user, "subscribed", en1=self.en1, en2sz=self.en2sz)
            self.subscribed.set()
        elif method == "mining.set_extranonce":
            self.en1, self.en2sz = msg["params"][0], msg["params"][1]
        elif method == "mining.set_difficulty":
            self.diff = msg["params"][0]
            emit(self.user, "difficulty", diff=self.diff)
        elif method == "mining.notify":
            p = msg["params"]
            placeholder = "00" * (len(self.en1) // 2 + self.en2sz)
            try:
                outs, value = count_outputs(binascii.unhexlify(p[2] + placeholder + p[3]))
            except Exception:
                outs, value = -1, -1
            emit(self.user, "notify", job=p[0], outputs=outs, value=value, clean=p[8])
            self.jobs.put(p)
        elif msg.get("id") == 2:
            emit(self.user, "authorized", ok=msg.get("result") is True, error=msg.get("error"))
        elif isinstance(msg.get("id"), int) and msg["id"] in self.sent:
            shared = self.sent.pop(msg["id"])
            emit(self.user, "submit_result", ok=msg.get("result") is True,
                 error=msg.get("error"), **shared)

    def mine_job(self, job, want_anchor):
        job_id, prev, cb1, cb2, branch, ver, nbits, ntime, _ = job
        pv = b"".join(u32le(int(prev[i:i + 8], 16)) for i in range(0, 64, 8))
        head = u32le(int(ver, 16)) + pv
        tail = u32le(int(ntime, 16)) + u32le(int(nbits, 16))
        # Not the pool's share target: pool_sv2 floors every channel at difficulty 2^10 (about
        # 2^42 hashes a share), out of a CPU's reach. A hash that meets the job's block target is
        # a Bitcoin block, and a block is accepted whatever the channel target; so never aim
        # easier than a block (on regtest the network tier is already harder than one).
        block = bits_target(int(nbits, 16))
        target = min(ANCHOR_TARGET if want_anchor else NS_TARGET, block)
        en2_start = RNG.getrandbits(24)
        for en2 in range(en2_start, en2_start + 0x10000):
            en2h = struct.pack("<I", en2 & 0xFFFFFFFF).hex().ljust(self.en2sz * 2, "0")[:self.en2sz * 2]
            root = dsha(binascii.unhexlify(cb1 + self.en1 + en2h + cb2))
            for b in branch:
                root = dsha(root + binascii.unhexlify(b))
            if GRIND is not None:
                found = self.grind(job_id, head + root + tail, target, en2h, ntime)
                if found is not None:
                    return found
                continue
            mid = hashlib.sha256(head + root[:28])
            rest = root[28:] + tail
            for nonce in range(0x100000):
                if nonce & 0xFFF == 0 and not self.jobs.empty():
                    return False
                h = mid.copy()
                h.update(rest + u32le(nonce))
                digest = hashlib.sha256(h.digest()).digest()
                value = int.from_bytes(digest, "little")
                if value <= target:
                    self.sent[self.rid] = {"job": job_id, "hash": digest[::-1].hex(),
                                           "ns": value <= NS_TARGET, "anchor": value <= ANCHOR_TARGET}
                    self.send("mining.submit", [self.user, job_id, en2h, ntime, f"{nonce:08x}"])
                    emit(self.user, "share", job=job_id, hash=digest[::-1].hex(),
                         ns=value <= NS_TARGET, anchor=value <= ANCHOR_TARGET)
                    return True
        return False

    def grind(self, job_id, header76, target, en2h, ntime):
        """Native nonce search over the whole nonce space of one extranonce2. True on a submit,
        False when a newer job arrived, None when the space is exhausted."""
        tbe = target.to_bytes(32, "big")
        for start in range(0, 1 << 32, GRIND_CHUNK):
            if not self.jobs.empty():
                return False
            nonce = GRIND(header76, tbe, start, GRIND_CHUNK)
            if nonce < 0:
                continue
            digest = dsha(header76 + u32le(nonce))
            value = int.from_bytes(digest, "little")
            self.sent[self.rid] = {"job": job_id, "hash": digest[::-1].hex(),
                                   "ns": value <= NS_TARGET, "anchor": value <= ANCHOR_TARGET}
            self.send("mining.submit", [self.user, job_id, en2h, ntime, f"{nonce:08x}"])
            emit(self.user, "share", job=job_id, hash=digest[::-1].hex(),
                 ns=value <= NS_TARGET, anchor=value <= ANCHOR_TARGET)
            return True
        return None

    def run(self):
        while True:
            try:
                self.sock = socket.create_connection((ARGS.host, ARGS.port), timeout=None)
                break
            except OSError:
                time.sleep(1)
        threading.Thread(target=self.reader, daemon=True).start()
        self.send("mining.subscribe", [self.agent])
        if self.serial:
            # cgminer's order: nothing more until the subscribe is answered.
            if not self.subscribed.wait(120):
                emit(self.user, "subscribe_unanswered")
                return
        self.send("mining.authorize", [self.user, "x"])
        emit(self.user, "connected", agent=self.agent, serial=self.serial)
        while True:
            job = self.jobs.get()
            while not self.jobs.empty():
                job = self.jobs.get()
            if job is None:
                return
            if self.mine_job(job, RNG.random() < ARGS.anchor_odds):
                time.sleep(RNG.uniform(0.5, 1.5) * ARGS.pace)
                # The next job: the newest one queued since the share, or this one again.
                if self.jobs.empty():
                    self.jobs.put(job)


miners = [Miner(s) for s in ARGS.miner]
for m in miners:
    m.start()
for m in miners:
    m.join()
