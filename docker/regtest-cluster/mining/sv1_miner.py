#!/usr/bin/env python3
"""Minimal SV1 stratum miner for the regtest dry-run.
Connects to the translator, mines at the pool's vardiff; regtest difficulty is
trivial so it finds block-difficulty shares fast. Username = payout address."""
import socket, json, sys, hashlib, struct, binascii

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3333
USER = sys.argv[3] if len(sys.argv) > 3 else "bcrt1qnmauq6v2p0uwrdg6vfjzevm7pffe5z8cpmcdcd.w1"

def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def u32le(x): return struct.pack("<I", x)

class Miner:
    def __init__(s):
        s.sock = socket.create_connection((HOST, PORT), timeout=60)
        s.buf = b""; s.rid = 1; s.en1 = ""; s.en2sz = 4; s.diff = 1.0
    def send(s, method, params):
        m = {"id": s.rid, "method": method, "params": params}; s.rid += 1
        s.sock.sendall((json.dumps(m) + "\n").encode()); return m["id"]
    def lines(s):
        while True:
            while b"\n" not in s.buf:
                d = s.sock.recv(4096)
                if not d: return
                s.buf += d
            line, s.buf = s.buf.split(b"\n", 1)
            if line.strip():
                try: yield json.loads(line)
                except Exception: pass
    def share_target(s):
        # pool/channel target: diff-1 (pdiff) scaled by the SV1 difficulty, then /256
        # to match the translator's channel target encoding (observed empirically).
        diff1 = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
        return int(diff1 / max(s.diff, 1e-9)) // 256
    @staticmethod
    def net_target(nbits):
        n = int(nbits, 16); exp = n >> 24; mant = n & 0xffffff
        return mant * (1 << (8 * (exp - 3)))
    def header(s, ver, prev, root, ntime, nbits, nonce):
        v  = u32le(int(ver, 16))
        # stratum prevhash = 8 big-endian 32-bit words -> pack each word little-endian
        pv = b"".join(u32le(int(prev[i:i+8], 16)) for i in range(0, 64, 8))
        nt = u32le(int(ntime, 16)); nb = u32le(int(nbits, 16))
        return v + pv + root + nt + nb + u32le(nonce)
    def mine_job(s, j):
        job_id, prev, cb1, cb2, branch, ver, nbits, ntime, clean = j
        ntarget = s.net_target(nbits)
        accept = s.share_target()   # must meet the POOL's share target (translator validates this)
        if not getattr(s, "_dbg", False):
            s._dbg = True
            pv = b"".join(u32le(int(prev[i:i+8], 16)) for i in range(0, 64, 8))
            print(f"[dbg] notify_prev={prev}", flush=True)
            print(f"[dbg] my_pv_in_header={pv.hex()}", flush=True)
            print(f"[dbg] ver={ver} nbits={nbits} ntime={ntime} en1={s.en1} en2sz={s.en2sz}", flush=True)
            print(f"[dbg] cb1={cb1[:40]}... cb2={cb2[:40]}... branches={len(branch)}", flush=True)
            print(f"[dbg] share_target={hex(s.share_target())} net_target={hex(ntarget)}", flush=True)
        for en2 in range(0, 0x100000):
            en2h = struct.pack("<I", en2).hex().ljust(s.en2sz * 2, "0")[:s.en2sz * 2]
            coinbase = binascii.unhexlify(cb1 + s.en1 + en2h + cb2)
            root = dsha(coinbase)
            for b in branch: root = dsha(root + binascii.unhexlify(b))
            for nonce in range(0, 0x40000):
                h = dsha(s.header(ver, prev, root, ntime, nbits, nonce))
                val = int.from_bytes(h, "little")
                if val <= accept:
                    # SV1 nonce is a big-endian hex string; the header still uses it LE
                    s.send("mining.submit", [USER, job_id, en2h, ntime, f"{nonce:08x}"])
                    print(f"[miner] SHARE en2={en2h} nonce={nonce:08x} "
                          f"{'*** BLOCK ***' if val <= ntarget else 'share'}", flush=True)
                    print(f"[hash] my_hash_be={h[::-1].hex()}", flush=True)
                    print(f"[hash] en1={s.en1} en2={en2h} ver={ver} ntime={ntime} nbits={nbits} nonce={nonce:08x}", flush=True)
                    print(f"[hash] coinbase={(cb1 + s.en1 + en2h + cb2)}", flush=True)
                    print(f"[hash] root_internal={root.hex()} pv_in_header={s.header(ver,prev,root,ntime,nbits,nonce)[4:36].hex()}", flush=True)
                    return True
        return False
    def run(s):
        s.send("mining.subscribe", ["rc-sv1-miner/1.0"])
        s.send("mining.authorize", [USER, "x"])
        print(f"[miner] connected {HOST}:{PORT} as {USER}", flush=True)
        for msg in s.lines():
            if msg.get("id") == 1 and msg.get("result"):
                r = msg["result"]; s.en1 = r[1]; s.en2sz = r[2]
                print(f"[miner] subscribed en1={s.en1} en2sz={s.en2sz}", flush=True)
            mm = msg.get("method")
            if mm == "mining.set_extranonce":
                s.en1 = msg["params"][0]; s.en2sz = msg["params"][1]
                print(f"[miner] set_extranonce en1={s.en1} en2sz={s.en2sz}", flush=True)
            if mm == "mining.set_difficulty":
                s.diff = msg["params"][0]; print(f"[miner] difficulty={s.diff}", flush=True)
            elif mm == "mining.notify":
                p = msg["params"]
                print(f"[miner] job {p[0]} clean={p[-1]}", flush=True)
                try: s.mine_job(p)
                except Exception as e: print(f"[miner] mine error: {e}", flush=True)
            elif isinstance(msg.get("id"), int) and msg["id"] > 2 and "result" in msg:
                print(f"[miner] submit -> result={msg.get('result')} err={msg.get('error')}", flush=True)

Miner().run()
