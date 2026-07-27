#!/usr/bin/env python3
"""Submit a REAL share as `<address>.<worker>` and let the operator check who got credited.

⚠ READ THIS BEFORE RELYING ON IT: at production difficulty this CANNOT SUCCEED.

It mines in pure Python at roughly 750k H/s. A share needs `difficulty * 2^32` hashes on
average, so at the hobby floor (~2,328) that is about 151 DAYS, and at the farm floor
(~232,831) about 41 years. It was previously described here as "the test that was missing"
when misattribution shipped — it could not have been that test, because it never finishes.
See #464.

It now measures its own hash rate against the difficulty the pool actually grants and refuses
immediately, with the arithmetic, rather than burning its 900s budget to reach the same
conclusion silently.

A `d=<difficulty>` directive in the password does NOT help: a declared difficulty is clamped
UP to the pool floor and never below it, so it can raise a miner above the floor but cannot
lower it for probing. Verified against a live node.

It is therefore useful only where a node can be made to grant a tiny difficulty — a canary
configured for it. On a production node, use `verify_attribution.sh` against REAL miner
traffic instead; that is the check that actually works.

Both times misattribution shipped, the failure was silent: shares kept flowing, they simply
landed on the translator's configured operator address instead of the miner. Nothing on the
wire says which identity a share was credited to — only the node's database does.

So this deliberately mines a share that is genuinely valid rather than asserting on
handshake fields. It behaves as a SERIALISING client (subscribe -> wait for reply ->
authorize), because that is the shape that forced this change: proxies and rented-hashrate
marketplaces wait for the subscribe response before authorising, so their channel has to be
opened before their address is known.

Usage:
  attribution_probe.py HOST PORT ADDRESS.WORKER [PASSWORD]

Exits 0 once a share is accepted. The caller then reads the node's `miners` table and checks
the credited miner_id.
"""
import hashlib, json, os, socket, struct, sys, time

HOST = sys.argv[1]
PORT = int(sys.argv[2])
USER = sys.argv[3]
PASSWORD = sys.argv[4] if len(sys.argv) > 4 else "x"


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def send(sock, obj):
    sock.sendall(json.dumps(obj).encode() + b"\n")


def reader(sock):
    """Yield decoded JSON messages as they arrive."""
    buf = b""
    while True:
        data = sock.recv(8192)
        if not data:
            return
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def difficulty_to_target(diff):
    # Stratum difficulty 1 target, scaled. Uses the exact constant, not 2^32.
    return int((0xFFFF * (1 << 208)) / diff) if diff > 0 else (1 << 256) - 1


def main():
    s = socket.create_connection((HOST, PORT), timeout=30)
    s.settimeout(60)
    rx = reader(s)

    # --- serialising handshake: subscribe, WAIT for the reply, only then authorize ---
    send(s, {"id": 1, "method": "mining.subscribe", "params": ["attribution-probe/1.0"]})

    extranonce1 = None
    extranonce2_size = None
    t0 = time.time()
    for msg in rx:
        if msg.get("id") == 1 and "result" in msg:
            res = msg["result"]
            extranonce1, extranonce2_size = res[1], res[2]
            break
        if time.time() - t0 > 30:
            print("FAIL: no subscribe reply"); return 1

    print(f"  subscribe -> extranonce1={extranonce1} extranonce2_size={extranonce2_size} "
          f"in {time.time()-t0:.2f}s")
    if extranonce1 is None:
        print("FAIL: no extranonce in subscribe reply"); return 1
    # A placeholder (all-zero, 8 bytes) means the channel had NOT opened yet — the very
    # behaviour this change exists to remove.
    if len(extranonce1) == 16 and set(extranonce1) == {"0"}:
        print("  NOTE: placeholder extranonce — channel was not open at subscribe time")
    else:
        print("  real extranonce at subscribe (no re-key needed)")

    send(s, {"id": 2, "method": "mining.authorize", "params": [USER, PASSWORD]})

    job = None
    difficulty = None
    authorized = None
    re_keyed = False
    t0 = time.time()
    for msg in rx:
        if msg.get("id") == 2 and "result" in msg:
            authorized = msg["result"]
            print(f"  authorize({USER}) -> {authorized}")
            if authorized is not True:
                print("FAIL: not authorized"); return 1
        m = msg.get("method")
        if m == "mining.set_difficulty":
            difficulty = float(msg["params"][0])
            print(f"  set_difficulty -> {difficulty}")
        elif m == "mining.set_extranonce":
            extranonce1, extranonce2_size = msg["params"][0], msg["params"][1]
            re_keyed = True
            print(f"  set_extranonce -> RE-KEYED to {extranonce1} (size {extranonce2_size})")
        elif m == "mining.notify":
            job = msg["params"]
        if job and difficulty and authorized:
            break
        if time.time() - t0 > 60:
            print("FAIL: no job/difficulty within 60s"); return 1

    (job_id, prevhash, coinb1, coinb2, merkle_branch,
     version, nbits, ntime, _clean) = job[:9]
    print(f"  job {job_id} difficulty={difficulty} re_keyed={re_keyed}")

    target = difficulty_to_target(difficulty)

    # Calibrate against THIS machine before committing to a 15-minute wait, and say plainly
    # when the arithmetic makes success impossible. A check that fails silently after a long
    # wait teaches nobody anything; one that says "this needs 151 days" is actionable.
    budget = float(os.environ.get("PROBE_MAX_SECONDS", "900"))
    cal_start = time.time()
    cal_head = b"\x00" * 76
    cal_n = 200_000
    for i in range(cal_n):
        sha256d(cal_head + struct.pack("<I", i))
    rate = cal_n / max(time.time() - cal_start, 1e-9)
    expected_s = difficulty * (2 ** 32) / rate
    print(f"  calibrated at {rate:,.0f} H/s; a share at difficulty {difficulty:,.1f} "
          f"needs ~{difficulty * (2 ** 32):,.0f} hashes")
    if expected_s > budget:
        print(f"REFUSING: expected time to find a share is ~{expected_s / 86400:,.1f} days "
              f"({expected_s:,.0f}s), far beyond the {budget:,.0f}s budget.")
        print("  This prober cannot verify attribution at this difficulty — see #464.")
        print("  Use scripts/ops/verify_attribution.sh against real miner traffic instead,")
        print("  or point this at a canary configured to grant a tiny difficulty.")
        s.close()
        return 2

    print(f"  mining for a share at difficulty {difficulty} ...")

    # --- actually mine ---
    en1 = bytes.fromhex(extranonce1)
    started = time.time()
    attempts = 0
    for en2_int in range(0, 1 << 32):
        en2 = en2_int.to_bytes(extranonce2_size, "little")
        coinbase = bytes.fromhex(coinb1) + en1 + en2 + bytes.fromhex(coinb2)
        merkle = sha256d(coinbase)
        for h in merkle_branch:
            merkle = sha256d(merkle + bytes.fromhex(h))

        # Stratum sends prevhash WORD-swapped: reverse each 4-byte word, not the whole
        # 32 bytes. Reversing wholesale produces a header the pool rejects as an
        # invalid share, which is what happened on the first attempt here.
        prev = bytes.fromhex(prevhash)
        prev_hdr = b"".join(prev[i:i + 4][::-1] for i in range(0, 32, 4))

        head = (bytes.fromhex(version)[::-1]
                + prev_hdr
                + merkle
                + bytes.fromhex(ntime)[::-1]
                + bytes.fromhex(nbits)[::-1])

        for nonce in range(0, 1 << 32):
            attempts += 1
            h = sha256d(head + struct.pack("<I", nonce))
            if int.from_bytes(h[::-1], "big") < target:
                elapsed = time.time() - started
                print(f"  FOUND after {attempts:,} hashes in {elapsed:.1f}s")
                send(s, {"id": 4, "method": "mining.submit",
                         "params": [USER, job_id, en2.hex(), ntime, f"{nonce:08x}"]})
                for msg in rx:
                    if msg.get("id") == 4:
                        ok = msg.get("result")
                        print(f"  submit -> {ok}  error={msg.get('error')}")
                        s.close()
                        return 0 if ok else 1
                return 1
            if attempts % 2_000_000 == 0:
                print(f"    {attempts:,} hashes, {time.time()-started:.0f}s ...")
            if time.time() - started > budget:
                print(f"FAIL: no share found in {budget:,.0f}s — difficulty too high for this "
                      f"prober (expected ~{expected_s / 86400:,.1f} days)")
                return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
