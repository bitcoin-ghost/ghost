#!/usr/bin/env python3
"""Submit a REAL share as `<address>.<worker>` and let the operator check who got credited.

This is the test that was missing the two times channel-open-on-subscribe was deployed and
misattributed ~395 shares. Both times the failure was silent: shares kept flowing, they
simply landed on the translator's configured operator address instead of the miner. Nothing
on the wire says which identity a share was credited to — only the node's database does.

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
import hashlib, json, socket, struct, sys, time

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
            if time.time() - started > 900:
                print("FAIL: no share found in 900s — difficulty too high for this prober")
                return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
