#!/usr/bin/env python3
"""Synthetic SV1 handshake smoke test for the Ghost translator.

Reproduces the real-world miner quirks that have bitten us, as a run-before-deploy
guard so a handshake regression can't reach the fleet silently again.

Cases:
  serializer      cgminer/Avalon: subscribe -> WAIT -> authorize. Must NOT deadlock
                  (the avalon-night bug). The translator must answer subscribe within
                  the ~1.5s timeout fallback even though authorize hasn't been sent.
  pipeliner       AxeOS/Bitaxe: subscribe+authorize together. Must get the REAL
                  extranonce in the subscribe response (the extranonce-subscribe-OFF
                  fix), not the 8-byte placeholder.
  bare-username   authorize without a `.worker` -> must be rejected (per-miner payout
                  policy), not silently accepted.
  version-rolling mining.configure (BIP310/AsicBoost, Antminer S19) -> must negotiate
                  a version-rolling mask.
  tls             AxeOS/Bitaxe with "Connection Security: TLS": same serializer handshake
                  but over a TLS-wrapped socket against the opt-in TLS port. The cert is NOT
                  validated (check_hostname=False, CERT_NONE) so the case works with the
                  canary's real Let's Encrypt cert OR a self-signed test cert. SKIPPED unless
                  a TLS port is supplied (4th arg or GHOST_TLS_PORT), since TLS is opt-in.

Usage:  python3 sv1_handshake_smoke.py [HOST] [PORT] [USER] [TLS_PORT]
        GHOST_TLS_PORT=3334 python3 sv1_handshake_smoke.py   # alternative for the TLS port
Exit 0 iff all cases pass (the TLS case is skipped, not failed, when no TLS port is set).
"""
import os, socket, ssl, json, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2] if len(sys.argv) > 2 else 3333)
USER = sys.argv[3] if len(sys.argv) > 3 else "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492.synthtest"
# Opt-in TLS port. From the 4th positional arg or the GHOST_TLS_PORT env var; unset -> skip.
_tls_arg = sys.argv[4] if len(sys.argv) > 4 else os.environ.get("GHOST_TLS_PORT")
TLS_PORT = int(_tls_arg) if _tls_arg else None
PLACEHOLDER = "0000000000000000"
# Minimum extranonce2_size a pool must advertise to be accepted by rented-hashrate
# marketplaces (Braiins requires >= 7). Override with GHOST_MIN_EXTRANONCE2_SIZE.
MIN_EXTRANONCE2_SIZE = int(os.environ.get("GHOST_MIN_EXTRANONCE2_SIZE", "7"))


def recv_until(sock, timeout, pred):
    sock.settimeout(timeout)
    buf = b""
    out = []
    t0 = time.time()
    try:
        while time.time() - t0 < timeout:
            data = sock.recv(4096)
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                out.append(msg)
                if pred(msg):
                    return out
    except socket.timeout:
        pass
    return out


def send(sock, obj):
    sock.sendall(json.dumps(obj).encode() + b"\n")


def test_serializer():
    s = socket.create_connection((HOST, PORT), timeout=10)
    send(s, {"id": 1, "method": "mining.subscribe", "params": ["synthtest/1.0"]})
    # Deliberately do NOT send authorize — a deadlocked translator never replies.
    t0 = time.time()
    msgs = recv_until(s, 4.0, lambda m: m.get("id") == 1 and "result" in m)
    dt = time.time() - t0
    sub = [m for m in msgs if m.get("id") == 1 and "result" in m]
    got = bool(sub)
    s.close()
    print(f"  [serializer]      {'PASS' if got else 'FAIL'} — subscribe answered in {dt:.2f}s "
          f"({'no deadlock' if got else 'DEADLOCK — no response'})")
    return got


def test_placeholder_extranonce2_size():
    """The subscribe-defer fallback must advertise the CONFIGURED extranonce2_size.

    A pool-capability probe (Braiins' hashrate marketplace, notably) sends mining.subscribe
    and never authorizes, so the ~1.5s fallback placeholder is the ONLY extranonce2_size it
    ever sees — the real channel-allocated value delivered later via mining.set_extranonce
    comes too late. Braiins rejects any pool advertising < 7 ("Pool exists but is not
    compatible"). This regressed once already: the placeholder was hardcoded to 4 in
    DownstreamData::new while the config said 8, so raising the config alone changed nothing
    for probes. Guard the placeholder, not just the real value.
    """
    s = socket.create_connection((HOST, PORT), timeout=10)
    send(s, {"id": 1, "method": "mining.subscribe", "params": ["synthtest/1.0"]})
    msgs = recv_until(s, 4.0, lambda m: m.get("id") == 1 and "result" in m)
    sub = [m for m in msgs if m.get("id") == 1 and "result" in m]
    r = sub[0]["result"] if sub and isinstance(sub[0]["result"], list) else None
    en2 = r[2] if r and len(r) > 2 and isinstance(r[2], int) else None
    s.close()
    ok = en2 is not None and en2 >= MIN_EXTRANONCE2_SIZE
    print(f"  [probe-en2-size]  {'PASS' if ok else 'FAIL'} — subscribe-only extranonce2_size={en2} "
          f"(need >= {MIN_EXTRANONCE2_SIZE}"
          f"{'' if ok else '; rented-hashrate marketplaces would reject this pool'})")
    return ok


def test_pipeliner():
    s = socket.create_connection((HOST, PORT), timeout=10)
    send(s, {"id": 1, "method": "mining.subscribe", "params": ["synthtest/1.0"]})
    send(s, {"id": 2, "method": "mining.authorize", "params": [USER, "x"]})
    msgs = recv_until(s, 6.0, lambda m: m.get("id") == 1 and "result" in m)
    sub = [m for m in msgs if m.get("id") == 1 and "result" in m]
    en1 = sub[0]["result"][1] if sub and isinstance(sub[0]["result"], list) else None
    # bonus: did a job arrive (NOT required — job cadence varies)
    notify = any(m.get("method") == "mining.notify"
                 for m in recv_until(s, 4.0, lambda m: m.get("method") == "mining.notify"))
    s.close()
    real = en1 is not None and en1 != PLACEHOLDER
    print(f"  [pipeliner]       {'PASS' if real else 'FAIL'} — subscribe extranonce1={en1} "
          f"({'real' if real else 'PLACEHOLDER — extranonce-OFF miners would reject'}); notify={notify}")
    return real


def test_bare_username():
    s = socket.create_connection((HOST, PORT), timeout=10)
    send(s, {"id": 1, "method": "mining.subscribe", "params": ["synthtest/1.0"]})
    send(s, {"id": 2, "method": "mining.authorize",
             "params": ["bc1qbareaddressnoworkerxxxxxxxxxxxxxxxxxxxxx", "x"]})
    msgs = recv_until(s, 5.0, lambda m: m.get("id") == 2)
    auth = [m for m in msgs if m.get("id") == 2]
    rejected = bool(auth) and (auth[0].get("result") in (False, None) or auth[0].get("error"))
    s.close()
    print(f"  [bare-username]   {'PASS' if rejected else 'FAIL'} — bare-worker authorize "
          f"{'rejected' if rejected else 'ACCEPTED (policy hole)'}")
    return rejected


def test_version_rolling():
    s = socket.create_connection((HOST, PORT), timeout=10)
    send(s, {"id": 1, "method": "mining.configure",
             "params": [["version-rolling"],
                        {"version-rolling.mask": "1fffe000", "version-rolling.min-bit-count": 2}]})
    msgs = recv_until(s, 5.0, lambda m: m.get("id") == 1 and "result" in m)
    res = [m for m in msgs if m.get("id") == 1 and "result" in m]
    r = res[0]["result"] if res else {}
    ok = isinstance(r, dict) and r.get("version-rolling") is True and r.get("version-rolling.mask")
    s.close()
    print(f"  [version-rolling] {'PASS' if ok else 'FAIL'} — "
          f"version-rolling={r.get('version-rolling') if isinstance(r, dict) else None} "
          f"mask={r.get('version-rolling.mask') if isinstance(r, dict) else None}")
    return bool(ok)


def test_tls_serializer():
    # Same serializer handshake (subscribe -> WAIT) as test_serializer, but over TLS.
    # The cert is NOT validated: AxeOS "TLS (System certificate)" would validate the chain,
    # but here we only prove the TLS listener terminates and drives the SAME downstream path.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((HOST, TLS_PORT), timeout=10)
    s = ctx.wrap_socket(raw, server_hostname=HOST)
    send(s, {"id": 1, "method": "mining.subscribe", "params": ["synthtest/1.0"]})
    # Deliberately do NOT send authorize — a deadlocked translator never replies.
    t0 = time.time()
    msgs = recv_until(s, 4.0, lambda m: m.get("id") == 1 and "result" in m)
    dt = time.time() - t0
    got = any(m.get("id") == 1 and "result" in m for m in msgs)
    s.close()
    print(f"  [tls]             {'PASS' if got else 'FAIL'} — subscribe answered over TLS in "
          f"{dt:.2f}s ({'no deadlock' if got else 'DEADLOCK — no response over TLS'})")
    return got


def main():
    print(f"SV1 handshake smoke test vs {HOST}:{PORT}")
    results = {
        "serializer": test_serializer(),
        "probe-en2-size": test_placeholder_extranonce2_size(),
        "pipeliner": test_pipeliner(),
        "bare-username": test_bare_username(),
        "version-rolling": test_version_rolling(),
    }
    if TLS_PORT is not None:
        print(f"  (TLS case vs {HOST}:{TLS_PORT})")
        results["tls"] = test_tls_serializer()
    else:
        print("  [tls]             SKIP — no TLS port set (pass 4th arg or GHOST_TLS_PORT)")
    print()
    bad = [k for k, v in results.items() if not v]
    if bad:
        print("RESULT: FAILED ❌ —", ", ".join(bad))
        return 1
    print("RESULT: ALL PASS ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
