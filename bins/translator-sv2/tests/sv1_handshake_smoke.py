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
  probe-no-auth   Braiins/marketplace probe shape: subscribe -> read reply -> disconnect
                  WITHOUT authorizing. Must be answered and cleaned up, and the next
                  connection must still be served. A probe that hangs looks to the
                  marketplace like an unreachable pool and nothing in our logs says why.
  default-diff    The floor a miner gets when it asks for NOTHING. Every other difficulty
                  case requests a value, so all of them pass identically on a correctly
                  and an incorrectly configured node — which is how four production nodes
                  came to serve 1,164 while the canaries served 23,283 with this file
                  fully green. Override with GHOST_EXPECT_DEFAULT_DIFFICULTY.
  attribution     authorize as `<address>.<worker>` -> must be accepted AND get a real
                  per-miner extranonce, not the placeholder. That is the wire-visible
                  precondition for share attribution, which was silently crediting the
                  operator address for months because nothing asserted any of it.
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


def _first_set_difficulty(sock, timeout=8.0):
    """Return the difficulty from the first mining.set_difficulty, or None."""
    msgs = recv_until(sock, timeout, lambda m: m.get("method") == "mining.set_difficulty")
    for m in msgs:
        if m.get("method") == "mining.set_difficulty":
            params = m.get("params") or []
            if params and isinstance(params[0], (int, float)):
                return float(params[0])
    return None


def _declared_difficulty_case(label, requested, pre_subscribe=None, password="x"):
    """Assert a miner-declared difficulty is honoured on the initial set_difficulty.

    Without this, every connection starts at the configured floor (sized for the smallest
    expected miner) and vardiff needs several 60s ticks to climb — it caps corrections above
    1000% to x3-x5 per tick — so a farm or a rented-hashrate order floods shares for minutes
    before converging. Marketplaces reject a pool whose starting difficulty is far below the
    hashrate they are pointing at it.
    """
    s = socket.create_connection((HOST, PORT), timeout=10)
    if pre_subscribe is not None:
        send(s, pre_subscribe)
    send(s, {"id": 1, "method": "mining.subscribe", "params": ["synthtest/1.0"]})
    send(s, {"id": 2, "method": "mining.authorize", "params": [USER, password]})
    got = _first_set_difficulty(s)
    s.close()
    # Allow 1% for the target->difficulty rounding through the SV2 channel.
    ok = got is not None and abs(got - requested) / requested < 0.01
    print(f"  [{label}]{' ' * max(0, 16 - len(label))}{'PASS' if ok else 'FAIL'} — "
          f"asked for difficulty {requested:,.0f}, pool set {got if got is None else f'{got:,.1f}'}")
    return ok


def test_password_difficulty():
    # The convention rented-hashrate marketplaces use: difficulty in the password.
    return _declared_difficulty_case("pw-difficulty", 1_000_000.0, password="x;d=1000000")


def test_suggest_difficulty():
    # The protocol-native route, sent before subscribe/authorize.
    return _declared_difficulty_case(
        "suggest-diff",
        1_000_000.0,
        pre_subscribe={"id": 0, "method": "mining.suggest_difficulty", "params": [1000000]},
    )


def test_default_difficulty():
    """Assert the floor a miner gets when it asks for NOTHING.

    Every other difficulty case here *requests* a value and asserts the pool honours it,
    which passes identically on a node with the right config and one with the wrong one.
    That gap is not theoretical: after v1.11.18's binaries were rolled, all four
    production nodes were still serving a floor of 1,164 while the canaries served
    23,283, every case in this file passed on both, and the drift was only found by
    reading config files by hand.

    Expected value comes from min_individual_miner_hashrate: difficulty =
    hashrate * (2^48 / 0xFFFF) / 2^32 / shares_per_minute-normalised — in practice
    10 TH/s -> ~23,283. Override for a node deliberately configured otherwise.
    """
    expected = float(os.environ.get("GHOST_EXPECT_DEFAULT_DIFFICULTY", "23282.7"))
    tol = float(os.environ.get("GHOST_DEFAULT_DIFFICULTY_TOLERANCE", "0.02"))
    s = socket.create_connection((HOST, PORT), timeout=10)
    send(s, {"id": 1, "method": "mining.subscribe", "params": ["synthtest/1.0"]})
    send(s, {"id": 2, "method": "mining.authorize", "params": [USER, "x"]})
    got = _first_set_difficulty(s)
    s.close()
    ok = got is not None and abs(got - expected) / expected < tol
    detail = f"pool set {got if got is None else f'{got:,.1f}'} (expected ~{expected:,.0f})"
    if got is not None and not ok:
        detail += " — config drift: this node is not serving the fleet floor"
    print(f"  [default-diff]    {'PASS' if ok else 'FAIL'} — asked for nothing, {detail}")
    return ok


def test_serializer_no_authorize():
    """The Braiins shape: subscribe, wait for the reply, then disconnect without authorizing.

    Rented-hashrate marketplaces probe a pool this way before dispatching — they open a
    connection, read the subscribe response to check extranonce2_size, and drop it. The
    pool must answer and then clean up without wedging the accept loop, and a second
    connection straight afterwards must still be served.

    This is the shape that matters because a probe that hangs looks to the marketplace
    like an unreachable pool, and nothing in our logs would say why.
    """
    t0 = time.time()
    s = socket.create_connection((HOST, PORT), timeout=10)
    send(s, {"id": 1, "method": "mining.subscribe", "params": ["braiins-probe/1.0"]})
    msgs = recv_until(s, 8.0, lambda m: m.get("id") == 1 and "result" in m)
    sub = [m for m in msgs if m.get("id") == 1 and "result" in m]
    answered = bool(sub)
    s.close()  # disconnect WITHOUT authorize

    # The pool must still serve the next connection — a leaked session or a blocked
    # accept loop shows up here and nowhere else.
    ok_second = False
    try:
        s2 = socket.create_connection((HOST, PORT), timeout=10)
        send(s2, {"id": 1, "method": "mining.subscribe", "params": ["braiins-probe/1.0"]})
        m2 = recv_until(s2, 8.0, lambda m: m.get("id") == 1 and "result" in m)
        ok_second = any(m.get("id") == 1 and "result" in m for m in m2)
        s2.close()
    except OSError:
        ok_second = False

    elapsed = time.time() - t0
    ok = answered and ok_second
    print(f"  [probe-no-auth]   {'PASS' if ok else 'FAIL'} — subscribe answered={answered}, "
          f"reconnect served={ok_second} ({elapsed:.2f}s)")
    return ok


def test_worker_attribution():
    """Assert the pool accepts `<address>.<worker>` and opens a channel for it.

    Attribution is only observable end-to-end by reading the share row on the node, which
    this test cannot do from outside — see the note in main(). What IS observable over the
    wire is the precondition: the address.worker identity is accepted, and the connection
    gets a real extranonce rather than the placeholder, meaning a channel was opened for
    this specific miner rather than the connection being aggregated.

    Shares from named workers were credited to the operator address for months because
    nothing asserted any part of this path.
    """
    worker = "attribtest"
    addr = USER.split(".")[0]
    ident = f"{addr}.{worker}"
    s = socket.create_connection((HOST, PORT), timeout=10)
    send(s, {"id": 1, "method": "mining.subscribe", "params": ["synthtest/1.0"]})
    send(s, {"id": 2, "method": "mining.authorize", "params": [ident, "x"]})

    # Wait for BOTH replies, not whichever lands first. recv_until returns the moment
    # its predicate matches, and the translator may answer authorize before it answers
    # the deferred subscribe — so a predicate on id==2 alone drops the subscribe result
    # and the extranonce reads as missing when it was merely not waited for.
    seen = set()

    def both(m):
        if m.get("id") in (1, 2) and "result" in m:
            seen.add(m["id"])
        return {1, 2} <= seen

    msgs = recv_until(s, 8.0, both)
    s.close()

    auth = [m for m in msgs if m.get("id") == 2 and "result" in m]
    authorized = bool(auth) and auth[0].get("result") is True
    sub = [m for m in msgs if m.get("id") == 1 and "result" in m]
    en1 = sub[0]["result"][1] if sub and isinstance(sub[0].get("result"), list) else None
    real_extranonce = en1 is not None and en1 != PLACEHOLDER

    ok = authorized and real_extranonce
    print(f"  [attribution]     {'PASS' if ok else 'FAIL'} — authorized {ident} as "
          f"{authorized}, per-miner extranonce1={en1}"
          f"{'' if real_extranonce else ' (PLACEHOLDER — no per-miner channel)'}")
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
        "probe-no-auth": test_serializer_no_authorize(),
        "default-diff": test_default_difficulty(),
        "pw-difficulty": test_password_difficulty(),
        "suggest-diff": test_suggest_difficulty(),
        "attribution": test_worker_attribution(),
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
