#!/usr/bin/env python3
"""Self-test for sv1_handshake_smoke.py's declared-difficulty case.

Drives that case against four fake pools with KNOWN behaviour and asserts it reports each one
correctly. Needs no node, no build and no network — just localhost sockets.

This exists because the case it guards was, in its first form, unable to tell "the pool delivered
the declaration two seconds late" from "the pool never delivered it": both printed
`pool set 23,282.7`. That identical message is what sent the #455 investigation looking for a
value being *ignored* when it was being *delayed*. A check that cannot distinguish the states it
claims to check is worth nothing, and the only way to find that out is to run it against
deliberately broken behaviour — which is what this file is.

Usage: sv1_handshake_smoke_selftest.py [path/to/sv1_handshake_smoke.py]
Exit 0 iff every discrimination check holds.
"""
import sys

# Loading the smoke module would otherwise litter a __pycache__ next to it, which is how a
# .pyc first got committed here.
sys.dont_write_bytecode = True

import importlib.util, json, os, socket, threading, time  # noqa: E402

SMOKE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "sv1_handshake_smoke.py")
DECLARED = 1_000_000.0
FLOOR = 23_282.7


def serve(behaviour, port_box, ready):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port_box.append(srv.getsockname()[1])
    srv.listen(1)
    ready.set()
    conn, _ = srv.accept()
    try:
        def sd(v):
            conn.sendall(json.dumps(
                {"id": None, "method": "mining.set_difficulty", "params": [v]}).encode() + b"\n")
        if behaviour == "immediate":
            sd(DECLARED)
        elif behaviour == "floor_only":
            sd(FLOOR)
        elif behaviour == "floor_then_declared":
            sd(FLOOR); time.sleep(2.0); sd(DECLARED)
        elif behaviour == "silent":
            pass
        time.sleep(8)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
        srv.close()


CASES = [
    ("immediate",           True,  "on the first set_difficulty"),
    ("floor_then_declared", True,  "DELAYED"),
    ("floor_only",          False, "never sent the declared value"),
    ("silent",              False, "NO set_difficulty"),
]

failures = 0
for behaviour, want_pass, want_text in CASES:
    box, ready = [], threading.Event()
    t = threading.Thread(target=serve, args=(behaviour, box, ready), daemon=True)
    t.start(); ready.wait(5)

    # Load a fresh copy of the smoke module pointed at this fake pool.
    spec = importlib.util.spec_from_file_location(f"smoke_{behaviour}", SMOKE)
    mod = importlib.util.module_from_spec(spec)
    sys.argv = ["smoke", "127.0.0.1", str(box[0]), "bc1qtest.worker"]
    spec.loader.exec_module(mod)

    import io, contextlib
    cap = io.StringIO()
    with contextlib.redirect_stdout(cap):
        got_pass = mod._declared_difficulty_case("probe", DECLARED, window=5.0)
    out = cap.getvalue().strip()

    ok = (got_pass == want_pass) and (want_text in out)
    if not ok:
        failures += 1
    print(f"  [{'ok ' if ok else 'BAD'}] server={behaviour:<20} "
          f"expect={'PASS' if want_pass else 'FAIL'} got={'PASS' if got_pass else 'FAIL'}")
    print(f"        {out}")

print()
if failures:
    print(f"*** {failures} of {len(CASES)} discrimination checks FAILED — the case is not "
          f"distinguishing what it claims to ***")
    sys.exit(1)
print(f"All {len(CASES)} discrimination checks passed: the case separates honoured / delayed / "
      f"withheld / silent.")
