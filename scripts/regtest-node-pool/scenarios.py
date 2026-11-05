"""Scenarios for harness.py, run in order. Each reports PASS, FAIL or UNMEASURED with evidence;
a reading that could not be taken is UNMEASURED, never a pass."""
import json
import os
import re
import subprocess
import time

from harness import (FIRST_EARNING_HEIGHT, logged, RPC_PASS, RPC_USER, SERIAL_AGENT, SLOT_CLASSES, TREASURY_SCRIPT as TREASURY,
                     check_coinbase, p2pkh_address, payee, result, say, subsidy, wait_for, Proc, HERE,
                     TIER_BASE, NETWORK, GENESIS_HEIGHT, audit_chain_args)
import sys

def genesis_args(h):
    """ghost-audit starts from the same genesis table the nodes imported, and refuses any other."""
    if not h.export_dir:
        return []
    root = getattr(h.nodes[0], "genesis_root", None)
    return (["--genesis-export", h.export_dir, "--export-digest", h.export_digest]
            + (["--genesis-table-digest", root] if root else []))


def settled_in(log, bh):
    """The block was settled against its anchor: directly, or provisionally and then confirmed.
    A block built on a partition's losing-side anchors, which a node that never held them
    cannot confirm, counts once retired provisionally (by what it paid)."""
    prov = logged(log, bh, "NP_SETTLE: pool block retired provisionally")
    return logged(log, bh, "NP_SETTLE: pool block settled") or (prov and (
        logged(log, bh, "NP_SETTLE: provisional block confirmed by its anchor")
        or bh in STATE.get("minority_blocks", set())))


# Shared between scenarios: what earlier ones measured.
STATE = {}


def _progress(h, label):
    n = h.nodes[0]
    st = n.status()
    sc, rs, se = st["share_chain"], st["relay_stats"], st["settlement"]
    say(f"  [{label} {time.time() - h.t0:5.0f}s] btc {n.rpc('getblockcount')}  anchors {sc['anchor_height']}"
        f" (btc {sc['btc_height']})  loose {sc['loose_shares']}  accepted {rs['shares_accepted']}"
        f" invalid {rs['shares_invalid']}/{rs['anchors_invalid']}  settled {se['matched']}"
        f"+{se['confirmed']} prov {len(se['provisional'])} mismatch {se['mismatched']}"
        f"  peers {st['peers']}  rss {h.rss_mb()} MB")


def bringup(h):
    say("\n== bring-up")
    for _ in range(h.args.nodes):
        h.add_node()
    dev = h.nodes[0].start_sv2_device(payee("node0/sv2-device", True)[0] + ".dev")
    STATE["sv2_device"] = dev
    ev, ok = [], True
    for n in h.nodes:
        line = next((l for l in n.read_log("pool_sv2").splitlines() if "NODE_POOL_START:" in l), None)
        if (not line or f"network={NETWORK}" not in line
                or f"genesis_btc_height={GENESIS_HEIGHT}" not in line):
            ok = False
        ev.append(f"node{n.i}: " + (line.split("NODE_POOL_START: ", 1)[1][:150] if line else "no NODE_POOL_START line"))
    try:
        wait_for(lambda: all(n.status()["peers"] >= len(h.nodes) - 1 for n in h.nodes), 60,
                 what="relay peers")
        ev.append("relay peers: " + ", ".join(f"node{n.i}={n.status()['peers']}" for n in h.nodes))
    except TimeoutError as e:
        ok = False
        ev.append(str(e))
    result(f"bring-up: every node on the {NETWORK} genesis, relays peered", "PASS" if ok else "FAIL", ev)


def mine(h):
    target = h.args.mine_to
    say(f"\n== mining to Bitcoin height {target}")
    deadline = time.time() + h.args.mine_timeout
    last = 0
    while time.time() < deadline:
        height = h.nodes[0].rpc("getblockcount")
        if height >= target:
            break
        dead = [f"node{n.i}/{k}" for n in h.nodes for k, p in n.procs.items() if not p.alive()]
        if dead:
            raise RuntimeError(f"processes died while mining: {dead}")
        if time.time() - last > 30:
            _progress(h, "mine")
            last = time.time()
        time.sleep(2)
    for n in h.nodes:
        n.pause_miners(True)
    height = h.nodes[0].rpc("getblockcount")
    say(f"  miners paused at height {height}")
    try:
        STATE["quiet"] = h.quiesce(240)
    except TimeoutError as e:
        STATE["quiet"] = None
        say(f"  {e}")
    _progress(h, "quiet")
    st = [n.status() for n in h.nodes]
    anchors = st[0]["share_chain"]["anchor_height"]
    invalid = {f"node{n.i}": s["relay_stats"]["anchors_invalid"] for n, s in zip(h.nodes, st)}
    verdict = ("PASS" if height >= target and STATE["quiet"] and anchors >= 5
               and not any(invalid.values()) else "FAIL")
    result(f"mining: pool reaches height {target}, the share chain grows, every node goes quiet on one tip",
           verdict, [f"height {height} after {time.time() - h.t0:.0f}s",
                     f"agreed (height, share-chain tip): {STATE['quiet']}",
                     f"share chain: {anchors} anchors; anchors refused as invalid: {invalid}"])


def earns(ledger):
    """Whether a miner's shares can have earned: one of its recent shares is on a job whose block
    pays a subsidy. Regtest halves every 150 blocks, so from block 4,950 the subsidy is 0 and a
    share there is credited 0 units; a long regtest soak runs far past that."""
    return any(subsidy(int(s.get("job_height", 0))) > 0 for s in ledger.get("recent_shares", []))


def balances_agree(h):
    if not STATE.get("quiet"):
        return result("balances: miners on every node earn, all nodes agree", "UNMEASURED",
                      "the nodes never went quiet on one tip, so their stores cannot be compared")
    ev, ok = [], True
    digests = {n.i: n.digests() for n in h.nodes}
    for i, d in digests.items():
        ev.append(f"node{i}: {d}")
    keys = ("ledger", "retirements", "settled_blocks", "batches", "anchors")
    for k in keys:
        if len({d[k] for d in digests.values()}) != 1:
            ok = False
            ev.append(f"DIFFER on {k}")
    if digests[0]["ledger_rows"] == 0:
        ok = False
        ev.append("the ledger is empty")
    miners = [(n.i, m) for n in h.nodes for m in n.miners]
    for i, (user, addr, script, agent, cls) in miners:
        seen, earning = [], False
        for n in h.nodes:
            led = n.ledger(addr)
            earning |= earns(led)
            seen.append((n.i, led.get("balance", {}).get("units"), len(led.get("recent_shares", []))))
        units = {s[1] for s in seen}
        credited = all(s[2] > 0 for s in seen)
        if earning:
            credited = credited and all(s[1] and int(s[1]) > 0 for s in seen)
        if len(units) != 1 or not credited:
            ok = False
        ev.append(f"node{i} miner {addr[:16]}.. ({agent}): balance units "
                  f"{'equal' if len(units) == 1 else 'DIFFER'} on {len(seen)} nodes = "
                  f"{seen[0][1]}; credited shares per node {[s[2] for s in seen]}"
                  + ("" if earning else "; every share past the last subsidy, so 0 is expected"))
    result("balances: miners on every node earn, all nodes agree (same store digests)",
           "PASS" if ok else "FAIL", ev)


def early_blocks(h):
    """Findings F and E. Pool blocks at heights 2..16 carry OP_2..OP_16 BIP34 heights, which
    Bitcoin accepts only as those opcodes; and work below the first earning height (genesis 0 +
    21) is served, said to earn nothing, and never made into an anchor peers would refuse."""
    blocks = STATE.get("pool_blocks") or h.pool_blocks(h.nodes[0])
    early = [b[0] for b in blocks if b[0] < FIRST_EARNING_HEIGHT]
    op_n = [x for x in early if x <= 16]
    ev, ok = [f"pool blocks below height {FIRST_EARNING_HEIGHT} on the best chain: {early}",
              f"of them at BIP34 heights 2-16 (OP_2..OP_16): {op_n}"], bool(op_n)
    for n in h.honest():
        log = n.read_log("pool_sv2")
        warned = sorted({int(m) for m in re.findall(r"NODE_POOL_VOID_WORK.*?height=(\d+)", log)})
        invalid = len(re.findall(r"invalid anchor: its own share: rule 6", log))
        st = n.status().get("earning") or {}
        good = (warned and max(warned) == FIRST_EARNING_HEIGHT - 1 and invalid == 0
                and st.get("first_earning_height") == FIRST_EARNING_HEIGHT and st.get("earns") is True)
        ok &= bool(good) if n.i < h.args.nodes else invalid == 0
        ev.append(f"node{n.i}: NODE_POOL_VOID_WORK for heights {warned[:3]}..{warned[-1:] or ''}; "
                  f"anchors refused for rule 6: {invalid}; status earning={st}")
    result("early blocks: OP_N BIP34 heights accepted; void work before genesis + 21 served, "
           "flagged, never anchored", "PASS" if ok else "FAIL", ev)


def miner_events(n, since=0.0):
    try:
        with open(os.path.join(n.dir, "miner-events.jsonl")) as f:
            return [e for e in (json.loads(l) for l in f if l.strip()) if e["t"] >= since]
    except OSError:
        return []


def serial_miner(h):
    """Finding C (and G): a cgminer-style miner, which authorises only once its subscribe is
    answered, gets a channel opened on subscribe and bound to its bare payout address on
    authorize; it mines and is credited like a pipelining miner."""
    n0 = h.nodes[0]
    serial = [m for m in n0.miners if m[3] == SERIAL_AGENT]
    if not serial:
        return result("serialising (cgminer-style) miner is served", "UNMEASURED", "run without --no-serial-miner")
    user, addr, script, agent, cls = serial[0]
    ev = miner_events(n0)
    mine = [e for e in ev if e["miner"] == addr]
    kinds = [e["ev"] for e in mine]
    first_sub = kinds.index("subscribed") if "subscribed" in kinds else None
    auth = next((e for e in mine if e["ev"] == "authorized"), None)
    ok_shares = sum(1 for e in mine if e["ev"] == "submit_result" and e.get("ok"))
    drops = kinds.count("disconnect")
    tr = n0.read_log("translator")
    bound_tr = re.search(r"binding downstream \d+'s provisional channel \d+ to " + re.escape(user), tr)
    bound_pool = "provisional channel bound to its payee" in n0.read_log("pool_sv2")
    led = n0.ledger(addr)
    units = int(led.get("balance", {}).get("units", 0) or 0)
    good = (first_sub is not None and auth and auth.get("ok") and kinds.index("authorized") > first_sub
            and ok_shares > 0 and drops == 0 and bool(bound_tr) and bound_pool and units > 0)
    result("serialising (cgminer-style) miner: channel opened on subscribe, bound to its bare "
           "address on authorize, mines and is credited", "PASS" if good else "FAIL",
           [f"{addr[:16]}.. ({agent}, bare address): subscribe answered then authorize "
            f"{'accepted' if auth and auth.get('ok') else auth}; {ok_shares} shares accepted; "
            f"{drops} disconnects",
            f"translator: {'bound: ' + bound_tr.group(0)[:120] if bound_tr else 'NO binding line'}",
            f"pool_sv2: 'provisional channel bound to its payee' logged={bound_pool}",
            f"ledger balance units on node0: {units}"])


def one_refused_miner(h):
    """Finding C: the pool refusing one SV1 miner's channel drops that miner only."""
    n0 = h.nodes[0]
    bad = f"{p2pkh_address('refused')}.bad"
    mark_tr = len(n0.read_log("translator"))
    events = os.path.join(h.work, "refused-miner.jsonl")
    for n in h.nodes:
        n.pause_miners(False)
    t = time.time()
    proc = Proc("refused-miner", [sys.executable, os.path.join(HERE, "cpu_miner.py"), "127.0.0.1",
                                  str(n0.sv1), "--events", events, "--miner", f"{bad}@bitaxe/v2.10.0",
                                  "--tier-base", TIER_BASE], os.path.join(n0.dir, "refused-miner.log"))
    try:
        def dropped():
            with open(events) as f:
                return any('"disconnect"' in l for l in f)
        try:
            wait_for(dropped, 60, what="the refused miner to be disconnected")
            gone = True
        except TimeoutError:
            gone = False
        time.sleep(5)
    finally:
        proc.stop()
        for n in h.nodes:
            n.pause_miners(True)
    others = [e for e in miner_events(n0, t) if e["ev"] == "disconnect"]
    tr = n0.read_log("translator")[mark_tr:]
    refused = re.search(r"the pool refused downstream \d+'s channel \(([^)]*)\)", tr)
    fallback = tr.count("fallback triggered")
    ok = gone and refused and not others and fallback == 0
    result("one refused SV1 miner is dropped alone; the translator's other miners keep mining",
           "PASS" if ok else "FAIL",
           [f"{bad[:20]}.. (P2PKH, refused by the pool) disconnected: {gone}",
            f"translator: {refused.group(0) if refused else 'NO per-miner refusal line'}; "
            f"'fallback triggered' {fallback} times",
            f"node0's own miners' disconnects meanwhile: {len(others)}"])
    try:
        STATE["quiet"] = h.quiesce(240)
    except TimeoutError:
        STATE["quiet"] = None


def blocks_settle(h):
    if not STATE.get("quiet"):
        return result("pool blocks: settled on every node, exact coinbase sums", "UNMEASURED",
                      "the nodes never went quiet")
    n0 = h.nodes[0]
    # Blocks a hostile node found (an earlier scenario on signet) are judged there, not here.
    blocks = [b for b in h.pool_blocks(n0) if b[1] not in STATE.get("hostile_hashes", set())]
    STATE["pool_blocks"] = blocks
    payees = ({m[2] for n in h.nodes for m in n.miners} | {payee("node0/sv2-device", True)[1]}
              | set(h.genesis))
    fees = {n.fee_script for n in h.nodes}
    ev, ok = [f"{len(blocks)} pool blocks on the best chain, heights {blocks[0][0]}..{blocks[-1][0]}"
              if blocks else "no pool blocks"], bool(blocks)
    paying = 0
    for height, bh, vouts in blocks:
        errs = check_coinbase(height, vouts, payees, fees)
        if errs:
            ok = False
            ev.append(f"h{height} {bh[:16]}: " + "; ".join(errs))
        if len(vouts) > 4 or (len(vouts) == 4 and vouts[1][1] in payees):
            paying += 1
    if h.genesis:
        paid = {}
        for _, _, vouts in blocks:
            for v, sc in vouts[1:]:
                if sc in h.genesis:
                    paid[sc] = paid.get(sc, 0) + v
        over = [sc for sc, v in paid.items() if v > h.genesis[sc]]
        full = sum(1 for sc, v in paid.items() if v == h.genesis[sc])
        below = [sc for sc in paid if h.genesis[sc] < 1000]
        ok &= not over and not below
        # The ledger API serves imported balances: owed now = genesis - paid, on every node.
        sample = sorted(h.genesis)[:: max(1, len(h.genesis) // 12)]
        wrong = []
        for n in h.honest():
            for sc in sample:
                led = n.ledger(h.genesis_addr[sc])
                want = h.genesis_face[sc] - (paid.get(sc, 0) << 32)
                got = int(led.get("balance", {}).get("units", -1))
                if got != want:
                    wrong.append(f"node{n.i} {h.genesis_addr[sc][:14]}.. {got} != {want}")
        ok &= not wrong
        ev.append(f"/api/v1/node-pool/ledger on {len(h.honest())} nodes, {len(sample)} genesis payees: balance = "
                  f"imported - paid, to the face unit: {'all' if not wrong else 'NO: ' + '; '.join(wrong[:4])}")
        ev.append(f"genesis rows: {full} paid in full, exactly; {len(paid) - full} partly; "
                  f"{len(h.genesis) - len(paid)} not yet; overpaid {len(over)}; below-floor rows paid "
                  f"{len(below)}; {sum(paid.values())} of {sum(h.genesis.values())} sats owed at genesis paid")
    ev.append(f"coinbase sums exact (treasury + miners = subsidy, treasury >= S/200, finder = fees) "
              f"on {len(blocks) - sum(1 for e in ev if e.startswith('h'))} of {len(blocks)}; "
              f"{paying} paid miners, the rest went to the treasury (empty snapshot table)")
    for n in h.honest():
        log = n.read_log("pool_sv2")
        settled = {bh for _, bh, _ in blocks if logged(log, bh, "NP_SETTLE: pool block settled")}
        prov = {bh for _, bh, _ in blocks if settled_in(log, bh) and bh not in settled}
        missing = [height for height, bh, _ in blocks if bh not in settled and bh not in prov]
        st = n.status()["settlement"]
        line = (f"node{n.i}: 'pool block settled' logged for {len(settled)}/{len(blocks)}, "
                f"'retired provisionally' then 'confirmed by its anchor' for {len(prov)};"
                f" status matched={st['matched']} confirmed={st['confirmed']} mismatched={st['mismatched']}"
                f" provisional_now={len(st['provisional'])}")
        if missing:
            ok = False
            line += f"; NO settlement line for heights {missing[:10]}{'...' if len(missing) > 10 else ''}"
            for height in missing[:5]:
                bh = next(b for hh, b, _ in blocks if hh == height)
                if logged(log, bh, "does not pay its anchor's canonical outputs"):
                    line += f"; h{height} refused as 'does not pay its anchor's canonical outputs'"
                    if any(f"building a job without its snapshot table" in l and f"height={height} " in l + " "
                           for n2 in h.honest() for l in n2.read_log("pool_sv2").splitlines()):
                        line += " (a node built jobs at that height without its snapshot table)"
        # Hostile blocks (an earlier scenario on signet) are the only mismatches allowed.
        hostile = len(STATE.get("hostile_hashes", ()))
        # The counter is in memory: after a pool_sv2 restart it holds only what came since.
        mism_bad = st["mismatched"] > hostile if n.restarts else st["mismatched"] != hostile
        # A block built on anchors this node never held (the losing side of a partition) stays
        # provisional here: it retired what it paid, the same as where it matched.
        minority = STATE.get("minority_blocks", set())
        prov = [p for p in st["provisional"] if str(p["block_hash"]).lower() not in minority]
        if st["provisional"] and not prov:
            line += f"; provisional for good {len(st['provisional'])} (the partition's losing-side blocks)"
        if mism_bad or prov:
            ok = False
            line += (f"; mismatched {st['mismatched']}, of which hostile blocks {hostile}; provisional "
                     f"{st['provisional'][:4]}")
        ev.append(line)
    result("pool blocks: every node logs settlement for each block; exact coinbase sums",
           "PASS" if ok else "FAIL", ev)


def _class_view(h):
    """Every connected miner's (node, address, kind, class, expected class, settled)."""
    out = []
    for n in h.honest():
        for m in n.status()["miners"]:
            want = next((cls for (u, a, s, ag, cls) in n.miners if a == m["address"]), None)
            if m["kind"] == "standard":
                want = 500
            sens = m.get("sensing") or {}
            out.append((n.i, m["address"], m["kind"], m["slot_class"], want,
                        m["kind"] == "standard" or sens.get("settled"), sens))
    return out


def slot_classes(h):
    """Every miner reaches its class and holds it. The harness pauses miners (SIGSTOP) between
    phases, past the no-share timeout, so a settled miner's class has been suspended a class per
    timeout by now (decided 2026-11-03: silence suspends, it does not fail): resumed, every
    miner must climb back to its class, and nothing may have failed for silence alone."""
    ev, ok = [], True
    seen_classes = set()
    marks = {n.i: len(n.read_log("pool_sv2")) for n in h.honest()}
    # The miners are paused here. Wait (up to --stall-wait seconds) for a settled miner's class to
    # be suspended by the no-share timeout while it stays connected, so the climb back below is
    # seen on this run and not only in earlier pauses.
    stall_seen = None
    try:
        t = time.time()
        wait_for(lambda: any("cause=Stalled" in l for n in h.honest()
                             for l in n.read_log("pool_sv2")[marks[n.i]:].splitlines()),
                 h.args.stall_wait, step=5, what="a class suspended by silence")
        stall_seen = f"{time.time() - t:.0f}s"
    except TimeoutError:
        pass
    before = {(x[0], x[1]): x[3] for x in _class_view(h)}
    for n in h.honest():
        n.pause_miners(False)
    t = time.time()

    def all_back():
        v = _class_view(h)
        return v and all(want is None or (cls == want and settled)
                         for (_, _, _, cls, want, settled, _) in v) and v
    try:
        wait_for(all_back, h.args.mine_timeout, step=3, what="every miner back at its class")
        back_in = f"{time.time() - t:.0f}s"
    except TimeoutError as e:
        back_in = None
        ok = False
        ev.append(str(e))
    for n in h.honest():
        n.pause_miners(True)
    for n in h.nodes:
        c = n.db()
        try:
            for cls, cnt in c.execute("SELECT slot_class, count(*) FROM np_shares GROUP BY slot_class"):
                seen_classes.add(cls)
                ev.append(f"node{n.i} store: {cnt} network shares committed slot_class {cls}")
        finally:
            c.close()
    for (i, addr, kind, cls, want, settled, sens) in _class_view(h):
        n = next(x for x in h.nodes if x.i == i)
        log = n.read_log("pool_sv2")
        changes = [l for l in log.splitlines() if "slot class changed" in l and addr in l]
        stalled = sum(1 for l in changes if "cause=Stalled" in l)
        silent_fail = sum(1 for l in changes if "Failed(NoShares)" in l)
        failed = sens.get("failed") or []
        agent_ok = kind == "standard" or sens.get("agent") not in (None, "SRI/Translator Proxy/")
        good = agent_ok and want is not None and cls == want and bool(settled)
        ok &= good
        ev.append(f"node{i} {kind} {addr[:14]}.. agent={sens.get('agent')!r} model={sens.get('model')!r} "
                  f"class={cls} (expected {want}) settled={settled} ceiling={sens.get('ceiling_class')}; "
                  f"before resuming {before.get((i, addr))}; whole run: {stalled} class(es) suspended by "
                  f"silence, {silent_fail} failed by silence (a trial), failed now {failed}")
    suspended = sum(1 for n in h.honest() for l in n.read_log("pool_sv2")[marks[n.i]:].splitlines()
                    if "cause=Stalled" in l)
    ev.insert(0, (f"paused miners: a class suspended by silence {stall_seen} into the pause ({suspended} "
                  f"suspensions in this scenario)" if stall_seen else
                  f"paused miners: no class suspended by silence within {h.args.stall_wait:.0f}s, so this "
                  f"run's climb back is UNMEASURED here (unit tests cover it)"))
    ev.insert(1, f"miners resumed: every miner back at its class and settled in {back_in}"
              if back_in else "miners resumed: NOT every miner got back to its class")
    try:
        STATE["quiet"] = h.quiesce(300)
    except TimeoutError as e:
        STATE["quiet"] = None
        ok = False
        ev.append(str(e))
    # The miners ran again: later scenarios read the chain as it is now.
    if STATE.get("pool_blocks") is not None:
        STATE["pool_blocks"] = [b for b in h.pool_blocks(h.nodes[0])
                                if b[1] not in STATE.get("hostile_hashes", set())]
    missing = [c for c in SLOT_CLASSES if c not in seen_classes]
    if missing:
        ok = False
        ev.append(f"classes never committed by a stored network share: {missing}")
    # Which class each settled block matched, and how many balances it paid. On regtest one
    # share credits about 2^41 blocks' worth (T/diff1 = 2^31 at tier 10), so only the genesis
    # table's small balances make a block's outputs depend on its class.
    hist = {}
    for line in h.nodes[0].read_log("pool_sv2").splitlines():
        m = re.search(r"NP_SETTLE: pool block settled.*slot_class=(\d+).*payees=(\d+)", line) or \
            re.search(r"slot_class=(\d+).*payees=(\d+).*NP_SETTLE: pool block settled", line)
        if m:
            c, p = int(m.group(1)), int(m.group(2))
            hist.setdefault(c, []).append(p)
    ev.append("settled blocks by matched class (node0): " + ", ".join(
        f"class {c}: {len(v)} blocks, up to {max(v)} payees" for c, v in sorted(hist.items())))
    multi = {c: max(v) for c, v in hist.items() if max(v) > 1}
    if not h.genesis:
        ev.append("no genesis table: every block pays one balance, so outputs that differ by class are UNMEASURED")
    elif len(multi) < 3:
        ok = False
        ev.append(f"fewer than 3 classes paid more than one balance: {multi}")
    result("slot classes: each class sensed, served and committed by network shares; every miner "
           "back at its class after the pauses", "PASS" if ok else "FAIL", ev)


def bitcoin_reorg(h):
    blocks = STATE.get("pool_blocks") or []
    if not STATE.get("quiet") or not blocks:
        return result("Bitcoin reorg across a pool block", "UNMEASURED", "no quiet pool chain to reorg")
    tip = h.nodes[0].rpc("getblockcount")
    paying = [b for b in blocks if b[0] <= tip - 1 and len(b[2]) >= 4 and b[2][1][1] != b[2][0][1]
              and not b[2][1][1].startswith("6a")]
    if not paying:
        return result("Bitcoin reorg across a pool block", "UNMEASURED",
                      "no pool block below the tip paid a miner, so a reorg would retire nothing")
    height, bh, vouts = paying[-1]
    before = {n.i: n.digests() for n in h.nodes}
    log_len = {n.i: len(n.read_log("pool_sv2")) for n in h.nodes}
    disc0 = {n.i: n.status()["settlement"]["disconnected"] for n in h.nodes}
    ev = [f"invalidateblock h{height} {bh[:16]}.. (pays {len(vouts) - 3} outputs) on every Bitcoin node;"
          f" tip was {tip}"]
    nodes = h.honest()
    invalidated = [bh]
    for n in nodes:
        n.rpc("invalidateblock", bh)
    # A node holding a stale sibling at that height reorgs onto it instead of stepping back;
    # invalidate those too, everywhere, so every node lands on the same tip below the block.
    for _ in range(6):
        above = {n.rpc("getblockhash", height) for n in nodes if n.rpc("getblockcount") >= height}
        if not above:
            break
        for x in above:
            invalidated.append(x)
            for n in nodes:
                try:
                    n.rpc("invalidateblock", x)
                except RuntimeError:
                    pass  # a node that never saw this sibling
    if len(invalidated) > 1:
        ev.append(f"also invalidated {len(invalidated) - 1} stale sibling(s) at h{height} some node had")
    ok = True
    try:
        mid_q = h.quiesce(180)
        mid = {n.i: n.digests() for n in h.nodes}
        ev.append(f"after invalidate: agreed tip {mid_q}")
        for n in h.nodes:
            new = n.read_log("pool_sv2")[log_len[n.i]:]
            undone = len(re.findall("left the best chain", new))
            mine = logged(new, bh, "NP_SETTLE: block left the best chain; its retirements are undone")
            disc = n.status()["settlement"]["disconnected"] - disc0[n.i]
            changed = mid[n.i]["retirements"] != before[n.i]["retirements"]
            good = mine and disc >= tip - height + 1 and changed
            ok &= good
            ev.append(f"node{n.i}: 'left the best chain' logged for {undone} blocks incl. h{height}={mine};"
                      f" disconnected +{disc}; retirements {before[n.i]['retirement_rows']} -> {mid[n.i]['retirement_rows']}")
        if len({json.dumps(d, sort_keys=True) for d in mid.values()}) != 1:
            ok = False
            ev.append("store digests DIFFER across nodes after the undo")
        else:
            ev.append(f"store digests equal on every node after the undo: {mid[0]}")
        # Only the block itself: its stale siblings stay invalid, so no node can tie-break onto one.
        log_len = {n.i: len(n.read_log("pool_sv2")) for n in h.nodes}
        for n in nodes:
            n.rpc("reconsiderblock", bh)
        end_q = h.quiesce(180)
        after = {n.i: n.digests() for n in h.nodes}
        ev.append(f"after reconsider: agreed tip {end_q}")
        for n in h.nodes:
            new = n.read_log("pool_sv2")[log_len[n.i]:]
            redone = logged(new, bh, "NP_SETTLE: pool block settled")
            same = after[n.i] == before[n.i]
            ok &= redone and same
            ev.append(f"node{n.i}: h{height} settled again={redone}; digests identical to before the reorg={same}")
    except TimeoutError as e:
        ok = False
        ev.append(str(e))
    result("Bitcoin reorg across a pool block: undone and redone identically on every node",
           "PASS" if ok else "FAIL", ev)


def fresh_node(h):
    if not STATE.get("quiet"):
        return result("fresh node syncs from scratch", "UNMEASURED", "no quiet network to join")
    say("\n== a fresh node joins")
    t = time.time()
    n = h.add_node(mine=False)
    ev, ok = [], True
    try:
        q = h.quiesce(h.args.sync_timeout)
        ev.append(f"agreed (height, tip) {q} {time.time() - t:.0f}s after start")
        d0, dn = h.nodes[0].digests(), n.digests()
        same = d0 == dn
        ok &= same
        ev.append(f"node0 {d0}")
        ev.append(f"node{n.i} {dn}  -> {'identical' if same else 'DIFFERENT'}")
        log = n.read_log("pool_sv2")
        blocks = STATE.get("pool_blocks") or []
        missing = [hh for hh, bh, _ in blocks if not settled_in(log, bh)]
        ok &= not missing
        ev.append(f"'pool block settled' logged for {len(blocks) - len(missing)}/{len(blocks)} pool blocks"
                  + (f"; missing heights {missing[:10]}" if missing else ""))
    except TimeoutError as e:
        ok = False
        ev.append(str(e))
        st = n.status()
        ev.append(f"node{n.i} status: chain {st['share_chain']} settlement {st['settlement']}")
    result("fresh node syncs from scratch to the same roots", "PASS" if ok else "FAIL", ev)


def audit(h):
    exe = os.path.join(h.args.bin_dir, "ghost-audit")
    if not os.access(exe, os.X_OK):
        return result("ghost-audit against an honest node", "UNMEASURED", f"no {exe}")
    target, peer = h.nodes[0], h.nodes[1 % len(h.nodes)]
    addr, _ = payee("auditor", False)
    data = os.path.join(h.work, "audit")
    argv = [exe, "audit"] + audit_chain_args() + ["--relay-peer", peer.relay_addr(),
            "--data-dir", data, "--rpc-port", str(target.rpc_port), "--rpc-user", RPC_USER,
            "--rpc-password", RPC_PASS, "--stratum", f"127.0.0.1:{target.sv1}",
            "--node-relay", target.relay_addr(), "--address", addr, "--jobs",
            str(h.args.audit_jobs), "--json", "--wait", "180", "--timeout", "120"] + genesis_args(h)
    # New jobs come with new blocks: let the miners go slowly while the auditor listens.
    tr_mark = len(target.read_log("translator"))
    for n in h.nodes:
        n.pause_miners(False)
    t = time.time()
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=600)
    finally:
        for n in h.nodes:
            n.pause_miners(True)
    with open(os.path.join(h.work, "audit.log"), "w") as f:
        f.write(out.stdout + "\n--- stderr\n" + out.stderr)
    reports = []
    for line in out.stdout.splitlines():
        try:
            reports.append(json.loads(line))
        except ValueError:
            pass
    verdicts = [r.get("verdict") for r in reports]
    ok = out.returncode == 0 and len(reports) >= h.args.audit_jobs and all(
        str(v).lower() == "pass" for v in verdicts)
    ev = [f"exit {out.returncode} after {time.time() - t:.0f}s; {len(reports)} jobs judged: {verdicts}"]
    ev += [json.dumps(r)[:300] for r in reports[:4]]
    if not reports:
        ev += [l[:300] for l in (out.stdout + out.stderr).strip().splitlines()[-8:]]
    tr = target.read_log("translator")[tr_mark:]
    refusals = re.findall(r"OpenMiningChannelError\([^)]*\)", tr)
    if refusals:
        drops = 0
        try:
            with open(os.path.join(target.dir, "miner-events.jsonl")) as f:
                drops = sum(1 for l in f if '"disconnect"' in l and json.loads(l)["t"] >= t)
        except OSError:
            pass
        ev.append(f"node{target.i} translator: {refusals[0]} -> 'fallback triggered' x"
                  f"{tr.count('fallback triggered')}; {drops} of node{target.i}'s miner connections dropped")
    verdict = "PASS" if ok else ("UNMEASURED" if reports and all(str(v).lower() in ("pass", "unchecked")
                                                                    for v in verdicts) else "FAIL")
    result("ghost-audit audit against an honest node: every job PASS", verdict, ev)
    try:
        STATE["quiet"] = h.quiesce(180)
    except TimeoutError:
        STATE["quiet"] = None


def genesis_import(h):
    if not h.export_dir:
        return result("genesis table import (migration v65)", "UNMEASURED", "run with --genesis-rows 0")
    ev, ok = [f"{'real' if h.args.genesis_export else 'synthetic'} export: {len(h.genesis)} rows, sha256 {h.export_digest[:16]}.., "
              f"{sum(1 for v in h.genesis.values() if v < 1000)} below the 1,000-sat floor"], True
    roots = set()
    for n in h.honest():
        imp = getattr(n, "genesis_lines", [])
        start = next((l for l in n.read_log("pool_sv2").splitlines() if "NODE_POOL_START:" in l), "")
        st = n.status()["start"]
        r = getattr(n, "genesis_root", None)
        roots.add(r)
        good = (len(imp) == 2 and imp[0].startswith("NODE_POOL_GENESIS_IMPORTED")
                and imp[1].startswith("NODE_POOL_GENESIS_VERIFIED") and f"rows={len(h.genesis)}" in imp[0]
                and f"table_root={r}" in imp[1] and f"genesis_table_digest={r}" in start
                and f"pinned_digest={r}" in start and st["genesis_table_digest"] == r)
        ok &= good
        ev.append(f"node{n.i}: {imp[0][:60] if imp else 'no import'}.. rows={len(h.genesis)} "
                  f"root={str(r)[:16]}..; verify {'VERIFIED' if len(imp) > 1 and 'VERIFIED' in imp[1] else 'missing'};"
                  f" relay started on it, pinned: {f'pinned_digest={r}' in start}")
    ok &= len(roots) == 1
    ev.append(f"one table_root on every node: {len(roots) == 1}")
    result("genesis table import (migration v65): every node imports, verifies and pins one root",
           "PASS" if ok else "FAIL", ev)


def past_halving(h):
    if not h.args.past_halving:
        return result("regtest halving (height 150)", "UNMEASURED",
                      "not run (pass --past-halving). Regtest halves every 150 blocks; pool_sv2 "
                      "follows the relay's network (Halving::REGTEST)")
    n0 = h.honest()[0]
    tip = n0.rpc("getblockcount")
    if tip < 146:
        n0.rpc("generatetoaddress", 146 - tip, payee("bootstrap")[0])
    log_len = {n.i: len(n.read_log("pool_sv2")) for n in h.honest()}
    for n in h.nodes:
        n.pause_miners(False)
    try:
        wait_for(lambda: n0.rpc("getblockcount") >= 155, 300, what="height 155")
    except TimeoutError:
        pass
    for n in h.nodes:
        n.pause_miners(True)
    height = n0.rpc("getblockcount")
    ev, ok = [f"height {height}"], True
    try:
        ev.append(f"agreed (height, share-chain tip): {h.quiesce(240)}")
    except TimeoutError as e:
        ok = False
        ev.append(str(e))
    for n in h.nodes:
        if n.fault:
            continue
        new = n.read_log("pool_sv2")[log_len.get(n.i, 0):]
        m = re.search(r"[^\n]*below the subsidy[^\n]*", new)
        alive = n.procs["pool_sv2"].alive()
        ok &= alive and not m
        ev.append(f"node{n.i}: pool_sv2 alive={alive}; " + (m.group(0)[-200:] if m else "no subsidy error"))
    blocks = [b for b in h.pool_blocks(n0) if b[0] >= 150]
    payees = ({m[2] for n in h.nodes for m in n.miners} | {payee("node0/sv2-device", True)[1]}
              | set(h.genesis))
    fees = {n.fee_script for n in h.nodes}
    ev.append(f"pool blocks at 150 or above: {len(blocks)} (heights {[b[0] for b in blocks]})")
    ok &= bool(blocks)
    for height_, bh, vouts in blocks:
        errs = check_coinbase(height_, vouts, payees, fees)
        settled = [n.i for n in h.honest() if settled_in(n.read_log("pool_sv2"), bh)]
        ok &= not errs and len(settled) == len(h.honest())
        ev.append(f"h{height_}: treasury {vouts[0][0]} + miners = {subsidy(height_)} (regtest era "
                  f"{height_ // 150}): {'exact' if not errs else '; '.join(errs)}; settled on nodes "
                  f"{settled}")
    result("regtest halving (height 150): pool blocks continue, pay the halved subsidy exactly "
           "and settle on every node", "PASS" if ok else "FAIL", ev)


# What ghost-audit must name for each fault: its reason code, and words its detail must hold.
FAULT_REASON = {
    "wrong-treasury": ("wrong_treasury", "not the treasury"),
    "fee-skim": ("fee_skim", "subsidy"),
    "payee-order": ("outputs_not_canonical", "not in rule order"),
    "no-root": ("malformed_coinbase", "no GHNP ledger commitment"),
    "overpay": ("inflated_balance", "canonical is"),
}


def hostile(h):
    if not h.args.hostile_binary:
        return result("hostile node: honest nodes and ghost-audit refuse it by name", "UNMEASURED",
                      "no --hostile-binary (pool_sv2 built with --features np-fault-injection)")
    honest = h.honest()
    for fault in h.args.faults:
        say(f"\n== hostile node: {fault}")
        marks = {n.i: len(n.read_log("pool_sv2")) for n in honest}
        before = {n.i: n.status()["settlement"] for n in honest}
        start = honest[0].rpc("getblockcount")
        stats0 = {n.i: n.status()["relay_stats"] for n in honest}
        # Mostly anchors, so honest relays meet the fault in an anchor's own share as well.
        bad = h.add_node(mine=True, fault=fault, agents=[("bitaxe/v2.10.0", 500)], anchor_odds=0.7)
        ev, ok = [], True

        def hostile_blocks():
            """Best-chain blocks the hostile node's miners found: every share they submit is a
            Bitcoin block (cpu_miner.py), so their share hashes name the blocks, whatever the
            fault left in the coinbase."""
            out = []
            for e in miner_events(bad):
                if e["ev"] != "share":
                    continue
                try:
                    hdr = honest[0].rpc("getblockheader", e["hash"])
                except RuntimeError:
                    continue  # never reached this node, or not a block
                if hdr.get("confirmations", -1) < 1 or hdr["height"] <= start:
                    continue
                cb = honest[0].rpc("getblock", e["hash"], 2)["tx"][0]
                vouts = [(round(v["value"] * 1e8), v["scriptPubKey"]["hex"]) for v in cb["vout"]]
                out.append((hdr["height"], e["hash"], vouts))
            return sorted(set((x, y, tuple(z)) for x, y, z in out))
        try:
            wait_for(lambda: len(hostile_blocks()) >= h.args.hostile_blocks, 240, step=3,
                     what=f"{h.args.hostile_blocks} blocks from the hostile node")
        except TimeoutError as e:
            ev.append(str(e))
        bad.pause_miners(True)
        fault_line = next((l for l in bad.read_log("pool_sv2").splitlines() if "NODE_POOL_FAULT" in l), "")
        ev.append(f"node{bad.i} pool_sv2: {fault_line.split('NODE_POOL_FAULT: ', 1)[-1][:120] or 'no fault line'}")
        blocks = hostile_blocks()
        STATE.setdefault("hostile_hashes", set()).update(bh for _, bh, _ in blocks)
        ev.append(f"{len(blocks)} blocks found by the hostile node: heights {[b[0] for b in blocks]}; "
                  f"miner outputs {[len(v) - 3 for _, _, v in blocks]}")
        try:
            h.quiesce(180)
        except TimeoutError as e:
            ok = False
            ev.append(str(e))
        for n in honest:
            new = n.read_log("pool_sv2")[marks[n.i]:]
            refused = [bh for _, bh, _ in blocks
                       if logged(new, bh, "does not pay its anchor's canonical outputs")]
            anchors = len(re.findall(r"invalid anchor: its own share: coinbase outputs are not canonical", new))
            st = n.status()["settlement"]
            rs = n.status()["relay_stats"]
            refused_shares = {k: rs[k] - stats0[n.i][k] for k in ("shares_invalid", "shares_stale", "anchors_invalid")}
            mism = st["mismatched"] - before[n.i]["mismatched"]
            # Nothing the hostile node's miner mined is credited on an honest node.
            credited = [m[1] for m in bad.miners
                        if int(n.ledger(m[1]).get("balance", {}).get("units", 0) or 0) != 0]
            settled = [bh for _, bh, _ in blocks if logged(new, bh, "NP_SETTLE: pool block settled")]
            good = (len(refused) == len(blocks) and len(blocks) > 0 and mism >= len(blocks)
                    and not credited and not settled)
            ok &= good
            ev.append(f"node{n.i}: 'does not pay its anchor's canonical outputs' for {len(refused)}/{len(blocks)}"
                      f" hostile blocks; settled {len(settled)}; mismatched +{mism}; hostile miner credited: "
                      f"{credited or 'no'}; hostile anchors refused as 'coinbase outputs are "
                      f"not canonical': {anchors}; relay counters {refused_shares}")
        digests = {n.i: n.digests() for n in honest}
        same = len({json.dumps(d, sort_keys=True) for d in digests.values()}) == 1
        ok &= same
        ev.append(f"honest nodes' stores {'identical' if same else 'DIFFER'}: {digests[honest[0].i]}")
        # ghost-audit against the hostile node must FAIL, naming the fault.
        exe = os.path.join(h.args.bin_dir, "ghost-audit")
        addr, _ = payee(f"auditor/{fault}")
        argv = [exe, "audit"] + audit_chain_args() + ["--relay-peer", honest[0].relay_addr(),
                "--data-dir", os.path.join(h.work, f"audit-{fault}"), "--rpc-port", str(honest[0].rpc_port),
                "--rpc-user", RPC_USER, "--rpc-password", RPC_PASS, "--stratum", f"127.0.0.1:{bad.sv1}",
                "--node-relay", bad.relay_addr(), "--address", addr, "--jobs", "1", "--json",
                "--wait", "120", "--timeout", "120"] + genesis_args(h)
        out = subprocess.run(argv, capture_output=True, text=True, timeout=400)
        with open(os.path.join(h.work, f"audit-{fault}.log"), "w") as f:
            f.write(out.stdout + "\n--- stderr\n" + out.stderr)
        reports = [json.loads(l) for l in out.stdout.splitlines() if l.startswith("{")]
        code, words = FAULT_REASON[fault]
        named = any(r.get("reason") == code and words in str(r.get("detail")) for r in reports)
        failed = any(str(r.get("verdict")).lower() == "fail" for r in reports)
        ok &= named and failed
        ev.append(f"ghost-audit vs node{bad.i}: exit {out.returncode}; " +
                  (json.dumps(reports[0])[:260] if reports else (out.stdout + out.stderr).strip()[-260:]))
        bad.stop()
        result(f"hostile node ({fault}): honest nodes and ghost-audit refuse it by name; honest nodes agree",
               "PASS" if ok else "FAIL", ev)


ALL = [bringup, genesis_import, mine, balances_agree, serial_miner, one_refused_miner, blocks_settle, early_blocks,
       slot_classes,
       bitcoin_reorg, fresh_node, audit, hostile, past_halving]
