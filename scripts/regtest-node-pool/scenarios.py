"""Scenarios for harness.py, run in order. Each reports PASS, FAIL or UNMEASURED with evidence;
a reading that could not be taken is UNMEASURED, never a pass."""
import json
import os
import re
import subprocess
import time

from harness import (logged, RPC_PASS, RPC_USER, SLOT_CLASSES, TREASURY_SCRIPT as TREASURY, check_coinbase,
                     payee, regtest_subsidy, result, say, subsidy, wait_for)

def settled_in(log, bh):
    """The block was settled against its anchor: directly, or provisionally and then confirmed."""
    return logged(log, bh, "NP_SETTLE: pool block settled") or (
        logged(log, bh, "NP_SETTLE: pool block retired provisionally")
        and logged(log, bh, "NP_SETTLE: provisional block confirmed by its anchor"))


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
        if not line or "network=regtest" not in line or "genesis_btc_height=0" not in line:
            ok = False
        ev.append(f"node{n.i}: " + (line.split("NODE_POOL_START: ", 1)[1][:150] if line else "no NODE_POOL_START line"))
    try:
        wait_for(lambda: all(n.status()["peers"] >= len(h.nodes) - 1 for n in h.nodes), 60,
                 what="relay peers")
        ev.append("relay peers: " + ", ".join(f"node{n.i}={n.status()['peers']}" for n in h.nodes))
    except TimeoutError as e:
        ok = False
        ev.append(str(e))
    result("bring-up: every node on the regtest genesis, relays peered", "PASS" if ok else "FAIL", ev)


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
        seen = []
        for n in h.nodes:
            led = n.ledger(addr)
            seen.append((n.i, led.get("balance", {}).get("units"), len(led.get("recent_shares", []))))
        units = {s[1] for s in seen}
        credited = all(s[1] and int(s[1]) > 0 and s[2] > 0 for s in seen)
        if len(units) != 1 or not credited:
            ok = False
        ev.append(f"node{i} miner {addr[:16]}.. ({agent}): balance units "
                  f"{'equal' if len(units) == 1 else 'DIFFER'} on {len(seen)} nodes = "
                  f"{seen[0][1]}; credited shares per node {[s[2] for s in seen]}")
    result("balances: miners on every node earn, all nodes agree (same store digests)",
           "PASS" if ok else "FAIL", ev)


def blocks_settle(h):
    if not STATE.get("quiet"):
        return result("pool blocks: settled on every node, exact coinbase sums", "UNMEASURED",
                      "the nodes never went quiet")
    n0 = h.nodes[0]
    blocks = h.pool_blocks(n0)
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
        if subsidy(height) != regtest_subsidy(height):
            ok = False
            ev.append(f"h{height}: Ghost's subsidy {subsidy(height)} != regtest's {regtest_subsidy(height)}")
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
        if st["mismatched"] or st["provisional"]:
            ok = False
        ev.append(line)
    result("pool blocks: every node logs settlement for each block; exact coinbase sums",
           "PASS" if ok else "FAIL", ev)


def slot_classes(h):
    ev, ok = [], True
    seen_classes = set()
    for n in h.nodes:
        c = n.db()
        try:
            for cls, cnt in c.execute("SELECT slot_class, count(*) FROM np_shares GROUP BY slot_class"):
                seen_classes.add(cls)
                ev.append(f"node{n.i} store: {cnt} network shares committed slot_class {cls}")
        finally:
            c.close()
        for m in n.status()["miners"]:
            sens = m.get("sensing") or {}
            want = next((cls for (u, a, s, ag, cls) in n.miners if a == m["address"]), None)
            agent_ok = m["kind"] == "standard" or sens.get("agent") not in (None, "SRI/Translator Proxy/")
            reached = m["kind"] == "standard" and m["slot_class"] == 500 or (want and m["slot_class"] == want)
            ok &= bool(agent_ok and reached)
            ev.append(f"node{n.i} {m['kind']} {m['address'][:14]}.. agent={sens.get('agent')!r} "
                      f"model={sens.get('model')!r} class={m['slot_class']} ceiling={sens.get('ceiling_class')} "
                      f"settled={sens.get('settled')} (expected {want if m['kind'] == 'extended' else 500})")
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
    result("slot classes: each class sensed, served and committed by network shares",
           "PASS" if ok else "FAIL", ev)


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
    for n in h.nodes:
        n.rpc("invalidateblock", bh)
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
        for n in h.nodes:
            n.rpc("reconsiderblock", bh)
        log_len = {n.i: len(n.read_log("pool_sv2")) for n in h.nodes}
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
    argv = [exe, "audit", "--network", "regtest", "--relay-peer", f"127.0.0.1:{peer.relay}",
            "--data-dir", data, "--rpc-port", str(target.rpc_port), "--rpc-user", RPC_USER,
            "--rpc-password", RPC_PASS, "--stratum", f"127.0.0.1:{target.sv1}",
            "--node-relay", f"127.0.0.1:{target.relay}", "--address", addr, "--jobs",
            str(h.args.audit_jobs), "--json", "--wait", "180", "--timeout", "120"]
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
    ev, ok = [f"synthetic export: {len(h.genesis)} rows, sha256 {h.export_digest[:16]}.., "
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
                      "not run (pass --past-halving). Regtest halves every 150 blocks; Ghost's subsidy "
                      "follows mainnet's 210,000, so above 149 the template is worth less than the "
                      "canonical coinbase")
    n0 = h.nodes[0]
    tip = n0.rpc("getblockcount")
    if tip < 148:
        n0.rpc("generatetoaddress", 148 - tip, payee("bootstrap")[0])
    log_len = {n.i: len(n.read_log("pool_sv2")) for n in h.nodes}
    for n in h.nodes:
        n.pause_miners(False)
    try:
        wait_for(lambda: n0.rpc("getblockcount") >= 151, 120, what="height 151")
    except TimeoutError:
        pass
    for n in h.nodes:
        n.pause_miners(True)
    height = n0.rpc("getblockcount")
    ev = [f"height {height}"]
    stuck = False
    for n in h.nodes:
        new = n.read_log("pool_sv2")[log_len[n.i]:]
        m = re.search(r"[^\n]*below the subsidy[^\n]*", new)
        alive = n.procs["pool_sv2"].alive()
        stuck |= bool(m) or not alive
        ev.append(f"node{n.i}: pool_sv2 alive={alive}; " + (m.group(0)[-200:] if m else "no subsidy error"))
    blocks = [b for b in h.pool_blocks(n0) if b[0] >= 150]
    ev.append(f"pool blocks at 150 or above: {len(blocks)}")
    result("regtest halving (height 150): pool blocks continue", "FAIL" if stuck or not blocks else "PASS", ev)


FAULT_REASON = {"wrong-treasury": "wrong treasury", "fee-skim": "fee skim"}


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
            out = []
            for height in range(start + 1, honest[0].rpc("getblockcount") + 1):
                bh = honest[0].rpc("getblockhash", height)
                cb = honest[0].rpc("getblock", bh, 2)["tx"][0]
                vouts = [(round(v["value"] * 1e8), v["scriptPubKey"]["hex"]) for v in cb["vout"]]
                if any(sc == bad.fee_script for _, sc in vouts) or vouts[0][1] != TREASURY:
                    out.append((height, bh, vouts))
            return out
        try:
            wait_for(lambda: len(hostile_blocks()) >= h.args.hostile_blocks, 240, step=3,
                     what=f"{h.args.hostile_blocks} blocks from the hostile node")
        except TimeoutError as e:
            ev.append(str(e))
        bad.pause_miners(True)
        fault_line = next((l for l in bad.read_log("pool_sv2").splitlines() if "NODE_POOL_FAULT" in l), "")
        ev.append(f"node{bad.i} pool_sv2: {fault_line.split('NODE_POOL_FAULT: ', 1)[-1][:120] or 'no fault line'}")
        blocks = hostile_blocks()
        ev.append(f"{len(blocks)} blocks found by the hostile node: heights {[b[0] for b in blocks]}")
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
            good = len(refused) == len(blocks) and len(blocks) > 0
            ok &= good
            ev.append(f"node{n.i}: 'does not pay its anchor's canonical outputs' for {len(refused)}/{len(blocks)}"
                      f" hostile blocks; mismatched +{mism}; hostile anchors refused as 'coinbase outputs are "
                      f"not canonical': {anchors}; relay counters {refused_shares}")
        digests = {n.i: n.digests() for n in honest}
        same = len({json.dumps(d, sort_keys=True) for d in digests.values()}) == 1
        ok &= same
        ev.append(f"honest nodes' stores {'identical' if same else 'DIFFER'}: {digests[honest[0].i]}")
        # ghost-audit against the hostile node must FAIL, naming the fault.
        exe = os.path.join(h.args.bin_dir, "ghost-audit")
        addr, _ = payee(f"auditor/{fault}")
        argv = [exe, "audit", "--network", "regtest", "--relay-peer", f"127.0.0.1:{honest[0].relay}",
                "--data-dir", os.path.join(h.work, f"audit-{fault}"), "--rpc-port", str(honest[0].rpc_port),
                "--rpc-user", RPC_USER, "--rpc-password", RPC_PASS, "--stratum", f"127.0.0.1:{bad.sv1}",
                "--node-relay", f"127.0.0.1:{bad.relay}", "--address", addr, "--jobs", "1", "--json",
                "--wait", "120", "--timeout", "120"]
        out = subprocess.run(argv, capture_output=True, text=True, timeout=400)
        with open(os.path.join(h.work, f"audit-{fault}.log"), "w") as f:
            f.write(out.stdout + "\n--- stderr\n" + out.stderr)
        reports = [json.loads(l) for l in out.stdout.splitlines() if l.startswith("{")]
        text = json.dumps(reports).lower()
        named = FAULT_REASON[fault].replace(" ", "_") in text.replace(" ", "_")
        failed = any(str(r.get("verdict")).lower() == "fail" for r in reports)
        ok &= named and failed
        ev.append(f"ghost-audit vs node{bad.i}: exit {out.returncode}; " +
                  (json.dumps(reports[0])[:260] if reports else (out.stdout + out.stderr).strip()[-260:]))
        bad.stop()
        result(f"hostile node ({fault}): honest nodes and ghost-audit refuse it by name; honest nodes agree",
               "PASS" if ok else "FAIL", ev)


ALL = [bringup, genesis_import, mine, balances_agree, blocks_settle, slot_classes, bitcoin_reorg, fresh_node, audit,
       hostile, past_halving]
