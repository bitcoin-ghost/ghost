"""Scenarios for harness.py --network signet: plan Phase 3, "our own signet" stage.

A custom signet of the run's own (harness.configure_network): plain blocks from ghostd's
generatetoaddress up to the genesis anchor and 20 past it (the Phase 4 operational rule), then
pool wins on demand from the nodes' CPU miners, paused and resumed by the harness. Every node is
pool_sv2 + relay + ghost-mining + translator + its own ghostd, peered only with each other.

The scenarios that are the same on every network come from scenarios.py; this file adds the
signet ones and runs them in this order. Each reports PASS, FAIL or UNMEASURED with evidence; a
reading that could not be taken is UNMEASURED, never a pass.

On a low-difficulty chain one network share credits far more than a block pays (2^10 against a
difficulty of 0.0011), so once miners' credits reach a snapshot (20 blocks after their first
share) every block pays them, and a block's other outputs are only the genesis table's small
balances in the oldest half. A coinbase paying 500 balances in full (503 outputs, no fees so no
finder output) is therefore built while the snapshot still holds only the genesis table: job
heights genesis + 21 to genesis + 40. The full-class miners climb the slot classes there.
"""
import json
import os
import re
import sys
import time

import harness as HX
from harness import (CUT_LAG, FIRST_EARNING_HEIGHT, GENESIS_ANCHOR, GENESIS_HEIGHT, REPO,
                     SIGNET_CHALLENGE, SLOT_CLASSES, TREASURY_SCRIPT, check_coinbase, logged,
                     payee, result, say, subsidy, wait_for)
import scenarios as S
from scenarios import STATE, _progress, miner_events, settled_in

sys.path.insert(0, os.path.join(REPO, "docs", "node-pool-reference"))
import refimpl_v3 as R  # noqa: E402 - the normative payout rule, used to check every coinbase

# The full-class agent (ESP-Miner up to 2.15, ceiling 500) and, per node, the others, so that
# every class is sensed somewhere.
FULL = ("bitaxe/v2.10.0", 500)
OTHERS = {0: [("bmminer/2.0.0", 9), ("cpuminer/2.5", 3)], 1: [("Antminer S21/Thu Jan 1", 44)],
          2: [("whatsminer/v1.1", 143)], 3: [("bosminer/1.0", 364)]}
# Rows a full-class miner's climb pays (one block at each class below 500) plus its 500.
CLIMB_ROWS = 3 + 9 + 44 + 143 + 364 + 500
# The last job height whose snapshot can hold only the genesis table.
LAST_GENESIS_ONLY = FIRST_EARNING_HEIGHT + CUT_LAG - 1


def start_node_miners(h, n):
    """A full-class miner process (`miner-full`) and one for the node's other agents
    (`miner`), both paused: pool wins come on demand."""
    full_user = payee(f"node{n.i}/full", False)
    n.miners.append((f"{full_user[0]}.full", full_user[0], full_user[1], FULL[0], FULL[1]))
    n.start_miners([(f"{full_user[0]}.full", FULL[0])], h.args.pace, h.args.anchor_odds,
                   name="miner-full")
    specs = []
    for k, (agent, cls) in enumerate(OTHERS.get(n.i % 4, [])):
        addr, script = payee(f"node{n.i}/miner{k}", k % 2 == 0)
        n.miners.append((f"{addr}.w{k}", addr, script, agent, cls))
        specs.append((f"{addr}.w{k}", agent))
    if specs:
        n.start_miners(specs, h.args.pace, h.args.anchor_odds, name="miner")
    n.pause_miners(True)


def bringup(h):
    say("\n== bring-up (signet)")
    t = time.time()
    for _ in range(h.args.nodes):
        n = h.add_node(mine=False)
        start_node_miners(h, n)
    ev, ok = [f"{len(h.nodes)} nodes up in {time.time() - t:.0f}s; signet challenge "
              f"{SIGNET_CHALLENGE} (network id push, OP_DROP, OP_TRUE)"], True
    for n in h.nodes:
        line = next((l for l in n.read_log("pool_sv2").splitlines() if "NODE_POOL_START:" in l), "")
        good = (f"network=signet genesis_anchor={GENESIS_ANCHOR} genesis_btc_height={GENESIS_HEIGHT}"
                in line and f"tier_base={HX.TIER_BASE}" in line)
        ok &= good
        ev.append(f"node{n.i}: " + (line.split("NODE_POOL_START: ", 1)[1][:200] if line else "no NODE_POOL_START line"))
    try:
        wait_for(lambda: all(n.status()["peers"] >= len(h.nodes) - 1 for n in h.nodes), 90,
                 what="relay peers")
        ev.append("relay peers: " + ", ".join(f"node{n.i}={n.status()['peers']}" for n in h.nodes))
    except TimeoutError as e:
        ok = False
        ev.append(str(e))
    result("bring-up: every node on the run's signet genesis, relays peered", "PASS" if ok else "FAIL", ev)


def signet_chain(h):
    """Each ghostd is on the run's own signet, peered only with the run's other ghostds, and
    on one chain: genesis + 20 plain blocks, mined by ghostd itself."""
    ev, ok = [], True
    ports = {n.p2p for n in h.nodes}
    tips = set()
    for n in h.nodes:
        bc = n.rpc("getblockchaininfo")
        gbt = n.rpc("getblocktemplate", {"rules": ["segwit", "signet"]})
        peers = n.rpc("getpeerinfo")
        hosts = {p["addr"].rsplit(":", 1)[0] for p in peers}
        outbound = {int(p["addr"].rsplit(":", 1)[1]) for p in peers if not p["inbound"]}
        good = (bc["chain"] == "signet" and gbt.get("signet_challenge") == SIGNET_CHALLENGE
                and hosts <= {"127.0.0.1"} and outbound <= ports and len(peers) >= 1)
        ok &= good
        tips.add((bc["blocks"], bc["bestblockhash"]))
        ev.append(f"node{n.i}: chain={bc['chain']} blocks={bc['blocks']} challenge "
                  f"{'ours' if gbt.get('signet_challenge') == SIGNET_CHALLENGE else gbt.get('signet_challenge')}"
                  f"; peers {len(peers)}, all on 127.0.0.1: {hosts <= {'127.0.0.1'}}, outbound to run "
                  f"nodes only: {outbound <= ports}; bits {gbt.get('bits')}")
    ok &= len(tips) == 1
    height = min(t[0] for t in tips)
    ok &= height >= HX.BOOTSTRAP_HEIGHT
    plain = sum(1 for b in h.pool_blocks(h.nodes[0]))
    ok &= plain == 0
    ev.append(f"one tip on every node: {len(tips) == 1} at height {height}; pool blocks so far {plain} "
              f"(genesis anchor at {GENESIS_HEIGHT}, plain blocks to {HX.BOOTSTRAP_HEIGHT}, first pool "
              f"job at {FIRST_EARNING_HEIGHT})")
    result("signet: each ghostd on the run's own signet, peered only with the run's nodes",
           "PASS" if ok else "FAIL", ev)


# ---------------------------------------------------------------------------------------------
def ref_state(h):
    """The genesis table as the payout rule's reference reads it: owed in face units,
    queue_since at the export height for balances at or above the floor."""
    st = {}
    for sc, sats in h.genesis.items():
        owed = sats << 32
        st[bytes.fromhex(sc)] = (owed, HX.EXPORT_HEIGHT if owed >= R.FLOOR else None)
    return st


def verify_exact(h, blocks):
    """Recompute every pool block whose snapshot can only be the genesis table (job height up
    to LAST_GENESIS_ONLY) with refimpl_v3, folding each block's retirements into the next, and
    compare the whole coinbase: treasury (S/200 + change), every miner output in rule order, the
    finder, the ledger root. Returns per-block rows and the problems."""
    assert R.TREASURY_SCRIPT.hex() == TREASURY_SCRIPT, "refimpl's treasury is not the harness's"
    state = ref_state(h)
    rows, problems = [], []
    for height, bh, vouts in sorted(blocks):
        if height > LAST_GENESIS_ONLY:
            break
        actual = [(v, bytes.fromhex(sc)) for v, sc in vouts]
        witness = actual[-1][1][6:]
        fees = sum(v for v, _ in actual) - subsidy(height)
        finder = actual[-3] if fees > 0 else (0, b"")
        match = None
        for cls in SLOT_CLASSES:
            want, _ = R.coinbase_outputs(height, state, cls, finder[1], finder[0], witness)
            if want == actual:
                match = cls
                break
        if match is None:
            problems.append(f"h{height} {bh[:16]}: no slot class's refimpl_v3 coinbase equals it "
                            f"({len(actual)} outputs)")
            break
        tre, outs, retired, info = R.build_outputs(height, state, match)
        rows.append({"height": height, "hash": bh, "class": match, "outputs": len(actual),
                     "paid": len(outs), "oldest": info["paid_oldest"],
                     "largest": len(outs) - info["paid_oldest"], "sats": sum(p for _, p in outs),
                     "treasury": tre, "change": info["change"],
                     "below_floor": sum(1 for _, p in outs if p < R.MIN_PAY)})
        R.apply_block(state, retired)
    return rows, problems


def pool_blocks_honest(h):
    return [b for b in h.pool_blocks(h.nodes[0]) if b[1] not in STATE.get("hostile_hashes", set())]


def genesis_payouts(h):
    """Wins on demand while the snapshot is the genesis table alone: full-class miners climb the
    slot classes one node at a time, each until it finds a block paying 500 balances (503
    outputs), and every such block must settle on every node, exactly as refimpl_v3 builds it."""
    eligible = sum(1 for v in h.genesis.values() if v >= 1000)
    climbers = max(1, min(len(h.nodes), 3, eligible // CLIMB_ROWS))
    say(f"\n== genesis payouts: {climbers} full-class climber(s); {eligible} eligible genesis rows; "
        f"genesis-only snapshots through job height {LAST_GENESIS_ONLY}")
    ev, ok = [], True
    full_blocks = []
    for n in h.nodes[:climbers]:
        t = time.time()
        n.pause_miners(False, only=["miner-full"])
        try:
            def full():
                if h.nodes[0].rpc("getblockcount") >= LAST_GENESIS_ONLY:
                    return "limit"
                return next((b for b in pool_blocks_honest(h) if len(b[2]) >= 503
                             and b[1] not in {x[1] for x in full_blocks}), None)
            got = wait_for(full, 600, step=2, what=f"node{n.i}'s full-class block")
        except TimeoutError as e:
            got = None
            ev.append(f"node{n.i}: {e}")
        n.pause_miners(True, only=["miner-full"])
        if isinstance(got, tuple):
            full_blocks.append(got)
            ev.append(f"node{n.i}: climbed to class 500 and found h{got[0]} {got[1][:16]}.. with "
                      f"{len(got[2])} outputs in {time.time() - t:.0f}s")
        else:
            ev.append(f"node{n.i}: no 503-output block before height {LAST_GENESIS_ONLY} ({got})")
    try:
        STATE["quiet"] = h.quiesce(240)
    except TimeoutError as e:
        STATE["quiet"] = None
        ok = False
        ev.append(str(e))
    blocks = pool_blocks_honest(h)
    rows, problems = verify_exact(h, blocks)
    STATE["exact_rows"] = rows
    ok &= bool(full_blocks) and not problems
    ev += problems
    for r in rows:
        ev.append(f"h{r['height']}: class {r['class']}, {r['outputs']} outputs, {r['paid']} paid "
                  f"({r['oldest']} oldest + {r['largest']} largest), {r['sats']} sats to miners, "
                  f"treasury {r['treasury']} = S/200 + change {r['change']}: exact (refimpl_v3)")
    for height, bh, vouts in full_blocks:
        miners = vouts[1:-2]
        row = next((r for r in rows if r["hash"] == bh), None)
        exact = row is not None and row["class"] == 500 and row["paid"] == 500
        halves = row is not None and row["oldest"] == 250 and row["largest"] == 250
        floor = all(v >= 1000 for v, _ in miners)
        sums = (vouts[0][0] + sum(v for v, _ in miners) == subsidy(height)
                and vouts[0][0] == subsidy(height) // 200 + (row or {}).get("change", -1))
        payees = [n.i for n in h.honest() if any(
            bh in l and "NP_SETTLE: pool block settled" in l and "payees=500" in l and "slot_class=500" in l
            for l in n.read_log("pool_sv2").splitlines())]
        good = exact and halves and floor and sums and len(payees) == len(h.honest())
        ok &= good
        ev.append(f"503-output block h{height} {bh[:16]}..: refimpl_v3 exact {exact}; halves 250 oldest + "
                  f"250 largest {halves}; every output >= 1,000 sats {floor}; treasury + miners = subsidy "
                  f"and treasury = S/200 + change {sums}; settled (slot_class=500 payees=500) on nodes "
                  f"{payees} of {[n.i for n in h.honest()]}")
    STATE["full_blocks"] = full_blocks
    result("genesis payouts: a 503-output coinbase from the imported table, built, exact and "
           "settled on every node", "PASS" if ok else "FAIL", ev)


def hostile(h):
    """scenarios.hostile with the signet faults; the hostile nodes are retired afterwards."""
    S.hostile(h)
    for n in [n for n in h.nodes if n.fault]:
        h.retire(n)


def mine(h):
    """Pool wins on demand across many blocks: every honest miner resumed until the target."""
    n0 = h.nodes[0]
    start = n0.rpc("getblockcount")
    target = start + h.args.signet_blocks
    say(f"\n== mining from {start} to {target}")
    inv0 = {n.i: n.status()["relay_stats"]["anchors_invalid"] for n in h.nodes}
    blocks0 = len(pool_blocks_honest(h))
    for n in h.nodes:
        n.pause_miners(False)
    deadline, last = time.time() + h.args.mine_timeout, 0
    while time.time() < deadline and n0.rpc("getblockcount") < target:
        dead = [f"node{n.i}/{k}" for n in h.nodes for k, p in n.procs.items() if not p.alive()]
        if dead:
            raise RuntimeError(f"processes died while mining: {dead}")
        if time.time() - last > 30:
            _progress(h, "mine")
            last = time.time()
        time.sleep(2)
    for n in h.nodes:
        n.pause_miners(True)
    height = n0.rpc("getblockcount")
    try:
        STATE["quiet"] = h.quiesce(300)
    except TimeoutError as e:
        STATE["quiet"] = None
        say(f"  {e}")
    _progress(h, "quiet")
    st = [n.status() for n in h.nodes]
    inv = {f"node{n.i}": s["relay_stats"]["anchors_invalid"] - inv0[n.i] for n, s in zip(h.nodes, st)}
    found = len(pool_blocks_honest(h)) - blocks0
    finders = {}
    for n in h.nodes:
        for e in miner_events(n):
            if e["ev"] == "share":
                finders[e["hash"]] = n.i
    by_node = {}
    for _, bh, _ in pool_blocks_honest(h):
        if bh in finders:
            by_node[finders[bh]] = by_node.get(finders[bh], 0) + 1
    ok = (height >= target and STATE["quiet"] and found >= h.args.signet_blocks // 2
          and not any(inv.values()) and len(by_node) == len(h.nodes))
    result(f"mining: pool wins on demand from {start} to {target}, one tip on every node",
           "PASS" if ok else "FAIL",
           [f"height {height} after {time.time() - h.t0:.0f}s; {found} pool blocks in this phase",
            f"pool blocks per finding node (whole run): {dict(sorted(by_node.items()))}",
            f"agreed (height, share-chain tip): {STATE['quiet']}",
            f"share chain: {st[0]['share_chain']['anchor_height']} anchors; anchors refused as invalid "
            f"in this phase: {inv}"])


def genesis_exact(h):
    """The whole run's honest pool blocks against the rule: genesis-only ones exactly
    (refimpl_v3), the rest by their sums; and what the genesis table was paid."""
    blocks = STATE.get("pool_blocks") or pool_blocks_honest(h)
    rows, problems = verify_exact(h, blocks)
    ev, ok = list(problems), not problems
    payees = {m[2] for n in h.all_nodes() for m in n.miners} | set(h.genesis)
    fees = {n.fee_script for n in h.all_nodes()}
    bad = [(b[0], check_coinbase(b[0], b[2], payees, fees)) for b in blocks]
    bad = [(x, e) for x, e in bad if e]
    ok &= not bad
    ev += [f"h{x}: {'; '.join(e)}" for x, e in bad[:6]]
    paid, outputs, change = {}, 0, 0
    for height, _, vouts in blocks:
        for v, sc in vouts[1:-2]:
            if sc in payees and sc not in fees:
                paid[sc] = paid.get(sc, 0) + v
                outputs += 1
        change += vouts[0][0] - subsidy(height) // 200
    g = {sc: v for sc, v in paid.items() if sc in h.genesis}
    full = sum(1 for sc, v in g.items() if v == h.genesis[sc])
    over = [sc for sc, v in g.items() if v > h.genesis[sc]]
    below = [sc for sc in g if h.genesis[sc] < 1000]
    ok &= not over and not below and bool(rows)
    sizes = sorted({r["outputs"] for r in rows})
    ev.append(f"{len(blocks)} honest pool blocks; {len(rows)} on genesis-only snapshots, every one equal "
              f"to refimpl_v3's coinbase (classes {sorted({r['class'] for r in rows})}, output counts {sizes})")
    ev.append(f"coinbase sums exact on {len(blocks) - len(bad)} of {len(blocks)} (treasury + miners = "
              f"subsidy, treasury >= S/200, every miner output >= 1,000 sats, finder = fees)")
    ev.append(f"{outputs} miner outputs paid to {len(paid)} payees; genesis rows: {full} paid in full, "
              f"{len(g) - full} partly, {len(h.genesis) - len(g)} not paid (of them "
              f"{sum(1 for v in h.genesis.values() if v < 1000)} below the floor, never payable); overpaid "
              f"{len(over)}; below-floor rows paid {len(below)}; {sum(g.values())} of "
              f"{sum(h.genesis.values())} genesis sats paid")
    ev.append(f"change to the treasury over the run (treasury less S/200, summed over the blocks): "
              f"{change} sats")
    result("payout rule over the run: genesis-only blocks exact against refimpl_v3; sums, floor "
           "and change exact on every block", "PASS" if ok else "FAIL", ev)


def genesis_rule(h):
    """Plan Phase 4's operational rule, rehearsed: the genesis anchor sits 20 blocks below the
    first pool job, so no work is void, and nodes say where earning starts."""
    blocks = STATE.get("pool_blocks") or pool_blocks_honest(h)
    first = min((b[0] for b in blocks), default=None)
    ev = [f"genesis anchor at {GENESIS_HEIGHT}; plain blocks to {HX.BOOTSTRAP_HEIGHT}; first pool block "
          f"at {first}; first earning height {FIRST_EARNING_HEIGHT}"]
    ok = first is not None and first >= FIRST_EARNING_HEIGHT
    for n in h.honest():
        log = n.read_log("pool_sv2")
        void = len(re.findall(r"NODE_POOL_VOID_WORK", log))
        st = n.status().get("earning") or {}
        good = void == 0 and st.get("first_earning_height") == FIRST_EARNING_HEIGHT and st.get("earns") is True
        ok &= good
        ev.append(f"node{n.i}: NODE_POOL_VOID_WORK lines {void}; status earning={st}")
    result("genesis anchor 20 blocks before the first pool job: no void work, earning from "
           "genesis + 21 on every node", "PASS" if ok else "FAIL", ev)


def signet_reorg(h):
    """A reorg of several blocks across a paying pool block: invalidate it everywhere, mine a
    shorter competing branch, then reconsider it so the original branch wins back. Settlement
    must be undone, and redone identically."""
    blocks = STATE.get("pool_blocks") or []
    n0 = h.nodes[0]
    tip = n0.rpc("getblockcount")
    depth = h.args.reorg_depth
    paying = [b for b in blocks if b[0] <= tip - depth + 1 and len(b[2]) >= 4
              and not b[2][1][1].startswith("6a")]
    if not STATE.get("quiet") or not paying:
        return result("signet reorg across pool blocks", "UNMEASURED",
                      f"no quiet chain with a paying pool block {depth} or more below the tip")
    height, bh, vouts = paying[-1]
    reorged = [b for b in blocks if b[0] >= height]
    before = {n.i: n.digests() for n in h.nodes}
    log_len = {n.i: len(n.read_log("pool_sv2")) for n in h.nodes}
    disc0 = {n.i: n.status()["settlement"]["disconnected"] for n in h.nodes}
    ev = [f"invalidateblock h{height} {bh[:16]}.. on every node: {tip - height + 1} blocks off the "
          f"best chain, {len(reorged)} of them pool blocks paying "
          f"{sum(len(v) - 3 for _, _, v in reorged)} outputs; tip was {tip}"]
    nodes = h.honest()
    for n in nodes:
        n.rpc("invalidateblock", bh)
    for _ in range(6):
        above = {n.rpc("getblockhash", height) for n in nodes if n.rpc("getblockcount") >= height}
        if not above:
            break
        for x in above:
            for n in nodes:
                try:
                    n.rpc("invalidateblock", x)
                except RuntimeError:
                    pass
    ok = True
    try:
        # A competing branch, shorter than the one invalidated: one plain block from ghostd.
        alt = h.generate(n0, 1, tag="reorg")[0]
        wait_for(lambda: all(n.rpc("getbestblockhash") == alt for n in nodes), 120,
                 what="every node on the competing block")
        mid_q = h.quiesce(240)
        mid = {n.i: n.digests() for n in h.nodes}
        ev.append(f"competing branch: plain block {alt[:16]}.. at h{height}; agreed {mid_q}")
        for n in h.nodes:
            new = n.read_log("pool_sv2")[log_len[n.i]:]
            undone = [b for b in reorged if logged(new, b[1], "NP_SETTLE: block left the best chain")]
            disc = n.status()["settlement"]["disconnected"] - disc0[n.i]
            good = len(undone) == len(reorged) and disc >= tip - height + 1
            good &= mid[n.i]["retirement_rows"] < before[n.i]["retirement_rows"]
            ok &= good
            ev.append(f"node{n.i}: 'left the best chain; its retirements are undone' for {len(undone)}/"
                      f"{len(reorged)} pool blocks; disconnected +{disc}; retirements "
                      f"{before[n.i]['retirement_rows']} -> {mid[n.i]['retirement_rows']}")
        same = len({json.dumps(d, sort_keys=True) for d in mid.values()}) == 1
        ok &= same
        ev.append(f"store digests {'equal on every node' if same else 'DIFFER'} on the competing branch")
        # Marked before reconsidering: a fast node settles the first block again at once.
        log_len = {n.i: len(n.read_log("pool_sv2")) for n in h.nodes}
        for n in nodes:
            n.rpc("reconsiderblock", bh)
        wait_for(lambda: all(n.rpc("getblockcount") == tip for n in nodes), 180,
                 what="every node back on the original branch")
        end_q = h.quiesce(240)
        after = {n.i: n.digests() for n in h.nodes}
        ev.append(f"reconsiderblock: back on the original branch, agreed {end_q}")
        for n in h.nodes:
            new = n.read_log("pool_sv2")[log_len[n.i]:]
            redone = [b for b in reorged if logged(new, b[1], "NP_SETTLE: pool block settled")]
            same = after[n.i] == before[n.i]
            ok &= len(redone) == len(reorged) and same
            ev.append(f"node{n.i}: settled again {len(redone)}/{len(reorged)}; store digests identical to "
                      f"before the reorg: {same}")
    except TimeoutError as e:
        ok = False
        ev.append(str(e))
    result(f"signet reorg of {tip - height + 1} blocks across {len(reorged)} pool blocks: settlement "
           "undone and redone identically on every node", "PASS" if ok else "FAIL", ev)


import scenarios_resilience as RS  # noqa: E402 - partition, lying sync peer, soak

ALL = [bringup, S.genesis_import, signet_chain, genesis_payouts, hostile, mine, S.balances_agree,
       S.blocks_settle, genesis_exact, genesis_rule, S.slot_classes, signet_reorg, RS.partition,
       S.balances_agree, S.blocks_settle, RS.lying_peer, S.fresh_node, S.audit]

# --soak-minutes: bring the network up, soak it, then check it as the main run does.
SOAK = [bringup, S.genesis_import, signet_chain, RS.soak, S.balances_agree, S.blocks_settle,
        genesis_exact, genesis_rule]
