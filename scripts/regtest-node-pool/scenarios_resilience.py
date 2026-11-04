"""Signet scenarios past the happy path (plan Phase 3): a share-chain partition, a lying sync
peer, and a soak. Run by harness.py --network signet from scenarios_signet.py; each reports PASS,
FAIL or UNMEASURED with its evidence, and a reading that could not be taken is UNMEASURED.

- partition: the relay network is split in two (every pool_sv2 restarted with only its own
  side's relays as peers; Bitcoin stays one network) for more Bitcoin blocks than the 20-block
  snapshot cut, both sides mining, then healed. Every node must reach one share-chain tip, one
  store digest and one settlement, every block built on the losing side's anchors must be
  settled the same way everywhere, and what happened to the losing side's credit is measured.
- lying_peer: a relay built with np-fault-injection serves tampered sync data
  (GHOST_NP_SYNC_FAULT, ghost-np-relay fault.rs) from a loopback address of its own. A fresh node
  syncs from it alone, then from it and honest peers: it must refuse every lie by name, reach the
  honest digests, and ban nobody but the liar.
- late_table: node0's relay answers every new height's snapshot table past pool_sv2's 2 s budget
  (the hostile build's GHOST_NP_TABLE_LATE_MS) while the network mines: every new tip is held,
  served when its table comes, and the templates that arrive during the hold are given back to
  the channels. pool_sv2 must never exit (the 24 h soak's crash: a SetNewPrevHash for a template
  the replay had dropped, escalated to a shutdown) and no channel may miss a tip.
- soak: the 4-node signet mining for --soak-minutes, miners joining, leaving and stalling past
  their no-share timeout, sampled every minute for memory and store size.
"""
import json
import os
import random
import re
import time

import harness as HX
from harness import AGENTS, payee, result, say, wait_for
import scenarios as S
from scenarios import STATE, _progress, miner_events, settled_in

# What the lying peer's fresh victim must log for each lie: a relay penalty line naming it.
LIE_REFUSAL = {
    "balances": "NP_RELAY: share body:",
    "stamps": "NP_RELAY: anchor: BIP34 height is not btc_height + 1",
    "truncate": "NP_RELAY: batch does not match its root",
}
THIEF_SCRIPT = "5120" + "77" * 32
LIAR_IP, VICTIM_IP = "127.0.0.2", "127.0.0.3"
DIGEST_KEYS = ("ledger", "retirements", "settled_blocks", "batches", "anchors")


def face(b):
    return int.from_bytes(b, "big", signed=True)


def best_chain(n):
    """The anchors of n's best share chain, tip first (upper-case hex)."""
    c = n.db()
    try:
        parent = dict(c.execute("SELECT hex(hash), hex(parent) FROM np_anchors"))
    finally:
        c.close()
    tip = n.status()["share_chain"]["tip"].upper()
    out = []
    while tip in parent:
        out.append(tip)
        tip = parent[tip]
    return out


def chain_credits(n, chain):
    """Every share credited by an anchor of `chain`: share id -> (payee hex, face, job height,
    including anchor's btc_height)."""
    on = set(chain)
    c = n.db()
    try:
        btc = dict(c.execute("SELECT hex(hash), btc_height FROM np_anchors"))
        out = {}
        for a, sid, f, sc, jh in c.execute(
                "SELECT hex(bs.anchor_hash), hex(bs.share_id), bs.face, hex(s.payee_script), "
                "s.job_height FROM np_batch_shares bs JOIN np_shares s ON s.share_id = bs.share_id"):
            if a in on:
                out[sid] = (sc.lower(), face(f), jh, btc.get(a))
        return out
    finally:
        c.close()


def same_digests(nodes):
    d = {n.i: n.digests() for n in nodes}
    differ = [k for k in DIGEST_KEYS if len({x[k] for x in d.values()}) != 1]
    return d, differ


def sats(units):
    return units / 2 ** 32


def partition_blocks(h, nodes, t0, above):
    """Bitcoin blocks on the best chain above height `above` found by the miners of `nodes`
    since t0: {hash: (height, finding node)}."""
    out = {}
    n0 = nodes[0]
    for n in nodes:
        for e in miner_events(n, t0):
            if e["ev"] != "share":
                continue
            try:
                hdr = n0.rpc("getblockheader", e["hash"])
            except RuntimeError:
                continue
            if hdr.get("confirmations", -1) >= 1 and hdr["height"] > above:
                out[e["hash"]] = (hdr["height"], n.i)
    return out


def wait_peers(nodes, want, timeout):
    return wait_for(lambda: all(n.status()["peers"] == want(n) for n in nodes), timeout, step=2,
                    what="relay peers " + ", ".join(f"node{n.i}={want(n)}" for n in nodes))


def partition(h):
    nodes = h.honest()
    name = (f"share-chain partition for {h.args.partition_blocks} Bitcoin blocks: one tip, one "
            "digest and one settlement after healing")
    if len(nodes) < 4 or not STATE.get("quiet"):
        return result(name, "UNMEASURED", f"needs 4 quiet honest nodes; have {len(nodes)}")
    say("\n== share-chain partition")
    A, B = nodes[:2], nodes[2:]
    side_of = {n.i: "A" for n in A} | {n.i: "B" for n in B}
    ev, ok = [], True
    for n in nodes:
        n.pause_miners(True)
    try:
        h.quiesce(240)
    except TimeoutError as e:
        return result(name, "FAIL", [f"not quiet before the split: {e}"])
    pre_chain = best_chain(nodes[0])
    pre_credits = chain_credits(nodes[0], pre_chain)
    hp = nodes[0].rpc("getblockcount")
    marks = {n.i: len(n.read_log("pool_sv2")) for n in nodes}
    reorgs0 = {n.i: n.status()["relay_stats"].get("reorgs", 0) for n in nodes}
    # Split: every pool_sv2 restarted with only its own side's relays. The address book and bans
    # live in memory, so nothing of the other side is remembered.
    t = time.time()
    # Every pool_sv2 stops before any starts: one still running would redial the others.
    for n in nodes:
        for k in n.miner_procs() + ["translator", "pool_sv2"]:
            n.procs[k].stop()
    for grp in (A, B):
        for n in grp:
            n.restart_pool([m.relay_addr() for m in grp if m is not n])
    try:
        wait_peers(nodes, lambda n: 1, 120)
    except TimeoutError as e:
        return result(name, "FAIL", [f"the split did not take: {e}"])
    ev.append(f"split at Bitcoin height {hp} (share-chain tip {pre_chain[0][:16]}.., {len(pre_chain)} "
              f"anchors): side A = nodes {[n.i for n in A]}, side B = nodes {[n.i for n in B]}, "
              f"each pool_sv2 restarted with its side's relay only, in {time.time() - t:.0f}s")
    # Both sides mine; side A with every miner, side B with its full-class miners only, so the
    # two sides' share chains differ in weight.
    t0 = time.time()
    for n in A:
        n.pause_miners(False)
    for n in B:
        n.pause_miners(False, only=["miner-full"])
    target = hp + h.args.partition_blocks
    cross, last = [], 0
    deadline = time.time() + h.args.mine_timeout
    while time.time() < deadline and nodes[0].rpc("getblockcount") < target:
        peers = {n.i: n.status()["peers"] for n in nodes}
        if any(v != 1 for v in peers.values()):
            cross.append(peers)
        if time.time() - last > 30:
            _progress(h, "split")
            last = time.time()
        time.sleep(2)
    for n in nodes:
        n.pause_miners(True)
    hs = nodes[0].rpc("getblockcount")
    ok &= hs >= target and not cross
    ev.append(f"mined to Bitcoin height {hs} ({hs - hp} blocks) in {time.time() - t0:.0f}s; peer "
              f"counts other than 1 seen in {len(cross)} samples {cross[:3]}")
    side_q, side_chain, side_credits = {}, {}, {}
    for label, grp in (("A", A), ("B", B)):
        try:
            side_q[label] = h.quiesce(240, nodes=grp)
        except TimeoutError as e:
            side_q[label] = None
            ok = False
            ev.append(f"side {label} never agreed internally: {e}")
        side_chain[label] = best_chain(grp[0])
        side_credits[label] = chain_credits(grp[0], side_chain[label])
    diverged = side_chain["A"][0] != side_chain["B"][0]
    found = partition_blocks(h, nodes, t0, hp)
    by_side = {s: sorted(v[0] for v in found.values() if side_of[v[1]] == s) for s in "AB"}
    ok &= diverged and all(by_side.values())
    reach = max((v[0] for v in found.values()), default=0)
    ok &= reach - 20 > hp
    ev.append(f"before healing: side A tip {side_chain['A'][0][:16]}.. ({len(side_chain['A'])} anchors), "
              f"side B tip {side_chain['B'][0][:16]}.. ({len(side_chain['B'])} anchors), diverged {diverged}; "
              f"agreed within each side {side_q}")
    ev.append(f"pool blocks found during the split: side A {len(by_side['A'])} (heights "
              f"{by_side['A'][:3]}..{by_side['A'][-2:]}), side B {len(by_side['B'])} (heights "
              f"{by_side['B'][:3]}..{by_side['B'][-2:]}); highest {reach}, so cut(H) = H - 20 = "
              f"{reach - 20} passed the split height {hp}: {reach - 20 > hp}")
    side_ledger = {}
    for label, grp in (("A", A), ("B", B)):
        side_ledger[label] = {m[1]: int(grp[0].ledger(m[1]).get("balance", {}).get("units", 0) or 0)
                              for n in nodes for m in n.miners}
    # Heal: node 0 restarted with every relay; addresses then spread by gossip.
    t = time.time()
    nodes[0].restart_pool([m.relay_addr() for m in nodes if m is not nodes[0]])
    try:
        wait_peers(nodes, lambda n: len(nodes) - 1, 120)
        ev.append(f"healed: node{nodes[0].i} restarted with every relay; full mesh by gossip in "
                  f"{time.time() - t:.0f}s")
    except TimeoutError:
        for n in nodes[1:]:
            n.restart_pool([m.relay_addr() for m in nodes if m is not n])
        ev.append("healed: gossip did not complete the mesh in 120 s, so every pool_sv2 was "
                  "restarted with every relay")
    try:
        q_heal = h.quiesce(300)
        ev.append(f"one tip after healing: {q_heal}")
    except TimeoutError as e:
        ok = False
        ev.append(f"no single tip after healing: {e}")
    healed = best_chain(nodes[0])
    on = set(healed)
    winner = next((s for s in "AB" if side_chain[s][0] in on), None)
    loser = {"A": "B", "B": "A"}.get(winner)
    ok &= winner is not None and side_chain[loser][0] not in on
    # Mine on, every miner, so the losing side's demoted shares can be re-included.
    for n in nodes:
        n.pause_miners(False)
    hh = nodes[0].rpc("getblockcount")
    try:
        wait_for(lambda: nodes[0].rpc("getblockcount") >= hh + h.args.heal_blocks, h.args.mine_timeout,
                 step=2, what=f"{h.args.heal_blocks} blocks after healing")
    except TimeoutError as e:
        ok = False
        ev.append(str(e))
    for n in nodes:
        n.pause_miners(True)
    try:
        STATE["quiet"] = h.quiesce(300)
    except TimeoutError as e:
        STATE["quiet"] = None
        ok = False
        ev.append(str(e))
    he = nodes[0].rpc("getblockcount")
    digests, differ = same_digests(nodes)
    ok &= not differ
    ev.append(f"after {he - hh} more blocks with every miner: agreed {STATE['quiet']}; store digests "
              f"{'identical on every node' if not differ else 'DIFFER on ' + str(differ)}: "
              f"{digests[nodes[0].i]}")
    reorgs = {f"node{n.i}": n.status()["relay_stats"].get("reorgs", 0) - reorgs0[n.i] for n in nodes}
    ev.append(f"winning side {winner} (its pre-heal tip is on the healed chain); losing side {loser}; "
              f"share-chain reorgs since the split {reorgs}")
    # Every block found during the split, on every node: how it was settled.
    loser_anchors = set(side_chain[loser][: len(side_chain[loser]) - len(pre_chain)]) if loser else set()
    for n in nodes:
        new = n.read_log("pool_sv2")[marks[n.i]:]
        kinds = {"settled": 0, "provisional": 0, "confirmed": 0, "mismatch": 0, "none": 0}
        for bh in found:
            if S.logged(new, bh, "does not pay its anchor's canonical outputs"):
                kinds["mismatch"] += 1
            elif S.logged(new, bh, "NP_SETTLE: pool block settled"):
                kinds["settled"] += 1
            elif S.logged(new, bh, "NP_SETTLE: pool block retired provisionally"):
                kinds["provisional"] += 1
                if S.logged(new, bh, "NP_SETTLE: provisional block confirmed by its anchor"):
                    kinds["confirmed"] += 1
            else:
                kinds["none"] += 1
        st = n.status()["settlement"]
        # Every pool_sv2 restarted at the split, so its counters count from then.
        mism = st["mismatched"]
        prov_now = [x for x in st["provisional"]]
        good = kinds["mismatch"] == 0 and kinds["none"] == 0 and mism == 0
        ok &= good
        ev.append(f"node{n.i} (side {side_of[n.i]}): of {len(found)} split blocks, settled against a held "
                  f"anchor {kinds['settled']}, retired provisionally {kinds['provisional']} (later confirmed "
                  f"{kinds['confirmed']}), refused {kinds['mismatch']}, no line {kinds['none']}; mismatched "
                  f"+{mism}; still provisional now {len(prov_now)}")
    # Credit: the losing side's shares, credited on its own chain during the split, against what
    # the healed chain credits.
    final = chain_credits(nodes[0], best_chain(nodes[0]))
    if loser:
        mine = {k: v for k, v in side_credits[loser].items() if k not in pre_credits}
        theirs = {k: v for k, v in side_credits[winner].items() if k not in pre_credits}
        kept = {k: v for k, v in mine.items() if k in final}
        void = {k: v for k, v in mine.items() if k not in final}
        win_lost = [k for k in theirs if k not in final]
        ok &= not win_lost
        fsum = sum(v[1] for v in mine.values())
        ksum = sum(final[k][1] for k in kept)
        ev.append(f"losing side {loser}: {len(mine)} shares credited on its own chain during the split, "
                  f"{sats(fsum):,.0f} sats of face; after healing {len(kept)} re-included on the winning chain "
                  f"({sats(ksum):,.0f} sats, {100 * ksum / fsum if fsum else 0:.1f}% of the face), {len(void)} "
                  f"never credited ({sats(fsum - ksum):,.0f} sats)")
        if void:
            gaps = sorted(v[3] - v[2] for v in void.values() if v[3] is not None)
            jh = sorted(v[2] for v in void.values())
            ev.append(f"  never-credited shares: job heights {jh[0]}..{jh[-1]}; on the losing chain they sat "
                      f"0..{max(gaps) if gaps else '?'} blocks below their including anchor's btc_height; "
                      f"a share re-included later must be within 12 blocks of its new includer (rule 5)")
        if kept:
            kj = sorted(v[2] for v in kept.values())
            ev.append(f"  re-included shares: job heights {kj[0]}..{kj[-1]}")
        ev.append(f"winning side {winner}: {len(theirs)} shares credited during the split, {len(win_lost)} "
                  f"of them lost after healing")
        per = {}
        for k, v in mine.items():
            p = per.setdefault(v[0], [0, 0])
            p[0] += v[1]
            p[1] += final[k][1] if k in final else 0
        for sc, (before, after) in sorted(per.items(), key=lambda kv: -kv[1][0]):
            addr = next((m[1] for n in nodes for m in n.miners if m[2] == sc), sc[:16])
            ev.append(f"  losing-side payee {addr[:16]}..: split credit {sats(before):,.0f} sats, kept "
                      f"{sats(after):,.0f} ({100 * after / before if before else 0:.1f}%); ledger on side "
                      f"{loser} before healing {sats(side_ledger[loser].get(addr, 0)):,.0f} sats, on every node "
                      f"now {sats(int(nodes[0].ledger(addr).get('balance', {}).get('units', 0) or 0)):,.0f}")
    # Blocks the losing side found on its own anchors: a node that never held those anchors
    # (the winning side, a fresh node) retires them provisionally, by what they paid, for good.
    if loser:
        STATE.setdefault("minority_blocks", set()).update(
            bh for bh, (_, i) in found.items() if side_of[i] == loser)
    STATE["pool_blocks"] = [b for b in h.pool_blocks(nodes[0])
                            if b[1] not in STATE.get("hostile_hashes", set())]
    result(name, "PASS" if ok else "FAIL", ev)


# ---------------------------------------------------------------------------------------------
def victim_lines(n, mark, needle):
    return [l for l in n.read_log("pool_sv2")[mark:].splitlines() if needle in l]


def bans(n, mark):
    """(peer address, reason) of every ban n logged since `mark`."""
    out = []
    for l in victim_lines(n, mark, "NP_RELAY: banned"):
        m = re.search(r"peer=(\S+)", l)
        out.append((m.group(1) if m else "?", l.split("NP_RELAY: banned: ", 1)[-1][:80]))
    return out


def lying_peer(h):
    name = ("lying sync peer: a fresh node refuses tampered sync data by name, syncs from honest "
            "peers to the same digests, and bans only the liar")
    if not h.args.hostile_binary:
        return result(name, "UNMEASURED", "no --hostile-binary (pool_sv2 built with --features "
                      "np-fault-injection)")
    honest = h.honest()
    if not STATE.get("quiet") or len(honest) < 2:
        return result(name, "UNMEASURED", "no quiet network")
    say("\n== lying sync peer")
    for n in honest:
        n.pause_miners(True)
    honest_marks = {n.i: len(n.read_log("pool_sv2")) for n in honest}
    faults = list(h.args.sync_faults)
    liar = h.add_node(mine=False, sync_fault=faults[0], relay_ip=LIAR_IP)
    ref = honest[0]
    ev, ok = [], True
    victim = None
    try:
        for k, fault in enumerate(faults):
            if k > 0:
                liar.sync_fault = fault
                liar.restart_pool()
            wait_for(lambda: liar.digests() == ref.digests(), h.args.sync_timeout, step=3,
                     what=f"the liar ({fault}) synced honestly")
            line = next((l for l in liar.read_log("pool_sv2").splitlines()[::-1]
                         if "serves TAMPERED sync data" in l and fault.capitalize() in l), "")
            say(f"  liar node{liar.i} on {liar.relay_addr()} lies with {fault}")
            # Alone with the liar, on a store of its own.
            if victim is None:
                victim = h.add_node(mine=False, relay_ip=VICTIM_IP, peers=[liar])
                mark = 0
            else:
                mark = len(victim.read_log("pool_sv2"))
                victim.restart_pool([liar.relay_addr()], wipe=True)
            time.sleep(h.args.liar_alone_secs)
            refusals = victim_lines(victim, mark, LIE_REFUSAL[fault])
            alone_bans = bans(victim, mark)
            d_alone = victim.digests()
            alone_peers = victim.status()["peers"]
            c = victim.db()
            try:
                thief = c.execute("SELECT count(*) FROM np_ledger WHERE lower(hex(script)) = ?",
                                  (THIEF_SCRIPT,)).fetchone()[0]
                thief_shares = c.execute("SELECT count(*) FROM np_shares WHERE lower(hex(payee_script)) = ?",
                                         (THIEF_SCRIPT,)).fetchone()[0]
            finally:
                c.close()
            ref_d = ref.digests()
            # Alone with a liar that hides its peers, nothing honest reaches the node: it must
            # refuse the lie by name and get nowhere, rather than store anything it was told.
            alone_ok = (bool(refusals) and thief == 0 and thief_shares == 0
                        and d_alone["anchors"] < ref_d["anchors"] and alone_peers <= 1
                        and all(a.startswith(LIAR_IP + ":") for a, _ in alone_bans))
            # Then with honest peers too, the liar first. A restart forgets bans.
            mark2 = len(victim.read_log("pool_sv2"))
            t = time.time()
            victim.restart_pool([liar.relay_addr()] + [n.relay_addr() for n in honest])
            try:
                wait_for(lambda: victim.digests() == ref.digests(), h.args.sync_timeout, step=3,
                         what="the victim at the honest digests")
                synced = f"{time.time() - t:.0f}s"
            except TimeoutError:
                synced = None
            later_refusals = victim_lines(victim, mark2, LIE_REFUSAL[fault])
            later_bans = bans(victim, mark2)
            honest_banned = [b for b in alone_bans + later_bans if not b[0].startswith(LIAR_IP + ":")]
            peers_now = victim.status()["peers"]
            good = alone_ok and synced is not None and not honest_banned
            ok &= good
            ev.append(f"{fault}: liar says '{line.split('NODE_POOL_FAULT: ', 1)[-1][:70]}'; alone with it for "
                      f"{h.args.liar_alone_secs:.0f}s the fresh node logged '{LIE_REFUSAL[fault]}' x{len(refusals)}"
                      f", bans {alone_bans[:2]}, stored the thief's script {thief} times in the ledger and "
                      f"{thief_shares} times in shares, reached {d_alone['anchors']} of {ref_d['anchors']} "
                      f"anchors (ledger rows {d_alone['ledger_rows']} vs {ref_d['ledger_rows']}), relay peers {alone_peers}")
            ev.append(f"{fault}: with the liar and {len(honest)} honest peers: honest digests reached "
                      f"{'in ' + synced if synced else 'NEVER'}; refusals meanwhile {len(later_refusals)}; bans "
                      f"{later_bans[:3]}; bans of anyone but the liar {honest_banned or 'none'}; peers now "
                      f"{peers_now}")
        if "stamps" in faults:
            ok &= audit_vs_liar(h, liar, honest, ev)
    except TimeoutError as e:
        ok = False
        ev.append(str(e))
    finally:
        for n in [x for x in (victim, liar) if x is not None]:
            h.retire(n)
    for n in honest:
        b = bans(n, honest_marks[n.i])
        bad = [x for x in b if not x[0].startswith(LIAR_IP + ":")]
        ok &= not bad
        ev.append(f"honest node{n.i}: bans since the scenario started {b or 'none'}")
    digests, differ = same_digests(h.honest())
    ok &= not differ
    ev.append(f"honest nodes' stores {'identical' if not differ else 'DIFFER on ' + str(differ)}")
    try:
        STATE["quiet"] = h.quiesce(180)
    except TimeoutError:
        STATE["quiet"] = None
    result(name, "PASS" if ok else "FAIL", ev)


def audit_vs_liar(h, liar, honest, ev):
    """ghost-audit against the liar while it serves altered job stamps: it must not pass."""
    exe = os.path.join(h.args.bin_dir, "ghost-audit")
    if not os.access(exe, os.X_OK):
        ev.append("ghost-audit vs the stamps liar: UNMEASURED (no ghost-audit)")
        return True
    liar.sync_fault = "stamps"
    liar.restart_pool()
    addr, _ = payee("auditor/liar")
    argv = [exe, "audit"] + HX.audit_chain_args() + [
        "--relay-peer", honest[0].relay_addr(), "--data-dir", os.path.join(h.work, "audit-liar"),
        "--rpc-port", str(honest[0].rpc_port), "--rpc-user", HX.RPC_USER, "--rpc-password",
        HX.RPC_PASS, "--stratum", f"127.0.0.1:{liar.sv1}", "--node-relay", liar.relay_addr(),
        "--address", addr, "--jobs", "1", "--json", "--wait", "120", "--timeout", "120"] + S.genesis_args(h)
    import subprocess
    out = subprocess.run(argv, capture_output=True, text=True, timeout=400)
    with open(os.path.join(h.work, "audit-liar.log"), "w") as f:
        f.write(out.stdout + "\n--- stderr\n" + out.stderr)
    reports = [json.loads(l) for l in out.stdout.splitlines() if l.startswith("{")]
    failed = any(str(r.get("verdict")).lower() == "fail" and r.get("reason") == "tag_not_binding"
                 for r in reports)
    ev.append(f"ghost-audit vs the liar serving altered job stamps: exit {out.returncode}; " +
              (json.dumps(reports[0])[:240] if reports else (out.stdout + out.stderr).strip()[-240:]))
    return failed


# ---------------------------------------------------------------------------------------------
def late_table(h):
    name = ("late snapshot table: every new tip held for its table, served when it comes, the "
            "templates that arrive meanwhile kept; pool_sv2 never exits, no channel misses a tip")
    if not h.args.hostile_binary:
        return result(name, "UNMEASURED", "no --hostile-binary (pool_sv2 built with --features "
                      "np-fault-injection)")
    n = h.nodes[0]
    say(f"\n== late snapshot table: node0's tables {h.args.table_late_ms} ms late")
    mark = len(n.read_log("pool_sv2"))
    n.table_late_ms = h.args.table_late_ms
    n.restart_pool()
    proc = n.procs["pool_sv2"]
    for m in h.nodes:
        m.pause_miners(False)
    start = n.rpc("getblockcount")
    target = start + h.args.late_table_blocks
    ev, ok = [], True
    deadline, last = time.time() + h.args.mine_timeout, 0
    try:
        while time.time() < deadline and n.rpc("getblockcount") < target:
            if not proc.alive():
                break
            if time.time() - last > 30:
                _progress(h, "late table")
                last = time.time()
            time.sleep(1)
    finally:
        for m in h.nodes:
            m.pause_miners(True)
    height = n.rpc("getblockcount")
    alive = proc.alive()
    # Settle what is in flight before reading the log.
    time.sleep(8)
    alive = alive and proc.alive()
    log = n.read_log("pool_sv2")[mark:]
    counts = {k: log.count(v) for k, v in (
        ("held", "NODE_POOL_NO_TABLE: the new Bitcoin tip is held"),
        ("served", "NODE_POOL: the held tip is served"),
        ("given_back", "arrived during the hold is given back to the channels"),
        ("tip_mismatch", "NODE_POOL_TIP_MISMATCH"),
        ("template_mismatch", "NODE_POOL_TEMPLATE_MISMATCH"),
        ("shutdown", "Pool shutdown complete"),
        ("shares", "Received SubmitSharesExtended"),
    )}
    fault_on = "withholds every snapshot table" in log
    # Every hold must end: served by the tick when its table comes, or left behind by the next
    # SetNewPrevHash that is served at once (the provider's second template on the same tip, or
    # a newer tip). A hold followed only by another hold, or by nothing, is not resolved.
    events = []
    for line in log.splitlines():
        if "NODE_POOL_NO_TABLE: the new Bitcoin tip is held" in line:
            events.append("held")
        elif "NODE_POOL: the held tip is served" in line:
            events.append("served")
        elif "Received: SetNewPrevHash" in line:
            events.append("snph")
    unresolved = 0
    for i, e in enumerate(events):
        if e != "held":
            continue
        rest = events[i + 1:]
        # The held SetNewPrevHash is logged before its "held": what follows decides. A
        # SetNewPrevHash that is itself held replaces this hold and is judged on its own.
        if not rest:
            unresolved += 1
    counts["unresolved"] = unresolved
    mined = height - start
    ok = (alive and fault_on and mined >= h.args.late_table_blocks
          and counts["held"] >= mined // 2 and counts["served"] >= 1 and unresolved == 0
          and counts["shutdown"] == 0 and counts["tip_mismatch"] == 0
          and counts["template_mismatch"] == 0 and counts["shares"] > 0)
    ev.append(f"{mined} Bitcoin blocks ({start} -> {height}) with node0's tables "
              f"{h.args.table_late_ms} ms late (fault line logged: {fault_on}); node0 pool_sv2 "
              f"{'still running, pid ' + str(proc.p.pid) if alive else 'EXITED'}")
    ev.append(f"node0 log: tips held {counts['held']}, held tips served {counts['served']}, future "
              f"templates from during a hold given back {counts['given_back']}, holds never "
              f"resolved {unresolved}, TIP_MISMATCH "
              f"{counts['tip_mismatch']}, TEMPLATE_MISMATCH {counts['template_mismatch']}, shutdowns "
              f"{counts['shutdown']}, shares received {counts['shares']}")
    if counts["given_back"] == 0:
        ev.append("the replay of a template that arrived during a hold did not come up in this run "
                  "(timing): the held-tip path ran, the crash's exact interleaving was not hit")
    # Back to an honest pool_sv2 for whatever runs next.
    n.table_late_ms = None
    n.restart_pool()
    try:
        STATE["quiet"] = h.quiesce(300)
    except TimeoutError as e:
        STATE["quiet"] = None
        ev.append(str(e))
    result(name, "PASS" if ok else "FAIL", ev)


def file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def dir_size(path):
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            total += file_size(os.path.join(root, f))
    return total


def store_bytes(n):
    d = os.path.join(n.dir, "pool")
    return sum(file_size(os.path.join(d, f)) for f in os.listdir(d) if f.startswith("node-pool.db"))


def sample(h, t0):
    nodes = h.honest()
    st = nodes[0].status()
    return {"t": round(time.time() - t0), "btc": nodes[0].rpc("getblockcount"),
            "anchors": st["share_chain"]["anchor_height"],
            "relayed": st["relay_stats"]["shares_accepted"],
            "difficulty": nodes[0].rpc("getdifficulty"), "rss_kb": h.rss_by_process(),
            "store": {f"node{n.i}": store_bytes(n) for n in nodes},
            "bitcoin_dir": {f"node{n.i}": dir_size(os.path.join(n.dir, "bitcoin")) for n in nodes},
            "miners": {f"node{n.i}": sorted(k for k in n.miner_procs() if n.procs[k].alive())
                       for n in nodes}}


LOOSE_STALL_SECS = 3600


def regtest_soak_bringup(h):
    """The soak's bring-up on regtest: the signet soak's miners (a full-class miner and the
    node's other agents, paused until the soak starts), on a chain whose difficulty never moves."""
    import scenarios_signet as SS  # noqa: E402 - only its miner set-up, no signet chain
    say("\n== bring-up (regtest soak)")
    for _ in range(h.args.nodes):
        n = h.add_node(mine=False)
        SS.start_node_miners(h, n)
    ev, ok = [], True
    try:
        wait_for(lambda: all(n.status()["peers"] >= len(h.nodes) - 1 for n in h.nodes), 90,
                 what="relay peers")
        ev.append("relay peers: " + ", ".join(f"node{n.i}={n.status()['peers']}" for n in h.nodes))
    except TimeoutError as e:
        ok = False
        ev.append(str(e))
    result("bring-up (regtest soak): nodes up with full-class and mixed miners, relays peered",
           "PASS" if ok else "FAIL", ev)


def soak(h):
    minutes = h.args.soak_minutes
    name = f"soak: {minutes:.0f} minutes of mining with miners joining, leaving and stalling"
    nodes = h.honest()
    say(f"\n== soak for {minutes:.0f} minutes (pace {h.args.pace}s per miner)")
    rng = random.Random(1234)
    t0 = time.time()
    end = t0 + 60 * minutes
    # The plan, in minutes from the start: a stall every 35 minutes from minute 15 on a different
    # node's full-class miner, a leave every 10 minutes from 3 and a join every 10 from 6.
    stall_at = [15 + 35 * k for k in range(int(minutes // 35) + 1) if 15 + 35 * k + h.args.soak_stall_secs / 60 < minutes - 5]
    stalls = []  # (node, proc, start, end)
    plan = sorted([(m * 60, "stall", k) for k, m in enumerate(stall_at)] +
                  [(m * 60, "leave", k) for k, m in enumerate(range(3, int(minutes) - 5, 10))] +
                  [(m * 60, "join", k) for k, m in enumerate(range(6, int(minutes) - 5, 10))])
    joined, left, log = [], [], []
    path = os.path.join(h.work, "soak-samples.jsonl")
    samples = []
    for n in nodes:
        n.pause_miners(False)
    marks = {n.i: len(n.read_log("pool_sv2")) for n in nodes}
    next_sample, ok, ev = 0, True, []
    while time.time() < end:
        now = time.time() - t0
        while plan and plan[0][0] <= now:
            _, kind, k = plan.pop(0)
            if kind == "stall":
                n = nodes[(1 + k) % len(nodes)]
                n.procs["miner-full"].signal(HX.signal.SIGSTOP)
                stalls.append([n, "miner-full", now, now + h.args.soak_stall_secs])
                log.append(f"{now / 60:.0f}m stall node{n.i}/miner-full for {h.args.soak_stall_secs:.0f}s")
            elif kind == "join":
                n = nodes[rng.randrange(len(nodes))]
                agent, cls = AGENTS[rng.randrange(len(AGENTS))]
                addr, script = payee(f"soak/join{k}", k % 2 == 0)
                user = f"{addr}.j{k}"
                n.miners.append((user, addr, script, agent, cls))
                pname = f"miner-j{k}"
                n.start_miners([(user, agent)], h.args.pace, h.args.anchor_odds, name=pname)
                joined.append((n, pname, addr, agent))
                log.append(f"{now / 60:.0f}m join node{n.i}/{pname} {addr[:14]}.. ({agent})")
            elif kind == "leave":
                cands = [(n, p) for n, p, _, _ in joined if n.procs[p].alive()] or \
                        [(n, "miner") for n in nodes if "miner" in n.procs and n.procs["miner"].alive()]
                if cands:
                    n, p = cands[rng.randrange(len(cands))]
                    n.procs[p].stop()
                    left.append((n, p))
                    log.append(f"{now / 60:.0f}m leave node{n.i}/{p}")
        for s in stalls:
            if s[3] is not None and now >= s[3]:
                s[0].procs[s[1]].signal(HX.signal.SIGCONT)
                log.append(f"{now / 60:.0f}m resume node{s[0].i}/{s[1]}")
                s[3] = None
        dead = [f"node{n.i}/{k}" for n in nodes for k, p in n.procs.items()
                if not p.alive() and not k.startswith("miner")]
        if dead:
            ok = False
            ev.append(f"processes died during the soak: {dead}")
            break
        if now >= next_sample:
            try:
                smp = sample(h, t0)
                samples.append(smp)
                with open(path, "a") as f:
                    f.write(json.dumps(smp) + "\n")
                if len(samples) % 10 == 1:
                    _progress(h, f"soak {now / 60:.0f}m")
                # A soak that stops relaying loose shares has stopped testing them. On a signet
                # the block target hardens 4x at each retarget past the first; once it is harder
                # than the anchor tier every CPU share is an anchor and loose shares end. Fail
                # loudly instead of mining blocks for hours (24h soak of 11-03 lost 8h this way).
                hour_ago = next((s for s in samples if s["t"] >= smp["t"] - LOOSE_STALL_SECS), None)
                if (smp["t"] >= LOOSE_STALL_SECS + 600 and hour_ago is not None
                        and hour_ago["t"] <= smp["t"] - LOOSE_STALL_SECS + 120
                        and smp["relayed"] == hour_ago["relayed"]):
                    ok = False
                    ev.append(f"no loose share relayed for {LOOSE_STALL_SECS // 60} min at {now / 60:.0f}m "
                              f"(Bitcoin {smp['btc']}, difficulty {smp['difficulty']:.6f}): every share is "
                              f"an anchor, the soak has stopped testing relay; slow --soak-pace")
                    break
            except Exception as e:  # noqa: BLE001 - a missed sample is reported, not fatal
                ev.append(f"sample at {now:.0f}s failed: {e}")
            next_sample += 60
        time.sleep(2)
    for s in stalls:
        if s[3] is not None:
            s[0].procs[s[1]].signal(HX.signal.SIGCONT)
    for n in nodes:
        n.pause_miners(True)
    try:
        STATE["quiet"] = h.quiesce(400)
    except TimeoutError as e:
        STATE["quiet"] = None
        ok = False
        ev.append(str(e))
    final = sample(h, t0)
    samples.append(final)
    with open(path, "a") as f:
        f.write(json.dumps(final) + "\n")
    digests, differ = same_digests(nodes)
    ok &= not differ
    first = samples[0]
    warm = next((s for s in samples if s["t"] >= 600), first)
    hours = max((final["t"] - warm["t"]) / 3600, 1e-9)
    ev.append(f"ran {final['t'] / 60:.0f} min: Bitcoin {first['btc']} -> {final['btc']} "
              f"({final['btc'] - first['btc']} blocks), share chain {first['anchors']} -> {final['anchors']} "
              f"anchors; loose shares relayed {first['relayed']} -> {final['relayed']}; difficulty "
              f"{first['difficulty']:.6f} -> {final['difficulty']:.6f}; agreed at the end {STATE['quiet']}")
    ev.append(f"store digests {'identical on every node' if not differ else 'DIFFER on ' + str(differ)}: "
              f"{digests[nodes[0].i]}")
    ev.append("events: " + "; ".join(log))
    # Memory: from the 10-minute sample (start-up and the first climbs over) to the end.
    for proc in sorted(final["rss_kb"]):
        a, b = warm["rss_kb"].get(proc), final["rss_kb"][proc]
        if a is None or proc.split("/", 1)[1].startswith("miner"):
            continue
        peak = max(s["rss_kb"].get(proc, 0) for s in samples)
        ev.append(f"RSS {proc}: {a / 1024:.0f} MB at {warm['t'] / 60:.0f} min -> {b / 1024:.0f} MB at the end "
                  f"({(b - a) / 1024:+.0f} MB, {(b - a) / 1024 / hours:+.1f} MB/h); peak {peak / 1024:.0f} MB")
    blocks = max(final["btc"] - first["btc"], 1)
    for k in sorted(final["store"]):
        a, b = first["store"][k], final["store"][k]
        ba, bb = first["bitcoin_dir"][k], final["bitcoin_dir"][k]
        ev.append(f"store {k}: node-pool.db {a / 1e6:.1f} MB -> {b / 1e6:.1f} MB ({(b - a) / 1e6:+.1f} MB, "
                  f"{(b - a) / blocks / 1024:.1f} KB per Bitcoin block, {(b - a) / 1e6 / (final['t'] / 3600):.1f} "
                  f"MB/h); ghostd datadir {ba / 1e6:.0f} -> {bb / 1e6:.0f} MB")
    # Joined miners are credited the same on every node.
    for n, p, addr, agent in joined:
        units = {int(m.ledger(addr).get("balance", {}).get("units", 0) or 0) for m in nodes}
        credited = len(units) == 1 and units.pop() > 0
        ok &= credited
        ev.append(f"joined node{n.i}/{p} {addr[:14]}.. ({agent}): credited, one balance on every node: "
                  f"{credited}")
    # Stalled miners: suspended by silence, then back at their class.
    for n, proc, start, _ in stalls:
        addr = next(m[1] for m in n.miners if m[3] == "bitaxe/v2.10.0")
        changes = [l for l in n.read_log("pool_sv2")[marks[n.i]:].splitlines()
                   if "slot class changed" in l and addr in l]
        stalled = sum(1 for l in changes if "cause=Stalled" in l)
        m = next((x for x in n.status()["miners"] if x["address"] == addr), None)
        back = m is not None and m["slot_class"] == 500
        ok &= stalled > 0 and back
        ev.append(f"stalled node{n.i}/{proc} {addr[:14]}..: suspended {stalled} class(es) by silence, "
                  f"class now {m and m['slot_class']} (500 expected)")
    ev.append(f"samples: {len(samples)} in {path}")
    result(name, "PASS" if ok else "FAIL", ev)
