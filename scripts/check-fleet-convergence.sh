#!/usr/bin/env bash
#
# Ask every node what it WOULD commit, and report whether they agree.
#
# This is the pre-arming check for the three dormant consensus gates:
#
#   MESH_NODE_LIST_CHECKPOINT_HEIGHT  (#402) — needs all four checkpoint roots to agree
#   ADDRESS_PROOF_ENFORCEMENT_HEIGHT  (#605) — needs the qualified sets to agree
#   ARCHIVE_TX_PROOF_HEIGHT           (#919) — inert while no node claims archive
#
# ## Why a script and not an ad-hoc query
#
# It was an ad-hoc query, and that is how the roster root went unnoticed. On 2026-09-27 the
# convergence endpoint reported two of the checkpoint's four roots; #943 had just made a third
# load-bearing for vote acceptance. A two-root comparison reads "converged" and a fleet that
# agrees on three roots out of four finalises nothing at all, silently, for ever. #945 fixed the
# endpoint; this fixes the habit.
#
# ## Two things it does that a loop of curls does not
#
# **It samples near-simultaneously.** `advert_root` is a function of live advert state and nodes
# republish every `MESH_ADVERT_REPUBLISH_SECS` (600s), so comparing vm1 at T and vm8 at T+30s can
# show a difference that is only elapsed time. All eight requests are fired in parallel.
#
# ## ⛔ Do not run this straight after a roll
#
# The advert store is in-memory and refills from gossip, and peers republish every
# `MESH_ADVERT_REPUBLISH_SECS` (600s). Until a restarted node holds a signed advert from every
# QUALIFIED node, `store.covering()` returns nothing and the whole `mesh_node_list` tuple is
# `None` — so all four roots read as null while the qualified sets still report fine.
#
# MEASURED 2026-09-27, after the arming roll (vm1..vm4 restarted 22:29-22:41, sampled 22:49):
#
#     vm4  restarted 21 min earlier  -> roots reported
#     vm3  restarted 18 min earlier  -> all four null
#     vm2  restarted 13 min earlier  -> all four null
#     vm1  restarted  9 min earlier  -> all four null
#
# That is warm-up, not divergence, and this script deliberately calls it a failure rather than
# comparing the nodes that happened to answer. Wait until every node has been up long enough to
# have heard a full republish cycle from all peers, then sample.
#
# ⚠ The same property applies to the gate itself: a node restarted shortly before
# `MESH_NODE_LIST_CHECKPOINT_HEIGHT` fires cannot propose or ratify a checkpoint until its advert
# store covers the qualified set. Nothing breaks — no checkpoint finalises until coverage exists.
#
# **It refuses on a partial sample.** A node that does not answer is not a node that agrees. Eight
# responses or INCONCLUSIVE — otherwise the check gets quieter exactly as the fleet gets sicker.
#
# Usage: scripts/check-fleet-convergence.sh [node...]      (default: ghost-vm1..8)
#
# Exit 0 = every node agrees on everything compared, 1 = a disagreement or a null field,
# 2 = INCONCLUSIVE (a node did not answer, or answered without the fields this compares).
set -uo pipefail

NODES=("$@")
[ ${#NODES[@]} -gt 0 ] || NODES=(ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4 ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8)

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "check-fleet-convergence: sampling ${#NODES[@]} node(s) in parallel at $(date -u +%FT%TZ)"

for n in "${NODES[@]}"; do
    (
        # ⛔ Generous on purpose. This endpoint derives the qualified set, the node list, the
        # coordinator roster and the signer set from the database, and these are 2-CPU nodes
        # (#537: "database connection held past the slow threshold ... parks a tokio worker").
        # MEASURED 2026-09-27, minutes after a fleet-wide restart: 24s, 25s, 31s. The first
        # version of this script allowed 15s, so it reported INCONCLUSIVE on six of eight nodes
        # at the one moment the answer mattered most — straight after the arming roll. A probe
        # whose budget is under the thing it measures fails when the fleet is busiest, which is
        # when you are most likely to be asking.
        timeout 120 ssh -o ConnectTimeout=10 -o BatchMode=yes "$n" \
            "curl -s --max-time 90 http://127.0.0.1:8080/api/v1/qualification/scoped-set" \
            > "$TMP/$n.json" 2>/dev/null
    ) &
done
wait

python3 - "$TMP" "${NODES[@]}" <<'PY'
import json, os, sys

tmp, nodes = sys.argv[1], sys.argv[2:]

# Every field compared, and which gate cares. A field that is None on any node is a failure, not
# a skip: "the endpoint did not tell us" and "the nodes agree" must never read the same.
ROOTS = [
    ("list_root",               "#402"),
    ("advert_root",             "#402"),
    ("coordinator_roster_root", "#402"),
    ("signer_set_root",         "#402"),
]
SETS = [
    ("unscoped",          "#605"),
    ("voter_set_scoped",  "#605"),
    ("assignment_scoped", "#605"),
]

docs, missing = {}, []
for n in nodes:
    p = os.path.join(tmp, f"{n}.json")
    try:
        with open(p) as fh:
            docs[n] = json.load(fh)
    except Exception as exc:
        missing.append(f"{n} ({type(exc).__name__})")

if missing:
    print("check-fleet-convergence: INCONCLUSIVE — no usable answer from:")
    for m in missing:
        print(f"    {m}")
    print("  A node that did not answer is not a node that agrees. Fix the probe or the node;")
    print("  do NOT arm a gate on the nodes that happened to reply.")
    sys.exit(2)

bad = 0

def compare(label, gate, values):
    """values: {node: value}. Disagreement or any None is a failure."""
    global bad
    nulls = [n for n, v in values.items() if v is None]
    distinct = {v for v in values.values() if v is not None}
    if nulls:
        print(f"  ⛔ {label:24} {gate}  NULL on: {', '.join(nulls)}")
        print(f"     The endpoint did not report this. That is not agreement — it is a blind spot,")
        print(f"     which is exactly what #945 was about.")
        bad += 1
        return
    if len(distinct) != 1:
        print(f"  ⛔ {label:24} {gate}  {len(distinct)} DISTINCT VALUES:")
        for v in sorted(distinct):
            who = sorted(n for n, x in values.items() if x == v)
            print(f"       {str(v)[:20]}  {' '.join(who)}")
        bad += 1
        return
    print(f"  ✓  {label:24} {gate}  agree  {str(next(iter(distinct)))[:20]}")

mesh = {n: (d.get("mesh_node_list") or {}) for n, d in docs.items()}

# has_fn False means the closure is not wired, so the roots are null by construction.
unwired = [n for n, m in mesh.items() if not m.get("has_fn")]
if unwired:
    print("check-fleet-convergence: INCONCLUSIVE — mesh_node_list_fn not wired on: "
          + ", ".join(sorted(unwired)))
    print("  Those nodes cannot report what they would commit, so nothing can be compared.")
    sys.exit(2)

print("\n mesh node-list checkpoint roots (all four are vote-rejection conditions):")
for field, gate in ROOTS:
    compare(field, gate, {n: m.get(field) for n, m in mesh.items()})

print("\n qualified sets:")
for field, gate in SETS:
    compare(field, gate, {n: (docs[n].get(field) or {}).get("hash") for n in docs})
    counts = {(docs[n].get(field) or {}).get("count") for n in docs}
    if len(counts) != 1:
        print(f"  ⛔ {field:24} {gate}  counts differ: {sorted(map(str, counts))}")
        bad += 1

print("\n context:")
heights = {d.get("checkpoint_height") for d in docs.values()}
print(f"  checkpoint_height        {sorted(map(str, heights))}"
      + ("   ⚠ differ — compare only same-height samples" if len(heights) != 1 else ""))
listed = {m.get("listed") for m in mesh.values()}
print(f"  listed                   {sorted(map(str, listed))}")
gaps = {n: m.get("missing_adverts") for n, m in mesh.items() if m.get("missing_adverts")}
if gaps:
    print("  ⛔ missing adverts — no checkpoint can finalise without full coverage:")
    for n, g in sorted(gaps.items()):
        print(f"       {n}: {g}")
    bad += 1
else:
    print("  missing_adverts          none (full coverage)")
# has_oracle False makes assignment_scoped a draw with no block-hash seeds, i.e. not the real thing.
oracles = {n: (docs[n].get("assignment_scoped") or {}).get("has_oracle") for n in docs}
without = sorted(n for n, v in oracles.items() if not v)
if without:
    print(f"  ⚠ has_oracle FALSE on: {' '.join(without)} — assignment_scoped is not the real draw there")

print()
if bad:
    print(f"check-fleet-convergence: {bad} disagreement(s) — DO NOT ARM")
    sys.exit(1)
print(f"check-fleet-convergence: all {len(docs)} node(s) agree on every field compared")
print("  ⚠ One sample is not stable convergence. These values track live advert state; take")
print("    several samples over time before arming a gate on them.")
sys.exit(0)
PY
