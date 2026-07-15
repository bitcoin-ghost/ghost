#!/usr/bin/env bash
#
# ONE-TIME unpaid-ledger reconciliation across the fleet.
#
# WHY THIS EXISTS
#
# The payout is computed from each node's unpaid share ledger, and GHOST-02 compares the
# resulting miner split for EXACT equality. Nodes that sum different share sets compute
# different splits, so every node rejects every payout — permanently.
#
# Share gossip is fire-and-forget and drops shares. GHOST-03 anti-entropy exists to repair
# that, but until schema v41 it (a) wrote backfills only to the in-memory round view, never to
# the `shares` table the ledger actually reads, and (b) only ever asked about the round in
# flight. So drops became permanent, and the fleet's ledgers drifted apart — measured at ~5% of
# total work and growing.
#
# v41 fixes the leak going forward: the signed proof is persisted with each share, so any node
# can serve and verify a backfill at any age, and convergence now sweeps the unpaid ledger.
#
# It cannot fix the BACKLOG. Shares written before v41 have no stored proof — their GHOST-09
# signatures exist nowhere — so no node can serve or verify them and no protocol can reconcile
# them. This script is the only way to make the fleet agree on that backlog.
#
# WHAT IT ASSUMES, PLAINLY
#
# It takes the UNION of the nodes' unpaid shares. That is sound because the divergence is nodes
# MISSING shares, never nodes holding fabricated ones: each node's set is a subset of the truth.
# The union is therefore the truth. But it is TRUSTED, not verified — those shares carry no
# signature any more. It is only defensible because every node in the mesh belongs to the same
# operator. Do not use this to admit shares from a node you do not control.
#
# PRECONDITIONS
#
#   1. Every node is on the v41 binary and has run the migration. v41 canonicalises share_hash
#      byte order; without it, `share_hash` is not a cross-node identity and the union would
#      insert the same share twice under two spellings and DOUBLE-COUNT the work.
#   2. Every node's DB is backed up. This writes to the live ledger.
#   3. Ideally the pool is quiet, so the ledger is not moving under you.
#
# It never deletes and never overwrites: dedup is UNIQUE(share_hash), miner rows are only
# created when absent. Safe to re-run.
#
# Usage:
#   ./scripts/reconcile-ledger.sh --dry-run     # report only, write nothing
#   ./scripts/reconcile-ledger.sh --apply
#
set -euo pipefail

NODES=(ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4 ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8)
BIN=/opt/ghost/bin/ghost-pool
CONF=/etc/ghost/pool.toml
REMOTE_DIR=/tmp/ledger-reconcile
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

MODE="${1:-}"
if [[ "$MODE" != "--dry-run" && "$MODE" != "--apply" ]]; then
    echo "usage: $0 --dry-run | --apply" >&2
    exit 2
fi
DRY=""
[[ "$MODE" == "--dry-run" ]] && DRY="--dry-run"

echo "==> Verifying every node is on schema v41 (share_hash must be canonical, or the union"
echo "    would insert the same share under two spellings and double-count the work)"
for n in "${NODES[@]}"; do
    v=$(ssh -o ConnectTimeout=10 "$n" \
        "sudo -u ghost sqlite3 /home/ghost/.ghost/ghost.db 'PRAGMA user_version;'" 2>/dev/null || echo "?")
    printf '    %-10s schema v%s\n' "$n" "$v"
    if [[ "$v" -lt 41 ]] 2>/dev/null; then
        echo "ABORT: $n is on schema v$v. Deploy the v41 binary and let it migrate first." >&2
        exit 1
    fi
done

echo
echo "==> Ledger BEFORE (this is the divergence we are repairing)"
for n in "${NODES[@]}"; do
    ssh "$n" "sudo -u ghost sqlite3 /home/ghost/.ghost/ghost.db \
        \"SELECT COUNT(*), ROUND(COALESCE(SUM(work),0)) FROM shares
          WHERE paid_in_proposal_hash IS NULL AND valid=1;\"" \
        | awk -v n="$n" -F'|' '{printf "    %-10s %8d shares  %16s work\n", n, $1, $2}'
done

echo
echo "==> Exporting each node's unpaid ledger"
for n in "${NODES[@]}"; do
    ssh "$n" "sudo mkdir -p $REMOTE_DIR && sudo chown ghost:ghost $REMOTE_DIR && \
              sudo -u ghost $BIN --config $CONF --ledger-export $REMOTE_DIR/$n.json" >/dev/null
    scp -q "$n:$REMOTE_DIR/$n.json" "$WORK/$n.json"
    printf '    %-10s %s\n' "$n" "$(python3 -c "import json,sys;print(f'{len(json.load(open(sys.argv[1]))):,} shares')" "$WORK/$n.json")"
done

echo
echo "==> Building the union (keyed on canonical share_hash)"
python3 - "$WORK" "${NODES[@]}" <<'PY'
import json, sys, pathlib
work = pathlib.Path(sys.argv[1]); nodes = sys.argv[2:]
union = {}
for n in nodes:
    for s in json.load(open(work / f"{n}.json")):
        # First writer wins. Two nodes holding the same share_hash hold the same share; only the
        # miner_id keying can differ (the origin stores the plaintext worker id, peers store the
        # hashed one), and either resolves to the same payout address.
        union.setdefault(s["share_hash"], s)
rows = list(union.values())
json.dump(rows, open(work / "union.json", "w"))
total = sum(r["work"] for r in rows)
missing = sum(1 for r in rows if not r.get("payout_address"))
print(f"    union: {len(rows):,} shares, {total:,.0f} work")
if missing:
    print(f"    WARNING: {missing:,} shares have no payout address — the payout query's INNER JOIN")
    print( "             on `miners` will drop them and they cannot be credited to anyone.")
for n in nodes:
    have = {s["share_hash"] for s in json.load(open(work / f"{n}.json"))}
    print(f"    {n:<10} missing {len(union) - len(have & union.keys()):,} of the union")
PY

echo
echo "==> Importing the union into each node ${DRY:+(DRY RUN — nothing will be written)}"
for n in "${NODES[@]}"; do
    scp -q "$WORK/union.json" "$n:$REMOTE_DIR/union.json"
    ssh "$n" "sudo chown ghost:ghost $REMOTE_DIR/union.json && \
              sudo -u ghost $BIN --config $CONF --ledger-import $REMOTE_DIR/union.json $DRY" 2>&1 \
        | grep -E "Ledger import complete|inserted|ERROR" | sed "s/^/    $n: /"
done

if [[ -n "$DRY" ]]; then
    echo
    echo "Dry run complete — nothing was written. Re-run with --apply when the numbers look right."
    exit 0
fi

echo
echo "==> Ledger AFTER (every node must now report the SAME counts, or the payout still cannot"
echo "    be ratified)"
for n in "${NODES[@]}"; do
    ssh "$n" "sudo -u ghost sqlite3 /home/ghost/.ghost/ghost.db \
        \"SELECT COUNT(*), ROUND(COALESCE(SUM(work),0)) FROM shares
          WHERE paid_in_proposal_hash IS NULL AND valid=1;\"" \
        | awk -v n="$n" -F'|' '{printf "    %-10s %8d shares  %16s work\n", n, $1, $2}'
done

echo
echo "If those rows are not identical, DO NOT expect a payout to ratify: GHOST-02 compares the"
echo "miner split for exact equality, and a node summing a different ledger will vote to reject."
