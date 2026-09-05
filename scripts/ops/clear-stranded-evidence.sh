#!/usr/bin/env bash
#
# One-off: clear the evidence backlog stranded below the retention window (#830).
#
# WHY A ONE-OFF
#
# #831 makes the fold sweep each epoch as it expires, which stops the growth — but it only ever
# touches the epoch currently ageing out. Rows already below the window were never swept and never
# will be, because no future fold will expire an epoch that expired weeks ago.
#
# WHAT IT DELETES, AND WHY THAT IS SAFE
#
# ONLY rows whose epoch this node has a signed summary for:
#
#     WHERE (r.block_height / EPOCH_BLOCKS) IN (SELECT epoch FROM shard_epochs)
#
# A summary exists only if the fold ran for that epoch, and the fold credits
# `shard_counters.accrued` and deletes evidence in ONE transaction. So a summarised epoch's work
# is already in the counter — for this node's own rows — and a peer's rows were never credited
# here at all (each node folds only its own column; the shard is the sum). Either way the row
# carries no claim.
#
# Measured 2026-09-05, per node:
#
#     summarised     1,027,061 - 1,141,296   <- this script deletes these
#     un-summarised          0 -       691   <- LEFT ALONE. May be uncredited work.
#     no rounds row     31,785 -    40,609   <- LEFT ALONE. Cannot be mapped to an epoch.
#
# The un-summarised rows are the ones that could cost a miner: no summary means the fold never ran
# for that epoch, so the work may never have reached a counter, and deleting it would destroy the
# claim with no record anywhere. They are ~0.05% of the table and are deliberately not touched.
#
# The orphans have no `rounds` row, so no epoch can be derived for them at all. They are a separate
# question (#830) and are also left alone.
#
# USAGE
#   scripts/ops/clear-stranded-evidence.sh <node> [--dry-run]
#
# Stops `ghost-pool` for the delete. `ghostd` stays up throughout.

set -euo pipefail

NODE="${1:-}"
DRY_RUN="${2:-}"
[ -n "$NODE" ] || { echo "usage: $0 <node> [--dry-run]" >&2; exit 1; }

DB=/home/ghost/.ghost/ghost.db
EPOCH_BLOCKS=6
SSH_OPTS=(-o ConnectTimeout=10 -o BatchMode=yes)

say() { echo "  $*"; }
die() { echo "REFUSED: $*" >&2; exit 1; }
remote() { timeout 900 ssh "${SSH_OPTS[@]}" "$NODE" "$@"; }

SAFE="SELECT COUNT(*) FROM shares s JOIN rounds r ON r.round_id=s.round_id
      WHERE (r.block_height/$EPOCH_BLOCKS) IN (SELECT epoch FROM shard_epochs)"
RISKY="SELECT COUNT(*) FROM shares s JOIN rounds r ON r.round_id=s.round_id
       WHERE (r.block_height/$EPOCH_BLOCKS) NOT IN (SELECT epoch FROM shard_epochs)"
ORPHAN="SELECT COUNT(*) FROM shares s LEFT JOIN rounds r ON r.round_id=s.round_id
        WHERE r.round_id IS NULL"

echo "==> $NODE: clear stranded evidence (#830)"

TOTAL=$(remote "sudo sqlite3 'file:$DB?mode=ro' 'SELECT COUNT(*) FROM shares;'")
N_SAFE=$(remote "sudo sqlite3 'file:$DB?mode=ro' \"$SAFE\"")
N_RISKY=$(remote "sudo sqlite3 'file:$DB?mode=ro' \"$RISKY\"")
N_ORPH=$(remote "sudo sqlite3 'file:$DB?mode=ro' \"$ORPHAN\"")

say "total=$TOTAL  summarised=$N_SAFE (delete)  un-summarised=$N_RISKY (KEEP)  orphans=$N_ORPH (KEEP)"

# A node with no summaries at all would make the IN-clause match nothing — correct, but it also
# means something is wrong upstream. Say so rather than silently doing nothing.
EPOCHS=$(remote "sudo sqlite3 'file:$DB?mode=ro' 'SELECT COUNT(*) FROM shard_epochs;'")
[ "$EPOCHS" -gt 0 ] || die "$NODE has no rows in shard_epochs — the fold has never run here. Investigate before deleting anything."

if [ "$DRY_RUN" = "--dry-run" ]; then
    say "DRY RUN — would delete $N_SAFE rows, keep $((N_RISKY + N_ORPH))"
    exit 0
fi
[ "$N_SAFE" -gt 0 ] || { say "nothing to clear"; exit 0; }

say "stopping ghost-pool (ghostd stays up)"
remote "sudo systemctl stop ghost-pool"

say "deleting $N_SAFE summarised rows"
START=$(date +%s)
remote "sudo sqlite3 $DB \"DELETE FROM shares WHERE id IN (
          SELECT s.id FROM shares s JOIN rounds r ON r.round_id=s.round_id
          WHERE (r.block_height/$EPOCH_BLOCKS) IN (SELECT epoch FROM shard_epochs));\""
ELAPSED=$(( $(date +%s) - START ))

AFTER=$(remote "sudo sqlite3 'file:$DB?mode=ro' 'SELECT COUNT(*) FROM shares;'")
KEPT_RISKY=$(remote "sudo sqlite3 'file:$DB?mode=ro' \"$RISKY\"")
say "after: total=$AFTER (was $TOTAL) in ${ELAPSED}s"

# The whole safety argument is that these survive. Assert it rather than trust it.
#
# The test is "did not SHRINK", not "did not change". The `before` count is taken while the pool is
# still running, so shares keep arriving until it stops — and a brand-new share is by definition in
# an epoch not yet summarised, so it lands in this very set. On ghost-vm4 the count went 1065 ->
# 1072 for exactly that reason and an equality check refused a correct run, leaving a production
# pool stopped. Growth here is normal; only a DECREASE means we deleted work that may be uncredited.
if [ "$KEPT_RISKY" -lt "$N_RISKY" ]; then
    die "un-summarised rows FELL from $N_RISKY to $KEPT_RISKY — STOP, that is the set that may hold uncredited work"
fi
say "un-summarised rows intact: $KEPT_RISKY (was $N_RISKY; growth is new arrivals)"

say "reclaiming freed pages (auto_vacuum is INCREMENTAL since #829)"
remote "sudo sqlite3 $DB 'PRAGMA incremental_vacuum;'" >/dev/null

# Truncate the WAL WHILE THE POOL IS STOPPED. A bulk delete leaves a high-water-mark WAL — 1.7-1.8
# GB was observed here — and `wal_checkpoint(TRUNCATE)` cannot truncate while a reader holds it, so
# running this after the pool restarts silently does nothing. That happened on ghost-vm7: the main
# file had shrunk to 2119 MB while a 1791 MB WAL sat beside it, and `du` on the pair still read
# ~3.9 GB. The checkpoint only worked after stopping the pool again.
say "checkpointing WAL (must happen with the pool stopped, or it will not truncate)"
remote "sudo sqlite3 $DB 'PRAGMA wal_checkpoint(TRUNCATE);'" >/dev/null
say "db+wal now $(remote "sudo du -scm $DB $DB-wal 2>/dev/null | tail -1 | cut -f1")MB"

say "integrity check"
INTEG=$(remote "sudo sqlite3 'file:$DB?mode=ro' 'PRAGMA integrity_check;' | head -1")
[ "$INTEG" = "ok" ] || die "integrity_check said '$INTEG' — do NOT restart the pool"

remote "sudo systemctl start ghost-pool"
sleep 20
ACTIVE=$(remote "systemctl is-active ghost-pool")
[ "$ACTIVE" = "active" ] || die "ghost-pool did not come back ($ACTIVE)"
say "OK: $NODE cleared, pool active"
