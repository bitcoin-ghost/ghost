#!/usr/bin/env bash
#
# Enable INCREMENTAL auto_vacuum on a node's pool database (#585).
#
# WHY THIS EXISTS
#
# `auto_vacuum=0` is the default, and under it a DELETE returns nothing to the filesystem — the
# pages go on the free list and are reused internally, so the file never shrinks. That is why the
# retention work already in place (`run_maintenance` prunes eight tables hourly) has not made the
# database smaller, and why v59's drop of the retired SBC tables would not have either.
#
# Switching to INCREMENTAL takes effect only on the next VACUUM, so the one-time VACUUM here is
# the price of admission. After it, `PRAGMA incremental_vacuum` reclaims cheaply and no further
# full VACUUM is needed.
#
# MEASURED on ghost-vm7, 2026-09-02 — this is not an estimate:
#
#     VACUUM took        1m19s
#     page_count         910,215 -> 888,245
#     file               3556 MB -> 3470 MB   (86 MB reclaimed by defragmentation alone)
#     auto_vacuum        0 -> 2 (INCREMENTAL)
#     integrity_check    ok
#
# The July plan treated this as a dangerous multi-hour job. On the live database it is 79 seconds.
# What made it dangerous was disk, not time: VACUUM writes a complete second copy before swapping,
# so it needs the database's size again in free space, and running it without that took ghost-vm6
# down once. This script refuses rather than repeats that.
#
# USAGE
#   scripts/ops/enable-incremental-autovacuum.sh <node> [--dry-run]
#
# It stops `ghost-pool` (the only writer) for the duration. `ghostd` keeps running throughout, so
# the node stays on the network and keeps its peers; it just stops accounting shares for ~90s.

set -euo pipefail

NODE="${1:-}"
DRY_RUN="${2:-}"
[ -n "$NODE" ] || { echo "usage: $0 <node> [--dry-run]" >&2; exit 1; }

DB=/home/ghost/.ghost/ghost.db
SSH_OPTS=(-o ConnectTimeout=10 -o BatchMode=yes)

say() { echo "  $*"; }
die() { echo "REFUSED: $*" >&2; exit 1; }

remote() { timeout 600 ssh "${SSH_OPTS[@]}" "$NODE" "$@"; }

echo "==> $NODE: enable INCREMENTAL auto_vacuum on $DB"

# ---------------------------------------------------------------- preconditions
CUR=$(remote "sudo sqlite3 'file:$DB?mode=ro' 'PRAGMA auto_vacuum;'" 2>/dev/null || echo "")
[ -n "$CUR" ] || die "cannot read auto_vacuum on $NODE — is the database there?"
if [ "$CUR" = "2" ]; then
    say "already INCREMENTAL — nothing to do"
    exit 0
fi
say "auto_vacuum is currently $CUR (0 = none, 1 = full, 2 = incremental)"

# VACUUM writes a full second copy before swapping. Without room for it the operation fails
# PART-WAY, which is how ghost-vm6 was lost — so this is a refusal, not a warning.
DB_MB=$(remote "sudo du -sm $DB | cut -f1")
FREE_MB=$(remote "df -m /home/ghost | tail -1 | awk '{print \$4}'")
NEED_MB=$((DB_MB * 2))
say "database ${DB_MB}MB, free ${FREE_MB}MB, VACUUM needs ~${NEED_MB}MB (2x: it writes a copy)"
[ "$FREE_MB" -gt "$NEED_MB" ] || die "$NODE has ${FREE_MB}MB free but needs ~${NEED_MB}MB. Free space first."

if [ "$DRY_RUN" = "--dry-run" ]; then
    say "DRY RUN — preconditions pass, stopping here"
    exit 0
fi

# ---------------------------------------------------------------- do it
say "stopping ghost-pool (ghostd stays up; the node keeps its peers)"
remote "sudo systemctl stop ghost-pool"

# Checkpoint first: a WAL holds committed pages the main file does not yet have, so a copy taken
# without this is not a usable backup.
say "checkpointing WAL"
remote "sudo sqlite3 $DB 'PRAGMA wal_checkpoint(TRUNCATE);'" >/dev/null

say "backing up to $DB.pre-vacuum"
remote "sudo cp -p $DB $DB.pre-vacuum"

BEFORE=$(remote "sudo sqlite3 $DB 'PRAGMA page_count;'")
say "before: page_count=$BEFORE"

say "running VACUUM (measured at ~1m20s on a 3.5GB database)"
START=$(date +%s)
remote "sudo sqlite3 $DB 'PRAGMA auto_vacuum=INCREMENTAL; VACUUM;'"
ELAPSED=$(( $(date +%s) - START ))

AFTER=$(remote "sudo sqlite3 $DB 'PRAGMA page_count;'")
MODE=$(remote "sudo sqlite3 $DB 'PRAGMA auto_vacuum;'")
NEW_MB=$(remote "sudo du -sm $DB | cut -f1")
say "after:  page_count=$AFTER auto_vacuum=$MODE size=${NEW_MB}MB (was ${DB_MB}MB) in ${ELAPSED}s"

# Verify the mode actually took. A VACUUM that ran but left auto_vacuum at 0 has done the
# expensive half and none of the useful half, and looks identical from the outside.
[ "$MODE" = "2" ] || die "VACUUM completed but auto_vacuum is $MODE, not 2 — the mode did not take"

say "integrity check"
INTEG=$(remote "sudo sqlite3 $DB 'PRAGMA integrity_check;' | head -1")
[ "$INTEG" = "ok" ] || die "integrity_check said '$INTEG' — DO NOT restart the pool; restore $DB.pre-vacuum"

say "restarting ghost-pool"
remote "sudo systemctl start ghost-pool"
sleep 20
ACTIVE=$(remote "systemctl is-active ghost-pool")
[ "$ACTIVE" = "active" ] || die "ghost-pool did not come back ($ACTIVE) — restore $DB.pre-vacuum"

say "OK: $NODE on INCREMENTAL auto_vacuum, reclaimed $((DB_MB - NEW_MB))MB, pool active"
say "backup left at $DB.pre-vacuum — remove it once you are satisfied"
