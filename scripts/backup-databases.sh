#!/usr/bin/env bash
# backup-databases.sh — Automated backup for ghost.db and ghost-pay.db
#
# Gzipped `sqlite3 .backup` copies into /var/backups/ghost/db, pruned by BOTH age and count.
# Logs to syslog. Usage: backup-databases.sh [--ghost-dir /home/ghost/.ghost]
#
# ⛔ Run as the database's OWNER, not as root. The databases are WAL mode with `ghost:ghost` 0600
# sidecars, and `sqlite3 .backup` opens the source read-write. Under the systemd unit this is fine
# because it sets `User=ghost`; a hand-run under sudo that has to recreate `-wal` or `-shm` leaves
# them ROOT-owned, after which the `ghost` user cannot open its own database for writing. The pool
# wedges and it reads as corruption. The guard below refuses rather than relying on anyone
# remembering that.
#
# ⛔ It refuses when there is no room, instead of writing until the filesystem says no. The old
# version did the latter, which on a node near full produced a failed backup AND a full root
# filesystem — the second of which takes the node down and has nothing to do with backups.
#
# ## The sizing this is built around
#
# MEASURED on the fleet 2026-10-04/05: ghost.db is 2.4–2.7 GB, and free space is
#
#     vm1 24,665M   vm2 26,639M   vm3 26,683M   vm4 26,495M
#     vm5 24,172M   vm6 24,004M   vm7 24,313M   vm8 12,217M
#
# Seven daily UNCOMPRESSED copies is 18.2 GB. That fills vm8 in about four days and leaves vm1–vm7
# with 6–9 GB, on nodes whose database grows and whose `optimize` path can still want twice the
# database free. This is why the file is gzipped: the two ceremony snapshots already on every node
# compress 2.6 GB to 788 MB and 901 MB, about 3x, so seven of them is ~6 GB and fits everywhere.

set -euo pipefail

GHOST_DIR="${1:-/home/ghost/.ghost}"
BACKUP_DIR="/var/backups/ghost/db"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
KEEP_COUNT="${BACKUP_KEEP_COUNT:-7}"
TIMESTAMP="$(date +%Y%m%d%H%M)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/backup-retention.sh
. "$SCRIPT_DIR/lib/backup-retention.sh"

log() {
    logger -t ghost-backup "$1"
    echo "[$(date -Iseconds)] $1"
}

die() {
    log "ERROR: $1"
    exit 1
}

# ⛔ An ERR trap, because `set -e` aborts without a word: a failure in a command substitution or a
# pipeline leaves the unit "failed" with the last log line being whatever succeeded before it, which
# reads as a backup that worked and then stopped for no reason.
trap 'rc=$?; [ "$rc" -ne 0 ] && log "ERROR: aborted at line $LINENO with status $rc"; exit $rc' ERR

if [ "$(id -u)" -eq 0 ]; then
    die "refusing to run as root. The databases are WAL mode with ghost-owned 0600 sidecars, and a
root-run sqlite3 that recreates -wal or -shm leaves them root-owned, after which the ghost user
cannot write its own database. Run as the owning user (the systemd unit sets User=ghost)."
fi

mkdir -p "$BACKUP_DIR"

# Back up one database: check there is room, copy, compress, verify the copy opens.
backup_one() {
    local label="$1" src="$2" prefix="$3"
    if [ ! -f "$src" ]; then
        log "WARN: $label not found at $src, skipping"
        return 0
    fi

    local db_kb avail_kb verdict
    db_kb="$(du -k "$src" | cut -f1)"
    # ⛔ `df -Pk` prints a header, so the available column is taken with NR==2. Guessing a field
    # offset off the whole output picks the header's "Capacity" string.
    avail_kb="$(df -Pk "$BACKUP_DIR" | awk 'NR==2{print $4}')"

    if ! verdict="$(backup_space_verdict "$db_kb" "$avail_kb")"; then
        die "$label: $verdict — need $(echo "$verdict" | awk '{print $2}')KB free under $BACKUP_DIR,
have $(echo "$verdict" | awk '{print $3}')KB. Refusing: filling the root filesystem to take a
backup takes the node down for a reason unrelated to backups."
    fi
    log "$label: ${db_kb}KB database, $(echo "$verdict" | awk '{print $3}')KB free — proceeding"

    local dest="$BACKUP_DIR/${prefix}-${TIMESTAMP}.db"
    log "$label: backing up to ${dest}.gz"
    sqlite3 "$src" ".backup '$dest'" || die "$label: sqlite3 .backup failed"

    # Verify BEFORE compressing, while it is still a database. A truncated file is still a file, and
    # a gzip of one is still a valid gzip — the kind of backup whose problem surfaces at restore.
    local ver
    ver="$(sqlite3 "file:$dest?mode=ro" 'PRAGMA user_version;' 2>/dev/null)" \
        || die "$label: the copy at $dest does not open as a database"
    case "$ver" in
        ''|*[!0-9]*) die "$label: the copy at $dest reports user_version='$ver'" ;;
    esac
    local integ
    integ="$(sqlite3 "file:$dest?mode=ro" 'PRAGMA quick_check;' 2>/dev/null)"
    [ "$integ" = "ok" ] || die "$label: quick_check on $dest said '$integ'"

    gzip -f "$dest" || die "$label: gzip failed"
    log "$label: complete — $(du -h "${dest}.gz" | cut -f1) compressed from ${db_kb}KB, user_version=$ver, quick_check=ok"
}

backup_one "ghost.db"     "$GHOST_DIR/ghost.db"                  "ghost"
backup_one "ghost-pay.db" "$GHOST_DIR/ghost-pay/ghost-pay.db"    "ghost-pay"

# Prune. Per prefix, so a missing ghost-pay.db cannot let ghost.db copies count towards its quota.
#
# ⛔ Both rules must condemn a file: older than RETENTION_DAYS *and* not among the newest
# KEEP_COUNT. Age alone was the whole policy and age alone has no bound on COUNT — a node that was
# off and caught up through `Persistent=true` holds any number of same-day copies, none old enough
# to prune, and the disk fills. The count rule alone would delete a copy that is the only recent one
# as soon as an eighth appears the same day. See scripts/test-backup-retention.sh.
for prefix in ghost ghost-pay; do
    listing=""
    for f in "$BACKUP_DIR/${prefix}-"*.db.gz; do
        [ -e "$f" ] || continue
        listing="${listing}$(stat -c '%Y' "$f") $f
"
    done
    [ -n "$listing" ] || continue

    pruned=0
    while IFS= read -r victim; do
        [ -n "$victim" ] || continue
        rm -f -- "$victim" && pruned=$((pruned + 1))
    done < <(backup_prune_list "$KEEP_COUNT" "$RETENTION_DAYS" "$(date +%s)" "$listing")
    [ "$pruned" -gt 0 ] && log "$prefix: pruned $pruned backup(s) (older than ${RETENTION_DAYS}d and beyond the newest ${KEEP_COUNT})"
done

log "Backup complete. Current backups:"
# ⛔ Report a COUNT, positively. `ls | while read` printed nothing when there were no backups, which
# is the same output as a successful run whose files had all just been pruned.
found=0
for f in "$BACKUP_DIR"/ghost*.db.gz; do
    [ -e "$f" ] || continue
    found=$((found + 1))
    log "  $(ls -lh "$f" | awk '{print $5, $9}')"
done
log "  $found backup file(s) in $BACKUP_DIR, $(df -Pk "$BACKUP_DIR" | awk 'NR==2{print $4}')KB free"
[ "$found" -gt 0 ] || die "no backup files present after a run that reported success"

exit 0
