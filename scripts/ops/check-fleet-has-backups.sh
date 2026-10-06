#!/usr/bin/env bash
#
# Assert every node actually has a recent, verifiable database backup (#996).
#
# ## Why this exists
#
# Nothing could see the absence. `check-fleet-uniformity.sh` compares nodes to each other and they
# agreed — on having no backups at all. `check-fleet-is-current.sh` compares the directives the
# INSTALLER writes, and `ghost-backup.timer` comes from a separate script, so it is outside that
# check's reach by construction.
#
# MEASURED 2026-10-04, all eight nodes: `/var/backups/ghost/db` did not exist, `ghost-backup.timer`
# was `not-found`, and the fleet's entire backup inventory was two ceremony snapshots from
# 2026-08-13 and 2026-08-18. `backup-databases.sh` says "Keeps 7 days of backups" in its own header
# and had never produced one, because `install-backup-timer.sh` was never run. Every check was green
# throughout.
#
# ## What it checks, per node
#
#   1. `ghost-backup.timer` is enabled AND active. Enabled-but-dead is the state that looks fine in
#      a unit file and produces nothing.
#   2. The timer's last run SUCCEEDED. A failing oneshot is silent — there is no `OnFailure=` here —
#      so "the timer exists" and "the timer works" are different claims.
#   3. At least one `ghost-*.db.gz` is newer than MAX_AGE_HOURS. This is the only one of the four
#      that is about outcomes rather than configuration, and it is the one that would have caught
#      the measured state.
#   4. Free space is above what `backup-databases.sh` will refuse at (database + 1 GiB), so a node
#      that is about to start skipping backups says so now rather than in a week.
#
# ⛔ Green is POSITIVE throughout: every field is read and validated, and a node that cannot be
# asked is INCONCLUSIVE, never a pass. A check whose green means "I found no failure words" is how
# the absence survived in the first place.
#
# Usage:
#   scripts/ops/check-fleet-has-backups.sh [<node> ...]      # defaults to all eight
#
# Exit 0 = every node has a recent backup, 1 = one does not, 2 = INCONCLUSIVE.
set -uo pipefail

MAX_AGE_HOURS="${BACKUP_MAX_AGE_HOURS:-36}"   # daily timer at 03:00 + jitter, so 36h tolerates one miss
BACKUP_DIR=/var/backups/ghost/db
HEADROOM_KB=1048576                            # must match BACKUP_HEADROOM_KB in backup-retention.sh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# The verdict lives in a library so it can be driven to GREEN by scripts/test-backup-health.sh.
# Every node fails this check today, so the fleet can only ever demonstrate the red path, and a
# check never seen to pass is a check nobody knows the shape of.
# shellcheck source=scripts/lib/backup-health.sh
. "$REPO_ROOT/scripts/lib/backup-health.sh"

NODES=("$@")
if [ ${#NODES[@]} -eq 0 ]; then
    NODES=(ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4 ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8)
fi

bad=0
unreadable=0

for node in "${NODES[@]}"; do
    probe="$(ssh -o ConnectTimeout=15 -o BatchMode=yes "$node" "
echo ENABLED \$(systemctl is-enabled ghost-backup.timer 2>&1 | head -1)
echo ACTIVE \$(systemctl is-active ghost-backup.timer 2>&1 | head -1)
echo LASTRUN \$(systemctl show ghost-backup.service -p Result --value 2>/dev/null)
echo NEWEST \$(sudo find $BACKUP_DIR -name 'ghost-*.db.gz' -printf '%T@\n' 2>/dev/null | sort -rn | head -1 | cut -d. -f1)
echo COUNT \$(sudo find $BACKUP_DIR -name 'ghost-*.db.gz' 2>/dev/null | wc -l)
echo DBKB \$(sudo du -k /home/ghost/.ghost/ghost.db 2>/dev/null | cut -f1)
echo AVKB \$(df -Pk /var | awk 'NR==2{print \$4}')
echo NOW \$(date +%s)
" 2>&1)"

    verdict="$(backup_health_verdict "$probe" "$MAX_AGE_HOURS" "$HEADROOM_KB")"
    rc=$?
    case "$rc" in
        0) printf '  ✓   %-10s %s\n' "$node" "$verdict" ;;
        1) echo "  *** $node"
           # One reason per line: a semicolon-joined list on one 200-column line is a list nobody
           # reads to the end of.
           printf '%s\n' "${verdict#PROBLEM }" | tr ';' '\n' | sed 's/^ *//; s/^/        /'
           bad=$((bad + 1)) ;;
        *) echo "  ??? $node — $verdict"
           printf '%s\n' "$probe" | sed 's/^/        /'
           unreadable=$((unreadable + 1)) ;;
    esac
done

echo
if [ "$unreadable" -gt 0 ]; then
    echo "check-fleet-has-backups: INCONCLUSIVE — $unreadable of ${#NODES[@]} node(s) could not be asked."
    echo "  A node that cannot be asked is not a node with a backup."
    exit 2
fi

if [ "$bad" -gt 0 ]; then
    echo "check-fleet-has-backups: $bad of ${#NODES[@]} node(s) have no recent verified backup."
    echo
    echo "  Install the timer with \`sudo scripts/install-backup-timer.sh\` on each node — it is a"
    echo "  timer, not a service restart, so it sheds no miners. \`deploy-node.sh\` backs up the"
    echo "  BINARY only, so restoring it does not undo a migration (#996)."
    exit 1
fi

echo "check-fleet-has-backups: all ${#NODES[@]} node(s) have an enabled, active timer whose last run"
echo "  succeeded, a backup newer than ${MAX_AGE_HOURS}h, and room for the next one"
exit 0
