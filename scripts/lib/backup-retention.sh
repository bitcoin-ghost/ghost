#!/usr/bin/env bash
#
# The sizing and retention decisions for scripts/backup-databases.sh (#996).
#
# ## Why this is a separate file
#
# Both decisions are arithmetic over a handful of numbers, and both are the kind of arithmetic that
# is wrong in a way nothing notices until a disk is full. They are driven directly by
# scripts/test-backup-retention.sh rather than by running a backup, which would need a 2.6 GB
# database to be interesting.
#
# ## The numbers these exist to respect
#
# MEASURED on the fleet 2026-10-04/05. Database 2.4–2.7 GB; free space:
#
#     vm1 24,665M   vm2 26,639M   vm3 26,683M   vm4 26,495M
#     vm5 24,172M   vm6 24,004M   vm7 24,313M   vm8 12,217M
#
# Seven daily UNCOMPRESSED copies is 18.2 GB, which fills vm8 in about four days and leaves vm1–vm7
# with 6–9 GB on a node whose `optimize` path can still want twice the database free. Gzip is the
# established shape here — the two ceremony snapshots on every node are already gzipped, at 788 MB
# and 901 MB against 2.6 GB raw, so about 3x. Seven of those is ~6 GB and fits everywhere.

# Decide whether there is room to take a backup.
#
# Usage: backup_space_verdict <db_kb> <avail_kb>
#
# A backup needs the FULL uncompressed size transiently — `.backup` writes a plain copy and gzip
# then reads it — plus headroom, so this asks for the database size plus a margin rather than the
# compressed size it will settle at. Prints one verdict and returns 0 to proceed, 1 to refuse:
#
#   OK <need_kb> <avail_kb>
#   REFUSE_SPACE <need_kb> <avail_kb>
#   REFUSE_PARSE <field> <value>
#
# ⛔ Refusing is the behaviour that was missing. `sqlite3 .backup` writes until it cannot and then
# fails, so on a node near full the old script produced a failed backup AND a full root filesystem —
# the second of which takes the node down and has nothing to do with backups.
BACKUP_HEADROOM_KB=${BACKUP_HEADROOM_KB:-1048576}   # 1 GiB

backup_space_verdict() {
    local db_kb="${1:-}" avail_kb="${2:-}"
    local field
    # Each field separately. Concatenating them and testing `*[!0-9]*` makes an EMPTY field
    # invisible whenever the others are numeric, which is how a probe that answered nothing reads
    # as a probe that answered fine.
    for field in "db_kb:${db_kb}" "avail_kb:${avail_kb}"; do
        case "${field#*:}" in
            ''|*[!0-9]*) echo "REFUSE_PARSE ${field%%:*} ${field#*:}"; return 1 ;;
        esac
    done

    local need_kb=$((db_kb + BACKUP_HEADROOM_KB))
    if [ "$avail_kb" -lt "$need_kb" ]; then
        echo "REFUSE_SPACE $need_kb $avail_kb"
        return 1
    fi
    echo "OK $need_kb $avail_kb"
    return 0
}

# Choose which backups to delete.
#
# Usage: backup_prune_list <keep_count> <retention_days> <now_epoch> <listing>
#
# `listing` is one `<epoch> <path>` line per existing backup, any order. Prints the paths to delete,
# newest-surviving-first order not guaranteed. Returns 0 always: "nothing to prune" is an answer.
#
# Two rules, and a file is deleted only when BOTH agree it may go:
#
#   * older than `retention_days`, AND
#   * not among the newest `keep_count`.
#
# ⛔ The age rule alone was the whole policy, and age alone has no bound on COUNT. A node that was
# off and caught up through `Persistent=true` can hold an unlimited number of same-day copies, none
# of which is old enough to prune. The count rule alone is not enough either: it would delete a
# backup that is the only one there is as soon as an eighth appears on the same day.
#
# ⛔ And the newest is never deleted, whatever the numbers say. A prune that can remove every copy
# is not a retention policy — see the `CONTROL: offset 1` case in test-deploy-gate.sh for the same
# mistake made with binaries.
backup_prune_list() {
    local keep="${1:-}" days="${2:-}" now="${3:-}" listing="${4:-}"
    case "${keep}${days}${now}" in
        ''|*[!0-9]*) echo "REFUSE_PARSE args ${keep}/${days}/${now}" >&2; return 1 ;;
    esac
    [ "$keep" -ge 1 ] || { echo "REFUSE_PARSE keep_count $keep" >&2; return 1; }

    local cutoff=$((now - days * 86400))
    # Newest first, so the line number IS the rank.
    printf '%s\n' "$listing" \
        | /usr/bin/grep -E '^[0-9]+ ' \
        | sort -k1,1nr \
        | awk -v cutoff="$cutoff" -v keep="$keep" '
            NR > keep && $1 < cutoff { $1 = ""; sub(/^ /, ""); print }
          '
}
