#!/usr/bin/env bash
#
# The per-node verdict for scripts/ops/check-fleet-has-backups.sh (#996).
#
# ## Why this is a separate file
#
# Today every node fails this check, so running it against the fleet can only ever demonstrate the
# RED path. A check that has never been seen to go green is a check nobody knows the shape of — and
# this one exists precisely because the old state (no timer, no backups, every check green) was
# invisible. So the verdict is a function, and scripts/test-backup-health.sh drives it to green, to
# red for each distinct reason, and to INCONCLUSIVE.
#
# ## What the probe looks like
#
# One `KEY value` line per field, as the remote shell emits them:
#
#   ENABLED enabled | ACTIVE active | LASTRUN success
#   NEWEST <epoch>  | COUNT <n>     | DBKB <n> | AVKB <n> | NOW <epoch>
#
# Prints one verdict line and returns 0 green, 1 red, 2 inconclusive:
#
#   OK <age_hours> <count> <avail_kb> <need_kb>
#   PROBLEM <reason>[; <reason>...]
#   INCONCLUSIVE <field>='<value>'

# Judge one node's backup state.
#
# Usage: backup_health_verdict <probe_text> <max_age_hours> <headroom_kb>
backup_health_verdict() {
    local probe="${1:-}" max_age="${2:-36}" headroom="${3:-1048576}"

    _bh_field() { printf '%s\n' "$probe" | sed -nE "s/^$1 (.*)\$/\\1/p" | head -1; }

    local enabled active lastrun newest count db_kb av_kb now
    enabled="$(_bh_field ENABLED)"; active="$(_bh_field ACTIVE)"; lastrun="$(_bh_field LASTRUN)"
    newest="$(_bh_field NEWEST)";   count="$(_bh_field COUNT)"
    db_kb="$(_bh_field DBKB)";      av_kb="$(_bh_field AVKB)"; now="$(_bh_field NOW)"

    # ⛔ Every numeric field SEPARATELY. Concatenating them and testing `*[!0-9]*` hides an empty
    # field whenever the others are numeric, so a probe that answered nothing reads as one that
    # answered fine. That exact mistake was caught by a self-test in the pre-migration backup gate.
    local fld
    for fld in "count:$count" "db_kb:$db_kb" "avail_kb:$av_kb" "now:$now"; do
        case "${fld#*:}" in
            ''|*[!0-9]*) echo "INCONCLUSIVE ${fld%%:*}='${fld#*:}'"; return 2 ;;
        esac
    done
    if [ -z "$enabled" ] || [ -z "$active" ]; then
        echo "INCONCLUSIVE unit_state enabled='$enabled' active='$active'"
        return 2
    fi

    local problems=()
    # Enabled-but-dead is the state that looks right in a unit file and produces nothing.
    [ "$enabled" = "enabled" ] || problems+=("timer is '$enabled', not enabled")
    [ "$active"  = "active"  ] || problems+=("timer is '$active', not active")
    # An empty Result means the oneshot has not run in this boot, which is not itself a failure —
    # the age check decides whether that matters. Anything else is a failed run, and a failed
    # oneshot here is silent: there is no OnFailure= on the unit.
    case "$lastrun" in
        ''|success) : ;;
        *) problems+=("last run Result='$lastrun'") ;;
    esac

    local age_h=-1
    if [ "$count" -eq 0 ]; then
        problems+=("NO backups present")
    else
        case "$newest" in
            ''|*[!0-9]*) problems+=("$count backup(s) but their mtime could not be read") ;;
            *) age_h=$(( (now - newest) / 3600 ))
               # A future mtime means a clock that moved, not a fresh backup, so it is a problem
               # rather than an age of 0 — and WSL2 has stepped a clock backwards here before.
               if [ "$age_h" -lt 0 ]; then
                   problems+=("newest backup is dated in the FUTURE (clock skew, not freshness)")
               elif [ "$age_h" -gt "$max_age" ]; then
                   problems+=("newest backup is ${age_h}h old (limit ${max_age}h)")
               fi ;;
        esac
    fi

    local need_kb=$((db_kb + headroom))
    if [ "$av_kb" -lt "$need_kb" ]; then
        problems+=("only ${av_kb}KB free, backup-databases.sh refuses below ${need_kb}KB")
    fi

    if [ ${#problems[@]} -gt 0 ]; then
        local joined
        joined="$(printf '%s; ' "${problems[@]}")"
        echo "PROBLEM ${joined%; }"
        return 1
    fi
    echo "OK $age_h $count $av_kb $need_kb"
    return 0
}
