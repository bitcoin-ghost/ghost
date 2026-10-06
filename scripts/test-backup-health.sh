#!/usr/bin/env bash
#
# Self-test for the per-node backup verdict (scripts/lib/backup-health.sh).
#
# ⛔ The reason this file exists: every node fails that check today, so running it against the fleet
# can only ever demonstrate RED. A check that has never been seen to go GREEN is a check nobody
# knows the shape of — and it exists because the measured state (no timer, no backups, every other
# check green) was invisible. So green is demonstrated here, and so is each distinct red.
#
# Usage: scripts/test-backup-health.sh
set -uo pipefail

SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$SRC_ROOT/scripts/lib/backup-health.sh"
[ -r "$LIB" ] || { echo "test-backup-health: INCONCLUSIVE — cannot read $LIB"; exit 2; }
# shellcheck source=scripts/lib/backup-health.sh
. "$LIB"

pass=0
fail=0
NOW=1790000000
HOUR=3600

# A healthy node, using vm5's real numbers: 2.6 GB database, 24.7 GB free.
#
# ⛔ `-` means "this field is EMPTY", not "use the default". Written as `${6:-2596528}` the two were
# indistinguishable, so the "du printed nothing" case below passed an empty DBKB, got the default
# back, and reported OK — a green that proved nothing. The library was right; the fixture was not.
# `${6-...}` (no colon) would also work, but a visible sentinel says which cases are deliberate.
probe() {
    local d
    _p() { if [ "${1:-}" = "-" ]; then printf ''; else printf '%s' "${1:-$2}"; fi; }
    printf 'ENABLED %s\nACTIVE %s\nLASTRUN %s\nNEWEST %s\nCOUNT %s\nDBKB %s\nAVKB %s\nNOW %s\n' \
        "$(_p "${1:-}" enabled)" "$(_p "${2:-}" active)" "$(_p "${3:-}" success)" \
        "$(_p "${4:-}" "$((NOW - 4 * HOUR))")" "$(_p "${5:-}" 7)" \
        "$(_p "${6:-}" 2596528)" "$(_p "${7:-}" 24751328)" "$(_p "${8:-}" "$NOW")"
}

expect() {
    local name="$1" want="$2" want_rc="$3" probe_text="$4"
    local got rc
    got="$(backup_health_verdict "$probe_text" 36 1048576)"; rc=$?
    if [ "$got" = "$want" ] && [ "$rc" -eq "$want_rc" ]; then
        echo "  ok   $name"
        pass=$((pass + 1))
    else
        echo "  FAIL $name"
        echo "         expected: '$want' (exit $want_rc)"
        echo "         got:      '$got' (exit $rc)"
        fail=$((fail + 1))
    fi
}

# ⭐ THE POSITIVE CONTROL. Without this passing, every red below could be red for any reason.
expect "healthy node (vm5 numbers)" "OK 4 7 24751328 3645104" 0 "$(probe)"
expect "backup 35h old is still inside the 36h window" "OK 35 7 24751328 3645104" 0 \
    "$(probe enabled active success $((NOW - 35 * HOUR)))"
expect "oneshot has not run this boot, but a recent backup exists" "OK 4 7 24751328 3645104" 0 \
    "$(probe enabled active -)"

# The measured fleet state, exactly as it was on 2026-10-04.
expect "the state the fleet was actually in" \
    "PROBLEM timer is 'not-found', not enabled; timer is 'inactive', not active; NO backups present" 1 \
    "$(probe not-found inactive - - 0)"

expect "enabled but dead — looks right in the unit file, produces nothing" \
    "PROBLEM timer is 'inactive', not active" 1 "$(probe enabled inactive)"
expect "timer fine, last run FAILED" \
    "PROBLEM last run Result='exit-code'" 1 "$(probe enabled active exit-code)"
expect "backup 37h old is one hour too stale" \
    "PROBLEM newest backup is 37h old (limit 36h)" 1 \
    "$(probe enabled active success $((NOW - 37 * HOUR)))"
expect "a future mtime is clock skew, not freshness" \
    "PROBLEM newest backup is dated in the FUTURE (clock skew, not freshness)" 1 \
    "$(probe enabled active success $((NOW + 2 * HOUR)))"
expect "no room for the next backup" \
    "PROBLEM only 1000000KB free, backup-databases.sh refuses below 3645104KB" 1 \
    "$(probe enabled active success $((NOW - 4 * HOUR)) 7 2596528 1000000)"
expect "several reasons at once are all reported" \
    "PROBLEM timer is 'disabled', not enabled; NO backups present; only 1000KB free, backup-databases.sh refuses below 3645104KB" 1 \
    "$(probe disabled active success - 0 2596528 1000)"

# A probe that did not answer must never be a pass, and never a red either — red would send someone
# to install a timer that is already there.
expect "du printed nothing" "INCONCLUSIVE db_kb=''" 2 "$(probe enabled active success $((NOW - HOUR)) 7 -)"
expect "df header leaked through" "INCONCLUSIVE avail_kb='Capacity'" 2 \
    "$(probe enabled active success $((NOW - HOUR)) 7 2596528 Capacity)"
expect "probe returned nothing at all" "INCONCLUSIVE count=''" 2 ""
expect "ssh error instead of output" "INCONCLUSIVE count=''" 2 "Permission denied (publickey)."
expect "systemctl answered but du did not" "INCONCLUSIVE db_kb=''" 2 \
    "$(printf 'ENABLED enabled\nACTIVE active\nLASTRUN success\nNEWEST %s\nCOUNT 3\nAVKB 100\nNOW %s\n' "$((NOW - HOUR))" "$NOW")"
expect "count is numeric but the unit state is missing" "INCONCLUSIVE unit_state enabled='' active=''" 2 \
    "$(printf 'LASTRUN success\nNEWEST %s\nCOUNT 3\nDBKB 10\nAVKB 99999999\nNOW %s\n' "$((NOW - HOUR))" "$NOW")"

echo
if [ "$fail" -gt 0 ]; then
    echo "test-backup-health: $fail of $((pass + fail)) case(s) FAILED"
    exit 1
fi
echo "test-backup-health: all $pass case(s) pass — green is demonstrated, each red is distinct,"
echo "  and a probe that did not answer is INCONCLUSIVE rather than either"
exit 0
