#!/usr/bin/env bash
#
# Self-test for the backup sizing and retention decisions (scripts/lib/backup-retention.sh).
#
# These exist because the old policy was "delete anything older than 7 days" and "write until the
# disk says no", and neither of those fails in a way anyone sees until a node is full. So every case
# here is a way that could happen, driven against the real library.
#
# The fleet numbers used below were measured 2026-10-04/05, so the realistic cases are checked
# against what the nodes actually report rather than round figures.
#
# Usage: scripts/test-backup-retention.sh
set -uo pipefail

SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$SRC_ROOT/scripts/lib/backup-retention.sh"
[ -r "$LIB" ] || { echo "test-backup-retention: INCONCLUSIVE — cannot read $LIB"; exit 2; }
# shellcheck source=scripts/lib/backup-retention.sh
. "$LIB"

pass=0
fail=0

check() {
    local name="$1" got="$2" want="$3"
    if [ "$got" = "$want" ]; then
        echo "  ok   $name"
        pass=$((pass + 1))
    else
        echo "  FAIL $name"
        echo "         expected: '$want'"
        echo "         got:      '$got'"
        fail=$((fail + 1))
    fi
}

space() {
    local name="$1" db="$2" avail="$3" want="$4" want_rc="$5"
    local got rc
    got="$(backup_space_verdict "$db" "$avail")"; rc=$?
    check "$name" "$got|$rc" "$want|$want_rc"
}

echo "space:"
# vm8 is the tightest node on the fleet and must still be allowed to back up.
space "vm8: 2.4GB db, 12.2GB free"  2408239 12510208 "OK 3456815 12510208" 0
space "vm5: 2.6GB db, 24.7GB free"  2596528 24751328 "OK 3645104 24751328" 0
# ⛔ The case the old script got wrong: it would have written until the filesystem refused.
space "nearly full: 2.6GB db, 1GB"  2596528  1048576 "REFUSE_SPACE 3645104 1048576" 1
space "room for the copy but no headroom" 2596528 2600000 "REFUSE_SPACE 3645104 2600000" 1
space "exactly enough"              1000000  2048576 "OK 2048576 2048576" 0
space "one KB short"                1000000  2048575 "REFUSE_SPACE 2048576 2048575" 1
# A `du` or `df` that printed nothing must refuse, not compare against an empty string.
space "du printed nothing"                ""  2048576 "REFUSE_PARSE db_kb " 1
space "df printed nothing"           1000000       "" "REFUSE_PARSE avail_kb " 1
space "df header leaked"             1000000 "Capacity" "REFUSE_PARSE avail_kb Capacity" 1

echo
echo "prune:"
NOW=1790000000
DAY=86400

# Eight daily backups. The extra hour matters: the timer fires at 03:00 and a prune evaluated at
# exactly N*86400 is NOT "older than N days" — `$1 < cutoff` is strict. The first draft of this
# fixture used exact multiples and the day-7 file sat precisely on the boundary, so two cases
# disagreed with the code and the code was right. Offset by an hour, day7 is unambiguously older.
EIGHT=""
for i in 0 1 2 3 4 5 6 7; do
    EIGHT="${EIGHT}$((NOW - i * DAY - 3600)) /b/ghost-day$i.db.gz
"
done
check "8 daily, keep 7, 7 days -> oldest only" \
    "$(backup_prune_list 7 7 "$NOW" "$EIGHT")" "/b/ghost-day7.db.gz"

check "8 daily, keep 10 -> nothing (count rule protects them)" \
    "$(backup_prune_list 10 7 "$NOW" "$EIGHT")" ""

check "8 daily, keep 2, 7 days -> only the ones BOTH rules condemn" \
    "$(backup_prune_list 2 7 "$NOW" "$EIGHT")" "/b/ghost-day7.db.gz"

# The boundary itself, asserted rather than assumed. "Older than 7 days" is strict, so a file aged
# exactly 7 days survives and one a second past it does not.
check "exactly 7 days old is NOT older than 7 days" \
    "$(backup_prune_list 1 7 "$NOW" "$(printf '%s /b/ghost-now.db.gz\n%s /b/ghost-exact.db.gz\n' "$NOW" "$((NOW - 7 * DAY))")")" ""
check "one second past 7 days is" \
    "$(backup_prune_list 1 7 "$NOW" "$(printf '%s /b/ghost-now.db.gz\n%s /b/ghost-past.db.gz\n' "$NOW" "$((NOW - 7 * DAY - 1))")")" "/b/ghost-past.db.gz"

# ⛔ The gap the age-only policy left: a node that was off and caught up through Persistent=true can
# hold many copies made within minutes of each other, NONE of them old enough to prune. Age alone
# deletes nothing and the disk fills.
BURST=""
for i in 0 1 2 3 4 5 6 7 8 9; do
    BURST="${BURST}$((NOW - i * 60)) /b/ghost-burst$i.db.gz
"
done
check "10 copies in 10 minutes, age-only would keep all; count rule still keeps them because none is old" \
    "$(backup_prune_list 3 7 "$NOW" "$BURST")" ""

# Everything ancient: the count rule is what stops this deleting the lot.
OLD=""
for i in 0 1 2 3 4 5; do
    OLD="${OLD}$((NOW - (100 + i) * DAY)) /b/ghost-old$i.db.gz
"
done
check "6 ancient copies, keep 2 -> the 4 beyond the newest 2" \
    "$(backup_prune_list 2 7 "$NOW" "$OLD")" "$(printf '/b/ghost-old2.db.gz\n/b/ghost-old3.db.gz\n/b/ghost-old4.db.gz\n/b/ghost-old5.db.gz')"

# ⛔ CONTROL. keep=1 against an all-ancient set must leave exactly one file standing. A prune that
# can empty the directory is not a retention policy.
check "CONTROL: 6 ancient, keep 1 -> five go, the newest survives" \
    "$(backup_prune_list 1 7 "$NOW" "$OLD")" "$(printf '/b/ghost-old1.db.gz\n/b/ghost-old2.db.gz\n/b/ghost-old3.db.gz\n/b/ghost-old4.db.gz\n/b/ghost-old5.db.gz')"

check "single ancient backup, keep 1 -> nothing (never delete the only copy)" \
    "$(backup_prune_list 1 7 "$NOW" "$((NOW - 400 * DAY)) /b/ghost-only.db.gz")" ""

check "empty listing -> nothing" "$(backup_prune_list 7 7 "$NOW" "")" ""

check "junk lines are ignored, not treated as epoch 0" \
    "$(backup_prune_list 1 7 "$NOW" "$(printf 'ls: cannot access /b: No such file or directory\n%s /b/ghost-a.db.gz\n' "$((NOW - 400 * DAY))")")" ""

# keep=0 would permit deleting every copy, so it is rejected rather than honoured.
out="$(backup_prune_list 0 7 "$NOW" "$OLD" 2>&1)"; rc=$?
check "keep_count 0 is refused" "$rc" "1"

echo
if [ "$fail" -gt 0 ]; then
    echo "test-backup-retention: $fail of $((pass + fail)) case(s) FAILED"
    exit 1
fi
echo "test-backup-retention: all $pass case(s) pass — a backup is refused rather than"
echo "  filling the disk, and a prune can never remove the newest copy"
exit 0
