#!/usr/bin/env bash
#
# Self-test for the pre-migration backup gate's decision (scripts/lib/migration-backup-gate.sh).
#
# The gate's whole value is that it REFUSES, so this drives it against deliberately-broken probe
# output and asserts it says no. ⛔ Two of these cases are not hypothetical: the first draft
# validated the three probe fields by CONCATENATING them and testing `*[!0-9]*`, which made an empty
# field invisible as long as the others were numeric. `sqlite silent fail` and `df header leaked`
# both passed that check, then hit `[: : integer expression expected` and carried on to deploy a
# migration with no backup. This file is why that was found before it shipped.
#
# The real-fleet numbers below were measured on ghost-vm5, 2026-10-04, so the happy path is checked
# against what the fleet actually reports rather than a round number.
#
# Usage: scripts/test-migration-backup-gate.sh
set -uo pipefail

SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$SRC_ROOT/scripts/lib/migration-backup-gate.sh"
[ -r "$LIB" ] || { echo "test-migration-backup-gate: INCONCLUSIVE — cannot read $LIB"; exit 2; }
# shellcheck source=scripts/lib/migration-backup-gate.sh
. "$LIB"

pass=0
fail=0

# `want`, the probe text, the expected verdict line, and the expected exit code. Both are asserted:
# a verdict with the wrong exit code would let a refusal through as something to act on.
expect() {
    local name="$1" want="$2" probe="$3" exp_out="$4" exp_rc="$5"
    local got rc
    got="$(migration_backup_verdict "$want" "$probe")"
    rc=$?
    if [ "$got" = "$exp_out" ] && [ "$rc" -eq "$exp_rc" ]; then
        echo "  ok   $name -> $got (exit $rc)"
        pass=$((pass + 1))
    else
        echo "  FAIL $name"
        echo "         expected: '$exp_out' (exit $exp_rc)"
        echo "         got:      '$got' (exit $rc)"
        fail=$((fail + 1))
    fi
}

REAL="$(printf 'VER 59\nDBKB 2596528\nAVKB 24751328\n')"

expect "live fleet, v59 -> v60"        60 "$REAL" "BACKUP 59 5193056 24751328" 0
expect "already migrated"              60 "$(printf 'VER 60\nDBKB 2596528\nAVKB 24751328\n')" "NOMIGRATE 60" 0
expect "ahead of this binary"          60 "$(printf 'VER 61\nDBKB 2596528\nAVKB 24751328\n')" "NOMIGRATE 61" 0
expect "fresh node, no database"       60 "NODB" "NODB" 0

# Refusals. Each one is a way the probe can fail to answer while looking like it did.
expect "not enough room for a copy"    60 "$(printf 'VER 59\nDBKB 2596528\nAVKB 1000000\n')" "REFUSE_SPACE 5193056 1000000" 1
expect "exactly one byte short"        60 "$(printf 'VER 59\nDBKB 100\nAVKB 199\n')" "REFUSE_SPACE 200 199" 1
expect "exactly enough room"           60 "$(printf 'VER 59\nDBKB 100\nAVKB 200\n')" "BACKUP 59 200 200" 0
expect "sqlite printed nothing"        60 "$(printf 'VER \nDBKB 2596528\nAVKB 24751328\n')" "REFUSE_PARSE live_schema " 1
expect "df header leaked through"      60 "$(printf 'VER 59\nDBKB 2596528\nAVKB Capacity\n')" "REFUSE_PARSE avail_kb " 1
expect "du printed nothing"            60 "$(printf 'VER 59\nDBKB \nAVKB 24751328\n')" "REFUSE_PARSE db_kb " 1
expect "probe returned nothing"        60 "" "REFUSE_PARSE live_schema " 1
expect "ssh error instead of output"   60 "Permission denied (publickey)." "REFUSE_PARSE live_schema " 1
expect "unreadable SCHEMA_VERSION"     "" "$REAL" "REFUSE_PARSE want_schema " 1
expect "non-numeric SCHEMA_VERSION"    "v60" "$REAL" "REFUSE_PARSE want_schema v60" 1

# ⛔ The NODB shortcut must not be reachable by a probe that merely MENTIONS the word, or a node
# whose sqlite3 error text happened to contain it would skip the backup entirely.
expect "NODB inside other output"      60 "$(printf 'sqlite3: NODB is not a command\nVER 59\nDBKB 100\nAVKB 400\n')" "BACKUP 59 200 400" 0

echo
if [ "$fail" -gt 0 ]; then
    echo "test-migration-backup-gate: $fail of $((pass + fail)) case(s) FAILED"
    exit 1
fi
echo "test-migration-backup-gate: all $pass case(s) pass — the gate refuses on every"
echo "  way the probe can fail to answer, and acts only on a fully-numeric one"
exit 0
