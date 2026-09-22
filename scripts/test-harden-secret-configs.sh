#!/usr/bin/env bash
#
# Self-test for harden-secret-configs.sh.
#
# The whole value of that script is that it NOTICES. A reconciler that walks an empty set, or
# one whose check reports PASS whatever it finds, is worth nothing — and that is the exact shape
# of the bug it exists to close (#916): the hardening in install-node.sh was real, ran once, and
# nothing ever asked again.
#
# So this drives it against deliberately-permissive fixtures and asserts it says no, then
# asserts it actually changed them, then asserts it goes quiet only once they are correct.
#
# Runs entirely against a temporary --root. No node is contacted and nothing real is chmod'd.
#
# Usage: scripts/test-harden-secret-configs.sh
set -uo pipefail

SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARDEN="$SRC_ROOT/scripts/ops/harden-secret-configs.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

check() {  # label expected actual
    if [ "$2" = "$3" ]; then
        echo "  ok    $1"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $1"
        echo "          expected: $2"
        echo "          actual:   $3"
        FAIL=$((FAIL + 1))
    fi
}

contains() {  # label haystack needle
    case "$2" in
        *"$3"*) echo "  ok    $1"; PASS=$((PASS + 1)) ;;
        *) echo "  FAIL  $1"
           echo "          output did not contain: $3"
           echo "          got: $2"
           FAIL=$((FAIL + 1)) ;;
    esac
}

absent() {  # label haystack needle
    case "$2" in
        *"$3"*) echo "  FAIL  $1"
                echo "          output should NOT contain: $3"
                FAIL=$((FAIL + 1)) ;;
        *) echo "  ok    $1"; PASS=$((PASS + 1)) ;;
    esac
}

# A fake filesystem root carrying the same paths a node has.
mk_fixtures() {  # mode_for_pool_config
    rm -rf "$TMP/fake"
    mkdir -p "$TMP/fake/etc/ghost" "$TMP/fake/etc/bitcoin" "$TMP/fake/opt/ghost/config"
    for f in \
        "$TMP/fake/etc/ghost/pool-config.toml" \
        "$TMP/fake/etc/ghost/pool-config.toml.bak.20260811-134730" \
        "$TMP/fake/etc/ghost/pool-config.toml.prev-tlv" \
        "$TMP/fake/opt/ghost/config/pool-config.toml" \
        "$TMP/fake/etc/ghost/pool.toml" \
        "$TMP/fake/etc/ghost/pool.toml.bak.20260704-195338" \
        "$TMP/fake/etc/bitcoin/bitcoin.conf"
    do
        echo 'authority_secret_key = "fixture-not-a-real-key"' > "$f"
        chmod "$1" "$f"
    done
}

echo "harden-secret-configs.sh self-test"
echo

# ── 1. An empty host must be INCONCLUSIVE, never a pass ──────────────────────────────────────
# This is the failure mode that matters most: a glob that matches nothing reporting a clean
# bill of health from a run that examined nothing.
mkdir -p "$TMP/empty"
OUT=$("$HARDEN" --check --root "$TMP/empty" 2>&1); RC=$?
check   "empty host exits 2 (INCONCLUSIVE), not 0" "2" "$RC"
contains "empty host says so out loud" "$OUT" "INCONCLUSIVE"
absent  "empty host does not claim PASS" "$OUT" "PASS:"

# ── 2. --check must FAIL on permissive fixtures ──────────────────────────────────────────────
mk_fixtures 644
OUT=$("$HARDEN" --check --root "$TMP/fake" 2>&1); RC=$?
check    "--check exits 1 when configs are 644" "1" "$RC"
contains "--check names the live config"   "$OUT" "etc/ghost/pool-config.toml"
contains "--check reports the transition"  "$OUT" "644 -> 600"
contains "--check covers the .bak sibling" "$OUT" "pool-config.toml.bak.20260811-134730"
contains "--check covers the .prev sibling" "$OUT" "pool-config.toml.prev-tlv"
contains "--check covers the /opt copy"    "$OUT" "opt/ghost/config/pool-config.toml"
contains "--check covers pool.toml"        "$OUT" "etc/ghost/pool.toml"
contains "--check covers bitcoin.conf"     "$OUT" "etc/bitcoin/bitcoin.conf"
absent   "--check does not claim PASS while 644" "$OUT" "PASS:"

# ── 2b. it must only ever TIGHTEN ────────────────────────────────────────────────────────────
# A backup is read by nobody, so it has no owner requirement. An earlier version of the table
# demanded ghost:ghost for pool.toml backups, which sit at root:root on the live fleet — that
# would have LOOSENED every one of them, a hardening tool granting the ghost user access it did
# not previously have. Live files keep their owner rule; backups must be mode-only.
OWNER_LINES=$(printf '%s\n' "$OUT" | grep '^  OWNER ')
OWNER_ON_BACKUPS=$(printf '%s\n' "$OWNER_LINES" | grep -cE '\.bak\.|\.prev-')
check "backups are never flagged for an owner change" "0" "$OWNER_ON_BACKUPS"
OWNER_ON_LIVE=$(printf '%s\n' "$OWNER_LINES" | grep -cE 'pool-config\.toml  |/pool\.toml  |bitcoin\.conf  ')
check "live configs still carry an owner rule" "4" "$OWNER_ON_LIVE"

# ── 3. --check must not MUTATE anything ──────────────────────────────────────────────────────
MODE_AFTER_CHECK=$(stat -c '%a' "$TMP/fake/etc/ghost/pool-config.toml")
check "--check left the mode alone" "644" "$MODE_AFTER_CHECK"

# ── 4. apply must actually change the files ──────────────────────────────────────────────────
OUT=$("$HARDEN" --root "$TMP/fake" 2>&1); RC=$?
check    "apply exits 0" "0" "$RC"
contains "apply reports a non-zero corrected count" "$OUT" "corrected=7"
check "live config is now 600" "600" "$(stat -c '%a' "$TMP/fake/etc/ghost/pool-config.toml")"
check "bak sibling is now 600" "600" "$(stat -c '%a' "$TMP/fake/etc/ghost/pool-config.toml.bak.20260811-134730")"
check "prev sibling is now 600" "600" "$(stat -c '%a' "$TMP/fake/etc/ghost/pool-config.toml.prev-tlv")"
check "/opt copy is now 600"   "600" "$(stat -c '%a' "$TMP/fake/opt/ghost/config/pool-config.toml")"
check "pool.toml is now 600"   "600" "$(stat -c '%a' "$TMP/fake/etc/ghost/pool.toml")"
check "bitcoin.conf is now 600" "600" "$(stat -c '%a' "$TMP/fake/etc/bitcoin/bitcoin.conf")"
check "pool.toml backup is now 600" "600" "$(stat -c '%a' "$TMP/fake/etc/ghost/pool.toml.bak.20260704-195338")"

# ── 5. once correct, --check passes and apply is a no-op ─────────────────────────────────────
OUT=$("$HARDEN" --check --root "$TMP/fake" 2>&1); RC=$?
check    "--check exits 0 once corrected" "0" "$RC"
contains "--check reports what it examined" "$OUT" "7 secret-bearing config(s) examined"

OUT=$("$HARDEN" --root "$TMP/fake" 2>&1)
contains "a second apply corrects nothing" "$OUT" "corrected=0"

# ── 6. a single permissive file is enough to fail ────────────────────────────────────────────
# Guards the arithmetic: a reconciler that only fails when EVERYTHING is wrong would pass here.
chmod 640 "$TMP/fake/etc/ghost/pool-config.toml.bak.20260811-134730"
OUT=$("$HARDEN" --check --root "$TMP/fake" 2>&1); RC=$?
check    "one group-readable sibling fails the check" "1" "$RC"
contains "and it is named"                  "$OUT" "640 -> 600"
contains "count is 1, not all 7"            "$OUT" "1 of 7"

echo
echo "  passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "  OK"
