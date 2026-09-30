#!/usr/bin/env bash
#
# Fail if the swarm-refusal test loops over an action no route refuses any more.
#
# ## Why this exists
#
# `swarm_control_routes_report_not_implemented_rather_than_fake_success` asserts that the
# fleet-control routes return an honest 501 instead of fabricating success. It does that by looping
# action strings through `swarm_not_implemented` and checking the shape of what comes back.
#
# ⛔ It tests the HELPER, not the routes. So when a route becomes real and stops calling that
# helper, its string stays in the loop and the test keeps passing — now asserting only that the
# helper echoes a string nothing passes it. Permanently green, describing code that no longer
# exists.
#
# That has now happened FOUR times, all within 2026-09-28..30:
#
#   restart node          became real, string left behind
#   refresh node status   became real (#941), string left behind
#   update node version   became a deliberate 403 refusal (#955), string left behind
#   configure node        became real (#959), string left behind
#
# Each was removed by hand, after being noticed by hand. The test's own doc comment warns about
# exactly this failure — it was written because `update-all` sat fabricating success while the test
# stayed green — and it still could not detect it happening to itself.
#
# ## What it checks
#
# Every action string the test loops over must be passed to `swarm_not_implemented` by a real call
# site. A string with no call site means that route no longer refuses, so the loop entry asserts
# nothing and must go — and the route wants its own test instead.
#
# ⚠ Deliberately one-directional. A route that refuses without appearing in the loop is not an
# error: `update_version` returns its own 403 and is tested separately. What must not happen is the
# loop claiming to cover something it does not.
#
# Exit 0 = every looped action is still refused, 1 = one is stale, 2 = INCONCLUSIVE.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

SRC="crates/ghost-verification/src/routes.rs"
[ -r "$SRC" ] || { echo "check-swarm-refusal-test-is-current: INCONCLUSIVE — cannot read $SRC"; exit 2; }

TESTFN="swarm_control_routes_report_not_implemented_rather_than_fake_success"
if ! grep -q "fn $TESTFN" "$SRC"; then
    echo "check-swarm-refusal-test-is-current: INCONCLUSIVE — $TESTFN not found in $SRC."
    echo "  It was renamed or removed; update this check or drop it with the test."
    exit 2
fi

# The strings the loop iterates: the `for action in [ ... ]` inside that test.
LOOPED="$(awk -v fn="fn $TESTFN" '
    index($0, fn) { inside = 1 }
    inside && /for action in \[/ { grab = 1; next }
    grab && /^\s*\] \{/ { exit }
    grab { print }
' "$SRC" | grep -oE '"[^"]+"' | tr -d '"')"

if [ -z "$LOOPED" ]; then
    echo "check-swarm-refusal-test-is-current: INCONCLUSIVE — found no action list in $TESTFN."
    echo "  The loop was reshaped; this examined nothing and must not report success."
    exit 2
fi

# Call sites that pass a STRING LITERAL as the action: the last quoted string immediately before
# the call's closing paren.
#
# ⚠ Non-greedy and NOT `[^)]*`. The first version of this check used `[^)]*`, which cannot cross
# the `)` inside `swarm_not_implemented(&format!("{:08x}", ...), "add node")` — so it reported a
# live call site as stale. A guard that mis-reads the thing it guards is worse than none.
#
# The `fn` definition line carries no string literal, and the test's own call passes the loop
# variable `action` rather than a literal, so both are excluded by construction rather than by
# line number.
REFUSED="$(perl -ne 'print "$1\n" while /swarm_not_implemented\(.*?"([^"]+)"\s*\)/g' "$SRC")"

if [ -z "$REFUSED" ]; then
    echo "check-swarm-refusal-test-is-current: INCONCLUSIVE — no \`swarm_not_implemented(.., \"..\")\`"
    echo "  call sites found. Either every route is now real, or the helper was renamed."
    exit 2
fi

stale=0
while IFS= read -r a; do
    [ -n "$a" ] || continue
    if grep -qxF "$a" <<<"$REFUSED"; then
        echo "  ✓  '$a' — still refused by a real call site"
    else
        echo "  *** '$a' — looped by the test, but NO route passes it to swarm_not_implemented"
        stale=$((stale + 1))
    fi
done <<< "$LOOPED"

if [ "$stale" -gt 0 ]; then
    echo
    echo "check-swarm-refusal-test-is-current: $stale stale entr(y/ies) in $TESTFN."
    echo
    echo "  That route became real or became a different kind of refusal, so the loop is now"
    echo "  asserting that the helper echoes a string nothing passes it — green, and about code"
    echo "  that no longer exists. Remove the entry and give the route its own test."
    exit 1
fi

echo "check-swarm-refusal-test-is-current: all $(grep -c . <<<"$LOOPED") looped action(s) are still refused"
exit 0
