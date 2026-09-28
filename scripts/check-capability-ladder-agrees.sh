#!/usr/bin/env bash
#
# Fail if the dashboard API's copy of the 5-4-3-2-1 ladder disagrees with the protocol constants.
#
# ## Why this exists
#
# The capability weights are protocol constants in `ghost-common/src/constants.rs`, and
# `NodeCapabilities::total_shares()` reads them. That is the value the payout path uses.
#
# The dashboard API does NOT read them. It open-codes the same ladder, twice:
#
#     if config.archive_mode { node_shares += 5; }
#     if config.ghost_pay    { node_shares += 4; }
#     ...
#
# plus `"max_shares": 15` as a literal in three places. So a reweight has to be made in up to six
# places, and missing one makes the dashboard disagree with the money.
#
# ⚠ That disagreement is quiet. Payouts divide by the SUM of actual shares, never by
# `MAX_NODE_SHARES` — so a stale API ladder does not change anyone's payment, it only makes the
# dashboard wrong. Nothing errors, nobody is underpaid, and the number just looks a bit off, which
# is exactly the kind of discrepancy that gets explained away rather than chased.
#
# ⛔ Written while DECIDING NOT to reweight for #736 (GhostPay removal). Proportional payout means
# removing a capability needs no reweight — the surviving 5:3:2:1 ratio is untouched — but the
# removal still has to delete `GHOST_PAY_SHARES` from six places. This makes five of them a CI
# failure; the sixth (`MAX_NODE_SHARES` vs the sum) is a compile error in constants.rs.
#
# Exit 0 = every copy agrees, 1 = a copy disagrees, 2 = INCONCLUSIVE (a source could not be read or
# the shape this depends on was not found).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

CONSTS="crates/ghost-common/src/constants.rs"
API="crates/ghost-verification/src/routes.rs"

for f in "$CONSTS" "$API"; do
    [ -r "$f" ] || { echo "check-capability-ladder-agrees: INCONCLUSIVE — cannot read $f"; exit 2; }
done

read_const() {
    local name="$1" v
    v="$(sed -nE "s/^pub const ${name}: i32 = ([0-9]+);.*/\1/p" "$CONSTS" | head -1)"
    [ -n "$v" ] || { echo "MISSING"; return; }
    printf '%s' "$v"
}

ARCHIVE="$(read_const ARCHIVE_MODE_SHARES)"
GHOSTPAY="$(read_const GHOST_PAY_SHARES)"
MINING="$(read_const PUBLIC_MINING_SHARES)"
REAPER="$(read_const REAPER_SHARES)"
ELDER="$(read_const ELDER_STATUS_SHARES)"
MAXN="$(read_const MAX_NODE_SHARES)"

for pair in "ARCHIVE_MODE_SHARES=$ARCHIVE" "GHOST_PAY_SHARES=$GHOSTPAY" \
            "PUBLIC_MINING_SHARES=$MINING" "REAPER_SHARES=$REAPER" \
            "ELDER_STATUS_SHARES=$ELDER" "MAX_NODE_SHARES=$MAXN"; do
    if [ "${pair#*=}" = "MISSING" ]; then
        echo "check-capability-ladder-agrees: INCONCLUSIVE — could not read ${pair%%=*} from $CONSTS."
        echo "  It was renamed or reshaped, so this examined less than it claims."
        exit 2
    fi
done

bad=0

# The open-coded ladders: each `if config.<field> { node_shares += N; }` in the API.
# Field -> expected weight, from the constants above.
check_field() {
    local field="$1" want="$2" found n
    # Grab the `+=` on the line following the `if config.<field> {`.
    found="$(grep -A1 -E "^[[:space:]]*if config\.${field} \{" "$API" \
             | grep -oE 'node_shares \+= [0-9]+' | grep -oE '[0-9]+' | sort -u)"
    if [ -z "$found" ]; then
        echo "  ?  config.${field} — no \`node_shares += N\` found after it in $API"
        echo "     Either the API stopped weighting this capability, or the shape changed."
        bad=$((bad + 1))
        return
    fi
    local copies; copies="$(printf '%s\n' "$found" | grep -c .)"
    if [ "$copies" -ne 1 ]; then
        echo "  *** config.${field} — copies DISAGREE with each other: $(printf '%s' "$found" | tr '\n' ' ')"
        bad=$((bad + 1))
        return
    fi
    n="$found"
    if [ "$n" != "$want" ]; then
        echo "  *** config.${field} — API adds ${n}, constants say ${want}"
        bad=$((bad + 1))
    else
        echo "  ✓  config.${field} — ${n} (matches)"
    fi
}

echo "check-capability-ladder-agrees: constants = archive:$ARCHIVE ghostpay:$GHOSTPAY mining:$MINING reaper:$REAPER elder:$ELDER max:$MAXN"
check_field archive_mode  "$ARCHIVE"
check_field ghost_pay     "$GHOSTPAY"
check_field public_mining "$MINING"
check_field reaper        "$REAPER"
check_field elder         "$ELDER"

# `"max_shares": N` literals must equal MAX_NODE_SHARES.
MAXLITS="$(grep -oE '"max_shares": [0-9]+' "$API" | grep -oE '[0-9]+' | sort -u)"
if [ -z "$MAXLITS" ]; then
    echo "  ?  no \"max_shares\": N literal found in $API"
    bad=$((bad + 1))
elif [ "$(printf '%s\n' "$MAXLITS" | grep -c .)" -ne 1 ] || [ "$MAXLITS" != "$MAXN" ]; then
    echo "  *** \"max_shares\" literals = $(printf '%s' "$MAXLITS" | tr '\n' ' '), MAX_NODE_SHARES = $MAXN"
    bad=$((bad + 1))
else
    echo "  ✓  \"max_shares\" literal — $MAXLITS (matches MAX_NODE_SHARES)"
fi

if [ "$bad" -gt 0 ]; then
    echo
    echo "check-capability-ladder-agrees: $bad disagreement(s) between the API and the constants."
    echo
    echo "  The payout path reads the constants; the dashboard open-codes them. A mismatch does not"
    echo "  change anyone's payment — payouts divide by the sum of actual shares — it just makes the"
    echo "  dashboard quietly wrong, which is the kind of thing that gets explained away."
    exit 1
fi

echo "check-capability-ladder-agrees: the API ladder matches the protocol constants"
exit 0
