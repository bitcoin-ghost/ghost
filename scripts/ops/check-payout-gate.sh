#!/usr/bin/env bash
#
# Judge the no-vote payout gate (`PAYOUT_FROM_SHARD_HEIGHT`, armed at 964_100).
#
# At that height each node stops putting the payout through a BFT vote and pays from its own
# shard view. The change is observable within minutes — the live proposal path is tip-driven and
# fires on every block, ~22 times a day — so this reports the three signals that matter and says
# whether they agree with the height the fleet is actually at.
#
# ## Why this is a script and not three greps
#
# Every one of these counters has a way of reading healthy while nothing works:
#
# ⛔ `journalctl -u ghost-pool -p err` returns 0 FOREVER. ghost-pool logs everything at info,
#    including its own `ERROR` lines — severity is in the message text, not the priority. Measured
#    2026-08-21: `-p err` = 0 while `grep " ERROR "` = 3.
# ⛔ `grep -ci finalis` counts the FAILURE line, "no payout checkpoint has finalised for N blocks".
#    On vm2 it read 3, of which 3 were failures and 0 were genuine finalisations. Both counts are
#    reported here, separately, because their difference is the whole story.
# ⛔ There are TWO "checkpoint FINALISED" strings — `payout ledger` and `mesh node-list`. A bare
#    grep for FINALISED counts the wrong path.
# ⛔ An ssh that fails, a journal that has rotated, or a typo'd unit name all yield 0 for every
#    counter, which is indistinguishable from "quiet". A positive control line count is taken
#    first and a node with no journal at all is reported as UNMEASURED, never as healthy.
#
# Usage:  scripts/ops/check-payout-gate.sh [hours]        (default 24)
set -uo pipefail

HOURS="${1:-24}"
NODES="${GHOST_NODES:-ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4 ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8}"
GATE="${PAYOUT_GATE_HEIGHT:-964100}"
SINCE="${HOURS} hours ago"

NOVOTE="Paying from this node's own shard view (no vote"
APPROVED="Payout consensus approved"
FINALISED="payout ledger checkpoint FINALISED"
STALLED="no payout checkpoint has finalised"

printf 'gate %s | window %sh\n\n' "$GATE" "$HOURS"
printf '%-11s %-8s %-7s %-8s %-9s %-8s %-7s %s\n' \
    NODE HEIGHT NO-VOTE APPROVED FINALISED STALLED ERRORS VERDICT

rc=0
for node in $NODES; do
    # ⚠ Two quoting traps, both hit while writing this, both worth stating.
    #
    # 1. ssh CONCATENATES its arguments into one remote command string — it does not preserve
    #    argv. `ssh host bash -s -- "$SINCE" "$NOVOTE"` therefore arrives as a flat string with
    #    the quotes eaten, and the strings here contain spaces, an apostrophe and parentheses.
    # 2. Building the journalctl call into a shell variable and re-expanding it word-splits
    #    `--since '6 hours ago'` into four arguments.
    #
    # Both produced empty counters on all eight nodes — which the positive control below caught
    # as UNMEASURED rather than reporting as a healthy fleet of zeros. The fix is to pass ONLY an
    # integer across the boundary and keep every string inside the quoted heredoc, where nothing
    # local can touch it.
    out=$(timeout 60 ssh -o BatchMode=yes -o ConnectTimeout=10 "$node" \
              "HOURS=$HOURS bash -s" <<'REMOTE' 2>/dev/null
set -u
S=$(command -v sudo >/dev/null && echo sudo || echo)
log=$($S journalctl -u ghost-pool --since "${HOURS} hours ago" --no-pager 2>/dev/null)

# Positive control FIRST: if the journal yields nothing at all, every counter below is a zero
# that means "not measured", and must not be read as "nothing happened".
printf '%s\n' "$log" | grep -c ''
printf '%s\n' "$log" | grep -acF "Paying from this node's own shard view (no vote"
printf '%s\n' "$log" | grep -acF "Payout consensus approved"
printf '%s\n' "$log" | grep -acF "payout ledger checkpoint FINALISED"
printf '%s\n' "$log" | grep -acF "no payout checkpoint has finalised"
printf '%s\n' "$log" | grep -ac " ERROR "
curl -s --max-time 10 http://127.0.0.1:8080/api/v1/mining/status 2>/dev/null \
    | tr ',' '\n' | grep -m1 block_height | tr -dc '0-9'
REMOTE
    )

    lines=$(sed -n 1p <<<"$out"); novote=$(sed -n 2p <<<"$out"); approved=$(sed -n 3p <<<"$out")
    final=$(sed -n 4p <<<"$out"); stalled=$(sed -n 5p <<<"$out"); errors=$(sed -n 6p <<<"$out")
    height=$(sed -n 7p <<<"$out")

    if [ -z "${lines:-}" ] || [ "${lines:-0}" -eq 0 ] 2>/dev/null; then
        printf '%-11s %-8s %-7s %-8s %-9s %-8s %-7s %s\n' \
            "${node#ghost-}" "${height:-?}" - - - - - "UNMEASURED — no journal"
        rc=1
        continue
    fi

    # The verdict is judged against the height this node actually reports, not against the clock.
    verdict="?"
    if [ -z "${height:-}" ]; then
        verdict="UNMEASURED — no height"; rc=1
    elif [ "$height" -lt "$GATE" ]; then
        # Pre-gate: the vote is still in the path.
        if [ "${novote:-0}" -gt 0 ]; then verdict="WRONG — no-vote before the gate"; rc=1
        elif [ "${final:-0}" -eq 0 ]; then verdict="WATCH — no checkpoints finalising"; rc=1
        else verdict="pre-gate, as expected"; fi
    else
        # Post-gate: the vote should be gone and payouts must continue.
        if [ "${final:-0}" -eq 0 ]; then verdict="STOP — checkpoints NOT finalising"; rc=1
        elif [ "${novote:-0}" -eq 0 ]; then verdict="WATCH — gate passed, no no-vote lines yet"; rc=1
        elif [ "${approved:-0}" -gt 0 ]; then verdict="MIXED — still approving votes"; rc=1
        else verdict="post-gate, as expected"; fi
    fi
    [ "${stalled:-0}" -gt 0 ] && verdict="$verdict (+${stalled} stall warnings)"

    printf '%-11s %-8s %-7s %-8s %-9s %-8s %-7s %s\n' \
        "${node#ghost-}" "${height:-?}" "${novote:-?}" "${approved:-?}" \
        "${final:-?}" "${stalled:-?}" "${errors:-?}" "$verdict"
done

cat <<'NOTE'

FINALISED is the full string "payout ledger checkpoint FINALISED" — not a `grep finalis`, which
counts the failure line, and not `FINALISED` alone, which also matches the mesh node-list path.
STALLED counts "no payout checkpoint has finalised": non-zero means the node is SAYING it is stuck.
ERRORS greps " ERROR " in the message text; `-p err` is always 0 here and proves nothing.

If checkpoints stop when the gate fires, the gate is not necessarily the cause — the 18-21 Aug
standoff looked identical and was #724. Rollback: docs/PAYOUT_GATE_ROLLBACK.md.
NOTE

exit $rc
