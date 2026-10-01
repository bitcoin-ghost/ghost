#!/usr/bin/env bash
#
# Record one fleet-convergence sample and say what CHANGED since the last one.
#
# `check-fleet-convergence.sh` answers "do the nodes agree right now?". It is run by hand, which is
# how #945's missing root went unnoticed. This wraps it so the answer is kept, compared, and —
# critically — so a run that goes wrong is still loud.
#
# ## Why it exists (#971)
#
# `MESH_NODE_LIST_CHECKPOINT_HEIGHT = 970_500`. The margin between the tip and that height is the
# whole reason it was picked: if the fleet stops agreeing on a root, the response is to roll
# ghost-pool and push the height out, and that only works if someone NOTICES while blocks remain.
#
# ⛔ The failure mode is SILENCE. No node logs anything when the fleet's roots diverge — each is
# happily computing its own answer. All four roots are vote-rejection conditions, so a fleet
# agreeing on three of four finalises nothing, for ever, quietly.
#
# ## The two traps this is built around
#
# 1. **Advert-store warm-up is not divergence.** The store is in memory and refills on the
#    `MESH_ADVERT_REPUBLISH_SECS` (600s) cycle. Until a node holds an advert from every qualified
#    node, `store.covering()` yields nothing and ALL FOUR roots read `null` — while the qualified
#    sets still look fine. MEASURED 2026-09-27 after a roll: a node up 21 min reported roots; nodes
#    up 18, 13 and 9 min reported four nulls each. That is warm-up.
#
#    A watcher that alerts on null cries wolf after every roll; one that ignores null cannot see a
#    real blind spot. So this reports nulls ALONGSIDE each node's restart age and says which it
#    thinks it is — it does not silently swallow either.
#
# 2. **A change-only monitor is mute through a stall.** If this only spoke on change, a probe that
#    broke on day one would look exactly like six quiet days. Every run prints a one-line verdict
#    whether or not anything moved, and the ledger records every sample.
#
# ## Usage
#
#   scripts/watch-fleet-convergence.sh                  # sample, record, report
#   scripts/watch-fleet-convergence.sh --ledger PATH    # or set GHOST_CONVERGENCE_LEDGER
#
# ⛔ The ledger defaults OUTSIDE the repo (`~/.ghost/fleet-convergence.tsv`). It is operator-local
# state, and an untracked file under the working tree would make `record-tests.sh` refuse — which
# would block a deploy for anyone who had run this, which is exactly the wrong failure to add to a
# monitoring tool. Point `--ledger` into the repo only if you intend to commit the samples.
#
# Exit 0 = sampled and nothing of concern changed, 1 = something changed that wants a human,
# 2 = INCONCLUSIVE (the underlying check could not sample the fleet).
#
# ⛔ Exit 0 does NOT mean "converged" — it means "this sample matched the last one and the
# underlying check was happy". Read the verdict line.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

LEDGER="${GHOST_CONVERGENCE_LEDGER:-$HOME/.ghost/fleet-convergence.tsv}"
NODES=()
while [ $# -gt 0 ]; do
    case "$1" in
        --ledger) LEDGER="${2:-}"; shift 2 ;;
        *) NODES+=("$1"); shift ;;
    esac
done
[ ${#NODES[@]} -gt 0 ] || NODES=(ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4 ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8)

CHECK="$REPO_ROOT/scripts/check-fleet-convergence.sh"
[ -x "$CHECK" ] || { echo "watch-fleet-convergence: INCONCLUSIVE — $CHECK is not executable"; exit 2; }

TS="$(date -u +%FT%TZ)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# ---- restart ages first, so a null root can be attributed rather than guessed ----------------
# Collected BEFORE the convergence sample: a node restarted between the two would otherwise look
# older than it is, which is the direction that hides warm-up.
for n in "${NODES[@]}"; do
    (
        v="$(timeout 45 ssh -o ConnectTimeout=10 -o BatchMode=yes "$n" \
             "systemctl show ghost-pool -p ActiveEnterTimestamp --value" 2>/dev/null)"
        if [ -n "$v" ]; then
            start_epoch="$(date -u -d "$v" +%s 2>/dev/null || echo "")"
            if [ -n "$start_epoch" ]; then
                printf '%s\t%s\n' "$n" "$(( ($(date -u +%s) - start_epoch) / 60 ))" > "$TMP/$n.age"
            fi
        fi
    ) &
done
wait

# ---- the sample ------------------------------------------------------------------------------
"$CHECK" "${NODES[@]}" > "$TMP/out" 2>&1
CHECK_RC=$?

# Roots and qualified-set hashes, as `field=value`, from the agreeing (✓) lines.
# A field that is NOT on a ✓ line is deliberately absent here, so it reads as a change.
AGREED="$(grep -E '^  ✓  ' "$TMP/out" \
          | sed -E 's/^  ✓  ([a-z_]+) +#[0-9]+ +agree +([0-9a-f]+).*/\1=\2/' \
          | grep -E '^[a-z_]+=[0-9a-f]+$' | sort)"

LISTED="$(grep -E '^  listed ' "$TMP/out" | sed -E "s/.*\[//;s/\].*//;s/'//g" | tr -d ' ')"
GAPS="$(grep -cE '^  ⛔ missing adverts' "$TMP/out" || true)"

mkdir -p "$(dirname "$LEDGER")"
[ -f "$LEDGER" ] || printf 'ts\trc\tlisted\tgaps\tfields\n' > "$LEDGER"
PREV="$(tail -n +2 "$LEDGER" | tail -1 | cut -f5)"
FIELDS="$(printf '%s' "$AGREED" | tr '\n' ',' | sed 's/,$//')"
printf '%s\t%s\t%s\t%s\t%s\n' "$TS" "$CHECK_RC" "${LISTED:-?}" "${GAPS:-0}" "$FIELDS" >> "$LEDGER"

# ---- report ----------------------------------------------------------------------------------
echo "watch-fleet-convergence: $TS  (underlying check exit=$CHECK_RC)"

AGES=""
for n in "${NODES[@]}"; do
    [ -f "$TMP/$n.age" ] && AGES="$AGES$(cat "$TMP/$n.age")  "
done
YOUNG="$(awk -F'\t' '$2 < 25 {printf "%s(%smin) ", $1, $2}' "$TMP"/*.age 2>/dev/null)"

if [ "$CHECK_RC" = "2" ]; then
    echo "  ⛔ INCONCLUSIVE — the fleet could not be sampled. A node that did not answer is not a"
    echo "     node that agrees. Output follows:"
    sed 's/^/     /' "$TMP/out"
    exit 2
fi

NULLS="$(grep -cE '^  ⛔ .*NULL on:' "$TMP/out" || true)"
if [ "${NULLS:-0}" -gt 0 ]; then
    echo "  ⛔ $NULLS field(s) NULL."
    grep -E '^  ⛔ .*NULL on:' "$TMP/out" | sed 's/^/     /'
    if [ -n "$YOUNG" ]; then
        echo "     ⚠ Recently restarted (<25 min): $YOUNG"
        echo "     That is the advert warm-up signature, not divergence — the store refills on the"
        echo "     600s republish cycle. Re-sample once every node has been up longer than that."
    else
        echo "     ⛔ NO node restarted recently, so warm-up does NOT explain this. Treat it as a"
        echo "        real blind spot and do not arm anything on it."
    fi
fi

if [ "${GAPS:-0}" -gt 0 ]; then
    echo "  ⛔ missing adverts reported — no checkpoint can finalise without full coverage:"
    grep -A4 -E '^  ⛔ missing adverts' "$TMP/out" | sed 's/^/     /'
fi

CHANGED=0
if [ -z "$PREV" ]; then
    echo "  ⓘ first sample recorded in $LEDGER — nothing to compare against yet"
elif [ "$PREV" = "$FIELDS" ]; then
    echo "  ✓  all $(printf '%s' "$AGREED" | grep -c . ) compared field(s) identical to the previous sample"
else
    CHANGED=1
    echo "  *** CHANGED since the previous sample:"
    diff <(printf '%s\n' "$PREV" | tr ',' '\n') <(printf '%s\n' "$FIELDS" | tr ',' '\n') \
        | grep -E '^[<>]' | sed 's/^/     /'
    echo "     A root that moved is not automatically wrong — the qualified set or the adverts may"
    echo "     legitimately have changed. A root that moved on SOME nodes and not others is."
fi

echo "  listed=${LISTED:-?}  nodes_sampled=${#NODES[@]}  ledger=$LEDGER"

if [ "$CHECK_RC" != "0" ] || [ "$CHANGED" = "1" ] || [ "${GAPS:-0}" -gt 0 ]; then
    echo
    echo "watch-fleet-convergence: wants a human."
    exit 1
fi
echo "watch-fleet-convergence: no change"
exit 0
