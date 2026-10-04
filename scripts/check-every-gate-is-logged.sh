#!/usr/bin/env bash
#
# Fail if a resolved activation gate is not stated in the startup log.
#
# ## Why this exists
#
# #780 requires a node to STATE which gates it enforces, because otherwise "is this node armed,
# and at what height?" has no answer short of reading the binary — which cost real time while
# arming FEE_DRIFT_MINER_SHARE_HEIGHT on 2026-08-30.
#
# `ADDRESS_PROOF_ENFORCEMENT` was resolved, stored in its `OnceLock`, and given an accessor — and
# never added to the log line. It stayed invisible until it was armed at 970,500 on 2026-09-27, at
# which point a node enforcing it looked exactly like one that was not. It is the gate that moves
# the node-reward split, so it was the worst possible one to omit.
#
# The existing test (`init_activation_heights_states_what_it_enforces`) could not catch it: it
# asserts that SOME armed height appears in the output. That is a sample, not completeness, and a
# missing field is invisible to it by construction.
#
# ## What it checks
#
# Every gate stored in `init_activation_heights` must appear as a
# field in the `tracing::info!` that follows. The gate list is derived from the `.set()` calls
# rather than written here, so a new gate cannot be added without this noticing.
#
# Exit 0 = every resolved gate is logged, 1 = one is not, 2 = INCONCLUSIVE (the source shape this
# depends on could not be found, so it examined less than it claims).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

SRC="bins/ghost-pool/src/lib.rs"
[ -r "$SRC" ] || { echo "check-every-gate-is-logged: INCONCLUSIVE — cannot read $SRC"; exit 2; }

# The gates that are RESOLVED and stored. `NETWORK_TIER_FLOOR` is deliberately excluded: it is a
# difficulty tier, not a height, and the log states it separately.
# ⚠ Matches BOTH spellings. The resolver originally used `gates::X.set(v)` directly; it now
# goes through the checked `set_gate(&gates::X, "X", v)` helper, which refuses to discard a
# dropped override silently. This check INCONCLUSIVE'd on that change rather than passing over an
# empty list — working as intended — and supporting both forms means it survives the next reshape
# too.
# ⛔ Matched on `&gates::NAME`, NOT on the enclosing call. rustfmt wraps
# `set_gate(&gates::X, "X", v)` across lines whenever it is long, so a pattern anchored to
# `set_gate(&gates::` catches only the SHORT ones — it found 5 of 18 and reported "all 5 resolved
# gates are stated", i.e. passed while examining a quarter of them. That is the exact
# check-that-cannot-fail shape this script exists to prevent, reintroduced in the script itself.
# `&gates::NAME` appears exactly once per resolution and nowhere else, in either spelling.
GATES="$( { grep -oE 'gates::[A-Z_]+\.set\(' "$SRC" | sed -E 's/gates::([A-Z_]+)\.set\(/\1/'
           grep -oE '&gates::[A-Z_]+' "$SRC" | sed -E 's/&gates::([A-Z_]+)/\1/'
         } | grep -v '^NETWORK_TIER_FLOOR$' | sort -u)"

# A floor, because "found almost none" and "found none" fail differently: the second is caught by
# the emptiness check below, the first silently narrows what this guard covers.
if [ "$(printf '%s\n' "$GATES" | grep -c .)" -lt 10 ]; then
    echo "check-every-gate-is-logged: INCONCLUSIVE — only $(printf '%s\n' "$GATES" | grep -c .)"
    echo "  gate resolution(s) found in $SRC. There are ~17; a number this low means the matcher"
    echo "  no longer fits the source, not that the resolver shrank."
    exit 2
fi

if [ -z "$GATES" ]; then
    echo "check-every-gate-is-logged: INCONCLUSIVE — found no gate resolutions in $SRC"
    echo "  (looked for both \`gates::X.set(\` and \`set_gate(&gates::X\`)."
    echo "  The resolver was reshaped; this examined nothing and must not report success."
    exit 2
fi

# The startup log line. Bounded to the `tracing::info!` that carries `network = ?network`, so an
# unrelated log elsewhere in this large file cannot stand in for it.
LOGGED="$(awk '/tracing::info!\(/{buf=""; inblk=1}
               inblk{buf=buf $0 "\n"}
               inblk && /^    \);/{if (buf ~ /network = \?network/) {print buf; exit} inblk=0}' "$SRC")"

if [ -z "$LOGGED" ]; then
    echo "check-every-gate-is-logged: INCONCLUSIVE — could not locate the activation-heights"
    echo "  \`tracing::info!\` (the one carrying \`network = ?network\`) in $SRC."
    exit 2
fi

missing=0
for g in $GATES; do
    # gates::ADDRESS_PROOF_ENFORCEMENT -> field `address_proof_enforcement`
    field="$(printf '%s' "$g" | tr '[:upper:]' '[:lower:]')"
    if ! grep -qE "^[[:space:]]*${field} = " <<<"$LOGGED"; then
        echo "  *** ${g} is resolved and stored, but no \`${field} = \` field is logged"
        missing=$((missing + 1))
    fi
done

if [ "$missing" -gt 0 ]; then
    echo
    echo "check-every-gate-is-logged: $missing resolved gate(s) are never stated."
    echo
    echo "  #780: a node must state which gates it enforces. Without the field, an armed node and"
    echo "  a dormant one produce identical logs, and the only way to tell them apart is to read"
    echo "  the binary. Add \`<field> = %h(<local>)\` to the activation-heights info! line."
    exit 1
fi

echo "check-every-gate-is-logged: all $(wc -w <<<"$GATES") resolved gate(s) are stated in the startup log"
exit 0
