#!/usr/bin/env bash
#
# Fail if a production `QualifiedCapabilityProvider` is built without its H-7 enforcement gate.
#
# ## Why this exists
#
# `with_address_enforcement` carries a CONSENSUS height (#605). Above it, a challenger caught
# lying about its own address stops counting toward a target's distinct-`/24` diversity floor —
# which changes which nodes QUALIFY, and therefore how the node-reward pool splits.
#
# A provider built without it silently keeps the old rule. One node doing that while its peers
# enforce is not a cosmetic difference: they compute different qualified sets from the same
# converged ledger, and the split diverges. Nothing in the type system objects, nothing logs, and
# the binary is correct in isolation — the classic shape of a gate that fires wrong.
#
# There were FIVE construction sites in `bins/ghost-pool/src/main.rs` when this was written. I
# estimated "one" before counting, which is exactly why remembering is not a strategy.
#
# ## What it checks
#
# Every `QualifiedCapabilityProvider::new(` in `bins/` must have `.with_address_enforcement(`
# within the next few lines. Deliberately narrow:
#
#   * `bins/` only. Tests in `crates/ghost-verification` construct providers to exercise the
#     qualification maths itself and have no business carrying a production gate; sweeping them
#     in would mean 14 edits that say nothing and a check people learn to ignore.
#   * A small line window rather than a parser. The builder chain is written one call per line
#     here, and a check that needs a Rust parser to be right is a check that rots.
#
# Exit 0 = every production site is wired; 1 = at least one is not; 2 = INCONCLUSIVE, the check
# found no construction sites at all and therefore proved nothing.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

NEEDLE='QualifiedCapabilityProvider::new('
GATE='.with_address_enforcement('
WINDOW=8

mapfile -t HITS < <(grep -rn --include=*.rs "$NEEDLE" bins/ 2>/dev/null | grep -v '/tests/' || true)

if [ "${#HITS[@]}" -eq 0 ]; then
    echo "check-address-enforcement-wiring: INCONCLUSIVE — no \`$NEEDLE\` found under bins/."
    echo "  Either the type was renamed or the search is wrong. Either way this examined nothing,"
    echo "  so it must not report success."
    exit 2
fi

BAD=0
for hit in "${HITS[@]}"; do
    file="${hit%%:*}"
    rest="${hit#*:}"
    line="${rest%%:*}"
    # The gate call must appear in the builder chain that starts on this line.
    if ! sed -n "${line},$((line + WINDOW))p" "$file" | grep -qF "$GATE"; then
        echo "  *** $file:$line builds a QualifiedCapabilityProvider without $GATE"
        BAD=$((BAD + 1))
    fi
done

if [ "$BAD" -gt 0 ]; then
    echo
    echo "check-address-enforcement-wiring: $BAD of ${#HITS[@]} production site(s) unwired."
    echo "  Add .with_address_enforcement(ghost_pool::address_proof_enforcement_height()) to the"
    echo "  builder chain. A provider missing it keeps the pre-#605 rule, so once the gate fires"
    echo "  this node's qualified set — and its node-reward split — disagrees with the fleet."
    exit 1
fi

echo "check-address-enforcement-wiring: all ${#HITS[@]} production site(s) carry the H-7 gate"
exit 0
