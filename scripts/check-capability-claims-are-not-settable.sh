#!/usr/bin/env bash
#
# Fail if a capability claim could become remotely settable without anything noticing.
#
# ## The decision this protects
#
# The config endpoint (#403) must never let an operator set a capability claim. A capability is
# earned by passing its verification challenges; declaring it over HTTP would hand an operator the
# 5-4-3-2-1 shares the challenge system exists to gate. `apply()` enforces that by default-deny —
# only paths in `SETTABLE` are accepted — and `capability_claims_are_refused` pins it.
#
# ## Why the test could not protect it alone
#
# It named four paths by hand, and by the time anyone looked the list had already drifted (#963):
#
#   pool.public_mining              named — and not a field of any settings struct. It was removed
#                                   when `mining_mode` replaced it, and config.rs cites it BY NAME
#                                   as the key that sat in live configs for months meaning nothing.
#   network.mining_mode             the real driver of public_mining (+3) — absent
#   coordinator.coordinator_enabled the real driver of the coordinator role — absent
#
# So one of four assertions refused a key the struct does not read, and two real claims went
# unmentioned. Adding either to `SETTABLE` would have passed.
#
# ## What it checks
#
# 1. Every field of `NodeCapabilities` has an entry in `CAPABILITY_CONFIG_PATHS`, and every entry
#    names a real field. Exact set equality, both directions — a field left behind after a removal
#    is drift too.
# 2. No config path in that table appears in `SETTABLE`.
#
# The field list is derived from the struct, so a new capability cannot be added without this
# failing. The path mapping stays declared — a config path cannot be read off a struct field — but
# its COMPLETENESS is derived, which is the part that rotted.
#
# Exit 0 = the table is complete and no claim is settable, 1 = drift, 2 = INCONCLUSIVE.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

CAPS="crates/ghost-common/src/types.rs"
CFG="crates/ghost-verification/src/node_config.rs"

for f in "$CAPS" "$CFG"; do
    [ -r "$f" ] || { echo "check-capability-claims-are-not-settable: INCONCLUSIVE — cannot read $f"; exit 2; }
done

# (1) The capability fields, from the struct itself.
FIELDS="$(awk '/pub struct NodeCapabilities/{on=1; next} on && /^}/{exit} on' "$CAPS" \
          | grep -oE '^\s*pub [a-z_]+: bool,' | grep -oE '[a-z_]+: bool' | cut -d: -f1 | sort -u)"

if [ -z "$FIELDS" ]; then
    echo "check-capability-claims-are-not-settable: INCONCLUSIVE — no bool fields found in"
    echo "  \`pub struct NodeCapabilities\` in $CAPS. It was renamed or reshaped, so this"
    echo "  examined nothing and must not report success."
    exit 2
fi

# (2) The declared mapping, first tuple element = the field it covers.
MAPPED="$(awk '/CAPABILITY_CONFIG_PATHS/{on=1} on && /^\s*\];/{exit} on' "$CFG" \
          | grep -oE '\("[a-z_]+",' | grep -oE '"[a-z_]+"' | tr -d '"' | sort -u)"

if [ -z "$MAPPED" ]; then
    echo "check-capability-claims-are-not-settable: INCONCLUSIVE — no CAPABILITY_CONFIG_PATHS"
    echo "  table found in $CFG. That table is what this compares against."
    exit 2
fi

bad=0

missing="$(comm -23 <(printf '%s\n' "$FIELDS") <(printf '%s\n' "$MAPPED"))"
extra="$(comm -13 <(printf '%s\n' "$FIELDS") <(printf '%s\n' "$MAPPED"))"

if [ -n "$missing" ]; then
    for m in $missing; do
        echo "  *** NodeCapabilities.$m has NO entry in CAPABILITY_CONFIG_PATHS"
    done
    echo "      A capability nothing maps is a capability nothing checks is unsettable."
    bad=$((bad + 1))
fi

if [ -n "$extra" ]; then
    for e in $extra; do
        echo "  *** CAPABILITY_CONFIG_PATHS names '$e', which is not a NodeCapabilities field"
    done
    echo "      Either it was renamed or it was removed and the entry outlived it."
    bad=$((bad + 1))
fi

[ "$bad" -eq 0 ] && echo "  ✓  all $(grep -c . <<<"$FIELDS") capability field(s) are mapped, and nothing extra"

# (3) No mapped config path may be in the allowlist.
PATHS="$(awk '/CAPABILITY_CONFIG_PATHS/{on=1} on && /^\s*\];/{exit} on' "$CFG" \
         | grep -oE 'Some\("[a-z_.]+"\)' | grep -oE '"[a-z_.]+"' | tr -d '"' | sort -u)"

SETTABLE="$(awk '/pub const SETTABLE/{on=1} on && /^\];/{exit} on' "$CFG" \
            | grep -oE '\("[a-z_.]+", "[a-z_.]+"' | sed -E 's/\("([a-z_.]+)", "([a-z_.]+)"?$/\1.\2/' | sort -u)"

if [ -z "$SETTABLE" ]; then
    echo "check-capability-claims-are-not-settable: INCONCLUSIVE — could not read the SETTABLE"
    echo "  allowlist from $CFG, so nothing could be compared against it."
    exit 2
fi

for p in $PATHS; do
    if grep -qxF "$p" <<<"$SETTABLE"; then
        echo "  *** '$p' drives a capability claim AND is in the SETTABLE allowlist"
        bad=$((bad + 1))
    fi
done

if [ "$bad" -gt 0 ]; then
    echo
    echo "check-capability-claims-are-not-settable: $bad problem(s)."
    echo
    echo "  A capability is earned by passing its verification challenges. Making one settable over"
    echo "  HTTP hands an operator the shares the challenge system exists to gate."
    exit 1
fi

echo "check-capability-claims-are-not-settable: $(grep -c . <<<"$PATHS") mapped path(s), none settable"
exit 0
