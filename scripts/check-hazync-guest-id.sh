#!/usr/bin/env bash
# The guest id ghostd trusts must equal the canonical Hazync guest id.
#
# A Hazync proof is only meaningful relative to the guest that produced it. ghostd pins the id it
# will accept (HAZYNC_EXPECTED_METHOD_ID); hazync publishes the canonical one in reproduce/METHOD_ID.
# A re-baseline moves the canonical id, and if ghostd's pin is not moved with it the node refuses
# every proof — or, far worse, if the pin were ever removed, silently trusts a retired guest.
#
# This is the ghostd-side counterpart of hazync's scripts/check-versions.sh. It fails the build when
# the two disagree, so the drift is caught at CI rather than by an operator whose node stopped
# accepting proofs.
#
# Usage:  HAZYNC_REPO=/path/to/hazync ./scripts/check-hazync-guest-id.sh
#         (defaults to ../hazync relative to this repo)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

HEADER="ghost-core/src/haze/hazync_proof.h"
HAZYNC_REPO="${HAZYNC_REPO:-../hazync}"
CANON_FILE="$HAZYNC_REPO/reproduce/METHOD_ID"

fail() { echo "FAIL: $*" >&2; exit 1; }

[ -f "$HEADER" ] || fail "$HEADER not found (run from the ghost repo root)"

# Pull the pinned id out of the header. Anchored on the constant's name so an unrelated 64-hex
# string elsewhere in the file cannot be picked up by accident.
pinned=$(grep -A3 'HAZYNC_EXPECTED_METHOD_ID' "$HEADER" | grep -oE '[0-9a-f]{64}' | head -1)
[ -n "$pinned" ] || fail "no 64-hex guest id found near HAZYNC_EXPECTED_METHOD_ID in $HEADER.
       If the pin was removed, ghostd would trust whatever verifier it happens to link. Restore it."

if [ ! -f "$CANON_FILE" ]; then
    echo "SKIP: $CANON_FILE not found — set HAZYNC_REPO=<path to hazync checkout>." >&2
    echo "      ghostd pins: $pinned" >&2
    # A missing sibling checkout is an environment gap, not a drift failure. Exit non-zero anyway if
    # the caller demanded strictness, so CI cannot pass by simply not having the repo.
    [ "${STRICT:-0}" = "1" ] && fail "STRICT=1 and the hazync checkout is absent"
    exit 0
fi

# reproduce/METHOD_ID may carry comments; take the first bare 64-hex line, not a commented one.
canonical=$(grep -oE '^[0-9a-f]{64}$' "$CANON_FILE" | head -1)
[ -n "$canonical" ] || fail "no bare 64-hex id in $CANON_FILE"

if [ "$pinned" != "$canonical" ]; then
    fail "guest id drift.
       ghostd pins  : $pinned  ($HEADER)
       hazync canon : $canonical  ($CANON_FILE)
       A re-baseline moves BOTH. Rebuild libhazync_verify.a from the canonical guest and update the
       pin in the same change, or ghostd will refuse every proof."
fi

echo "OK: ghostd's pinned Hazync guest id matches the canonical id ($pinned)"
