#!/usr/bin/env bash
#
# Fail if the mesh node-list checkpoint commits a root the convergence endpoint does not report.
#
# ## Why this exists
#
# `/api/v1/qualification/scoped-set` is the instrument that decides whether
# `MESH_NODE_LIST_CHECKPOINT_HEIGHT` gets armed (#402). Its whole job is to answer "would every
# node on the fleet commit the same checkpoint?", and it answers it by publishing the roots each
# node would commit so they can be compared.
#
# That answer is only as good as the set of roots it publishes. #943 added
# `coordinator_roster_root` to the checkpoint and made vote acceptance depend on it — and this
# endpoint was not updated. So it would have reported `list_root` and `advert_root` agreeing
# fleet-wide, the pre-arming check would have read "converged", and a roster-root disagreement
# would have blocked every checkpoint from finalising after arming. Silently, because a fleet that
# agrees on three roots out of four does not error: it just votes reject for ever.
#
# The failure mode is not a bug in either piece of code. It is that they are in different files and
# nothing connected them. This connects them.
#
# ## What it checks
#
# Every `pub <name>_root` field on `MeshNodeListCheckpointMessage` must appear:
#
#   * as a field of `MeshNodeListConvergence` (so the value is carried), and
#   * as a JSON key in the `mesh_node_list` block of the convergence handler (so it is served).
#
# Both, because carrying a value nobody serves is the same gap one step later.
#
# Exit 0 = every root is covered, 1 = one is not, 2 = INCONCLUSIVE (a source could not be read, so
# this examined less than it claims and must not report success).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

MSG="crates/ghost-consensus/src/message.rs"
STATE="crates/ghost-verification/src/server.rs"
ROUTES="crates/ghost-verification/src/routes.rs"

for f in "$MSG" "$STATE" "$ROUTES"; do
    [ -r "$f" ] || { echo "check-convergence-covers-every-root: INCONCLUSIVE — cannot read $f"; exit 2; }
done

# The committed roots, read out of the checkpoint struct itself rather than listed here. A list in
# this file would be a third place to update, and the whole point is that a fourth root must not be
# addable without something objecting.
ROOTS="$(awk '/pub struct MeshNodeListCheckpointMessage[[:space:]]*\{/,/^}/' "$MSG" \
         | grep -oE 'pub [a-z_]+_root' | sed 's/^pub //' | sort -u)"

if [ -z "$ROOTS" ]; then
    echo "check-convergence-covers-every-root: INCONCLUSIVE — found no \`*_root\` fields on"
    echo "  MeshNodeListCheckpointMessage in $MSG. It was renamed or reshaped, so this examined nothing."
    exit 2
fi

# The convergence struct must exist, or there is nothing to check coverage against.
if ! grep -qE 'pub struct MeshNodeListConvergence[[:space:]]*\{' "$STATE"; then
    echo "check-convergence-covers-every-root: INCONCLUSIVE — MeshNodeListConvergence not found"
    echo "  in $STATE. It was renamed; update this check."
    exit 2
fi

CONV_FIELDS="$(awk '/pub struct MeshNodeListConvergence[[:space:]]*\{/,/^}/' "$STATE")"
# Just the mesh_node_list JSON block, so a root mentioned anywhere else in this large file cannot
# stand in for one that is actually served.
SERVED="$(awk '/"mesh_node_list": \{/,/^        \},/' "$ROUTES")"
if [ -z "$SERVED" ]; then
    echo "check-convergence-covers-every-root: INCONCLUSIVE — could not locate the"
    echo "  \"mesh_node_list\" block in $ROUTES. This examined nothing."
    exit 2
fi

missing=0
for r in $ROOTS; do
    in_struct=no
    in_json=no
    grep -qE "^[[:space:]]*pub $r:" <<<"$CONV_FIELDS" && in_struct=yes
    grep -qF "\"$r\"" <<<"$SERVED" && in_json=yes
    if [ "$in_struct" = no ] || [ "$in_json" = no ]; then
        echo "  *** $r — carried in MeshNodeListConvergence: $in_struct; served as JSON: $in_json"
        missing=$((missing + 1))
    fi
done

if [ "$missing" -gt 0 ]; then
    echo
    echo "check-convergence-covers-every-root: $missing committed root(s) are not fully reported."
    echo
    echo "  The checkpoint commits them and the vote path can reject on them, so two nodes that"
    echo "  disagree on one will never finalise a checkpoint — and the pre-arming convergence"
    echo "  check would still read \"converged\", because it never compared that root (#943)."
    echo
    echo "  Add each to MeshNodeListConvergence, populate it where the closure is built in"
    echo "  bins/ghost-pool/src/main.rs, and serve it in the \"mesh_node_list\" block."
    exit 1
fi

echo "check-convergence-covers-every-root: all $(wc -w <<<"$ROOTS") committed root(s) are reported"
exit 0
