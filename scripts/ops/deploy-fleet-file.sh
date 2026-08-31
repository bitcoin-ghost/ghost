#!/usr/bin/env bash
#
# Converge a canonical ops file from scripts/ops/fleet-files/ onto the fleet (#759).
#
# deploy-node.sh swaps BINARIES and verifies the node still credits work. Nothing
# governed the ops scripts sitting in /opt/ghost/bin, so they were whatever
# successive hand-edits had left behind — wait-for-ghostd-sync.sh existed in three
# variants across eight nodes with no repo copy to compare against.
#
# Files here are boot-path scripts, not running services: replacing one changes
# nothing until the unit next runs. This deliberately does NOT restart anything.
#
# Usage:
#   scripts/ops/deploy-fleet-file.sh <name> [<node> ...]   # defaults to all eight
#   scripts/ops/deploy-fleet-file.sh --dry-run <name> [...]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEST_DIR=/opt/ghost/bin

DRY=false
if [ "${1:-}" = "--dry-run" ]; then DRY=true; shift; fi

NAME="${1:-}"
[ -n "$NAME" ] || { echo "usage: $0 [--dry-run] <name> [<node> ...]"; exit 2; }
shift

SRC="$REPO_ROOT/scripts/ops/fleet-files/$NAME"
[ -f "$SRC" ] || { echo "No such canonical file: scripts/ops/fleet-files/$NAME"; exit 2; }
bash -n "$SRC" || { echo "REFUSING: $NAME is not valid bash"; exit 1; }

NODES=("$@")
if [ ${#NODES[@]} -eq 0 ]; then
    NODES=(ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4 ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8)
fi

WANT="$(sha256sum "$SRC" | cut -c1-16)"
echo "Canonical $NAME = $WANT"
$DRY && echo "(dry run — nothing will be written)"
echo

rc=0
diverged=0
for n in "${NODES[@]}"; do
    printf '%-10s ' "$n"

    got="$(ssh -o ConnectTimeout=15 -o BatchMode=yes "$n" \
        'S=$(command -v sudo >/dev/null && echo sudo || echo); $S sha256sum '"$DEST_DIR/$NAME"' 2>/dev/null | cut -c1-16' 2>/dev/null)"
    got="${got:-<missing>}"

    if [ "$got" = "$WANT" ]; then
        echo "already canonical"
        continue
    fi

    diverged=$((diverged + 1))

    if $DRY; then
        echo "WOULD UPDATE (has $got)"
        continue
    fi

    # Pipe the file in over stdin: the content never becomes part of a remote
    # command line, so no quoting in it can be eaten locally on the way — which
    # is how vm1-vm5 acquired their mangled variant in the first place.
    out="$(ssh -o ConnectTimeout=20 -o BatchMode=yes "$n" \
        'S=$(command -v sudo >/dev/null && echo sudo || echo)
         t="$(mktemp)"
         cat > "$t"
         bash -n "$t" || { echo "REMOTE-SYNTAX-FAIL"; rm -f "$t"; exit 1; }
         if [ -f '"$DEST_DIR/$NAME"' ]; then
             $S cp -a '"$DEST_DIR/$NAME"' '"$DEST_DIR/$NAME"'.bak."$(date +%Y%m%d-%H%M%S)"
         fi
         $S install -m 0755 -o root -g root "$t" '"$DEST_DIR/$NAME"'
         rm -f "$t"
         $S sha256sum '"$DEST_DIR/$NAME"' | cut -c1-16' < "$SRC" 2>&1)"

    new="$(echo "$out" | tail -1)"
    if [ "$new" = "$WANT" ]; then
        echo "updated ($got -> $new)"
    else
        echo "FAILED (still $new) :: $(echo "$out" | head -3 | tr '\n' ' ')"
        rc=1
    fi
done

echo
if $DRY; then
    # A dry run reports what IS, so divergence is the finding, not success.
    if [ "$diverged" -eq 0 ]; then
        echo "RESULT: all ${#NODES[@]} node(s) already carry the canonical $NAME"
    else
        echo "RESULT: $diverged of ${#NODES[@]} node(s) differ from the canonical $NAME"
        rc=1
    fi
elif [ $rc -eq 0 ]; then
    echo "RESULT: all ${#NODES[@]} node(s) carry the canonical $NAME ($diverged updated)"
else
    echo "RESULT: at least one node did not converge"
fi
exit $rc
