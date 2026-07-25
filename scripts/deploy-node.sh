#!/usr/bin/env bash
#
# Enforced node deploy.
#
# Every rule here exists because it was broken, and the breakage cost something real:
#
#   * Binaries were built from a dirty tree, so production ran code whose source existed
#     only on one laptop.                                        -> requires a clean tree
#   * Unverified changes went straight to nodes carrying real miners, twice misdirecting
#     share attribution.                                         -> requires canary soak
#   * "It compiled" was treated as "it works".                   -> requires tests + smoke
#   * Recovery was manual and improvised each time.              -> backup + auto-rollback
#
# Usage:
#   scripts/deploy-node.sh <node> <binary> [--canary]
#
#   <node>    ssh alias, e.g. ghost-vm5
#   <binary>  one of: ghost-pool | pool_sv2 | translator_sv2
#   --canary  target is a canary node (not in DNS, no miners); relaxes the soak requirement
#             but NOT the clean-tree or test requirements.
#
# Exit codes: 0 ok, 1 precondition failed, 2 deploy failed, 3 smoke failed (rolled back).

set -euo pipefail

NODE="${1:-}"
BINARY="${2:-}"
CANARY="${3:-}"

CANARY_NODES="ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8"
PRODUCTION_NODES="ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4"
SOAK_MINUTES="${SOAK_MINUTES:-60}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${HOME}/.ghost-deploy"
mkdir -p "$STATE_DIR"

die()  { echo "REFUSED: $*" >&2; exit 1; }
info() { echo "  $*"; }

[ -n "$NODE" ] && [ -n "$BINARY" ] || die "usage: deploy-node.sh <node> <binary> [--canary]"
case "$BINARY" in
  ghost-pool|pool_sv2|translator_sv2) ;;
  *) die "unknown binary '$BINARY'" ;;
esac

cd "$REPO_ROOT"

# ---------------------------------------------------------------- preconditions

# 1. Clean tree. A binary must be reproducible from a commit, or rollback is guesswork
#    and nobody can tell later what was actually running.
[ -z "$(git status --porcelain)" ] || die "working tree is dirty — commit or stash first"

SHA="$(git rev-parse HEAD)"
SHORT="$(git rev-parse --short HEAD)"

# 2. Production deploys must come from main. Canaries may run a branch, which is the
#    entire point of having canaries.
if echo "$PRODUCTION_NODES" | grep -qw "$NODE"; then
    git merge-base --is-ancestor "$SHA" origin/main 2>/dev/null \
        || die "$SHORT is not on origin/main — production deploys come from main only"
fi

# 3. Tests must have passed for THIS commit. Not for something near it.
MARKER="$STATE_DIR/tested-$SHA"
[ -f "$MARKER" ] || die "no passing test record for $SHORT
       run: scripts/deploy-node.sh --record-tests   (after a green suite)"

# 4. Canary soak before production. The bugs that hurt were behavioural and only showed
#    under real traffic over time — an hourly livelock, and attribution that looked fine
#    until a share was actually mined and its DB row inspected.
if echo "$PRODUCTION_NODES" | grep -qw "$NODE"; then
    SOAKED=""
    for c in $CANARY_NODES; do
        if [ -f "$STATE_DIR/soaked-$SHA-$c" ]; then
            started=$(cat "$STATE_DIR/soaked-$SHA-$c")
            elapsed=$(( ( $(date +%s) - started ) / 60 ))
            [ "$elapsed" -ge "$SOAK_MINUTES" ] && SOAKED="$c (${elapsed}m)" && break
        fi
    done
    [ -n "$SOAKED" ] || die "$SHORT has not soaked ${SOAK_MINUTES}m on a canary
       deploy to a canary first: scripts/deploy-node.sh <canary> $BINARY --canary"
    info "soak satisfied: $SOAKED"
fi

BIN_PATH="$REPO_ROOT/target/release/$BINARY"
[ -f "$BIN_PATH" ] || die "$BIN_PATH not built"

# ---------------------------------------------------------------- deploy

SUDO='$(command -v sudo >/dev/null && echo sudo || echo)'
TS="$(date +%Y%m%d-%H%M%S)"
info "deploying $BINARY @ $SHORT to $NODE"

scp -q -o ConnectTimeout=10 "$BIN_PATH" "$NODE:/tmp/$BINARY.new" || exit 2

# Backup, atomic swap, restart. Atomic mv so a partially-copied binary is never executable.
ssh -o ConnectTimeout=10 "$NODE" "
set -e
S=$SUDO
\$S cp /opt/ghost/bin/$BINARY /opt/ghost/bin/$BINARY.bak.$TS
\$S cp /tmp/$BINARY.new /opt/ghost/bin/$BINARY.staged
\$S chmod 755 /opt/ghost/bin/$BINARY.staged
\$S mv /opt/ghost/bin/$BINARY.staged /opt/ghost/bin/$BINARY
" || exit 2

case "$BINARY" in
  ghost-pool)      SERVICE=ghost-pool ;;
  pool_sv2)        SERVICE=sri-pool ;;
  translator_sv2)  SERVICE=sri-translator ;;
esac

ssh -o ConnectTimeout=10 "$NODE" "S=$SUDO; \$S systemctl restart $SERVICE" || exit 2
sleep 20

# ---------------------------------------------------------------- verify

ACTIVE=$(ssh -o ConnectTimeout=10 "$NODE" "systemctl is-active $SERVICE" || echo failed)
[ "$ACTIVE" = "active" ] || { echo "SERVICE NOT ACTIVE — rolling back" >&2; ROLLBACK=1; }

# Smoke test the stratum path for anything that serves miners. A green service that
# cannot complete a handshake is not a successful deploy.
if [ -z "${ROLLBACK:-}" ] && [ "$BINARY" != "ghost-pool" ]; then
    IP=$(ssh -o ConnectTimeout=10 "$NODE" "hostname -I | awk '{print \$1}'")
    if ! python3 "$REPO_ROOT/bins/translator-sv2/tests/sv1_handshake_smoke.py" "$IP" 3333 >/dev/null 2>&1; then
        echo "SMOKE TEST FAILED — rolling back" >&2
        ROLLBACK=1
    fi
fi

if [ -n "${ROLLBACK:-}" ]; then
    ssh -o ConnectTimeout=10 "$NODE" "
set -e
S=$SUDO
\$S cp /opt/ghost/bin/$BINARY.bak.$TS /opt/ghost/bin/$BINARY.staged
\$S chmod 755 /opt/ghost/bin/$BINARY.staged
\$S mv /opt/ghost/bin/$BINARY.staged /opt/ghost/bin/$BINARY
\$S systemctl restart $SERVICE
"
    echo "rolled back to $BINARY.bak.$TS" >&2
    exit 3
fi

# Start the soak clock for this commit on this node.
if echo "$CANARY_NODES" | grep -qw "$NODE"; then
    date +%s > "$STATE_DIR/soaked-$SHA-$NODE"
    info "soak clock started for $SHORT on $NODE (${SOAK_MINUTES}m required before production)"
fi

info "OK: $BINARY @ $SHORT live on $NODE (backup: $BINARY.bak.$TS)"
