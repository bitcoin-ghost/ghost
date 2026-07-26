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
#
# A CALLER LOOPING OVER BINARIES MUST STOP ON ANY NON-ZERO EXIT. These three binaries talk
# to each other and are not independently deployable. Rolling v1.11.18 to vm8, pool_sv2
# failed its smoke test and rolled back correctly — but the surrounding `for` loop carried
# on to translator_sv2, leaving the node on new ghost-pool + new translator + OLD pool_sv2.
# A combination nobody chose, that happened to work. Write:
#
#   for b in ghost-pool pool_sv2 translator_sv2; do
#       scripts/deploy-node.sh "$NODE" "$b" || break     # <- the `|| break` is not optional
#   done
#
# Note also that a mid-roll smoke failure is ambiguous: "this binary is broken" and "this
# node is only half rolled" produce the same signal. That vm8 failure was the latter — the
# new pool_sv2 was being tested against an old translator that existed on no other node,
# and it deployed cleanly once the translator was current.

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

# ConnectTimeout only bounds ESTABLISHING the connection. A session that stalls
# mid-transfer hangs forever. That happened rolling v1.11.18 to vm3: the copy stopped
# at 7,733,248 of 24,974,600 bytes and sat there — no progress, no error, no exit,
# leaving the node with a new ghost-pool against an old pool_sv2 and nothing saying so.
#
# ServerAliveInterval makes a dead peer detectable; the hard `timeout` bounds the rest.
SSH_OPTS=(-o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -o BatchMode=yes)
XFER_TIMEOUT="${XFER_TIMEOUT:-300}"
REMOTE_TIMEOUT="${REMOTE_TIMEOUT:-120}"

LOCAL_SHA="$(sha256sum "$BIN_PATH" | cut -d' ' -f1)"
LOCAL_SIZE="$(stat -c%s "$BIN_PATH")"

copied=""
for attempt in 1 2 3; do
    if timeout "$XFER_TIMEOUT" scp -q "${SSH_OPTS[@]}" "$BIN_PATH" "$NODE:/tmp/$BINARY.new"; then
        # Verify what landed. A transfer that dies at the wrong moment leaves a truncated
        # file that would otherwise go straight into chmod + mv. The only reason that did
        # not happen on vm3 is that the copy stalled rather than exited.
        remote="$(timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$NODE" \
                    "sha256sum /tmp/$BINARY.new 2>/dev/null | cut -d' ' -f1; stat -c%s /tmp/$BINARY.new 2>/dev/null" || true)"
        rsha="$(printf '%s' "$remote" | sed -n 1p)"
        rsize="$(printf '%s' "$remote" | sed -n 2p)"
        if [ "$rsha" = "$LOCAL_SHA" ] && [ "$rsize" = "$LOCAL_SIZE" ]; then
            copied=yes
            break
        fi
        echo "  attempt $attempt: staged copy does not match (${rsize:-?}/$LOCAL_SIZE bytes) — retrying" >&2
    else
        echo "  attempt $attempt: transfer failed or timed out after ${XFER_TIMEOUT}s — retrying" >&2
    fi
    timeout 30 ssh "${SSH_OPTS[@]}" "$NODE" "rm -f /tmp/$BINARY.new" 2>/dev/null || true
done

if [ -z "$copied" ]; then
    echo "REFUSED: could not place a verified copy of $BINARY on $NODE after 3 attempts." >&2
    echo "         $NODE is UNCHANGED for this binary, but if you are mid-roll it may be" >&2
    echo "         running a MIXED set. Check: ssh $NODE 'sha256sum /opt/ghost/bin/*'" >&2
    exit 2
fi

# Backup, atomic swap, restart. Atomic mv so a partially-copied binary is never executable.
timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$NODE" "
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

timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$NODE" "S=$SUDO; \$S systemctl restart $SERVICE" || exit 2
sleep 20

# ---------------------------------------------------------------- verify

ACTIVE=$(timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$NODE" "systemctl is-active $SERVICE" || echo failed)
[ "$ACTIVE" = "active" ] || { echo "SERVICE NOT ACTIVE — rolling back" >&2; ROLLBACK=1; }

# Smoke test the stratum path for anything that serves miners. A green service that
# cannot complete a handshake is not a successful deploy.
if [ -z "${ROLLBACK:-}" ] && [ "$BINARY" != "ghost-pool" ]; then
    IP=$(timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$NODE" "hostname -I | awk '{print \$1}'")
    if ! python3 "$REPO_ROOT/bins/translator-sv2/tests/sv1_handshake_smoke.py" "$IP" 3333 >/dev/null 2>&1; then
        echo "SMOKE TEST FAILED — rolling back" >&2
        ROLLBACK=1
    fi
fi

if [ -n "${ROLLBACK:-}" ]; then
    timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$NODE" "
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
