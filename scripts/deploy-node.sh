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
# Overridable alongside STATE_DIR so scripts/test-deploy-gate.sh can drive the gate against a
# clean throwaway checkout while running THIS copy of the script. A guard nobody can drive is a
# guard nobody has checked, which is how #459 went unnoticed.
REPO_ROOT="${GHOST_DEPLOY_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# Overridable so the gate can be exercised against throwaway state by
# scripts/test-deploy-gate.sh. A guard nobody can drive is a guard nobody has checked.
STATE_DIR="${STATE_DIR:-${HOME}/.ghost-deploy}"
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

# 3b. The commit must still be what main says, not merely something main once contained.
#
#     `git merge-base --is-ancestor` above stays true FOREVER once a commit is merged, so a
#     REVERTED commit passes it happily. That is not theoretical: 7706f2870 sat on main with a
#     full tested+soaked record while carrying the #455 regression that #456 reverted, and this
#     script would have deployed it to production reporting every gate satisfied (#459).
#
#     Cheapest sound check: the paths this deploy actually ships must match current main. If a
#     revert (or anything else) has moved them, the built binary no longer represents main.
if echo "$PRODUCTION_NODES" | grep -qw "$NODE"; then
    case "$BINARY" in
        ghost-pool)      SRC_PATHS="bins/ghost-pool crates" ;;
        pool_sv2)        SRC_PATHS="bins/pool-sv2 crates" ;;
        translator_sv2)  SRC_PATHS="bins/translator-sv2 crates" ;;
        *)               SRC_PATHS="" ;;
    esac
    if [ -n "$SRC_PATHS" ] && ! git diff --quiet "$SHA" origin/main -- $SRC_PATHS 2>/dev/null; then
        die "$SHORT no longer matches origin/main for: $SRC_PATHS
       main has moved (a revert, or newer commits) — rebuild from current main.
       This is the guard that would have caught the #447 revert (#459)."
    fi
fi

# 4. Canary soak before production. The bugs that hurt were behavioural and only showed
#    under real traffic over time — an hourly livelock, and attribution that looked fine
#    until a share was actually mined and its DB row inspected.
#
#    The marker is per-BINARY as well as per-commit. It used to be per-commit-per-node only,
#    which meant soaking `ghost-pool` alone on a canary satisfied this gate for
#    `translator_sv2` — a binary that had then never run on any canary (#459).
#
#    It also records the deployed binary's hash ON THE NODE. A soak asserts "this build ran
#    here for N minutes"; if the node no longer runs that build the claim is void, which is
#    exactly what a mid-roll rollback produces.
if echo "$PRODUCTION_NODES" | grep -qw "$NODE"; then
    SOAKED=""
    for c in $CANARY_NODES; do
        f="$STATE_DIR/soaked-$SHA-$c-$BINARY"
        [ -f "$f" ] || continue
        read -r started recorded_hash < "$f" 2>/dev/null || continue
        elapsed=$(( ( $(date +%s) - started ) / 60 ))
        [ "$elapsed" -ge "$SOAK_MINUTES" ] || continue

        # Still running what it soaked? A rollback restores the .bak and the hash changes.
        if [ -n "${recorded_hash:-}" ]; then
            live_hash=$(timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$c" \
                "sha256sum /opt/ghost/bin/$BINARY 2>/dev/null | cut -d' ' -f1" 2>/dev/null || true)
            if [ -n "$live_hash" ] && [ "$live_hash" != "$recorded_hash" ]; then
                info "ignoring soak on $c: $BINARY no longer matches what soaked (rolled back?)"
                rm -f "$f"
                continue
            fi
        fi
        SOAKED="$c (${elapsed}m)"
        break
    done
    [ -n "$SOAKED" ] || die "$BINARY @ $SHORT has not soaked ${SOAK_MINUTES}m on a canary
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

# Wait for the service to be SERVING, not merely started.
#
# This was `sleep 20`, and 20s is not enough for pool_sv2: it does not bind :34255 until it
# has completed a Noise handshake with the template provider on :8442, which takes ~60s.
# systemd reports the unit active almost immediately, and its monitoring port :9090 comes up
# early too, so neither is a readiness signal.
#
# The cost of getting this wrong is not a slow deploy, it is a WRONG VERDICT: the smoke test
# ran against a pool that was not serving yet, failed, and rolled back a binary that was in
# fact fine — leaving the node half-rolled, which this script's own header calls out as
# indistinguishable from a genuinely broken binary. Measured on ghost-vm5: rolled back, then
# the identical build passed all 11 smoke cases once given time.
#
# So wait on the port the service is supposed to answer on.
case "$BINARY" in
  ghost-pool)      READY_PORT=8442 ;;   # TDP, what pool_sv2 connects to
  pool_sv2)        READY_PORT=34255 ;;  # SV2, what the translator connects to
  translator_sv2)  READY_PORT=3333 ;;   # SV1, what miners connect to
esac

READY_TIMEOUT="${READY_TIMEOUT:-180}"
echo "  waiting for $SERVICE to listen on :$READY_PORT (up to ${READY_TIMEOUT}s)"
READY=no
for _ in $(seq 1 "$READY_TIMEOUT"); do
    if timeout 10 ssh "${SSH_OPTS[@]}" "$NODE" \
         "ss -ltn 2>/dev/null | grep -q ':${READY_PORT}'" 2>/dev/null; then
        READY=yes
        break
    fi
    sleep 1
done

# ---------------------------------------------------------------- verify

ACTIVE=$(timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$NODE" "systemctl is-active $SERVICE" || echo failed)
[ "$ACTIVE" = "active" ] || { echo "SERVICE NOT ACTIVE — rolling back" >&2; ROLLBACK=1; }

if [ -z "${ROLLBACK:-}" ] && [ "$READY" != "yes" ]; then
    echo "SERVICE NEVER LISTENED ON :$READY_PORT after ${READY_TIMEOUT}s — rolling back" >&2
    ROLLBACK=1
fi

# Smoke test the stratum path for anything that serves miners. A green service that
# cannot complete a handshake is not a successful deploy.
if [ -z "${ROLLBACK:-}" ] && [ "$BINARY" != "ghost-pool" ]; then
    IP=$(timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$NODE" "hostname -I | awk '{print \$1}'")
    # Retry rather than judge on one attempt. A listening port means the process is accepting,
    # not that the whole SV1 -> SV2 -> TDP chain has settled — the translator can be listening
    # while its upstream handshake is still in progress. One failed attempt used to roll back a
    # working binary and leave the node half-rolled.
    SMOKE_OK=no
    for attempt in 1 2 3; do
        if python3 "$REPO_ROOT/bins/translator-sv2/tests/sv1_handshake_smoke.py" "$IP" 3333 >/dev/null 2>&1; then
            SMOKE_OK=yes
            break
        fi
        [ "$attempt" -lt 3 ] && { echo "  smoke attempt $attempt failed, retrying in 20s"; sleep 20; }
    done
    if [ "$SMOKE_OK" != "yes" ]; then
        echo "SMOKE TEST FAILED after 3 attempts — rolling back" >&2
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
    # The node no longer runs this build, so any soak record claiming it does is a lie.
    # Leaving it is how a half-rolled canary went on vouching for a commit (#459).
    rm -f "$STATE_DIR/soaked-$SHA-$NODE-$BINARY"
    echo "rolled back to $BINARY.bak.$TS (soak record for $BINARY @ $SHORT on $NODE cleared)" >&2
    exit 3
fi

# Start the soak clock for this commit on this node.
if echo "$CANARY_NODES" | grep -qw "$NODE"; then
    # Record WHAT soaked, not just when. The hash lets the production gate confirm the node is
    # still running this build rather than something a rollback restored underneath it.
    LIVE_HASH=$(timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$NODE" \
        "sha256sum /opt/ghost/bin/$BINARY 2>/dev/null | cut -d' ' -f1" 2>/dev/null || true)
    printf '%s %s\n' "$(date +%s)" "${LIVE_HASH:-}" > "$STATE_DIR/soaked-$SHA-$NODE-$BINARY"
    info "soak clock started for $BINARY @ $SHORT on $NODE (${SOAK_MINUTES}m required before production)"
fi

info "OK: $BINARY @ $SHORT live on $NODE (backup: $BINARY.bak.$TS)"
