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

# Order matters: the soak gate below takes the FIRST canary with a valid marker, so whichever
# is listed first is the one that gets soaked in practice.
#
# ghost-vm5 leads because it is the only canary carrying a real miner (bitaxe3, ~60 shares per
# 30 minutes). Real submitted traffic is the one thing a synthetic probe cannot reproduce, and
# soaking on a canary with none is how the gate stayed blind to the submission path (#461).
# vm5 is also at schema 46 like production, where vm6 and vm8 carry the drift from #523.
CANARY_NODES="ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8"
PRODUCTION_NODES="ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4"
SOAK_MINUTES="${SOAK_MINUTES:-60}"

# Declared HERE, not further down: the soak-verification block below reaches for both to
# ssh a canary and confirm it still runs the binary it soaked. They used to be defined
# after that block, so a production deploy died with
#   deploy-node.sh: line 135: REMOTE_TIMEOUT: unbound variable
# the moment a soak record carried a recorded hash. Canary deploys skip the block, so it
# only ever failed on the production path — the one that matters.
SSH_OPTS=(-o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -o BatchMode=yes)
XFER_TIMEOUT="${XFER_TIMEOUT:-300}"
REMOTE_TIMEOUT="${REMOTE_TIMEOUT:-120}"
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
#
#    The remedy this used to print — `deploy-node.sh --record-tests` — does not exist and never
#    did; this script takes `<node> <binary> [--canary]` and nothing else, so following the
#    instruction produced a usage error. `scripts/record-tests.sh` is what writes the marker.
#
#    Worth stating the per-SHA part explicitly, because merging is where it bites: testing a
#    branch records the BRANCH commit, and the merge commit is a different SHA with a different
#    tree whenever main has moved underneath it. Two independently-tested branches merged into
#    main produce a combination neither run covered.
MARKER="$STATE_DIR/tested-$SHA"
[ -f "$MARKER" ] || die "no passing test record for $SHORT
       run: scripts/record-tests.sh   (records HEAD; re-run it after a merge — the merge
       commit is a different SHA, and its tree is what actually ships)"

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

# Exercise the SHARE-SUBMISSION path against a node, synthetically.
#
# A canary has no miners (#461), so "healthy for 60 minutes" says nothing about the code path
# where both of the regressions that motivated this gate actually lived: attribution, and a
# declared difficulty that never reached the wire. A node can sit green for the whole window
# with either bug fully present and the soak will still report satisfied — the same
# can't-fail-shape as #459.
#
# The smoke suite synthesises a real SV1 client, so it works on a node with zero miners. It is
# the only part of the soak that touches submission at all, which is why it is mandatory here
# rather than a remembered manual step.
#
# Returns 0 if the submission path answered correctly.
exercise_submission_path() {
    local node="$1" host
    host=$(ssh_host_for "$node") || return 1
    [ -n "$host" ] || return 1

    timeout 120 python3 "$REPO_ROOT/bins/translator-sv2/tests/sv1_handshake_smoke.py" \
        "$host" 3333 2>&1 | sed 's/^/      /'
    return "${PIPESTATUS[0]}"
}

# Resolve a node alias to something the smoke client can connect to. The probes run from HERE,
# not on the node, so `localhost` is wrong — it needs the address ssh would dial.
ssh_host_for() {
    ssh -G "$1" 2>/dev/null | awk '/^hostname /{print $2; exit}'
}

# Validate that a remote read produced ONE clean integer, or say so.
#
# The share count used to go through `tr -cd '0-9'`, which cannot fail: any stray line sharing
# stdout (a banner, a warning, an echoed value) has its digits CONCATENATED into the count, so a
# read that half-worked comes out looking like a confident number. Anything other than a single
# integer now reads as "unreadable" (empty, non-zero return), which every caller already treats
# as not-measurable rather than as zero.
one_clean_integer() {
    local out="${1:-}"
    # Trim LEADING and TRAILING whitespace only. Deleting all whitespace would quietly weld two
    # output lines into one number — the exact failure this function exists to refuse.
    out="${out#"${out%%[![:space:]]*}"}"
    out="${out%"${out##*[![:space:]]}"}"
    case "$out" in
        ''|*[!0-9]*) return 1 ;;
        *) printf '%s\n' "$out" ;;
    esac
}

# Count shares this node took from its OWN miners since a unix timestamp.
#
# `miner_id like '%.%'` is the discriminator: a locally-submitted share carries a plaintext
# `address.worker`, whereas one that arrived by gossip carries a 16-hex hash, because peers only
# ever see the hashed form. Without that filter a node with no miners still counts its peers'
# traffic and every throughput check passes vacuously.
local_shares_since() {
    local out
    out=$(timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$1" \
        "sudo -u ghost sqlite3 /home/ghost/.ghost/ghost.db \
         \"select count(*) from shares where timestamp > $2 and miner_id like '%.%';\"" \
        2>/dev/null) || true
    one_clean_integer "$out"
}

# Count ESTABLISHED miner connections on the node's stratum ports (SV1 :3333, farm tier :4444,
# direct SV2 :34255), excluding loopback peers — the node's own translator holds a permanent
# 127.0.0.1 connection to pool_sv2 on :34255 and must not read as a miner.
#
# This is what separates the two causes of post-swap silence:
#
#   * H-13: miners still CONNECTED, work arriving and silently discarded  -> conns > 0
#   * a shed: ALL EIGHT nodes are in the mining DNS, so the restart this script just issued
#     drops the node's miners and they rehome on another node in seconds  -> conns == 0
#
# Measured on the night of 2026-08-10/11: avalonQ's last share on vm3 landed at 1786408429 and
# its first on vm2 at 1786408453 — 24 seconds after vm3's restart. Four healthy binaries were
# rolled back that night (vm6, vm3, vm1 twice) because the silence they left behind was read as
# the H-13 signature.
#
# `wc -l` runs REMOTELY, so a transport failure yields an empty string (unreadable), never 0:
# "no miners attached" is only ever a genuine measurement.
miner_connections() {
    local out
    out=$(timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$1" \
        "ss -Htn state established '( sport = :3333 or sport = :4444 or sport = :34255 )' 2>/dev/null \
         | awk '\$NF !~ /^(127\\.|\\[::1\\])/' | wc -l" 2>/dev/null) || true
    one_clean_integer "$out"
}

# The throughput verdict, as a function rather than inline, so the gate self-test can drive it.
#
# Extracted deliberately. The H-13 fix that motivated all of this had two tests that passed while
# production was broken, because both re-implemented the transformation under test instead of
# calling it. A verdict buried inside the deploy path is the same shape of untestable: the only
# way to exercise it would be to break production again.
#
# 0 = regressed (roll back), 1 = fine or not measurable.
throughput_regressed() {
    local baseline="${1:-}" post="${2:-}" conns="${3:-}"
    # No traffic before the swap: nothing to lose, and nothing to conclude.
    [ -n "$baseline" ] || return 1
    [ "$baseline" -gt 0 ] 2>/dev/null || return 1
    # An unreadable count is not a zero. Tested explicitly because `[ "" -eq 0 ]` is TRUE in bash
    # — the empty string evaluates to 0 in arithmetic context — so the obvious spelling of this
    # guard treats a failed ssh or sqlite read as an outage and rolls back a healthy binary. The
    # gate self-test caught exactly that.
    [ -n "$post" ] || return 1
    # Shares still being credited: fine, whatever the connection count says.
    [ "$post" -eq 0 ] 2>/dev/null || return 1
    # Traffic before and none after is only H-13 if somebody is still SENDING work. All eight
    # nodes sit in the mining DNS, so the restart this script just issued sheds every miner the
    # node had, and they rehome elsewhere within seconds — silence with zero miners attached is
    # the EXPECTED aftermath of the swap, not an outage. On 2026-08-11 four healthy binaries
    # were rolled back (vm6, vm3, vm1 twice) because this function could not tell the two apart:
    # the deploy chased one cohort of miners around the fleet all night, and every node they had
    # just been shed FROM reported the H-13 signature.
    #
    # An unreadable connection count gets the same treatment as an unreadable share count: not
    # measurable, and a binary is not rolled back on evidence that was never collected.
    [ -n "$conns" ] || return 1
    [ "$conns" -gt 0 ] 2>/dev/null || return 1
    return 0
}

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
        # Re-run at the END of the window, not only at the start. A one-shot check at minute
        # zero cannot see anything that emerges under sustained traffic — drift, a leak, a
        # livelock, vardiff misbehaving over many ticks. The hourly OOM took hours to show.
        info "re-checking the submission path on $c after ${elapsed}m"
        if ! exercise_submission_path "$c"; then
            info "ignoring soak on $c: submission path FAILS at the end of the window"
            rm -f "$f"
            continue
        fi

        # How much REAL traffic this canary took while it soaked.
        #
        # A share submitted here carries a plaintext `address.worker` miner_id; one that arrived
        # by gossip carries a 16-hex hash, because peers only ever see the hashed form. That is
        # the reliable discriminator — `received_by` length is NOT, since it is a concatenation
        # of 8-character node-id prefixes and length 8 merely means one node has recorded it.
        #
        # This does not gate: the synthetic probe above already covers the submission path, and
        # blocking every deploy on a miner being connected would be worse than the problem. It
        # exists so "this soak observed no real traffic" is stated rather than assumed.
        local_shares=$(timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$c" \
            "sudo -u ghost sqlite3 /home/ghost/.ghost/ghost.db \
             \"select count(*) from shares where timestamp > $started and miner_id like '%.%';\"" \
            2>/dev/null || true)
        if [ "${local_shares:-0}" -gt 0 ] 2>/dev/null; then
            SOAKED="$c (${elapsed}m, submission path verified, ${local_shares} real shares)"
        else
            info "note: $c took NO real submitted shares while soaking — the synthetic probe passed,"
            info "      but nothing that needs sustained real traffic was exercised (#461)"
            SOAKED="$c (${elapsed}m, submission path verified, no real traffic)"
        fi
        break
    done
    [ -n "$SOAKED" ] || die "$BINARY @ $SHORT has not soaked ${SOAK_MINUTES}m on a canary
       deploy to a canary first: scripts/deploy-node.sh <canary> $BINARY --canary"
    info "soak satisfied: $SOAKED"
fi

BIN_PATH="$REPO_ROOT/target/release/$BINARY"
[ -f "$BIN_PATH" ] || die "$BIN_PATH not built"

# Baseline: was this node taking shares from its own miners BEFORE the swap?
#
# This is the measurement the post-deploy check below compares against, and it has to be taken
# now, because after a rollback the traffic returns and the evidence of the outage is gone.
#
# It exists because of the H-13 outage. A PoW check with the operands in the wrong byte order
# rejected every locally-submitted share on all eight nodes for ~30 minutes. Throughout, every
# signal this script looked at was green: the unit was active, the port was listening, /health
# answered, there were no restarts and no error lines. Miners stayed CONNECTED and their work
# was silently discarded. Nothing in the deploy path measured whether work was still being
# credited, so nothing objected.
BASELINE_WINDOW="${BASELINE_WINDOW:-300}"
BASELINE_READ_AT=$(date +%s)
BASELINE_FROM=$(( BASELINE_READ_AT - BASELINE_WINDOW ))
BASELINE_SHARES=$(local_shares_since "$NODE" "$BASELINE_FROM" || true)
NODE_CLOCK=$(timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$NODE" "date +%s" 2>/dev/null || true)
# Absolute bounds, both clocks, and the RAW value — so a disputed count is diagnosable from the
# transcript alone. The 2026-08-11 investigation initially concluded this baseline was
# fabricated, because the verifying query was run against a window an hour adrift of the gate's
# actual one (the deploy host keeps BST, the nodes keep UTC); with the epochs printed here the
# same check is a single copy-paste.
info "baseline window ($BASELINE_FROM, $BASELINE_READ_AT] epoch, node clock ${NODE_CLOCK:-unreadable}, raw count '${BASELINE_SHARES}'"
if [ "${BASELINE_SHARES:-0}" -gt 0 ] 2>/dev/null; then
    info "baseline: $BASELINE_SHARES local shares in the last $((BASELINE_WINDOW / 60))m — throughput WILL be re-checked after the swap"
elif [ -z "$BASELINE_SHARES" ]; then
    info "baseline: could NOT be read from $NODE — throughput will not be re-checked"
else
    info "baseline: NO local shares in the last $((BASELINE_WINDOW / 60))m — throughput cannot be re-checked on this node"
fi

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

SWAP_EPOCH=$(date +%s)
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

# Did work start being CREDITED again?
#
# This is the check the H-13 outage walked straight through, and it applies to all three binaries
# — every one of them sits on the share path. `ghost-pool` in particular had no functional
# verification at all before this: the smoke test above is explicitly skipped for it, so a
# ghost-pool deploy was judged solely on "unit active" and "port listening", neither of which
# moves when shares are accepted and then thrown away.
#
# Only gates when the baseline proved there was traffic to lose. A node with no miners cannot
# fail this, and must not be able to pass it either — silence there means "not measured", which
# is stated rather than assumed.
#
# The settle delay is not politeness. ghost-pool bypasses its own PoW height gate while
# `current_height` is still 0, for roughly 90s after every restart, so a sample taken inside that
# window can show shares flowing through a check that is not yet running. 180s clears it.
if [ -z "${ROLLBACK:-}" ] && [ "$BASELINE_SHARES" -gt 0 ] 2>/dev/null; then
    SETTLE="${SETTLE:-180}"
    info "waiting ${SETTLE}s for the PoW height gate to establish, then re-checking throughput"
    sleep "$SETTLE"

    # NOT coerced to 0. sqlite3 `count(*)` always answers with a number, so an empty string means
    # the read itself failed — a different thing from "no shares", and one that must not roll back
    # a healthy binary. `select count(*)` returning "0" is the only genuine zero.
    POST_SHARES=$(local_shares_since "$NODE" "$SWAP_EPOCH" || true)
    MINER_CONNS=$(miner_connections "$NODE" || true)
    info "post-swap window ($SWAP_EPOCH, $(date +%s)] epoch, raw count '${POST_SHARES}', established miner connections '${MINER_CONNS}'"
    if [ -z "$POST_SHARES" ]; then
        info "WARNING: could not read the share count from $NODE — throughput NOT verified"
    elif throughput_regressed "$BASELINE_SHARES" "$POST_SHARES" "$MINER_CONNS"; then
        echo "NO LOCAL SHARES CREDITED in ${SETTLE}s after the swap, but $BASELINE_SHARES arrived in the" >&2
        echo "  $((BASELINE_WINDOW / 60))m before it, and $MINER_CONNS miner connection(s) are still ESTABLISHED." >&2
        echo "  Work is arriving and being discarded. This is the H-13 signature. Rolling back." >&2
        ROLLBACK=1
    elif [ "$POST_SHARES" -eq 0 ] 2>/dev/null && [ "$MINER_CONNS" = "0" ]; then
        info "no local shares since the swap, and NO miners are attached: the restart shed them and"
        info "  they have rehomed via the mining DNS (all eight nodes are in it). Not H-13 —"
        info "  throughput on this node is UNVERIFIED, not regressed. Proceeding."
    elif [ "$POST_SHARES" -eq 0 ] 2>/dev/null; then
        info "WARNING: no shares since the swap and the miner connection count is UNREADABLE —"
        info "  cannot distinguish H-13 from a routine DNS shed; NOT rolling back on unmeasured evidence"
    else
        info "throughput OK: $POST_SHARES local shares credited since the swap (baseline $BASELINE_SHARES/$((BASELINE_WINDOW / 60))m)"
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

    # Do not start a clock on a build whose submission path is already broken. Waiting an hour
    # to discover that is an hour spent proving nothing (#461).
    info "exercising the share-submission path on $NODE before starting the clock"
    if ! exercise_submission_path "$NODE"; then
        die "submission-path smoke FAILED on $NODE — no soak clock started for $BINARY @ $SHORT
       a canary cannot vouch for a build whose miners cannot handshake"
    fi
    info "submission path OK on $NODE"

    printf '%s %s\n' "$(date +%s)" "${LIVE_HASH:-}" > "$STATE_DIR/soaked-$SHA-$NODE-$BINARY"
    info "soak clock started for $BINARY @ $SHORT on $NODE (${SOAK_MINUTES}m required before production)"
fi

info "OK: $BINARY @ $SHORT live on $NODE (backup: $BINARY.bak.$TS)"
