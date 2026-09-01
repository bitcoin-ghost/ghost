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
#   * ghost-pool was deployed to a node whose pool_sv2 could not yet SIGN share batches,
#     so every batch 401'd and was destroyed rather than retried.  -> requires a webhook secret
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
# Environment escape hatch:
#
#   GHOST_DEPLOY_ALLOW_UNSIGNED_WEBHOOK=1
#       Skips the share-webhook secret precondition (gate 3c) for `ghost-pool` ONLY. It exists
#       for exactly one situation: ROLLING BACK to a ghost-pool build that predates #742 and
#       therefore does not require a signature. Anything newer will 401 and destroy shares, so
#       do not reach for this to "get the deploy through". It prints a banner every time.
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
# Overridable so scripts/test-deploy-gate.sh can drive the ONE precondition that has to talk to a
# node (gate 3c) against a stub, rather than being the one guard in this file that nobody can
# exercise. Deliberately scoped to that gate: the deploy and verify paths below still call `ssh`
# and `scp` directly, so nothing here can redirect a real transfer.
SSH_BIN="${GHOST_DEPLOY_SSH:-ssh}"
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
  ghost-pool|pool_sv2|translator_sv2|ghost-pay|ghost-gsp) ;;
  *) die "unknown binary '$BINARY'" ;;
esac

# Does this binary sit on the SHARE PATH?
#
# It decides two gates below, and getting it wrong is not a slow deploy but a WRONG VERDICT:
#
#   * the SV1 stratum smoke test, which dials :3333 — a port the TRANSLATOR owns. Run it for
#     ghost-pay and it passes whether or not ghost-pay works, because it is not testing
#     ghost-pay at all. A check that cannot fail, guarding a rollback.
#   * the post-swap throughput check, which rolls back when shares stop being credited.
#     ghost-pay and ghost-gsp do not carry shares, so their deploy would be judged — and
#     could be rolled back — on traffic they never touch.
#
# So they get their own health check instead, on the port they actually serve.
case "$BINARY" in
  ghost-pool|pool_sv2|translator_sv2) SHARE_PATH_BINARY=yes ;;
  *)                                  SHARE_PATH_BINARY=no  ;;
esac

# The systemd unit each binary runs as. Declared HERE rather than just before the restart,
# because the soak gate below needs it to ask a canary whether it carries this binary at all.
case "$BINARY" in
  ghost-pool)      SERVICE=ghost-pool ;;
  pool_sv2)        SERVICE=sri-pool ;;
  translator_sv2)  SERVICE=sri-translator ;;
  ghost-pay)       SERVICE=ghost-pay ;;
  ghost-gsp)       SERVICE=ghost-gsp ;;
esac

# Binaries that NO canary node carries.
#
# `ghost-pay` and `ghost-gsp` are installed only on vm1-vm4, and every one of those is a
# PRODUCTION node. The canary soak is therefore not merely skipped for them, it is
# UNSATISFIABLE: there is no canary to soak on, so the gate could only ever refuse, and the
# binaries had no enforced path to production at all (#759).
#
# For these the FIRST production node deployed acts as the canary: it soaks the full
# SOAK_MINUTES before any other production node accepts the build. That keeps a real soak —
# real traffic, real time — rather than waiving it.
PRODUCTION_ONLY_BINARIES="ghost-pay ghost-gsp"

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
        ghost-pay)       SRC_PATHS="bins/ghost-pay crates" ;;
        ghost-gsp)       SRC_PATHS="bins/ghost-gsp crates" ;;
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
# Poll a TCP port until it accepts, or give up. Uses bash's /dev/tcp so it needs no `nc`.
#
# Polling beats sleeping: the dependency chain here is ghost-pool -> pool_sv2 resolving its node
# identity -> :34255 -> translator -> :3333, and only the last link is what the smoke test needs.
# A fixed sleep is either too short on a slow node or wasted on a fast one.
wait_for_tcp() {
    local host="$1" port="$2" secs="${3:-150}" waited=0
    # `0` means do not wait at all and assume reachable. The deploy-gate self-test sets this:
    # it drives the submission path through a stub smoke script, so a real TCP poll would make
    # the test non-hermetic AND blow its `timeout 60` per-run cap (this wait is up to 150s).
    #
    # ⚠ Found the hard way. The self-test passed locally only because `ssh_host_for ghost-vm1`
    # resolves to the REAL production node and this machine can reach vm1:3333, so the poll
    # returned instantly. In CI, with no such access, packets are dropped rather than refused,
    # every attempt burned its full 2s timeout, the run hit the 60s cap and two cases failed.
    # A test that reaches production to pass is not testing what it claims to.
    [ "$secs" -eq 0 ] 2>/dev/null && return 0
    while [ "$waited" -lt "$secs" ]; do
        if timeout 2 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
            return 0
        fi
        sleep 3
        waited=$((waited + 3))
    done
    return 1
}

exercise_submission_path() {
    local node="$1" host
    host=$(ssh_host_for "$node") || return 1
    [ -n "$host" ] || return 1

    # ⚠ Restarting ghost-pool makes pool_sv2 re-resolve its identity, and until it does it exits
    # with "share_tier_binding is configured but this node's identity could not ...". Measured on
    # ghost-vm6 during the v1.11.28 roll: 9 restarts and ~60s before :34255 bound, during which
    # the translator crash-looped on "All upstreams failed" and :3333 was CLOSED.
    #
    # The smoke test then read that as a broken build and halted the roll. It was a race, not a
    # fault — the node converged on its own minutes later. Wait for the port the probe needs.
    if ! wait_for_tcp "$host" 3333 "${GHOST_DEPLOY_PORT_WAIT_SECS:-150}"; then
        echo "      :3333 never opened on $node within 150s — the translator did not come up" >&2
        return 1
    fi

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

# What `pool_sv2` actually did at the share boundary since $2 (epoch seconds).
#
# Echoes "loglines batches submits":
#   loglines - total sri-pool journal lines in the window. POSITIVE CONTROL: zero means the probe
#              itself did not work (no sudo, journald rotated, ssh trouble), which is a different
#              thing from "nothing happened" and must never be read as evidence.
#   batches  - "Share batch sent successfully": pool_sv2 POSTed a batch and ghost-pool ACCEPTED the
#              POST. Work provably crossed the boundary.
#   submits  - "SubmitShares": work provably ARRIVED at pool_sv2 from a miner.
#
# This exists because the connection count could not carry the weight put on it (#753). It was
# meant to answer "is somebody still sending work", and an established TCP socket does not answer
# that: on 2026-08-23 ghost-vm1 sat at zero local shares with EIGHT established non-loopback
# stratum connections while perfectly healthy, and the gate would have rolled back a deploy to it.
# These counters are the event itself rather than a proxy for it.
webhook_activity_since() {
    timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$1" \
        "S=\$(sudo journalctl -u sri-pool --since '@$2' --no-pager 2>/dev/null); \
         printf '%s %s %s' \
           \"\$(printf '%s\\n' \"\$S\" | grep -c .)\" \
           \"\$(printf '%s\\n' \"\$S\" | grep -c 'Share batch sent successfully')\" \
           \"\$(printf '%s\\n' \"\$S\" | grep -c 'SubmitShares')\"" \
        2>/dev/null || true
}

# Count ESTABLISHED miner connections on the node's stratum ports (SV1 :3333, farm tier :4444,
# direct SV2 :34255), excluding loopback peers — the node's own translator holds a permanent
# 127.0.0.1 connection to pool_sv2 on :34255 and must not read as a miner.
#
# ⚠ #753: this count is now REPORTED, not DECIDED on. It was the discriminator between H-13 and a
# routine DNS shed, on the reasoning that a still-attached miner means work is still arriving. It
# does not mean that. An idle, half-open or just-reconnected socket counts identically to a busy
# one, and on 2026-08-23 ghost-vm1 sat healthy at zero local shares with EIGHT established
# non-loopback stratum connections — the gate would have rolled back a deploy to it for nothing.
#
# `webhook_activity_since` now carries that decision, because it counts the EVENT (work arriving at
# pool_sv2, batches crossing to ghost-pool) rather than a socket that might carry one.
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
# Decide whether a node's config may receive this binary. Pure, and takes the four measured
# values rather than a node, so scripts/test-deploy-gate.sh can drive every branch without one.
#
# Echoes the reasons to refuse, one per line. EMPTY output means "may proceed".
#
# ⚠ `parse` is the POSITIVE CONTROL. It is always `ok` or `FAIL` when the probe ran at all, so an
# empty value means the probe itself did not run — which is not a passing config and must refuse.
config_gate_failures() {
    local parse="${1:-}" dead="${2:-}" mode="${3:-}" tdp="${4:-}"
    if [ -z "$parse" ]; then
        echo "the config gate produced no verdict — the probe did not run"
        return
    fi
    [ "$parse" = "ok" ] || echo "pool.toml does NOT parse with the incoming binary — the node would not come back from its next restart"
    [ -z "$dead" ] || echo "config carries key(s) for removed features: $dead"
    [ -n "$mode" ] || echo "mining_mode is not set — resolved from MiningMode::default(), which decides whether payouts go through BFT"
}

# Conditions worth saying out loud that must NOT stop a deploy.
#
# ⚠ `[tdp]` was a blocking failure here and should never have been. No node on the fleet carries
# the block — it has been absent on all eight for the life of the config — so the moment the gate
# above started working, it would have refused every deploy on every node, during a release.
#
# A missing `[tdp]` means template distribution runs on compiled defaults. That is the status quo
# and breaks nothing; it is unconverged config, not a node that fails to start. Blocking belongs to
# "this binary will not come back": a config that does not parse, keys for deleted features, an
# unset `mining_mode`. Convergence is #759's job and wants its own change, not a release hostage.
config_gate_warnings() {
    local tdp="${1:-}"
    [ "${tdp:-0}" -gt 0 ] 2>/dev/null || echo "TDP runs on compiled defaults (the sri-pool unit passes no --tdp-port). NOT fixable in pool.toml: [tdp] is not a NodeConfig section and adding it fails deny_unknown_fields (#759, #761)"
}

throughput_regressed() {
    local baseline="${1:-}" post="${2:-}" loglines="${3:-}" submits="${4:-}"
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
    # An unreadable count gets the same treatment as an unreadable share count: not measurable,
    # and a binary is not rolled back on evidence that was never collected.
    #
    # #753: the discriminator is no longer the CONNECTION count. `conns > 0` was standing in for
    # "somebody is still sending work", and it does not mean that — an idle or half-open socket
    # counts the same as a busy miner. Measured 2026-08-23, ghost-vm1 was healthy at zero local
    # shares with EIGHT established non-loopback stratum connections, so this function would have
    # rolled back a deploy to it. It did roll back a healthy v1.11.27 on ghost-vm6 for exactly
    # that reason: the node's single miner had rehomed via the mining DNS during the restart this
    # script issued, and the leftover socket read as "still sending".
    #
    # `submits` is the event itself: work provably arriving at pool_sv2 from a miner.
    [ -n "$loglines" ] || return 1
    [ "$loglines" -gt 0 ] 2>/dev/null || return 1   # probe did not work -> conclude nothing
    [ -n "$submits" ] || return 1
    [ "$submits" -gt 0 ] 2>/dev/null || return 1    # nothing arrived -> a shed, not a discard

    # MINIMUM SAMPLE. "Nothing was credited" only means something when enough work arrived that
    # zero is surprising. It is not surprising at n=2.
    #
    # ghost-vm7, 2026-08-23: rolled back on `submits=2, batches=1, credited=0`. A local share for
    # that window DID exist — the read simply happened before the insert landed. One late row on a
    # sample of two produced a confident verdict about a healthy binary, and the node it convicted
    # was the busiest on the fleet (103 local shares/5m before the swap), so the restart's own
    # miner shed is exactly what shrank the sample that then condemned it.
    #
    # Two independent things can each explain a single uncredited share and neither is an outage:
    # insert lag against a fixed-width window, and an ordinary share rejection (stale, duplicate,
    # below target). Requiring several means both would have to happen repeatedly.
    #
    # This BOUNDS a correct signal; it does not replace one. Below the floor the answer is
    # "not measurable", which the caller reports as UNVERIFIED and proceeds — never as healthy.
    H13_MIN_SUBMITS="${H13_MIN_SUBMITS:-8}"
    [ "$submits" -ge "$H13_MIN_SUBMITS" ] 2>/dev/null || return 1

    # Work arrived in quantity and NOTHING was credited. That is the H-13 signature.
    return 0
}

# Read the `secret` under `[share_webhook]` out of a pool_sv2 config, and say why it is not
# usable when it is not.
#
# Pure, and takes the config TEXT rather than a path, so scripts/test-deploy-gate.sh can drive
# every branch without a node. The parsing is the part that goes wrong, and it goes wrong
# silently: `grep -q secret` over the whole file matches `internal_api_secret` in a different
# section, matches a commented-out line, and matches `secret = ""`. All three are the shape this
# gate exists to refuse, and all three would have read as satisfied.
#
# Section scoping is not decorative either. On ghost-vm5 the very next line after the
# `[share_webhook]` block is `[template_provider_type.Sv2Tp]` with no blank line between them,
# so an extractor that does not stop at the next `[` header runs straight on into the next
# section.
#
# Prints a REASON and returns 1 when unusable; prints nothing and returns 0 when usable. The
# secret's value is never printed, on either path.
webhook_secret_verdict() {
    local conf="${1:-}" line value
    [ -n "$conf" ] || { echo "the config could not be read (empty)"; return 1; }
    line=$(printf '%s\n' "$conf" | awk '
        # A section header is a line whose first non-blank character is `[`. A commented-out
        # header (`#[share_webhook]`) is therefore correctly NOT a header.
        /^[[:space:]]*\[/ { in_s = ($0 ~ /^[[:space:]]*\[share_webhook\]/); next }
        # `secret` must start the line (after indentation), so `# secret = ...` and
        # `internal_api_secret = ...` are both skipped.
        in_s && /^[[:space:]]*secret[[:space:]]*=/ { print; exit }
    ')
    if [ -z "$line" ]; then
        if printf '%s\n' "$conf" | grep -q '^[[:space:]]*\[share_webhook\]'; then
            echo "[share_webhook] is present but has no 'secret' key"
        else
            echo "there is no [share_webhook] section at all"
        fi
        return 1
    fi
    value=${line#*=}
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    # Strip one matching pair of TOML quotes, then re-trim: `secret = "   "` is empty.
    case "$value" in
        '"'*'"') value=${value#\"}; value=${value%\"} ;;
        "'"*"'") value=${value#\'}; value=${value%\'} ;;
    esac
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    case "$value" in
        '')    echo "'secret' under [share_webhook] is empty"; return 1 ;;
        # config/sri/pool-config.toml and scripts/install-node.sh both ship this key as a shell
        # placeholder (`${INTERNAL_API_SECRET}`, `${APISECRET}`) to be substituted at install
        # time. A config where the substitution never happened has a non-empty `secret` that
        # cannot possibly match ghost-pool's, which is the 401 case wearing a passing shape.
        *'$'*) echo "'secret' under [share_webhook] is an unexpanded install placeholder"; return 1 ;;
    esac
    return 0
}

# Has the config been edited since the pool_sv2 that is RUNNING read it?
#
# The precondition is not "the secret is in the file", it is "the running pool_sv2 is signing
# with it" — a secret written but not yet loaded produces exactly the outage this gate exists to
# stop. sri-pool's ExecStartPre (`update-pool-signature.sh`) rewrites this file on every start,
# so in the healthy case the mtime always lands just BEFORE ActiveEnterTimestamp; measured on
# ghost-vm1 and ghost-vm5, both read equal to the second. An mtime AFTER the unit went active
# therefore means a human edited it and did not restart.
#
# 0 = stale (refuse), 1 = current, or not measurable. Unreadable stamps are not evidence of
# staleness and must not block a deploy on a measurement that was never taken.
webhook_config_is_stale() {
    local mtime="${1:-}" started="${2:-}"
    [ -n "$mtime" ] && [ -n "$started" ] || return 1
    [ "$mtime" -gt 0 ] 2>/dev/null || return 1
    [ "$started" -gt 0 ] 2>/dev/null || return 1
    [ "$mtime" -gt "$started" ] 2>/dev/null || return 1
    return 0
}

# 3c. ghost-pool may not be deployed to a node whose pool_sv2 cannot SIGN share batches.
#
#     Since #742 ghost-pool authenticates POST /api/internal/shares with an HMAC-SHA256 over
#     `timestamp || body` under the co-located pool_sv2's `[share_webhook] secret`. So the two
#     sides must be brought up in one order and one order only: pool_sv2 configured and
#     RESTARTED first, ghost-pool second.
#
#     Backwards, the node does not merely lag. pool_sv2 treats a 401 as PERMANENT — deliberately,
#     because retrying cannot fix a credential — so it drops the batch and forgets its skeletons
#     rather than spending a retry budget on it. Every share submitted during a mis-ordered
#     window is DESTROYED, not delayed, and the only signal is a log line on the pool_sv2 side.
#     Nothing downstream objects: the unit is active, :8442 listens, /health answers, and the
#     post-deploy throughput check below reads the node as simply having no traffic.
#
#     Only `ghost-pool` is gated. `pool_sv2` is how the secret reaches the node in the first
#     place, and `translator_sv2` never touches this path — gating either would deadlock the
#     remedy this message prints.
#
#     Fails CLOSED. A config that cannot be read is not evidence that the secret is there, and
#     the cost of assuming it is is total, silent share loss.
if [ "$BINARY" = "ghost-pool" ]; then
  if [ "${GHOST_DEPLOY_ALLOW_UNSIGNED_WEBHOOK:-}" = "1" ]; then
    echo "  ###############################################################################" >&2
    echo "  #  GHOST_DEPLOY_ALLOW_UNSIGNED_WEBHOOK=1 — the share-webhook secret gate is" >&2
    echo "  #  SKIPPED for $NODE." >&2
    echo "  #" >&2
    echo "  #  This is correct for ONE thing: rolling back to a build that predates #742." >&2
    echo "  #  Anything newer will 401 every share batch, and a 401 is not retried — the" >&2
    echo "  #  shares are DESTROYED, not delayed." >&2
    echo "  ###############################################################################" >&2
  else
    POOL_SV2_CONF="/etc/ghost/pool-config.toml"
    # The file is root-owned 0600 on vm5-8 and ghost-owned on vm1-4, so it needs the same
    # sudo-if-present dance the deploy uses. Read into a variable and parsed HERE; the value
    # never reaches a log line, a message, or the terminal.
    WEBHOOK_CONF=$(timeout "$REMOTE_TIMEOUT" "$SSH_BIN" "${SSH_OPTS[@]}" "$NODE" \
        "S=\$(command -v sudo >/dev/null && echo sudo || echo); \$S cat $POOL_SV2_CONF 2>/dev/null" \
        2>/dev/null) || WEBHOOK_CONF=""

    if ! WEBHOOK_WHY=$(webhook_secret_verdict "$WEBHOOK_CONF"); then
        die "pool_sv2 on $NODE cannot sign share batches — $WEBHOOK_WHY
       ($POOL_SV2_CONF)

       ghost-pool has required an HMAC on every share batch since #742, and pool_sv2
       treats a 401 as PERMANENT rather than retrying it. Deploying ghost-pool to this
       node now would make every batch it produces 401 and be DISCARDED. The mis-ordered
       window does not delay shares, it destroys them.

       Do this, in this order:
         1. set 'secret' under [share_webhook] in $POOL_SV2_CONF on $NODE to
            ghost-pool's [network] internal_api_secret from /etc/ghost/pool.toml,
            byte-for-byte (64 hex characters)
         2. scripts/deploy-node.sh $NODE pool_sv2      <- deliberately NOT gated on this
         3. re-run this command

       Rolling BACK to a ghost-pool that predates #742 is the one case where this gate is
       wrong. Set GHOST_DEPLOY_ALLOW_UNSIGNED_WEBHOOK=1 for that, and nothing else."
    fi

    # The secret is in the file — but can the RUNNING pool_sv2 binary even sign? (#752)
    #
    # #745 gated on the config alone, which is a different claim. Signing ships in the pool_sv2
    # BINARY (#742), so a node can hold a perfect config, restarted cleanly, and still run a
    # pre-#742 pool_sv2 with no signing code in it at all. Measured on the live fleet on
    # 2026-08-23: all eight nodes satisfied the config gate while being unable to sign — the
    # gate would have permitted the exact deploy it exists to refuse.
    #
    # `grep -ac` on the binary rather than `strings`, which is absent on some nodes.
    #
    # ⚠ The positive control is NOT optional. An unreadable path, a missing `sudo` or a renamed
    # binary all return 0, which is indistinguishable from "cannot sign" — and on a deploy gate
    # "the check did not run" must never look like a verdict.
    #
    # ⚠ `grep -c` prints its count AND exits 1 when that count is zero, so `|| echo 0` would
    # emit a SECOND line and shift every field below it. `|| true` keeps the count and drops
    # only the status.
    POOL_SV2_BIN="/opt/ghost/bin/pool_sv2"
    WEBHOOK_BIN_PROBE=$(timeout "$REMOTE_TIMEOUT" "$SSH_BIN" "${SSH_OPTS[@]}" "$NODE" "
S=\$(command -v sudo >/dev/null && echo sudo || echo)
\$S grep -ac X-Ghost-Signature $POOL_SV2_BIN 2>/dev/null || true
\$S grep -ac share_webhook $POOL_SV2_BIN 2>/dev/null || true
" 2>/dev/null) || WEBHOOK_BIN_PROBE=""
    SIGN_HITS=$(one_clean_integer "$(printf '%s\n' "$WEBHOOK_BIN_PROBE" | sed -n 1p)" || true)
    SIGN_CTRL=$(one_clean_integer "$(printf '%s\n' "$WEBHOOK_BIN_PROBE" | sed -n 2p)" || true)

    if [ -z "$SIGN_CTRL" ] || [ "$SIGN_CTRL" = "0" ]; then
        die "the pool_sv2 signing probe did not run on $NODE — control returned '${SIGN_CTRL:-<nothing>}'
       ($POOL_SV2_BIN)

       The control greps for a string every pool_sv2 has ever contained, so a zero there means
       the PROBE failed — unreadable path, no sudo, or a renamed binary — not that the binary
       cannot sign. Refusing rather than guessing: those two must not look alike on a gate.

       Check by hand:
         ssh $NODE 'sudo grep -ac share_webhook $POOL_SV2_BIN'"
    fi

    if [ -z "$SIGN_HITS" ] || [ "$SIGN_HITS" = "0" ]; then
        die "pool_sv2 on $NODE predates #742 and cannot sign share batches
       ($POOL_SV2_BIN carries no X-Ghost-Signature; the control matched $SIGN_CTRL times)

       The config is correct, but signing ships in the BINARY, not the config. Deploying
       ghost-pool here now would make every batch this node's own pool_sv2 submits 401 — and
       pool_sv2 treats a 401 as PERMANENT, so those shares are DESTROYED, not delayed.

       Do this, in this order:
         1. scripts/deploy-node.sh $NODE pool_sv2      <- deliberately NOT gated on this
         2. re-run this command

       Rolling BACK to a ghost-pool that predates #742 is the one case where this gate is
       wrong. Set GHOST_DEPLOY_ALLOW_UNSIGNED_WEBHOOK=1 for that, and nothing else."
    fi

    info "pool_sv2 on $NODE carries the share-batch signing code (marker $SIGN_HITS, control $SIGN_CTRL)"

    # The secret is in the file. Is the pool_sv2 that is RUNNING actually using it?
    WEBHOOK_STAMPS=$(timeout "$REMOTE_TIMEOUT" "$SSH_BIN" "${SSH_OPTS[@]}" "$NODE" "
S=\$(command -v sudo >/dev/null && echo sudo || echo)
\$S stat -c %Y $POOL_SV2_CONF 2>/dev/null || echo
date -d \"\$(\$S systemctl show sri-pool -p ActiveEnterTimestamp --value 2>/dev/null)\" +%s 2>/dev/null || echo
" 2>/dev/null) || WEBHOOK_STAMPS=""
    CONF_MTIME=$(one_clean_integer "$(printf '%s\n' "$WEBHOOK_STAMPS" | sed -n 1p)" || true)
    SRI_POOL_STARTED=$(one_clean_integer "$(printf '%s\n' "$WEBHOOK_STAMPS" | sed -n 2p)" || true)
    if webhook_config_is_stale "$CONF_MTIME" "$SRI_POOL_STARTED"; then
        die "$POOL_SV2_CONF on $NODE was edited AFTER sri-pool last started
       (config mtime $CONF_MTIME, sri-pool active since $SRI_POOL_STARTED)

       The secret is in the file but the running pool_sv2 has not loaded it, which signs
       every batch with the OLD credential — the same 401, the same destroyed shares.

       Do this, in this order:
         1. ssh $NODE 'systemctl restart sri-pool'   (it does not bind :34255 for ~60s)
         2. re-run this command"
    fi
    if [ -z "$CONF_MTIME" ] || [ -z "$SRI_POOL_STARTED" ]; then
        info "note: could not read $POOL_SV2_CONF's mtime and sri-pool's start time on $NODE —"
        info "      the secret is present, but that it has been LOADED is unverified"
    else
        info "share-webhook secret present on $NODE and loaded by sri-pool (config $CONF_MTIME <= start $SRI_POOL_STARTED)"
    fi
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
#    ⚠ PRODUCTION-ONLY binaries (see PRODUCTION_ONLY_BINARIES) have no canary to soak on, so
#    the pool of nodes whose soak counts becomes the OTHER production nodes. A node still
#    cannot vouch for itself — it is excluded — so the first one deployed soaks alone for the
#    full window before any second node accepts the build.
#
#    The "no canary carries it" claim is VERIFIED here, not trusted. If a canary has since had
#    the unit installed, the relaxation is refused and the normal canary soak is demanded
#    again. A static list that silently outlives its reason is how a waiver becomes permanent.
if echo "$PRODUCTION_NODES" | grep -qw "$NODE"; then
    SOAK_POOL="$CANARY_NODES"
    if echo "$PRODUCTION_ONLY_BINARIES" | grep -qw "$BINARY"; then
        CARRIER=""
        for c in $CANARY_NODES; do
            # $SSH_BIN, not bare `ssh`: this is a GATE question, so it must be drivable by
            # scripts/test-deploy-gate.sh. Using `ssh` here would make the self-test reach the
            # real fleet to decide the case — the exact trap that file's header calls out.
            if timeout "$REMOTE_TIMEOUT" "$SSH_BIN" "${SSH_OPTS[@]}" "$c" \
                 "test -f /etc/systemd/system/$SERVICE.service" 2>/dev/null; then
                CARRIER="$c"; break
            fi
        done
        if [ -n "$CARRIER" ]; then
            die "$BINARY is listed in PRODUCTION_ONLY_BINARIES, but $CARRIER now carries
       $SERVICE.service. The reason for treating a production node as its canary is gone.
       Soak it on $CARRIER the normal way, and drop $BINARY from PRODUCTION_ONLY_BINARIES."
        fi
        SOAK_POOL=$(echo "$PRODUCTION_NODES" | tr ' ' '\n' | grep -vw "$NODE" | tr '\n' ' ')
        info "no canary carries $SERVICE.service — a production node acts as canary for $BINARY"
    fi
    SOAKED=""
    for c in $SOAK_POOL; do
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
    # Has ANY node recorded a soak for this build at all — including one too young, one that
    # rolled back, or this node's own? If so we are NOT the first, and must wait like anyone
    # else. Only a total absence of records means there is nothing to wait on.
    #
    # This distinction is the whole safety of the bootstrap. Keying it on "$SOAKED is empty"
    # instead would fire for a soak that is merely 5 minutes old, and every node would
    # bootstrap past the window in turn — the soak would never bind at all.
    # Counted with a glob, NOT `ls | wc -l`: under `set -e` + `pipefail` an unmatched `ls`
    # exits non-zero, takes the pipeline with it and kills the whole script — which silently
    # broke three unrelated share-path cases that expected a refusal and got no output at all.
    EXISTING_SOAKS=0
    for _soak in "$STATE_DIR"/soaked-"$SHA"-*-"$BINARY"; do
        if [ -e "$_soak" ]; then EXISTING_SOAKS=$((EXISTING_SOAKS + 1)); fi
    done
    if [ -z "$SOAKED" ] && [ "$EXISTING_SOAKS" -eq 0 ] \
       && echo "$PRODUCTION_ONLY_BINARIES" | grep -qw "$BINARY"; then
        # No canary can carry this binary, and no other production node has soaked it yet — so
        # THIS node is the first, and there is nothing for it to wait on. It becomes the canary:
        # the clock starts below, and every other production node then needs the full window.
        #
        # Permitted automatically rather than behind a flag. `--canary` is inert (assigned once
        # at the top and never read), so the previous refusal named a remedy that could not
        # work: the binaries stayed undeployable and the gate could still only refuse.
        #
        # This cannot be abused into a general soak bypass. It is reachable only for a binary in
        # PRODUCTION_ONLY_BINARIES, only after the ssh probe has confirmed no canary carries it,
        # and only while NO other production node holds a soak record for this commit. The
        # second node finds one and waits.
        info "$BINARY has soaked nowhere yet and no canary can carry it —"
        info "  $NODE is the FIRST node for this build and becomes its canary."
        info "  Every other production node will require ${SOAK_MINUTES}m before taking it."
        SOAKED="$NODE (first node — soak starts here)"
    fi

    if [ -z "$SOAKED" ]; then
        die "$BINARY @ $SHORT has not soaked ${SOAK_MINUTES}m on a canary
       deploy to a canary first: scripts/deploy-node.sh <canary> $BINARY --canary"
    fi
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

# ---------------------------------------------------------------- config gate (#759)
#
# The staged binary is on the node and verified, but NOT yet installed. This is the only moment
# where the INCOMING binary and the node's config can be tested against each other while the swap
# is still free to abandon.
#
# It exists because config on this fleet is whatever successive hand-edits left behind, and nothing
# converged it. Measured 2026-08-23: vm4 carried `bond_ledger_*` for a feature deleted in #699;
# vm2-4 carried the deprecated `public_mining` while LACKING `mining_mode`, so the setting that
# decides whether payouts go through BFT was resolved by `MiningMode::default()`; vm1 had no `[tdp]`
# block at all. Every one was correct-by-accident — a value nobody chose — and every one would have
# survived any number of deploys, because a deploy has never looked at a config file.
#
# ⚠ The parse check runs the STAGED binary, not the installed one. Asking the old binary whether
# the file is acceptable answers the wrong question: what matters is whether the node comes back
# after the swap, and that is the new binary's opinion.
if [ "$BINARY" = "ghost-pool" ]; then
    info "config gate: checking /etc/ghost/pool.toml against the INCOMING $BINARY"
    cfg_out="$(timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$NODE" "
        S=$SUDO
        \$S chmod 755 /tmp/$BINARY.new 2>/dev/null || true
        dead=\$(\$S grep -ohE '^[[:space:]]*(public_mining|bond_ledger_url|bond_ledger_token)[[:space:]]*=' /etc/ghost/pool.toml 2>/dev/null | tr -d ' =' | sort -u | paste -sd, -)
        mode=\$(\$S grep -oP '^\\s*mining_mode\\s*=\\s*\"\\K[^\"]+' /etc/ghost/pool.toml 2>/dev/null | head -1)
        tdp=\$(\$S grep -cE '^\\[tdp\\]' /etc/ghost/pool.toml 2>/dev/null)
        \$S /tmp/$BINARY.new --config /etc/ghost/pool.toml --show-identity >/dev/null 2>&1 && parse=ok || parse=FAIL
        printf 'dead=%s\\nmode=%s\\ntdp=%s\\nparse=%s\\n' \"\$dead\" \"\$mode\" \"\$tdp\" \"\$parse\"
    " 2>/dev/null || true)"

    cg_dead="$(printf '%s\n' "$cfg_out" | sed -n 's/^dead=//p')"
    cg_mode="$(printf '%s\n' "$cfg_out" | sed -n 's/^mode=//p')"
    cg_tdp="$(printf '%s\n' "$cfg_out" | sed -n 's/^tdp=//p')"
    cg_parse="$(printf '%s\n' "$cfg_out" | sed -n 's/^parse=//p')"

    # A gate that cannot read its evidence must not pass. `parse` is the positive control: it is
    # always either `ok` or `FAIL`, so an EMPTY value means the probe itself did not run.
    if [ -z "$cg_parse" ]; then
        echo "REFUSED: the config gate could not run on $NODE — no verdict was produced." >&2
        echo "         That is not the same as a passing config. $NODE is UNCHANGED." >&2
        # A gate that refuses without saying what it saw sends you hunting the wrong thing.
        # Print the raw probe output so the next person does not have to reconstruct it by hand.
        echo "         raw probe output follows (empty means the ssh itself produced nothing):" >&2
        printf '%s\n' "$cfg_out" | sed 's/^/         | /' >&2
        timeout 30 ssh "${SSH_OPTS[@]}" "$NODE" "rm -f /tmp/$BINARY.new" 2>/dev/null || true
        exit 2
    fi

    cg_warn="$(config_gate_warnings "$cg_tdp")"
    [ -z "$cg_warn" ] || printf '  WARN: %s\n' "$cg_warn" >&2

    cg_fail="$(config_gate_failures "$cg_parse" "$cg_dead" "$cg_mode" "$cg_tdp")"

    if [ -n "$cg_fail" ]; then
        echo "REFUSED: config gate failed on $NODE:" >&2
        # quoted + read, because the reasons contain spaces: `printf ... $cg_fail` word-splits
        # and prints one WORD per line, which turns a readable refusal into confetti.
        printf '%s\n' "$cg_fail" | while IFS= read -r line; do echo "         - $line" >&2; done
        echo "         $NODE is UNCHANGED. Fix the config, then re-run." >&2
        echo "         (see scripts/ops/check-fleet-uniformity.sh for the fleet-wide view)" >&2
        timeout 30 ssh "${SSH_OPTS[@]}" "$NODE" "rm -f /tmp/$BINARY.new" 2>/dev/null || true
        exit 2
    fi
    info "config gate: parses with the incoming binary, no dead keys, mining_mode set"
fi

# Backup, atomic swap, restart. Atomic mv so a partially-copied binary is never executable.
timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$NODE" "
set -e
S=$SUDO
\$S cp /opt/ghost/bin/$BINARY /opt/ghost/bin/$BINARY.bak.$TS
\$S cp /tmp/$BINARY.new /opt/ghost/bin/$BINARY.staged
\$S chmod 755 /opt/ghost/bin/$BINARY.staged
\$S mv /opt/ghost/bin/$BINARY.staged /opt/ghost/bin/$BINARY
# Every failure path above removes the staging copy; the success path did not, so a
# ~30-50 MB binary was left in /tmp on every successful deploy. Bounded (same name each
# time) but it is dead weight on nodes that run close to full, and a full root disk is
# how state files stop persisting.
\$S rm -f /tmp/$BINARY.new
" || exit 2

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
  ghost-pay)       READY_PORT=8800 ;;   # HTTPS API, what the dashboard reads
  ghost-gsp)       READY_PORT=8900 ;;   # HTTPS API
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
if [ -z "${ROLLBACK:-}" ] && [ "$SHARE_PATH_BINARY" = "no" ]; then
    # Not on the share path: verify the service answers on ITS OWN port. Same retry shape as
    # the stratum smoke below — a listening socket is not a working service, and one failed
    # attempt must not roll back a binary that is still settling.
    #
    # `-k` because the cert is identity-derived and we are on localhost; the integrity that
    # matters here is the binary swap already verified by hash, not the transport.
    HEALTH_OK=no
    for attempt in 1 2 3; do
        HCODE=$(timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$NODE" \
            "curl -k -s -o /dev/null -w '%{http_code}' --max-time 8 https://127.0.0.1:$READY_PORT/health" 2>/dev/null || true)
        if [ "$HCODE" = "200" ]; then HEALTH_OK=yes; break; fi
        [ "$attempt" -lt 3 ] && { echo "  health attempt $attempt got '${HCODE:-none}', retrying in 20s"; sleep 20; }
    done
    if [ "$HEALTH_OK" != "yes" ]; then
        echo "HEALTH CHECK FAILED: $SERVICE /health != 200 on :$READY_PORT — rolling back" >&2
        ROLLBACK=1
    else
        info "health OK: $SERVICE /health=200 on :$READY_PORT"
    fi
fi

if [ -z "${ROLLBACK:-}" ] && [ "$SHARE_PATH_BINARY" = "yes" ] && [ "$BINARY" != "ghost-pool" ]; then
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
if [ -z "${ROLLBACK:-}" ] && [ "$SHARE_PATH_BINARY" = "yes" ] && [ "$BASELINE_SHARES" -gt 0 ] 2>/dev/null; then
    SETTLE="${SETTLE:-180}"
    info "waiting ${SETTLE}s for the PoW height gate to establish, then re-checking throughput"
    sleep "$SETTLE"

    # NOT coerced to 0. sqlite3 `count(*)` always answers with a number, so an empty string means
    # the read itself failed — a different thing from "no shares", and one that must not roll back
    # a healthy binary. `select count(*)` returning "0" is the only genuine zero.
    POST_SHARES=$(local_shares_since "$NODE" "$SWAP_EPOCH" || true)
    MINER_CONNS=$(miner_connections "$NODE" || true)
    read -r WH_LINES WH_BATCHES WH_SUBMITS <<<"$(webhook_activity_since "$NODE" "$SWAP_EPOCH")"
    info "post-swap window ($SWAP_EPOCH, $(date +%s)] epoch, credited '${POST_SHARES}', pool_sv2 submits '${WH_SUBMITS:-?}', batches delivered '${WH_BATCHES:-?}', sri-pool loglines '${WH_LINES:-?}', miner conns '${MINER_CONNS}'"
    if [ -z "$POST_SHARES" ]; then
        info "WARNING: could not read the share count from $NODE — throughput NOT verified"
    elif throughput_regressed "$BASELINE_SHARES" "$POST_SHARES" "$WH_LINES" "$WH_SUBMITS"; then
        echo "NO LOCAL SHARES CREDITED in ${SETTLE}s after the swap, but pool_sv2 logged" >&2
        echo "  ${WH_SUBMITS} SubmitShares and delivered ${WH_BATCHES} batch(es) in the same window." >&2
        echo "  Work IS arriving and is being discarded. This is the H-13 signature. Rolling back." >&2
        ROLLBACK=1
    elif [ "$POST_SHARES" -eq 0 ] 2>/dev/null && [ -n "${WH_LINES:-}" ] && [ "${WH_LINES:-0}" -gt 0 ] 2>/dev/null && [ "${WH_SUBMITS:-0}" -eq 0 ] 2>/dev/null; then
        info "no local shares since the swap, and pool_sv2 received NO submissions either: the"
        info "  restart shed this node's miners and they have rehomed via the mining DNS (all eight"
        info "  nodes are in it). Not H-13 — throughput here is UNVERIFIED, not regressed. Proceeding."
    elif [ "$POST_SHARES" -eq 0 ] 2>/dev/null && [ -n "${WH_SUBMITS:-}" ] && [ "${WH_SUBMITS:-0}" -gt 0 ] 2>/dev/null && [ "${WH_SUBMITS:-0}" -lt "${H13_MIN_SUBMITS:-8}" ] 2>/dev/null; then
        info "WARNING: no shares credited since the swap, but only ${WH_SUBMITS} submission(s) arrived —"
        info "  below the ${H13_MIN_SUBMITS:-8} needed for 'nothing credited' to mean anything. A single"
        info "  uncredited share is explained by insert lag or an ordinary rejection. Throughput here is"
        info "  UNVERIFIED, not regressed. Proceeding — re-check this node by hand."
    elif [ "$POST_SHARES" -eq 0 ] 2>/dev/null; then
        info "WARNING: no shares since the swap and pool_sv2's activity is UNREADABLE"
        info "  (loglines='${WH_LINES:-}' submits='${WH_SUBMITS:-}') — cannot distinguish H-13 from a"
        info "  routine DNS shed; NOT rolling back on unmeasured evidence"
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
#
# Canaries always soak. A production node soaks only when it is standing in for one, which is
# exactly the PRODUCTION_ONLY case — otherwise every production deploy would start a clock and
# the "soaked somewhere else first" requirement would dissolve.
START_SOAK=no
if echo "$CANARY_NODES" | grep -qw "$NODE"; then
    START_SOAK=yes
elif echo "$PRODUCTION_ONLY_BINARIES" | grep -qw "$BINARY"; then
    START_SOAK=yes
fi

if [ "$START_SOAK" = "yes" ]; then
    # Record WHAT soaked, not just when. The hash lets the production gate confirm the node is
    # still running this build rather than something a rollback restored underneath it.
    LIVE_HASH=$(timeout "$REMOTE_TIMEOUT" ssh "${SSH_OPTS[@]}" "$NODE" \
        "sha256sum /opt/ghost/bin/$BINARY 2>/dev/null | cut -d' ' -f1" 2>/dev/null || true)

    # Do not start a clock on a build whose submission path is already broken. Waiting an hour
    # to discover that is an hour spent proving nothing (#461).
    # Only meaningful for a binary that carries shares. For the others the /health check
    # above IS the equivalent gate, and dialling :3333 would prove nothing about them.
    if [ "$SHARE_PATH_BINARY" = "no" ]; then
        info "submission path not exercised: $BINARY carries no shares (its /health check is the equivalent)"
    else
    info "exercising the share-submission path on $NODE before starting the clock"
    if ! exercise_submission_path "$NODE"; then
        die "submission-path smoke FAILED on $NODE — no soak clock started for $BINARY @ $SHORT
       a canary cannot vouch for a build whose miners cannot handshake
       ⚠ THE SWAP ALREADY HAPPENED: $NODE is running $BINARY @ $SHORT UNVERIFIED. This is not a
         refusal that left the node untouched — check it, and roll back with
         /opt/ghost/bin/$BINARY.bak.* if it is not serving work."
    fi
    info "submission path OK on $NODE"
    fi

    printf '%s %s\n' "$(date +%s)" "${LIVE_HASH:-}" > "$STATE_DIR/soaked-$SHA-$NODE-$BINARY"
    info "soak clock started for $BINARY @ $SHORT on $NODE (${SOAK_MINUTES}m required before production)"
fi

info "OK: $BINARY @ $SHORT live on $NODE (backup: $BINARY.bak.$TS)"
