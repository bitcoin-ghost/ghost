#!/usr/bin/env bash
#
# Self-test for deploy-node.sh's preconditions.
#
# The whole value of that script is that it REFUSES. A gate that cannot fail is worth nothing,
# and that is not a hypothetical here: for a while it would have deployed a reverted commit to
# production reporting all four gates satisfied (#459). So this drives the gate against
# deliberately-bad state and asserts it says no.
#
# Runs entirely against a temporary STATE_DIR and a fake node list. Nothing is deployed, no ssh
# is attempted for the cases that must fail before reaching one.
#
# Usage: scripts/test-deploy-gate.sh
set -uo pipefail

SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Build a HERMETIC repo to drive the gate against, rather than borrowing the real one.
#
# Two reasons. First, gate 1 is "clean working tree" and gate 2 is "commit is on origin/main";
# either fires before anything under test, so a dirty checkout or a missing ref makes every
# later assertion pass for the wrong reason. Second, CI checks out shallow and without an
# `origin/main` ref at all, so a worktree-based harness dies there — which is exactly how this
# first failed.
#
# So: a throwaway repo, committed clean, with refs/remotes/origin/main pointed at that commit.
REPO_ROOT="$TMP/repo"
mkdir -p "$REPO_ROOT/scripts" "$REPO_ROOT/bins/translator-sv2/tests" "$REPO_ROOT/crates"
cp "$SRC_ROOT/scripts/deploy-node.sh" "$REPO_ROOT/scripts/deploy-node.sh"
: > "$REPO_ROOT/crates/.keep"

# Stand-in for the SV1 smoke suite, which the soak gate now runs against a canary (#461).
# Committed here rather than written mid-test, because creating a file later would dirty the
# tree and trip the clean-tree gate before the case under test is reached.
#
# Its exit code is driven by GATE_SMOKE_EXIT so a single committed file can play both a healthy
# and a broken submission path.
cat > "$REPO_ROOT/bins/translator-sv2/tests/sv1_handshake_smoke.py" <<'SMOKE_STUB'
#!/usr/bin/env python3
import os, sys
sys.exit(int(os.environ.get("GATE_SMOKE_EXIT", "0")))
SMOKE_STUB
chmod +x "$REPO_ROOT/bins/translator-sv2/tests/sv1_handshake_smoke.py"

# Stand-in for ssh, for the ONE precondition that has to ask a node a question: gate 3c, the
# share-webhook secret. Without it that gate is the only one in the file nobody can drive, which
# is the position #459 was found in.
#
# deploy-node.sh reaches for it through GHOST_DEPLOY_SSH, and ONLY for gate 3c — the transfer and
# verify paths call `ssh`/`scp` directly, so this cannot silently stand in for a real deploy.
# Committed rather than written mid-test, for the same reason as the smoke stub: creating a file
# later dirties the tree and trips gate 1 before the case under test is reached.
cat > "$REPO_ROOT/scripts/ssh-stub.sh" <<'SSH_STUB'
#!/usr/bin/env bash
# The remote command is the last argument; everything before it is ssh options and the host.
cmd="${@: -1}"
case "$cmd" in
    *"cat /etc/ghost/pool-config.toml"*)
        # An ssh or `cat` that fails yields NO output and a non-zero status, which is what a
        # root-owned 0600 config on a node we cannot sudo on looks like.
        [ "${STUB_CONF_UNREADABLE:-0}" = 1 ] && exit 1
        printf '%s\n' "$STUB_CONF" ;;
    *"stat -c %Y"*)
        # Two lines: config mtime, then sri-pool's ActiveEnterTimestamp as an epoch. Either may
        # be empty, which is how an unreadable stamp reaches the caller.
        printf '%s\n%s\n' "${STUB_MTIME:-}" "${STUB_START:-}" ;;
    *)  exit 1 ;;
esac
SSH_STUB
chmod +x "$REPO_ROOT/scripts/ssh-stub.sh"
git -C "$REPO_ROOT" init -q
git -C "$REPO_ROOT" add -A
git -C "$REPO_ROOT" -c user.email=t@t -c user.name=t commit -qm "gate under test"
# Make the commit look like current main so gate 2 and the revert check both pass cleanly.
git -C "$REPO_ROOT" update-ref refs/remotes/origin/main HEAD
DEPLOY="$REPO_ROOT/scripts/deploy-node.sh"

pass=0
fail=0

# Run the gate with an isolated state dir; returns its exit code and captures stderr.
run_gate() {
    local node="$1" binary="$2"
    ( cd "$REPO_ROOT" \
        && GHOST_DEPLOY_REPO_ROOT="$REPO_ROOT" STATE_DIR="$TMP/state" SOAK_MINUTES=60 \
        GATE_SMOKE_EXIT="${GATE_SMOKE_EXIT:-0}" \
        GHOST_DEPLOY_ALLOW_UNSIGNED_WEBHOOK="${GHOST_DEPLOY_ALLOW_UNSIGNED_WEBHOOK:-}" \
        STUB_CONF="${STUB_CONF:-}" STUB_CONF_UNREADABLE="${STUB_CONF_UNREADABLE:-0}" \
        STUB_MTIME="${STUB_MTIME:-}" STUB_START="${STUB_START:-}" \
        GHOST_DEPLOY_SSH="${GHOST_DEPLOY_SSH:-ssh}" \
        timeout 60 bash "$DEPLOY" "$node" "$binary" 2>&1 )
}

check() {
    local name="$1" expect="$2" out="$3"
    if grep -qiE "$expect" <<<"$out"; then
        printf "  [ok ] %s\n" "$name"
        pass=$((pass+1))
    else
        printf "  [BAD] %s\n" "$name"
        printf "        expected to match: %s\n" "$expect"
        printf "        got: %s\n" "$(head -3 <<<"$out" | tr '\n' ' ')"
        fail=$((fail+1))
    fi
}

# The mirror of check(): assert something is NOT in the output. Needed because half of what a
# gate has to prove is that it PERMITS — a guard that refuses everything passes every refusal
# assertion in this file and is still useless.
check_absent() {
    local name="$1" forbid="$2" out="$3"
    if grep -qiE "$forbid" <<<"$out"; then
        printf "  [BAD] %s\n" "$name"
        printf "        must NOT have matched: %s\n" "$forbid"
        printf "        got: %s\n" "$(head -3 <<<"$out" | tr '\n' ' ')"
        fail=$((fail+1))
    else
        printf "  [ok ] %s\n" "$name"
        pass=$((pass+1))
    fi
}

mkdir -p "$TMP/state"
SHA="$(cd "$REPO_ROOT" && git rev-parse HEAD)"

# Neither the clean-tree nor the on-main gate may be what we are measuring — if either fires,
# every later assertion passes for the wrong reason.
_probe="$(run_gate ghost-vm1 ghost-pool)"
if grep -qiE "working tree is dirty|is not on origin/main" <<<"$_probe"; then
    echo "test harness bug: an earlier gate fires first, later assertions would be vacuous" >&2
    echo "  $(head -1 <<<"$_probe")" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. No test record -> refuse. The most basic gate.
# ---------------------------------------------------------------------------
out="$(run_gate ghost-vm1 ghost-pool)"
check "refuses with no passing test record" "no passing test record" "$out"

# ---------------------------------------------------------------------------
# 2. Test record present, but no soak -> still refuse, and the message must name
#    the BINARY. A per-commit-only message is what let a soak of one binary vouch
#    for another (#459).
# ---------------------------------------------------------------------------
: > "$TMP/state/tested-$SHA"
out="$(run_gate ghost-vm1 translator_sv2)"
check "refuses with no soak, naming the binary" "translator_sv2 @ .* has not soaked" "$out"

# ---------------------------------------------------------------------------
# 3. THE #459 CASE: a soak recorded for a DIFFERENT binary must not satisfy the
#    gate for this one. Soaking ghost-pool alone used to green-light translator_sv2.
# ---------------------------------------------------------------------------
printf '%s %s\n' "$(( $(date +%s) - 7200 ))" "deadbeef" \
    > "$TMP/state/soaked-$SHA-ghost-vm5-ghost-pool"
out="$(run_gate ghost-vm1 translator_sv2)"
check "a soak of another binary does NOT satisfy this one" "translator_sv2 @ .* has not soaked" "$out"

# ---------------------------------------------------------------------------
# 4. A soak that has not run long enough must not satisfy the gate.
# ---------------------------------------------------------------------------
printf '%s %s\n' "$(( $(date +%s) - 300 ))" "deadbeef" \
    > "$TMP/state/soaked-$SHA-ghost-vm5-translator_sv2"
out="$(run_gate ghost-vm1 translator_sv2)"
check "a 5-minute soak does not satisfy a 60-minute requirement" "has not soaked" "$out"

# ---------------------------------------------------------------------------
# 5. A LONG ENOUGH soak whose submission path is broken must NOT satisfy the gate.
#
#    This is the #461 case. A canary has no miners, so "healthy for 60 minutes" says nothing
#    about the path where both motivating regressions lived. Before this, the gate accepted a
#    soak purely on elapsed time and a matching hash — a build could handshake-deadlock every
#    miner and still be waved into production.
# ---------------------------------------------------------------------------
printf '%s %s\n' "$(( $(date +%s) - 7200 ))" "" \
    > "$TMP/state/soaked-$SHA-ghost-vm5-translator_sv2"
out="$(GATE_SMOKE_EXIT=1 run_gate ghost-vm1 translator_sv2)"
check "a 2-hour soak with a FAILING submission path does not satisfy the gate" \
    "has not soaked" "$out"

# The refused record must also be cleared, so a later run cannot inherit the same bad vouch.
if [ -f "$TMP/state/soaked-$SHA-ghost-vm5-translator_sv2" ]; then
    printf "  [BAD] a soak refused for a broken submission path was left on disk\n"
    fail=$((fail+1))
else
    printf "  [ok ] a refused soak record is cleared, not left to be re-read\n"
    pass=$((pass+1))
fi

# ---------------------------------------------------------------------------
# 6. The same soak with a PASSING submission path DOES satisfy the gate — so the
#    check above is a real gate and not a blanket refusal.
# ---------------------------------------------------------------------------
printf '%s %s\n' "$(( $(date +%s) - 7200 ))" "" \
    > "$TMP/state/soaked-$SHA-ghost-vm5-translator_sv2"
out="$(run_gate ghost-vm1 translator_sv2)"
if grep -qi "has not soaked" <<<"$out"; then
    printf "  [BAD] a good soak with a passing submission path was still refused\n"
    fail=$((fail+1))
else
    printf "  [ok ] a soak with a verified submission path satisfies the gate\n"
    pass=$((pass+1))
fi

# ---------------------------------------------------------------------------
# 7. Canary deploys must NOT require a soak — that is the point of a canary.
#    It should get past the soak gate and fail later (on ssh or a missing binary).
# ---------------------------------------------------------------------------
rm -f "$TMP/state/soaked-$SHA"-*
out="$(run_gate ghost-vm5 translator_sv2)"
# Must get PAST the soak gate and fail on something later (the binary is not built here).
if grep -qi "has not soaked\|working tree is dirty\|no passing test record" <<<"$out"; then
    printf "  [BAD] canary blocked before reaching the deploy stage: %s\n" "$(head -1 <<<"$out")"
    fail=$((fail+1))
elif grep -qiE "not built|No such file" <<<"$out"; then
    printf "  [ok ] canary passes the soak gate and proceeds to the deploy stage\n"
    pass=$((pass+1))
else
    printf "  [BAD] canary reached an unexpected state: %s\n" "$(head -1 <<<"$out")"
    fail=$((fail+1))
fi

# ---------------------------------------------------------------------------
# 8. The share-webhook secret gate (3c), end to end.
#
#    Since #742 ghost-pool authenticates every share batch with an HMAC under the co-located
#    pool_sv2's `[share_webhook] secret`, so the two must be brought up in one order: pool_sv2
#    configured and restarted FIRST. Backwards, pool_sv2 gets a 401 — which it treats as
#    PERMANENT, on purpose, because retrying cannot fix a credential — and drops the batch.
#    Every share submitted into a mis-ordered window is destroyed, not delayed, and nothing
#    downstream objects: the unit is active, the port listens, /health answers.
#
#    Driven through a stub ssh (GHOST_DEPLOY_SSH), because this is the one precondition that has
#    to ask a node a question, and an unexerciseable guard is the position #459 was found in.
# ---------------------------------------------------------------------------
SSH_STUB_BIN="$REPO_ROOT/scripts/ssh-stub.sh"
GOOD_CONF=$'[share_webhook]\nurl = "http://127.0.0.1:8080/api/internal/shares"\nsecret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"\nbatch_size = 1\n[template_provider_type.Sv2Tp]\naddress = "127.0.0.1:8442"\n'

# The fleet's ACTUAL state on 2026-08-23, measured on all eight nodes: a [share_webhook] section
# with url/batch_size/timeout/retries and no `secret` at all. This is the case that matters.
out="$(GHOST_DEPLOY_SSH="$SSH_STUB_BIN" \
      STUB_CONF=$'[share_webhook]\nurl = "http://127.0.0.1:8080/api/internal/shares"\nbatch_size = 1\nmax_retries = 3\n[template_provider_type.Sv2Tp]\naddress = "127.0.0.1:8442"\n' \
      run_gate ghost-vm5 ghost-pool)"
check "refuses ghost-pool when [share_webhook] has no secret" "cannot sign share batches" "$out"

# `grep -q secret` over the whole file would match `internal_api_secret` in [network], a
# commented-out line, and `secret = \"\"`. All three are the shape this gate exists to refuse.
out="$(GHOST_DEPLOY_SSH="$SSH_STUB_BIN" \
      STUB_CONF=$'[network]\ninternal_api_secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"\n[share_webhook]\nurl = "u"\n# secret = "deadbeef"\n' \
      run_gate ghost-vm5 ghost-pool)"
check "a secret in ANOTHER section, and a commented-out one, do not satisfy it" \
    "cannot sign share batches" "$out"

out="$(GHOST_DEPLOY_SSH="$SSH_STUB_BIN" STUB_CONF=$'[share_webhook]\nsecret = ""\n' \
      run_gate ghost-vm5 ghost-pool)"
check "an empty secret is refused" "is empty" "$out"

# config/sri/pool-config.toml and install-node.sh both ship this key as a shell placeholder.
out="$(GHOST_DEPLOY_SSH="$SSH_STUB_BIN" STUB_CONF=$'[share_webhook]\nsecret = "${APISECRET}"\n' \
      run_gate ghost-vm5 ghost-pool)"
check "an unexpanded install placeholder is refused" "unexpanded install placeholder" "$out"

# FAIL CLOSED. A config that could not be read is not evidence that the secret is there, and the
# cost of assuming it is is total, silent share loss.
out="$(GHOST_DEPLOY_SSH="$SSH_STUB_BIN" STUB_CONF_UNREADABLE=1 run_gate ghost-vm5 ghost-pool)"
check "an unreadable config refuses rather than assuming the best" "could not be read" "$out"

# The gate must PERMIT. Reaching "not built" means it cleared 3c and went on to the deploy stage.
out="$(GHOST_DEPLOY_SSH="$SSH_STUB_BIN" STUB_CONF="$GOOD_CONF" \
      STUB_MTIME=1787036059 STUB_START=1787036059 run_gate ghost-vm5 ghost-pool)"
check_absent "a node with a usable secret is NOT refused" "cannot sign share batches|was edited AFTER" "$out"
check "a node with a usable secret proceeds to the deploy stage" "not built" "$out"

# Written but not LOADED is the same outage: sri-pool's ExecStartPre rewrites this file on every
# start, so in the healthy case its mtime always lands just before ActiveEnterTimestamp (measured
# equal to the second on ghost-vm1 and ghost-vm5). An mtime AFTER it means nobody restarted.
out="$(GHOST_DEPLOY_SSH="$SSH_STUB_BIN" STUB_CONF="$GOOD_CONF" \
      STUB_MTIME=1787036999 STUB_START=1787036059 run_gate ghost-vm5 ghost-pool)"
check "a secret written but not loaded is refused, naming the restart" "was edited AFTER sri-pool last started" "$out"

# Unreadable stamps are not evidence of staleness, and must not block a deploy on a measurement
# that was never taken — but the gap must be STATED, not assumed away.
out="$(GHOST_DEPLOY_SSH="$SSH_STUB_BIN" STUB_CONF="$GOOD_CONF" run_gate ghost-vm5 ghost-pool)"
check_absent "unreadable stamps do not block" "was edited AFTER" "$out"
check "unreadable stamps are reported as unverified, not as satisfied" "is unverified" "$out"

# SCOPE. pool_sv2 is how the secret REACHES the node, so gating it would deadlock the remedy the
# refusal above prints; translator_sv2 never touches this path. Both are driven against the most
# hostile node state there is — a config that cannot even be read.
for b in pool_sv2 translator_sv2; do
    out="$(GHOST_DEPLOY_SSH="$SSH_STUB_BIN" STUB_CONF_UNREADABLE=1 run_gate ghost-vm5 "$b")"
    check_absent "$b is NOT gated on the webhook secret" "cannot sign share batches" "$out"
    check "$b still reaches the deploy stage" "not built" "$out"
done

# The escape hatch, which exists for exactly one thing: rolling back to a ghost-pool that
# predates #742. It must work, and it must be impossible to miss in a transcript.
out="$(GHOST_DEPLOY_ALLOW_UNSIGNED_WEBHOOK=1 GHOST_DEPLOY_SSH="$SSH_STUB_BIN" \
      STUB_CONF_UNREADABLE=1 run_gate ghost-vm5 ghost-pool)"
check_absent "the override skips the gate" "cannot sign share batches" "$out"
check "the override announces itself loudly" "GHOST_DEPLOY_ALLOW_UNSIGNED_WEBHOOK=1" "$out"
check "the override says what it is for" "predates #742" "$out"

# ---------------------------------------------------------------------------
# 9. The webhook-config parsing predicates, directly.
#
#    Sourced out of the real script rather than re-implemented, for the reason section 10 gives:
#    the H-13 fix shipped with two tests that passed against broken production because both
#    re-implemented the transformation under test.
# ---------------------------------------------------------------------------
eval "$(sed -n '/^webhook_secret_verdict()/,/^}/p' "$DEPLOY")"
eval "$(sed -n '/^webhook_config_is_stale()/,/^}/p' "$DEPLOY")"

secret_case() {  # label config want("usable"|"refused")
    local label="$1" conf="$2" want="$3" got=usable
    webhook_secret_verdict "$conf" >/dev/null || got=refused
    if [ "$got" = "$want" ]; then
        printf "  [ok ] %s\n" "$label"
        pass=$((pass+1))
    else
        printf "  [BAD] %s (wanted %s, got %s)\n" "$label" "$want" "$got"
        fail=$((fail+1))
    fi
}

# Section scoping is not decorative: on ghost-vm5 the line after the [share_webhook] block is
# [template_provider_type.Sv2Tp] with NO blank line between them, so an extractor that does not
# stop at the next `[` header runs straight on into the next section and reads its keys.
secret_case "a secret in the FOLLOWING section is not this section's" \
    $'[share_webhook]\nurl = "u"\n[template_provider_type.Sv2Tp]\nsecret = "deadbeef"\n' refused
secret_case "no [share_webhook] section at all"        $'[network]\nsecret = "aa"\n'   refused
secret_case "a commented-out section header is not a section" $'#[share_webhook]\nsecret = "aa"\n' refused
secret_case "whitespace-only secret is empty"          $'[share_webhook]\nsecret = "   "\n' refused
secret_case "a real 64-hex secret is usable"           $'[share_webhook]\nsecret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"\n' usable
secret_case "an unquoted value is usable"              $'[share_webhook]\nsecret=abc123\n' usable
secret_case "indentation and trailing spaces survive"  $'[share_webhook]\n  secret =  "abc"  \n' usable

stale_case() {  # label mtime started want(yes|no)
    local label="$1" got=no
    webhook_config_is_stale "$2" "$3" && got=yes
    if [ "$got" = "$4" ]; then
        printf "  [ok ] %s\n" "$label"
        pass=$((pass+1))
    else
        printf "  [BAD] %s (wanted stale=%s, got %s)\n" "$label" "$4" "$got"
        fail=$((fail+1))
    fi
}

stale_case "edited after the unit went active -> stale"           200 100 yes
# The real reading on ghost-vm1 and ghost-vm5: ExecStartPre rewrites the file, so mtime and
# ActiveEnterTimestamp land in the SAME second. Equal must not read as stale, or the gate
# refuses every healthy node on the fleet.
stale_case "mtime equal to the start second -> current"           1787036059 1787036059 no
stale_case "restarted after the edit -> current"                  100 200 no
stale_case "unreadable mtime -> not measurable, do not block"     "" 100 no
stale_case "unreadable start -> not measurable, do not block"     100 "" no
stale_case "a non-numeric stamp -> not measurable, do not block"  "x" 100 no

# ---------------------------------------------------------------------------
# 10. The post-deploy throughput verdict.
#
#    This is the check the H-13 outage went straight through: a PoW check with its operands in
#    the wrong byte order rejected every locally-submitted share on all eight nodes for ~30
#    minutes, while the unit stayed active, the port stayed open, /health answered, and no
#    error line was logged. Miners remained CONNECTED and their work was discarded.
#
#    Driven by sourcing the verdict function out of the real script, so this tests the code that
#    runs rather than a copy of it — the failure mode that let two H-13 tests pass green against
#    broken production.
# ---------------------------------------------------------------------------
eval "$(sed -n '/^throughput_regressed()/,/^}/p' "$DEPLOY")"

verdict_case() {  # label baseline post loglines submits want_regressed
    local label="$1" baseline="$2" post="$3" loglines="$4" submits="$5" want="$6" got=no
    throughput_regressed "$baseline" "$post" "$loglines" "$submits" && got=yes
    if [ "$got" = "$want" ]; then
        printf "  [ok ] %s\n" "$label"
        pass=$((pass+1))
    else
        printf "  [BAD] %s (wanted regressed=%s, got %s)\n" "$label" "$want" "$got"
        fail=$((fail+1))
    fi
}

# The outage itself: traffic before, silence after, and pool_sv2 CONFIRMS work kept arriving.
# Nothing else in the deploy path sees this.
verdict_case "traffic before, silence after, work still arriving -> ROLL BACK"  52 0 400 30 yes
verdict_case "traffic before and after -> proceed"                              52 47 400 30 no
# A single share is enough to prove the path is credited; this must not gate on a rate.
verdict_case "one share after a busy baseline -> proceed"                       52 1 400 30 no

# THE 2026-08-11 CASE. All eight nodes are in the mining DNS, so the swap's own restart sheds
# every miner the node had and they rehome elsewhere within seconds (measured: avalonQ's first
# share on vm2 landed 24s after its last on vm3). Silence with NO work arriving is the expected
# aftermath of the restart, not H-13 — four healthy binaries (vm6, vm3, vm1 twice) were rolled
# back for it in one night.
verdict_case "silence after, and pool_sv2 got no submissions -> proceed"        52 0 400 0 no

# THE 2026-08-23 CASE (#753). The previous discriminator was the CONNECTION count, and it rolled
# back a healthy v1.11.27 on ghost-vm6: the node's one miner had rehomed during the restart and a
# leftover socket read as "still sending". Measured the same hour, ghost-vm1 was healthy at zero
# local shares with EIGHT established non-loopback connections. An idle socket must not convict.
verdict_case "silence, sockets attached, but NO submissions -> proceed"         52 0 400 0 no

# A canary with no miners must not be able to PASS this either — silence there is "not measured".
verdict_case "no baseline, no post -> not measurable, proceed"                   0 0 400 0 no
verdict_case "no baseline but shares appear -> proceed"                          0 9 400 30 no

# The counts come off a remote sqlite3/journalctl through ssh; an empty or failed read must not
# read as an outage and trigger a spurious rollback of a healthy binary.
verdict_case "unreadable baseline -> not measurable, proceed"                   "" "" "" "" no
verdict_case "unreadable post with a real baseline -> proceed"                  52 "" 400 30 no
verdict_case "unreadable submit count with silence -> proceed"                  52 0 400 "" no

# ⛔ MINIMUM SAMPLE (ghost-vm7, 2026-08-23). A verdict of "nothing was credited" only carries
# information when enough work arrived that zero is surprising. vm7 was rolled back on submits=2,
# and a local share for that window DID exist — the read happened before the insert landed. The
# node it convicted was the busiest on the fleet; the restart's own miner shed is what shrank the
# sample that then condemned it. Insert lag and an ordinary share rejection each explain one
# uncredited share, and neither is an outage.
verdict_case "work arrived but only 2 submissions -> too small to convict"      52 0 400 2 no
verdict_case "just below the floor -> too small to convict"                     52 0 400 7 no
verdict_case "at the floor with nothing credited -> ROLL BACK"                  52 0 400 8 yes
verdict_case "well above the floor with nothing credited -> ROLL BACK"          52 0 400 90 yes

# ⛔ THE PROBE ITSELF FAILING. `loglines` is the positive control: zero means journalctl returned
# nothing — no sudo, rotated journal, ssh trouble — which is NOT the same as "no work arrived".
# Without this the gate reads a broken probe as a clean shed and proceeds on evidence it never
# collected; with `submits` also 0 it would look identical to the healthy shed case above.
verdict_case "probe returned NOTHING -> not measurable, proceed"                52 0 0 0 no
verdict_case "probe unreadable -> not measurable, proceed"                      52 0 "" 30 no

# ---------------------------------------------------------------------------
# 10b. The config gate (#759). A deploy has never looked at a config file, so config on the fleet
#     was whatever successive hand-edits left behind: vm4 carried `bond_ledger_*` for a feature
#     DELETED in #699; vm2-4 carried the deprecated `public_mining` while LACKING `mining_mode`,
#     so the setting that decides whether payouts go through BFT came from MiningMode::default();
#     vm1 had no `[tdp]` block at all. Each was correct-by-accident and each would have survived
#     any number of deploys.
#
#     Driven by sourcing the verdict function out of the real script, so this tests the code that
#     runs rather than a copy of it.
# ---------------------------------------------------------------------------
eval "$(sed -n '/^config_gate_failures()/,/^}/p' "$DEPLOY")"

cfg_case() {  # label parse dead mode tdp want_reasons
    local label="$1" got
    got="$(config_gate_failures "$2" "$3" "$4" "$5" | grep -c .)"
    if [ "$got" = "$6" ]; then
        printf "  [ok ] %s\n" "$label"; pass=$((pass+1))
    else
        printf "  [BAD] %s (wanted %s reason(s), got %s)\n" "$label" "$6" "$got"; fail=$((fail+1))
    fi
}

cfg_case "clean config -> proceed"                          ok   ""                public_pool 1 0
cfg_case "does not parse with the incoming binary -> REFUSE" FAIL ""               public_pool 1 1
cfg_case "dead key for a removed feature -> REFUSE"         ok   "bond_ledger_url" public_pool 1 1
cfg_case "deprecated public_mining -> REFUSE"               ok   "public_mining"   public_pool 1 1
cfg_case "mining_mode unset -> REFUSE"                      ok   ""                ""          1 1
# ⚠ `[tdp]` is a WARNING, not a refusal, and the count below pins that deliberately. No node on
#    the fleet carries the block, so making it blocking would refuse every deploy on every node.
#    Compiled defaults are the status quo and break nothing; convergence is #759's job.
cfg_case "no [tdp] block -> allowed, warned elsewhere"      ok   ""                public_pool 0 0
cfg_case "several faults -> one reason each"                FAIL "public_mining"   ""          0 3

# ⛔ THE PROBE ITSELF NOT RUNNING. `parse` is always `ok` or `FAIL` when the probe ran, so empty
#    means it did not. A gate that cannot read its evidence must REFUSE, not pass: "the config is
#    fine" and "I could not tell" are different answers and only one of them is safe to act on.
cfg_case "probe produced no verdict -> REFUSE"              ""   ""                public_pool 1 1

#    ...and it must say the RIGHT thing. Counting reasons is not enough: with the no-verdict guard
#    removed, an empty `parse` still refuses (it is not "ok"), so the count is identical — but the
#    reason it gives is "does not parse", which sends the reader to debug a config file that may be
#    perfectly fine. Mutation-testing caught this test being weaker than it looked; assert the text.
if config_gate_failures "" "" public_pool 1 | grep -q "the probe did not run"; then
    printf "  [ok ] no-verdict is reported as a PROBE failure, not a parse failure\n"; pass=$((pass+1))
else
    printf "  [BAD] no-verdict was misreported (got: %s)\n" "$(config_gate_failures "" "" public_pool 1 | head -1)"; fail=$((fail+1))
fi

# ---------------------------------------------------------------------------
# 11. The remote-read validator. Its predecessor was `tr -cd '0-9'`, which cannot fail: any
#    stray stdout line has its digits CONCATENATED into the count, so a read that half-worked
#    came back as a confident wrong number instead of as "unreadable".
# ---------------------------------------------------------------------------
eval "$(sed -n '/^one_clean_integer()/,/^}/p' "$DEPLOY")"

int_case() {  # label input want_output ("" = must be unreadable)
    local label="$1" input="$2" want="$3" got
    got="$(one_clean_integer "$input")" || got=""
    if [ "$got" = "$want" ]; then
        printf "  [ok ] %s\n" "$label"
        pass=$((pass+1))
    else
        printf "  [BAD] %s (wanted '%s', got '%s')\n" "$label" "$want" "$got"
        fail=$((fail+1))
    fi
}

int_case "a clean count passes through"                          "55" "55"
int_case "surrounding whitespace and newline are stripped"       $' 55\n' "55"
int_case "an empty read is unreadable, not zero"                 "" ""
int_case "banner junk sharing the pipe is unreadable, not 2555"  $'motd 2 you\n55' ""
int_case "an error line with digits is unreadable, not a count"  "Error: near line 1" ""
int_case "two result rows are unreadable, not welded into 55"    $'5\n5' ""

echo
if [ "$fail" -ne 0 ]; then
    echo "*** $fail of $((pass+fail)) deploy-gate checks FAILED — the gate is not refusing what it must ***"
    exit 1
fi
echo "All $pass deploy-gate checks passed: the gate refuses untested, unsoaked, wrong-binary, short, and submission-path-broken soaks; refuses ghost-pool on a node whose pool_sv2 cannot sign share batches, while leaving pool_sv2 and translator_sv2 free to fix it; and rolls back a deploy that stops crediting work."
