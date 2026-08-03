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
# 8. The post-deploy throughput verdict.
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

verdict_case() {  # label baseline post want_regressed
    local label="$1" baseline="$2" post="$3" want="$4" got=no
    throughput_regressed "$baseline" "$post" && got=yes
    if [ "$got" = "$want" ]; then
        printf "  [ok ] %s\n" "$label"
        pass=$((pass+1))
    else
        printf "  [BAD] %s (wanted regressed=%s, got %s)\n" "$label" "$want" "$got"
        fail=$((fail+1))
    fi
}

# The outage itself: traffic before, silence after. Nothing else in the deploy path sees this.
verdict_case "traffic before the swap and none after -> ROLL BACK" 52 0 yes
verdict_case "traffic before and after -> proceed"                 52 47 no
# A single share is enough to prove the path is credited; this must not gate on a rate.
verdict_case "one share after a busy baseline -> proceed"          52 1 no
# A canary with no miners must not be able to PASS this either — silence there is "not measured".
verdict_case "no baseline, no post -> not measurable, proceed"      0 0 no
verdict_case "no baseline but shares appear -> proceed"             0 9 no
# The count comes off a remote sqlite3 through ssh; an empty or failed read must not read as an
# outage and trigger a spurious rollback of a healthy binary.
verdict_case "unreadable baseline -> not measurable, proceed"      "" "" no
verdict_case "unreadable post with a real baseline -> proceed"     52 "" no

echo
if [ "$fail" -ne 0 ]; then
    echo "*** $fail of $((pass+fail)) deploy-gate checks FAILED — the gate is not refusing what it must ***"
    exit 1
fi
echo "All $pass deploy-gate checks passed: the gate refuses untested, unsoaked, wrong-binary, short, and submission-path-broken soaks, and rolls back a deploy that stops crediting work."
