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
# 5. Canary deploys must NOT require a soak — that is the point of a canary.
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

echo
if [ "$fail" -ne 0 ]; then
    echo "*** $fail of $((pass+fail)) deploy-gate checks FAILED — the gate is not refusing what it must ***"
    exit 1
fi
echo "All $pass deploy-gate checks passed: the gate refuses untested, unsoaked, wrong-binary and short soaks."
