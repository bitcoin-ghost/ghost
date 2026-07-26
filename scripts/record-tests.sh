#!/usr/bin/env bash
#
# Run the gates and, only if they all pass, record that THIS commit is deployable.
#
# `deploy-node.sh` refuses to deploy a commit without this record. The record is keyed by
# the full commit sha, so amending, rebasing or "just one more tweak" invalidates it —
# which is the point. Yesterday's damage came from binaries that compiled but were never
# exercised.
#
# Usage: scripts/record-tests.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${HOME}/.ghost-deploy"
mkdir -p "$STATE_DIR"
cd "$REPO_ROOT"

# Tauri GUI crates are excluded exactly as CI excludes them: they need a sidecar binary
# that isn't built here, and their absence is not a code failure.
EXCLUDES="--exclude wraith-wallet-gui --exclude ghost-tap-desktop"

[ -z "$(git status --porcelain)" ] || { echo "REFUSED: dirty tree — the record must describe a commit" >&2; exit 1; }

echo "==> fmt"
cargo fmt --all -- --check || { echo "FAILED: formatting" >&2; exit 1; }

# Cheap and first, because a broken workflow does not fail until after merge — the
# Coverage job was red on main for six commits before anyone looked (#428).
echo "==> workflow line continuations"
./scripts/check-workflow-scalars.sh || { echo "FAILED: workflow scalars" >&2; exit 1; }

echo "==> inlined installer copies"
./scripts/check-inlined-copies.sh || { echo "FAILED: inlined copies drifted" >&2; exit 1; }

# NB: do NOT write these as `cmd | grep ... && { fail }`. With `set -o pipefail` a failing
# cargo makes the whole pipeline non-zero, the `&&` short-circuits, the failure branch never
# runs — and the gate reports success while not gating. That exact bug let a commit with two
# clippy errors be recorded as tested. Capture output and exit code explicitly instead.
run_gate() {
    local name="$1"; shift
    echo "==> $name"
    local out status
    out="$("$@" 2>&1)" && status=0 || status=$?
    if [ "$status" -ne 0 ] || grep -qE "^error" <<<"$out"; then
        echo "$out" | grep -E "^error" -A 6 | head -40 >&2
        echo "FAILED: $name" >&2
        exit 1
    fi
    echo "$out"
}

run_gate clippy cargo clippy --workspace $EXCLUDES --all-targets >/dev/null
run_gate "check (all targets, all features)" \
    cargo check --workspace $EXCLUDES --all-targets --all-features >/dev/null

echo "==> tests"
test_out="$(cargo test --workspace $EXCLUDES --lib --bins 2>&1)" || {
    echo "$test_out" | grep -E "FAILED|^error" | head -20 >&2
    echo "FAILED: tests" >&2; exit 1; }
grep -E "^test result" <<<"$test_out" | tail -5
grep -qE "FAILED" <<<"$test_out" && { echo "FAILED: test failures" >&2; exit 1; }

SHA="$(git rev-parse HEAD)"
date +%s > "${STATE_DIR}/tested-${SHA}"
echo "OK: recorded $(git rev-parse --short HEAD) as tested — deploy-node.sh will now accept it"
