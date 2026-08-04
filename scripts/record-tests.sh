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

echo "==> stratum config agreement"
./scripts/check-stratum-config-agreement.sh || { echo "FAILED: stratum config sources disagree" >&2; exit 1; }

# The pre-deploy SV1 smoke test asserts a declared difficulty reaches the miner. Its first
# form could not tell "delivered late" from "never delivered" — both printed the floor — which
# is what misdirected the #455 investigation. This checks the check.
# The deploy gate's only value is that it refuses. Drive it against deliberately-bad state.
echo "==> deploy-gate self-test"
./scripts/test-deploy-gate.sh \
    || { echo "FAILED: deploy-gate self-test" >&2; exit 1; }

echo "==> fuzz targets build"
./scripts/check-fuzz-targets.sh \
    || { echo "FAILED: fuzz targets" >&2; exit 1; }

# Documentation, with the SAME flags CI uses.
#
# CI runs `cargo doc --no-deps --all-features` under `RUSTDOCFLAGS: -D warnings` in a job that only
# ever runs on main — so a broken intra-doc link cannot fail a pull request and is invisible until
# after the push. Main sat red for three consecutive pushes on 2026-08-03 for exactly this: five
# rustdoc errors, none of which any local gate looked at (#609).
#
# Cheap to run here and it closes the gap between "record-tests is green" and "main will be green".
# COMPILE the 18 sv2 integration targets, without running them.
#
# CI now does this too, and locally is where it matters: `tests/integration` stopped compiling when
# f1c14cdb9 added a field to `ShareConvergenceResponse` and nobody noticed for weeks, because nothing
# built it. Four `PoolConfig` initializers went the same way during the ghost-registry deletion.
#
# They cannot be RUN here — 191 call sites spin up real SRI pool/template-provider processes — but
# compiling them is ~3 minutes and catches that whole class of rot. Running them properly is #580.
echo "==> sv2 integration targets compile (no run)"
cargo test -p integration_tests_sv2 --no-run --quiet \
    || { echo "FAILED: sv2 integration targets do not compile" >&2; exit 1; }

echo "==> documentation (-D warnings, as CI runs it)"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace $EXCLUDES --all-features --quiet \
    || { echo "FAILED: documentation — a rustdoc error here turns main red after the push" >&2; exit 1; }

echo "==> SV1 smoke self-test"
python3 bins/translator-sv2/tests/sv1_handshake_smoke_selftest.py \
    || { echo "FAILED: SV1 smoke self-test" >&2; exit 1; }

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
