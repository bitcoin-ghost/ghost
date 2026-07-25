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

echo "==> clippy"
cargo clippy --workspace $EXCLUDES --all-targets 2>&1 | grep -E "^error" && {
    echo "FAILED: clippy errors" >&2; exit 1; }

echo "==> check (all targets, all features)"
cargo check --workspace $EXCLUDES --all-targets --all-features 2>&1 | grep -E "^error" && {
    echo "FAILED: check errors" >&2; exit 1; }

echo "==> tests"
cargo test --workspace $EXCLUDES --lib --bins 2>&1 | tee /tmp/ghost-test-out.txt | grep -E "^test result" | tail -5
grep -qE "FAILED" /tmp/ghost-test-out.txt && { echo "FAILED: test failures" >&2; exit 1; }

SHA="$(git rev-parse HEAD)"
date +%s > "${STATE_DIR}/tested-${SHA}"
echo "OK: recorded $(git rev-parse --short HEAD) as tested — deploy-node.sh will now accept it"
