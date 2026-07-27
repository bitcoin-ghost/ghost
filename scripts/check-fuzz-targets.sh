#!/usr/bin/env bash
#
# Build every fuzz target.
#
# Fuzz targets depend on internal APIs, so they rot the moment a signature changes — and
# nothing built them. `fuzz_stratum_username` had been importing a module that no longer
# existed for some time, and it went unnoticed because no job compiled it (#468). You would
# have discovered it on the day you actually wanted to fuzz something, which is the day you
# are already worried about a bug.
#
# BUILD ONLY. Running the fuzzers belongs in a scheduled job, not on every PR. This also uses
# plain `cargo check` rather than `cargo fuzz`, so it needs no nightly toolchain and no
# sanitiser runtime — it catches API rot, which is the failure that actually happened.
#
# Also asserts every target FILE is registered as a [[bin]]. A file nothing references is a
# target nobody builds, which is the same failure wearing different clothes.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ -d fuzz ] || { echo "check-fuzz-targets: no fuzz/ directory"; exit 0; }

# NOTE the character class: [a-z0-9_], not [a-z_]. Target names contain digits
# (fuzz_l2_requests, fuzz_p2p_payloads) and a letters-only class silently skips them —
# the same bug that once made the stratum-config check report more keys than it compared.
mapfile -t registered < <(grep -oE 'name = "fuzz_[a-z0-9_]+"' fuzz/Cargo.toml \
    | sed -E 's/.*"(.*)"/\1/' | sort -u)
mapfile -t files < <(find fuzz/fuzz_targets -name '*.rs' -exec basename {} .rs \; | sort -u)

orphans=$(comm -23 <(printf '%s\n' "${files[@]}") <(printf '%s\n' "${registered[@]}"))
if [ -n "$orphans" ]; then
    echo "check-fuzz-targets: target files with no [[bin]] entry — nothing builds these:" >&2
    printf '  %s\n' $orphans >&2
    exit 1
fi

echo "check-fuzz-targets: ${#files[@]} targets, ${#registered[@]} registered — building"
# `--locked` because `fuzz/` is a SEPARATE cargo workspace with its own lockfile, and
# `cargo update --workspace` at the repo root does not reach it. Without this flag a version
# bump leaves fuzz/Cargo.lock stale, this build silently rewrites it, and the rewrite dirties
# the tree — which then trips `deploy-node.sh`'s clean-tree check AFTER the gate has already
# reported success. That is a confusing way to discover a stale lockfile; failing here names it.
if ! ( cd fuzz && cargo check --bins --quiet --locked ); then
    echo "check-fuzz-targets: a fuzz target no longer builds, or fuzz/Cargo.lock is stale" >&2
    echo "  if the workspace version changed, run: ( cd fuzz && cargo update --workspace )" >&2
    exit 1
fi
echo "check-fuzz-targets: all ${#files[@]} fuzz targets build"
