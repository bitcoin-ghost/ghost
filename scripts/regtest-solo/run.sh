#!/usr/bin/env bash
# Ghost Pool solo end-to-end harness, regtest (harness.py has the scenario list). Native processes
# in one temp dir, no Docker: two peered nodes, each ghostd -> ghost-mining -> pool_sv2 [solo]
# (submit_rpc = the other node) -> translator_sv2 (SV1 3333, 4444), and miners on 3333, 4444 and
# SV2 34255.
#
#   scripts/regtest-solo/run.sh --fetch-ghostd [TAG]  # download + verify a released ghostd
#   scripts/regtest-solo/run.sh --build              # debug-build what it needs, then run
#   scripts/regtest-solo/run.sh [harness options]    # run on existing debug builds
#   scripts/regtest-solo/run.sh --help               # every option
#
# The Bitcoin node is ghostd: GHOSTD= or --bitcoind, else the newest release --fetch-ghostd
# verified and cached, else `ghostd` on PATH or /opt/ghost/bin/ghostd. --build also builds the
# hostile pool_sv2 (feature solo-fault-injection, which skims the treasury) under target/hostile/,
# which the harness then checks ghost-audit refuses. CARGO_TARGET_DIR is honoured. Needs python3.
#
# Every scenario prints PASS, FAIL or UNMEASURED with its evidence. Exit status: 1 if any FAIL.
# Everything started is stopped on exit, Ctrl-C or SIGTERM, and the teardown is itself checked.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
target="${CARGO_TARGET_DIR:-$repo/target}"
cache="${XDG_CACHE_HOME:-$HOME/.cache}/ghost-regtest"
# The release signing key the installer pins (scripts/install-node.sh, GPG_KEY_FP).
release_fp="777FE81F8CC077FD3D08055E852C2B3190F5B928"
release_key_url="https://get.bitcoinghost.org/ghost-release-key.asc"

# Download a released ghostd into its own directory under the cache, verified as the installer
# verifies a release: SHA256SUMS.txt signed by the pinned key, then the tarball's checksum. Only
# ghostd is kept from the tarball.
fetch_ghostd() {
  local tag="${1:-}" repo_gh="bitcoin-ghost/ghost"
  command -v gh >/dev/null || { echo "fetch-ghostd: needs the gh CLI" >&2; exit 1; }
  command -v gpg >/dev/null || { echo "fetch-ghostd: needs gpg" >&2; exit 1; }
  if [[ -z "$tag" ]]; then
    # The newest final release (v*): ghostd is built by release.yml on the v* channel.
    tag="$(gh api "repos/$repo_gh/releases?per_page=50" \
            --jq '.[] | select(.draft | not) | select(.prerelease | not) | .tag_name' \
            | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1)"
    [[ -n "$tag" ]] || { echo "fetch-ghostd: no v* release found" >&2; exit 1; }
  fi
  local dest="$cache/ghostd-$tag"
  if [[ -x "$dest/ghostd" ]]; then
    echo "$dest/ghostd"
    return
  fi
  local dl gpghome x tarball="bitcoin-ghost-${tag}-x86_64-unknown-linux-gnu.tar.gz"
  dl="$(mktemp -d)"; gpghome="$(mktemp -d)"; x="$(mktemp -d)"
  trap 'GNUPGHOME="$gpghome" gpgconf --kill gpg-agent 2>/dev/null; rm -rf "$dl" "$gpghome" "$x"' RETURN
  chmod 700 "$gpghome"
  gh release download "$tag" -R "$repo_gh" -D "$dl" -p "$tarball" -p SHA256SUMS.txt \
    -p SHA256SUMS.txt.asc >&2
  curl -fsSL --retry 3 --max-time 60 "$release_key_url" -o "$gpghome/key.asc"
  GNUPGHOME="$gpghome" gpg --quiet --import "$gpghome/key.asc" 2>/dev/null
  if ! GNUPGHOME="$gpghome" gpg --status-fd=1 --verify "$dl/SHA256SUMS.txt.asc" \
        "$dl/SHA256SUMS.txt" 2>/dev/null | grep -q "VALIDSIG $release_fp"; then
    echo "fetch-ghostd: SHA256SUMS.txt is not signed by $release_fp" >&2
    exit 1
  fi
  ( cd "$dl" && grep " ${tarball}\$" SHA256SUMS.txt | sha256sum -c - >&2 ) \
    || { echo "fetch-ghostd: checksum mismatch for $tarball" >&2; exit 1; }
  tar -xzf "$dl/$tarball" -C "$x" ghostd
  mkdir -p "$dest"
  install -m 0755 "$x/ghostd" "$dest/ghostd"
  echo "$dest/ghostd"
}

if [[ "${1:-}" == "--fetch-ghostd" ]]; then
  shift
  tag=""
  [[ $# -gt 0 && "$1" != --* ]] && { tag="$1"; shift; }
  fetch_ghostd "$tag"
  [[ $# -eq 0 ]] && exit 0
fi

if [[ "${1:-}" == "--build" ]]; then
  shift
  cd "$repo"
  # Debug builds, two jobs: the harness is meant for a small machine.
  cargo build -j 2 -p pool_sv2 --features solo-fault-injection
  mkdir -p "$target/hostile"
  cp "$target/debug/pool_sv2" "$target/hostile/pool_sv2"
  cargo build -j 2 -p ghost-mining -p pool_sv2 -p translator_sv2 -p ghost-audit \
    -p integration_tests_sv2 --bin ghost-mining --bin pool_sv2 --bin translator_sv2 \
    --bin ghost-audit --bin mining_device
fi
if [[ -x "$target/hostile/pool_sv2" ]]; then
  set -- --hostile-binary "$target/hostile/pool_sv2" "$@"
fi

exec python3 "$here/harness.py" --bin-dir "$target/debug" --ghostd-cache "$cache" "$@"
