#!/usr/bin/env bash
#
# Fetch the SV2 integration harness's two external tarballs BEFORE the tests run.
#
# ## Why this exists
#
# `template_provider.rs` downloads Bitcoin Core and sv2-tp lazily, on first use, from
# bitcoincore.org and github.com. Neither was cached, so every CI run fetched both — and because
# the fetch happens inside the first test target, its latency is charged against that target's
# `timeout 420`.
#
# `pool_solo_mining` is first in the list and is also the heaviest target (~192 s measured on
# green runs), so it had the least headroom and paid for both downloads. Measured 2026-09-26:
#
#     green run 36233410868   Core download 11 s      target finished in 192 s
#     red   run 36234833097   Core download >418 s    "pool_solo_mining failed or exceeded 420s"
#
# A 38x swing on an uncached external fetch, inside a fixed budget, reported under the name of a
# test that never got to run. Four earlier reds were dismissed as SV2 flakes on that message.
#
# So: fetch both here, where a slow mirror costs the step's own timeout and says so, and cache
# them across runs. The harness already supports this — `BITCOIN_CORE_TARBALL_FILE` and
# `SV2TP_TARBALL_FILE` make it read from disk instead of the network. Nothing in CI ever set them.
#
# ## Versions are DERIVED, never written here
#
# Both versions are read out of `template_provider.rs`. A copy in this file would be a second
# place to update, and the failure mode of getting it wrong is silent: the tarball on disk would
# not be the one the tests want, so `bitcoin_node_bin.exists()` stays false, the tarball we handed
# over unpacks to the wrong directory, and the test fails on a missing binary rather than on a
# version mismatch. Deriving them means the cache key rotates with the source on its own.
#
# Writes `BITCOIN_CORE_TARBALL_FILE` and `SV2TP_TARBALL_FILE` to $GITHUB_ENV when running under
# Actions, and prints them otherwise so it can be run by hand.
#
# Exit 0 = both tarballs present, 1 = a fetch failed, 2 = the versions could not be read (so this
# cannot know what to fetch and must not leave CI believing it succeeded).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

SRC="tests/integration-sv2/lib/template_provider.rs"
CACHE_DIR="${SV2_TARBALL_CACHE:-/tmp/sv2-tarballs}"

read_version() {
    local name="$1" v
    v="$(sed -nE "s/^const ${name}: &str = \"([^\"]+)\";.*/\1/p" "$SRC" | head -1)"
    if [ -z "$v" ]; then
        echo "prefetch-sv2-tp-tarballs: INCONCLUSIVE — could not read ${name} from $SRC." >&2
        echo "  It was renamed, moved, or reformatted. Guessing a version here would fetch a" >&2
        echo "  tarball the tests do not want, which fails later as a missing binary." >&2
        exit 2
    fi
    printf '%s' "$v"
}

CORE_VERSION="$(read_version VERSION_BITCOIN_CORE)"
SV2TP_VERSION="$(read_version VERSION_SV2_TP)"

# Only the linux/x86_64 runner names are needed; this script runs on ubuntu-latest. The harness
# picks its own filename per platform, so a macOS runner would simply fall back to downloading.
CORE_FILE="bitcoin-${CORE_VERSION}-x86_64-linux-gnu.tar.gz"
SV2TP_FILE="sv2-tp-${SV2TP_VERSION}-x86_64-linux-gnu.tar.gz"

CORE_URL="${BITCOIN_CORE_DOWNLOAD_ENDPOINT:-https://bitcoincore.org/bin/bitcoin-core-${CORE_VERSION}}/${CORE_FILE}"
SV2TP_URL="${SV2TP_DOWNLOAD_ENDPOINT:-https://github.com/stratum-mining/sv2-tp/releases/download}/v${SV2TP_VERSION}/${SV2TP_FILE}"

mkdir -p "$CACHE_DIR"

fetch() {
    local url="$1" dest="$2"
    # A cache hit is the normal path. Size-check it: actions/cache restoring a truncated entry
    # would otherwise be handed to the tests as a valid tarball, and `tarball::unpack` panics on
    # it with nothing pointing back here.
    if [ -s "$dest" ] && [ "$(stat -c %s "$dest")" -gt 1000000 ]; then
        echo "  cached: $(basename "$dest") ($(stat -c %s "$dest") bytes)"
        return 0
    fi
    [ -e "$dest" ] && { echo "  discarding short/empty $(basename "$dest")"; rm -f "$dest"; }

    echo "  fetching: $url"
    # --max-time bounds the whole transfer, --speed-time/--speed-limit abandon a stalled mirror
    # rather than crawling to --max-time. Download to a temporary name and move on success, so an
    # interrupted fetch cannot leave a partial file that the size check above waves through.
    if ! curl --fail --silent --show-error --location \
              --retry 3 --retry-delay 5 --retry-all-errors \
              --connect-timeout 20 --max-time 300 \
              --speed-time 30 --speed-limit 10240 \
              -o "$dest.part" "$url"; then
        echo "prefetch-sv2-tp-tarballs: failed to fetch $url" >&2
        rm -f "$dest.part"
        return 1
    fi
    mv "$dest.part" "$dest"
    echo "  fetched: $(basename "$dest") ($(stat -c %s "$dest") bytes)"
}

echo "prefetch-sv2-tp-tarballs: Bitcoin Core $CORE_VERSION, sv2-tp $SV2TP_VERSION"
fetch "$CORE_URL" "$CACHE_DIR/$CORE_FILE"
fetch "$SV2TP_URL" "$CACHE_DIR/$SV2TP_FILE"

if [ -n "${GITHUB_ENV:-}" ]; then
    echo "BITCOIN_CORE_TARBALL_FILE=$CACHE_DIR/$CORE_FILE" >> "$GITHUB_ENV"
    echo "SV2TP_TARBALL_FILE=$CACHE_DIR/$SV2TP_FILE" >> "$GITHUB_ENV"
    echo "  exported BITCOIN_CORE_TARBALL_FILE and SV2TP_TARBALL_FILE"
else
    echo "  BITCOIN_CORE_TARBALL_FILE=$CACHE_DIR/$CORE_FILE"
    echo "  SV2TP_TARBALL_FILE=$CACHE_DIR/$SV2TP_FILE"
fi
