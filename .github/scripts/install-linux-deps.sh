#!/usr/bin/env bash
#
# Install the workspace's system build dependencies, with the Ubuntu mirrors kept OFF the
# critical path.
#
# Why this exists
# ---------------
# On 2026-08-19 CI on main stopped completing. Six jobs sat 42-45 minutes on
# `apt-get update && apt-get install`, `cargo` never ran, and because a job that exceeds
# `timeout-minutes` is reported by Actions as `cancelled` rather than `failure`, main looked
# manually stopped rather than broken.
#
# The cause is not one phase of apt — it is that the Ubuntu mirrors are intermittently
# unusable from the hosted runners. Both phases were seen failing:
#
#     apt-get update    stalled 44 min mid-fetch of `noble-security InRelease`
#     apt-get install   Fetched 3747 kB in 3min 54s   (16.0 kB/s)
#
# The only package actually downloaded is the Cap'n Proto trio, needed by
# `crates/bitcoin-core-sv2`'s build script. `libsqlite3-dev` is already on the runner image
# ("already the newest version"), so it costs nothing but is kept for the case where a future
# image drops it.
#
# So: cache the .deb files. On a cache hit nothing is downloaded at all and install is a local
# `dpkg` — the mirrors cannot stall what we never ask them for. On a miss we fall back to a
# BOUNDED apt (`Acquire::*::Timeout` per fetch, `Retries` for a transient failure), and seed the
# cache for next time.
#
# The caller sets `timeout-minutes` as the final backstop.

set -euo pipefail

DEB_CACHE=/tmp/apt-debs
PKGS=${LINUX_DEPS:-"libsqlite3-dev capnproto libcapnp-dev"}

# Runtime libraries for the released `ghostd`, which the Integration tests job runs as a regtest
# node (#770). That binary is dynamically linked, and the hosted image does not carry libevent:
#
#     ghostd: error while loading shared libraries: libevent_extra-2.1.so.7
#
# Appended unconditionally rather than folded into LINUX_DEPS, and that is deliberate:
#
# ⚠ The cache key is `hashFiles('.github/scripts/install-linux-deps.sh')` — THIS file — but
# LINUX_DEPS is set in the workflow env. Adding packages there would NOT rotate the key, so the
# job would restore a cache of the old .debs and install exactly what it had before, while
# looking like it had been given more. Package changes have to land here to be picked up.
#
# The `-dev` names are chosen over the runtime ones on purpose: Ubuntu 24.04 renamed the runtime
# packages for the 64-bit time_t transition (`libevent-2.1-7` -> `libevent-2.1-7t64`), while the
# dev package names are stable across releases and pull the right runtime libs as dependencies.
PKGS="$PKGS libevent-dev libzmq3-dev"

# `dpkg -i` on a partial set can leave unmet dependencies; `apt-get -f install` repairs it.
# That repair CAN touch the network, so it is a fallback and never the happy path.
install_from_cache() {
  sudo dpkg -i "$DEB_CACHE"/*.deb || sudo apt-get -f install -y
}

if compgen -G "$DEB_CACHE/*.deb" > /dev/null 2>&1; then
  echo "apt cache HIT — installing $(find "$DEB_CACHE" -name "*.deb" | wc -l) cached .deb(s), no download"
  install_from_cache
  exit 0
fi

echo "apt cache MISS — fetching from the mirrors (bounded), then seeding the cache"
sudo apt-get -o Acquire::Retries=3 \
             -o Acquire::http::Timeout=20 \
             -o Acquire::https::Timeout=20 \
             update

# Download without installing so the .debs land in apt's archive directory, where we can copy
# them out to be cached. Packages already present on the image simply download nothing.
# shellcheck disable=SC2086  # word splitting is intended: $PKGS is a package LIST
sudo apt-get install -y --download-only $PKGS

mkdir -p "$DEB_CACHE"
# `|| true`: if every package was already installed there are no .debs to copy, which is a
# legitimate outcome and must not fail the step.
sudo cp /var/cache/apt/archives/*.deb "$DEB_CACHE"/ 2>/dev/null || true
sudo chown -R "$(id -u):$(id -g)" "$DEB_CACHE" 2>/dev/null || true

if compgen -G "$DEB_CACHE/*.deb" > /dev/null 2>&1; then
  install_from_cache
else
  echo "nothing to install from cache — packages already present on the image"
  # shellcheck disable=SC2086  # word splitting is intended here too
  sudo apt-get install -y $PKGS
fi
