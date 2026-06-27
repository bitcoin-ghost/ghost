#!/usr/bin/env bash
# Reconcile the Stratum firewall ports to the node's mining mode.
#
# Opens BOTH Stratum V1 (3333) and V2 (34255) when the node is a public pool;
# closes them for a private / solo node. Driven entirely by `mining_mode` in
# /etc/ghost/pool.toml, so the firewall follows the operator's public-mining
# choice however it is changed — dashboard, `ghost-setup`, or a hand edit.
#
# Run by `ghost-mining-firewall.service`, which is triggered at boot and by
# `ghost-mining-firewall.path` whenever pool.toml changes. Idempotent.
set -euo pipefail

CONF="${GHOST_POOL_CONF:-/etc/ghost/pool.toml}"
PORTS=(3333 34255)

# Public mining is ON if EITHER form is set: the production boolean
# `public_mining = true`, or the installer's `mining_mode = "public_pool"`.
# (The two provisioning paths use different keys; accept both.)
public="no"
if [[ -r "$CONF" ]]; then
  if grep -qE '^[[:space:]]*public_mining[[:space:]]*=[[:space:]]*true([[:space:]]|$)' "$CONF" 2>/dev/null \
   || grep -qE '^[[:space:]]*mining_mode[[:space:]]*=[[:space:]]*"?public_pool"?' "$CONF" 2>/dev/null; then
    public="yes"
  fi
fi

if [[ "$public" == "yes" ]]; then
  for p in "${PORTS[@]}"; do
    ufw allow "${p}/tcp" >/dev/null 2>&1 || true
  done
  logger -t ghost-mining-firewall "public mining ON -> Stratum 3333+34255 OPEN"
else
  # Private/solo (or unset/unreadable): don't expose stratum to the network.
  for p in "${PORTS[@]}"; do
    ufw delete allow "${p}/tcp" >/dev/null 2>&1 || true
  done
  logger -t ghost-mining-firewall "public mining OFF -> Stratum 3333+34255 CLOSED"
fi
