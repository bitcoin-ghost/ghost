#!/usr/bin/env bash
# Reconcile the Stratum and Wraith coordinator firewall ports to the node's config.
#
# Run by `ghost-mining-firewall.service`, triggered at boot and by
# `ghost-mining-firewall.path` whenever pool.toml changes. Idempotent.
#
# This file is inlined VERBATIM in scripts/install-node.sh, which is fetched
# standalone over curl and has no repo to read from. check-inlined-copies.sh
# compares the two byte-for-byte — edit both, or neither.
set -euo pipefail
CONF="${GHOST_POOL_CONF:-/etc/ghost/pool.toml}"
PORTS=(3333 34255)
# External miners are accepted in public_pool AND private_pool — both open the
# Stratum ports (public_pool to anyone, private_pool to password-holders). Only
# private_solo keeps them closed. mining_mode is the single source of truth: the
# legacy public_mining bool was removed and is ignored by ghost-pool, so we key
# purely off mining_mode here to stay consistent with the running node.
accept_miners="no"
if [[ -r "$CONF" ]] \
 && grep -qE '^[[:space:]]*mining_mode[[:space:]]*=[[:space:]]*"?(public_pool|private_pool)"?' "$CONF" 2>/dev/null; then
  accept_miners="yes"
fi
if [[ "$accept_miners" == "yes" ]]; then
  for p in "${PORTS[@]}"; do ufw allow "${p}/tcp" >/dev/null 2>&1 || true; done
  logger -t ghost-mining-firewall "external miners ON (public_pool/private_pool) -> Stratum 3333+34255 OPEN"
else
  for p in "${PORTS[@]}"; do ufw delete allow "${p}/tcp" >/dev/null 2>&1 || true; done
  logger -t ghost-mining-firewall "external miners OFF (private_solo) -> Stratum 3333+34255 CLOSED"
fi

# Wraith coordinator listen port (9100) follows [coordinator]
# coordinator_role_enabled, exactly as the Stratum ports follow public mining.
coord="no"
if [[ -r "$CONF" ]] \
 && grep -qE '^[[:space:]]*coordinator_role_enabled[[:space:]]*=[[:space:]]*true([[:space:]]|$)' "$CONF" 2>/dev/null; then
  coord="yes"
fi
if [[ "$coord" == "yes" ]]; then
  ufw allow 9100/tcp >/dev/null 2>&1 || true
  logger -t ghost-mining-firewall "coordinator role ON -> Wraith 9100 OPEN"
else
  ufw delete allow 9100/tcp >/dev/null 2>&1 || true
  logger -t ghost-mining-firewall "coordinator role OFF -> Wraith 9100 CLOSED"
fi
