#!/usr/bin/env bash
# Reconcile the Stratum firewall ports to the node's config.
#
# Run by `ghost-mining-firewall.service`, triggered at boot and by
# `ghost-mining-firewall.path` whenever pool.toml changes. Idempotent.
#
# This file is inlined VERBATIM in scripts/install-node.sh, which is fetched
# standalone over curl and has no repo to read from. check-inlined-copies.sh
# compares the two byte-for-byte — edit both, or neither.
set -euo pipefail
PORTS=(3333 34255)
# Every node is a public Ghost Pool node, so external miners are always accepted.
# There is no mining mode left to key off: an older pool.toml that still carries a
# `mining_mode` line is ignored by ghost-mining, and is ignored here too.
for p in "${PORTS[@]}"; do ufw allow "${p}/tcp" >/dev/null 2>&1 || true; done
logger -t ghost-mining-firewall "external miners ON -> Stratum 3333+34255 OPEN"

# Farm/rental tier (#410) listens on 4444 on every node.
#
# It must track `install-node.sh`, which always emits the [farm_tier] block. If these two ever
# disagree the node either advertises a port nothing listens on, or listens on a port nothing
# can reach — the second is what the config comment warns about.
ufw allow 4444/tcp >/dev/null 2>&1 || true
logger -t ghost-mining-firewall "farm tier ON -> Stratum 4444 OPEN"

# 9100 was the Wraith coordinator port. Nothing listens on it any more, so a rule
# left open by an older install is closed.
ufw delete allow 9100/tcp >/dev/null 2>&1 || true
