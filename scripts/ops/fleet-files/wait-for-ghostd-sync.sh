#!/usr/bin/env bash
#
# Deployed to /opt/ghost/bin/wait-for-ghostd-sync.sh — the ExecStart of
# ghost-mining-gate.service. ghost-mining and ghost-pay are BOTH disabled at boot;
# this gate is what starts them, once ghostd reports it has left initial block
# download. Starting ghost-mining against a syncing ghostd is what the gate exists
# to prevent.
#
# This file is the canonical copy (#759). It used to exist only on the fleet, in
# three variants that no repo file governed:
#
#   * vm1-vm5  escaped-double-quote form — the signature of a payload pushed over
#              ssh with its quotes eaten locally, and NO ghost-pay block
#   * vm6-vm7  identical logic, single-quoted, still no ghost-pay block
#   * vm8      this file — the only copy that starts ghost-pay, on the one node
#              that has no ghost-pay installed
#
# The split was inert (vm1-vm4 start ghost-pay because ghost-gsp.service happens
# to carry `Wants=ghost-pay.service`), but it was inert by accident. Drop that
# Wants and ghost-pay silently stops coming back after a reboot, with nothing
# reporting it. The gate owns the start explicitly instead.
#
# Change this file, then run scripts/ops/deploy-fleet-file.sh to converge the
# fleet. check-fleet-uniformity.sh fails if any node drifts from what is here.
set -u
CONF=/etc/bitcoin/bitcoin.conf
RPCUSER=$(grep -m1 '^rpcuser=' "$CONF" | cut -d= -f2-)
RPCPW=$(grep -m1 '^rpcpassword=' "$CONF" | cut -d= -f2-)
echo "[ghost-mining-gate] waiting for ghostd to finish initial sync..."
while true; do
  RESP=$(curl -s --max-time 8 --user "$RPCUSER:$RPCPW" \
    --data '{"jsonrpc":"1.0","method":"getblockchaininfo","params":[]}' \
    http://127.0.0.1:8332/ 2>/dev/null)
  IBD=$(echo "$RESP" | grep -oE '"initialblockdownload":[[:space:]]*(true|false)' | grep -oE 'true|false')
  if [ "$IBD" = "false" ]; then
    # The node unit was `ghost-pool` until #1018, and this file reaches a node separately from
    # that rename — deploy-fleet-file.sh before it, or the unit switch before this. Start
    # whichever the node has, so neither order leaves a node that does not mine after a reboot.
    UNIT=ghost-mining
    [ -e /etc/systemd/system/ghost-mining.service ] || UNIT=ghost-pool
    echo "[ghost-mining-gate] ghostd synced — starting $UNIT"
    systemctl start "$UNIT"
    # ghost-pay (when installed) also needs a live ghostd + ghost-mining, so the
    # gate owns its first start too — mirrors ghost-mining, which is not enabled
    # at boot.
    if [ -f /etc/systemd/system/ghost-pay.service ]; then
      echo "[ghost-mining-gate] starting ghost-pay"
      systemctl start ghost-pay
    fi
    exit 0
  fi
  sleep 30
done
