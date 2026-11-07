#!/usr/bin/env bash
#
# Deployed to /opt/ghost/bin/wait-for-ghostd-sync.sh — the ExecStart of
# ghost-mining-gate.service. ghost-mining is disabled at boot; this gate is what
# starts it, once ghostd reports it has left initial block download. Starting
# ghost-mining against a syncing ghostd is what the gate exists to prevent.
#
# This file is the canonical copy (#759). It used to exist only on the fleet, in
# three variants that no repo file governed.
#
# Ghost Pay is retired: the gate starts nothing for it. A host that still has a
# ghost-pay unit keeps it exactly as it is — not started here, not stopped.
#
# The gate owns the stratum stack's start too (#1020). `sri-pool.service` used to carry
# `Wants=ghost-mining.service`, which made systemd start the node whenever sri-pool started —
# at boot, and on the installer's first `enable --now sri-pool`. So the node came up ahead of
# this script every time, and on a fresh install it joined the live mesh at chain height 0 and
# broadcast an MPC contribution while this script was still printing "waiting". sri-pool and
# sri-translator now order themselves after the node without pulling it in, are not enabled at
# boot, and are started here, after the node, once ghostd is synced.
#
# Change this file, then run scripts/ops/deploy-fleet-file.sh to converge the
# fleet. check-fleet-uniformity.sh fails if any node drifts from what is here.
set -u
# Overridable so scripts/test-boot-gate.sh can run this against a throwaway directory.
CONF="${GHOST_BITCOIN_CONF:-/etc/bitcoin/bitcoin.conf}"
UNIT_DIR="${GHOST_UNIT_DIR:-/etc/systemd/system}"
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
    [ -e "$UNIT_DIR/ghost-mining.service" ] || UNIT=ghost-pool
    echo "[ghost-mining-gate] ghostd synced — starting $UNIT"
    # Without the node there is nothing for the stratum stack to serve; it would only restart
    # in a loop. Fail instead, so the unit shows as failed (and is retried where it has Restart=).
    systemctl start "$UNIT" || { echo "[ghost-mining-gate] $UNIT did not start"; exit 1; }
    rc=0
    for SVC in sri-pool sri-translator; do
      [ -f "$UNIT_DIR/$SVC.service" ] || continue
      echo "[ghost-mining-gate] starting $SVC"
      if ! systemctl start "$SVC"; then
        echo "[ghost-mining-gate] $SVC did not start"
        rc=1
      fi
    done
    exit "$rc"
  fi
  sleep 30
done
