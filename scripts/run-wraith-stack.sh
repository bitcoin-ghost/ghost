#!/usr/bin/env bash
# run-wraith-stack.sh — bring up the local Wraith Wallet dev stack.
#
# Starts (or reuses, if already running):
#   • ghostd (signet)          — assumed running on 127.0.0.1:38335
#                                with rpcuser=local rpcpassword=localtest.
#                                Override via $GHOSTD_RPC_URL +
#                                $GHOSTD_RPC_USER + $GHOSTD_RPC_PASSWORD.
#                                bitcoind is RPC-compatible and works
#                                interchangeably here.
#   • ghost-pay                — :8800, REST API
#   • ghost-gsp                — :8900, REST + WS (--insecure-http for dev)
#   • wraithd                  — local Unix socket
#
# Logs land in /tmp/wraith-stack/<service>.log.
# Run again to restart: idempotent — kills the previous instance first.
#
# Usage:
#   bash scripts/run-wraith-stack.sh up
#   bash scripts/run-wraith-stack.sh down
#   bash scripts/run-wraith-stack.sh status

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."  && pwd)"
LOG_DIR="${WRAITH_STACK_LOG_DIR:-/tmp/wraith-stack}"
GHOST_PAY_DATA="${WRAITH_STACK_GHOST_PAY_DIR:-/tmp/wraith-stack/ghost-pay}"
GSP_DATA="${WRAITH_STACK_GSP_DIR:-/tmp/wraith-stack/gsp}"
WALLETS_DIR="${WRAITH_STACK_WALLETS_DIR:-/tmp/wraith-stack/wallets}"

GHOSTD_RPC_URL="${GHOSTD_RPC_URL:-http://127.0.0.1:38335}"
GHOSTD_RPC_USER="${GHOSTD_RPC_USER:-local}"
GHOSTD_RPC_PASSWORD="${GHOSTD_RPC_PASSWORD:-localtest}"

mkdir -p "$LOG_DIR" "$GHOST_PAY_DATA" "$GSP_DATA" "$WALLETS_DIR"

# Shared X-Internal-Auth secret. ghost-pay accepts it as the
# authenticated-route bypass; ghost-gsp uses it when proxying to
# ghost-pay; wraithd uses it for the L1 UTXO scanner endpoint.
# Persist across `up` invocations in the same stack so restarts
# don't break already-authenticated connections.
SECRET_FILE="$LOG_DIR/internal-secret"
if [[ ! -f "$SECRET_FILE" ]]; then
    openssl rand -base64 32 > "$SECRET_FILE"
fi
INTERNAL_SECRET="$(cat "$SECRET_FILE")"
export INTERNAL_SECRET

action="${1:-up}"

probe_ghostd() {
  curl -s --user "$GHOSTD_RPC_USER:$GHOSTD_RPC_PASSWORD" \
    -H 'content-type: text/plain' \
    --data '{"jsonrpc":"1.0","id":"x","method":"getblockchaininfo","params":[]}' \
    "$GHOSTD_RPC_URL/" | head -c 80
}

stop_one() {
  local name="$1"
  local pidfile="$LOG_DIR/$name.pid"
  if [[ -f "$pidfile" ]]; then
    local pid
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      sleep 0.5
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  fi
  # Also clean up by binary name (covers stale processes outside our pidfile).
  pkill -x "$name" 2>/dev/null || true
}

start_ghost_pay() {
  stop_one ghost-pay
  echo "starting ghost-pay → $LOG_DIR/ghost-pay.log"
  # ghost-pay reads BITCOIN_RPC_{USER,PASSWORD} from env (upstream
  # Bitcoin Core convention — ghostd is RPC-compatible).
  # GHOST_PAY_INTERNAL_SECRET is the X-Internal-Auth bypass secret
  # shared with ghost-gsp and wraithd.
  BITCOIN_RPC_USER="$GHOSTD_RPC_USER" \
  BITCOIN_RPC_PASSWORD="$GHOSTD_RPC_PASSWORD" \
  GHOST_PAY_API_SECRET="$(openssl rand -base64 32)" \
  GHOST_PAY_INTERNAL_SECRET="$INTERNAL_SECRET" \
    "$ROOT/target/debug/ghost-pay" \
      --bitcoin-rpc "$GHOSTD_RPC_URL" \
      --network signet \
      --api-listen 127.0.0.1:8800 \
      --data-dir "$GHOST_PAY_DATA" \
      > "$LOG_DIR/ghost-pay.log" 2>&1 &
  echo $! > "$LOG_DIR/ghost-pay.pid"
}

start_ghost_gsp() {
  stop_one ghost-gsp
  echo "starting ghost-gsp → $LOG_DIR/ghost-gsp.log"
  GHOST_PAY_INTERNAL_SECRET="$INTERNAL_SECRET" \
    "$ROOT/target/debug/ghost-gsp" \
      --network signet \
      --listen 127.0.0.1:8900 \
      --pay-node-url http://127.0.0.1:8800 \
      --data-dir "$GSP_DATA" \
      --insecure-http \
      > "$LOG_DIR/ghost-gsp.log" 2>&1 &
  echo $! > "$LOG_DIR/ghost-gsp.pid"
}

start_wraithd() {
  stop_one wraithd
  echo "starting wraithd → $LOG_DIR/wraithd.log"
  WRAITHD_WALLETS_DIR="$WALLETS_DIR" \
  WRAITHD_GSP=ws://127.0.0.1:8900/ws/v1 \
  WRAITHD_GHOST_PAY=http://127.0.0.1:8800 \
  WRAITHD_GHOST_PAY_INTERNAL_AUTH="$INTERNAL_SECRET" \
  WRAITHD_WRAITH_COORDINATOR=http://127.0.0.1:9100 \
    "$ROOT/target/debug/wraithd" \
      > "$LOG_DIR/wraithd.log" 2>&1 &
  echo $! > "$LOG_DIR/wraithd.pid"
}

start_wraith_coordinator() {
  stop_one wraith-coordinator
  echo "starting wraith-coordinator → $LOG_DIR/wraith-coordinator.log"
  # Mock bond + broadcaster: refused on mainnet by the binary, fine
  # on signet/regtest. The coordinator binds 127.0.0.1:9100, which
  # matches the Mix screen's DEFAULT_COORDINATOR. Without this in
  # the stack the GUI Mix flow returns connection refused.
  #
  # --ghostd-url alongside --mock-broadcaster is deliberate: /inputs
  # verifies every input UTXO against the node (#699) and refuses
  # submissions without it, while practice rounds still stay off the
  # network.
  "$ROOT/target/debug/wraith-coordinator" \
      --listen 127.0.0.1:9100 \
      --network signet \
      --mock-bond-ledger \
      --mock-broadcaster \
      --ghostd-url "$GHOSTD_RPC_URL" \
      --ghostd-user "$GHOSTD_RPC_USER" \
      --ghostd-pass "$GHOSTD_RPC_PASSWORD" \
      > "$LOG_DIR/wraith-coordinator.log" 2>&1 &
  echo $! > "$LOG_DIR/wraith-coordinator.pid"
}

status() {
  for svc in ghost-pay ghost-gsp wraith-coordinator wraithd; do
    pidfile="$LOG_DIR/$svc.pid"
    if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
      echo "  ok    $svc (pid $(cat "$pidfile"))"
    else
      echo "  off   $svc"
    fi
  done
}

case "$action" in
  up)
    if ! probe_ghostd > /dev/null 2>&1; then
      echo "ERROR: ghostd not reachable at $GHOSTD_RPC_URL"
      echo "       expected creds $GHOSTD_RPC_USER:$GHOSTD_RPC_PASSWORD"
      echo "       set GHOSTD_RPC_URL / _USER / _PASSWORD env if elsewhere."
      exit 1
    fi
    start_ghost_pay
    sleep 2
    start_ghost_gsp
    sleep 2
    start_wraith_coordinator
    sleep 1
    start_wraithd
    sleep 1
    echo
    echo "stack up:"
    status
    echo
    echo "  $ ./target/debug/wraith doctor"
    ;;
  down)
    stop_one wraithd
    stop_one wraith-coordinator
    stop_one ghost-gsp
    stop_one ghost-pay
    echo "stack down"
    ;;
  status)
    status
    ;;
  *)
    echo "usage: $0 {up|down|status}"
    exit 2
    ;;
esac
