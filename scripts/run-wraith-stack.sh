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
#   • wraith-coordinator       — :9100, the Mix screen's default
#   • wraithd                  — local Unix socket, pointed at ghostd
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
WALLETS_DIR="${WRAITH_STACK_WALLETS_DIR:-/tmp/wraith-stack/wallets}"

GHOSTD_RPC_URL="${GHOSTD_RPC_URL:-http://127.0.0.1:38335}"
GHOSTD_RPC_USER="${GHOSTD_RPC_USER:-local}"
GHOSTD_RPC_PASSWORD="${GHOSTD_RPC_PASSWORD:-localtest}"

mkdir -p "$LOG_DIR" "$WALLETS_DIR"

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

start_wraithd() {
  stop_one wraithd
  echo "starting wraithd → $LOG_DIR/wraithd.log"
  WRAITHD_WALLETS_DIR="$WALLETS_DIR" \
  WRAITHD_GHOSTD_URL="$GHOSTD_RPC_URL" \
  WRAITHD_GHOSTD_USER="$GHOSTD_RPC_USER" \
  WRAITHD_GHOSTD_PASS="$GHOSTD_RPC_PASSWORD" \
  WRAITHD_WRAITH_COORDINATOR=http://127.0.0.1:9100 \
    "$ROOT/target/debug/wraithd" \
      > "$LOG_DIR/wraithd.log" 2>&1 &
  echo $! > "$LOG_DIR/wraithd.pid"
}

start_wraith_coordinator() {
  stop_one wraith-coordinator
  echo "starting wraith-coordinator → $LOG_DIR/wraith-coordinator.log"
  # Mock broadcaster: refused on mainnet by the binary, fine
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
      --mock-broadcaster \
      --ghostd-url "$GHOSTD_RPC_URL" \
      --ghostd-user "$GHOSTD_RPC_USER" \
      --ghostd-pass "$GHOSTD_RPC_PASSWORD" \
      > "$LOG_DIR/wraith-coordinator.log" 2>&1 &
  echo $! > "$LOG_DIR/wraith-coordinator.pid"
}

status() {
  for svc in wraith-coordinator wraithd; do
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
