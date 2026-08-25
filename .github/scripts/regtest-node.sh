#!/usr/bin/env bash
#
# Start / stop a regtest ghostd for the ghost-pool e2e targets (#770).
#
# ## Why this exists
#
# Three ghost-pool e2e files return early when no regtest node is reachable. Nothing in CI
# ever started one, so they were built, run, printed SKIP, and reported green — seven tests
# that had never executed. `GHOST_REGTEST_REQUIRED=1` makes an absent node a FAILURE rather
# than a skip, and this script is what makes that requirement satisfiable.
#
# ## Where ghostd comes from
#
# `ghostd` is not built from this workspace — it lives in the Bitcoin Core port — so it is
# taken from the published release tarball, which ships it alongside the pool binaries.
# Pinned rather than "latest": CI should not change behaviour because someone cut a release.
#
# ⚠ The `ghost-cli` in that same tarball is the POOL ADMINISTRATION cli (`ghost-cli status`,
# `miner`, `payout`, …), NOT a Core-style RPC client. It shares its name with the Core-style
# ghost-cli deployed at /opt/ghost/bin/ghost-cli on the fleet and takes entirely different
# arguments. So RPC here is driven with curl, deliberately.
set -uo pipefail

GHOSTD_VERSION="${GHOSTD_VERSION:-v1.11.28}"
PORT="${GHOST_REGTEST_PORT:-18453}"
RPCUSER="${BITCOIN_RPC_USER:-ghost}"
RPCPASS="${BITCOIN_RPC_PASSWORD:-ghostpass}"
WALLET="${GHOST_REGTEST_WALLET:-etest}"
PRIME_BLOCKS="${GHOST_REGTEST_BLOCKS:-200}"

RUNDIR="${RUNNER_TEMP:-/tmp}/ghost-regtest"
DATA="$RUNDIR/data"
BIN="$RUNDIR/ghostd"

rpc() {
    local method="$1" params="${2:-[]}" wallet="${3:-}"
    local url="http://127.0.0.1:$PORT/"
    [ -n "$wallet" ] && url="${url}wallet/${wallet}"
    curl -s --max-time 20 --user "$RPCUSER:$RPCPASS" \
        -H 'content-type: text/plain;' \
        --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"ci\",\"method\":\"$method\",\"params\":$params}" \
        "$url"
}
rpc_result() { rpc "$@" | jq -r '.result // empty'; }

start() {
    mkdir -p "$RUNDIR"
    if [ ! -x "$BIN" ]; then
        echo "fetching ghostd $GHOSTD_VERSION from the published release"
        gh release download "$GHOSTD_VERSION" \
            --pattern '*x86_64-unknown-linux-gnu.tar.gz' \
            --dir "$RUNDIR" --clobber
        tar xzf "$RUNDIR"/*x86_64-unknown-linux-gnu.tar.gz -C "$RUNDIR" ghostd
        chmod +x "$BIN"
    fi
    "$BIN" --version | head -1

    rm -rf "$DATA"; mkdir -p "$DATA"
    "$BIN" -regtest -datadir="$DATA" -rpcport="$PORT" -rpcuser="$RPCUSER" \
        -rpcpassword="$RPCPASS" -fallbackfee=0.0002 -daemon >/dev/null 2>&1

    # Poll for RPC rather than sleeping a guessed amount — a fixed sleep is how a step like
    # this becomes flaky on a slow runner.
    local ready=no
    for _ in $(seq 1 90); do
        if [ -n "$(rpc getblockcount | jq -r '.result // empty')" ]; then ready=yes; break; fi
        sleep 1
    done
    if [ "$ready" != yes ]; then
        echo "FAIL: ghostd never answered RPC on :$PORT" >&2
        tail -20 "$DATA/regtest/debug.log" 2>/dev/null >&2
        return 1
    fi

    # Coinbase maturity is 100, so a chain shorter than ~101 has nothing spendable and the
    # wallet-driven tests fail for a reason unrelated to what they test.
    #
    # ⚠ Prime with the SAME wallet the tests use. `empty_template_e2e` resolves wallet RPCs on
    # the BASE url, which only works while exactly ONE wallet is loaded. Priming with a second
    # wallet makes that call ambiguous and the test fails with nothing to do with templates —
    # measured, not guessed.
    rpc createwallet "[\"$WALLET\"]" >/dev/null 2>&1
    rpc loadwallet   "[\"$WALLET\"]" >/dev/null 2>&1
    local addr
    addr=$(rpc_result getnewaddress '[]' "$WALLET")
    if [ -z "$addr" ]; then
        echo "FAIL: could not get an address from wallet $WALLET" >&2
        return 1
    fi
    rpc generatetoaddress "[$PRIME_BLOCKS, \"$addr\"]" "$WALLET" >/dev/null 2>&1

    local height balance
    height=$(rpc_result getblockcount)
    balance=$(rpc_result getbalance '[]' "$WALLET")
    echo "regtest ready on :$PORT — height $height, spendable $balance"
    [ "${height:-0}" -ge "$PRIME_BLOCKS" ] || { echo "FAIL: chain did not prime" >&2; return 1; }
}

stop() {
    rpc stop >/dev/null 2>&1
    sleep 3
    pkill -f "$BIN" 2>/dev/null
    echo "regtest stopped"
}

case "${1:-}" in
    start) start ;;
    stop)  stop ;;
    *)     echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
