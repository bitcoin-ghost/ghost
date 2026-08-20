#!/usr/bin/env bash
# Regtest end-to-end demo of a Wraith Lite CoinJoin.
#
# Boots ghostd + ghost-pay + ghost-gsp + wraith-coordinator +
# wraithd, funds 5 BIP86 UTXOs on the same wallet, runs 5
# parallel `wraith mix run` calls each enrolling a different
# ghost_id, and asserts the assembled CoinJoin tx hits the chain
# with 5 inputs and 5 denom-sized outputs.
#
# This is the contract test for the headline privacy feature —
# without it the Mix screen and the wraith stack are unverified
# end-to-end against a real bitcoind.
#
# Architectural note: 5 ghost_ids on one wraithd is the same
# mechanic the wraith_e2e.rs in-process integration test uses.
# Each enrolls separately, contributes its own UTXO, and signs
# its own input — the coordinator can't tell they share a wallet.
# In production the 5 participants would be 5 different users,
# but for a single-machine regtest demo this is the cleanest
# shape.
#
# Prerequisites:
#   - ghostd + ghost-cli on PATH (Ghost Core, Bitcoin Core v30
#     fork). bitcoind/bitcoin-cli also work.
#   - jq on PATH
#   - this repo built (`cargo build --workspace`)
#
# Usage:
#   ./scripts/regtest-wraith-mix-demo.sh

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/target/debug"
DATADIR="$(mktemp -d -t ghost-regtest-mix-demo.XXXXXX)"
SAVED_LOGS_DIR="${SAVED_LOGS_DIR:-/tmp/wraith-mix-demo-logs}"
mkdir -p "$SAVED_LOGS_DIR"

GHOST_PAY_PID=""
GSP_PID=""
COORD_PID=""
WRAITHD_PID=""
GHOSTD_DIR=""
GHOSTD_PORT=18443
N=5

cleanup() {
    set +e
    [ -n "$WRAITHD_PID" ] && kill "$WRAITHD_PID" 2>/dev/null
    [ -n "$COORD_PID" ] && kill "$COORD_PID" 2>/dev/null
    [ -n "$GSP_PID" ] && kill "$GSP_PID" 2>/dev/null
    [ -n "$GHOST_PAY_PID" ] && kill "$GHOST_PAY_PID" 2>/dev/null
    if [ -n "$GHOSTD_DIR" ]; then
        $GHOST_CLI -regtest -datadir="$GHOSTD_DIR" \
            -rpcuser=demo -rpcpassword=demo stop 2>/dev/null || true
    fi
    sleep 1
    cp "$DATADIR/"*.log "$SAVED_LOGS_DIR/" 2>/dev/null || true
    cp "$DATADIR/"mix-*.out "$SAVED_LOGS_DIR/" 2>/dev/null || true
    rm -rf "$DATADIR"
    echo "(logs preserved at $SAVED_LOGS_DIR)"
}
trap cleanup EXIT

GHOSTD="${GHOSTD:-$(command -v ghostd || command -v bitcoind || true)}"
GHOST_CLI="${GHOST_CLI:-$(command -v ghost-cli || command -v bitcoin-cli || true)}"
if [ -z "$GHOSTD" ]; then
    echo "ERROR: neither ghostd nor bitcoind found on PATH" >&2
    exit 1
fi
if [ -z "$GHOST_CLI" ]; then
    if command -v ghost > /dev/null 2>&1; then
        GHOST_CLI="ghost rpc"
    elif command -v bitcoin > /dev/null 2>&1; then
        GHOST_CLI="bitcoin rpc"
    else
        echo "ERROR: no RPC client found" >&2
        exit 1
    fi
fi

GHOSTD_DIR="$DATADIR/ghostd"
GHOSTD_RPC_URL="http://127.0.0.1:${GHOSTD_PORT}/"
mkdir -p "$GHOSTD_DIR"
GHOST_PAY_DIR="$DATADIR/ghost-pay"
GHOST_PAY_URL="http://127.0.0.1:8800"
GSP_URL="ws://127.0.0.1:8900/ws/v1"
COORD_URL="http://127.0.0.1:9100"
WRAITH_SOCK="$DATADIR/wraithd.sock"

step() { echo; echo "--- $* ---"; }

# ---- ghostd ---------------------------------------------------------------
step "starting ghostd regtest"
"$GHOSTD" -regtest \
    -datadir="$GHOSTD_DIR" \
    -rpcuser=demo -rpcpassword=demo \
    -rpcport=$GHOSTD_PORT \
    -port=18444 \
    -fallbackfee=0.0001 \
    -daemon \
    -txindex
sleep 2
BCLI="$GHOST_CLI -regtest -datadir=$GHOSTD_DIR -rpcuser=demo -rpcpassword=demo"
$BCLI -named createwallet wallet_name=demo descriptors=true || true
$BCLI loadwallet demo || true
DEMO_ADDR=$($BCLI -rpcwallet=demo getnewaddress)
$BCLI -rpcwallet=demo generatetoaddress 101 "$DEMO_ADDR" >/dev/null

GHOST_PAY_API_SECRET="$(openssl rand -base64 32)"
INTERNAL_SECRET="$(openssl rand -base64 32)"

# ---- ghost-pay --------------------------------------------------------------
step "starting ghost-pay"
BITCOIN_RPC_USER=demo \
BITCOIN_RPC_PASSWORD=demo \
GHOST_PAY_API_SECRET="$GHOST_PAY_API_SECRET" \
GHOST_PAY_INTERNAL_SECRET="$INTERNAL_SECRET" \
"$BIN/ghost-pay" \
    --network regtest \
    --bitcoin-rpc "$GHOSTD_RPC_URL" \
    --api-listen 127.0.0.1:8800 \
    --data-dir "$GHOST_PAY_DIR" \
    >"$DATADIR/ghost-pay.log" 2>&1 &
GHOST_PAY_PID=$!

# ---- ghost-gsp --------------------------------------------------------------
step "starting ghost-gsp"
GHOST_PAY_INTERNAL_SECRET="$INTERNAL_SECRET" \
"$BIN/ghost-gsp" \
    --network regtest \
    --pay-node-url "$GHOST_PAY_URL" \
    --listen 127.0.0.1:8900 \
    --data-dir "$DATADIR/gsp" \
    --insecure-http \
    >"$DATADIR/gsp.log" 2>&1 &
GSP_PID=$!
sleep 4

# Bootstrap operator keys.
step "bootstrapping ghost-pay operator keys"
curl -fsS -X POST -H "X-Internal-Auth: $INTERNAL_SECRET" \
    -H "Content-Type: application/json" \
    "$GHOST_PAY_URL/api/v1/keys/generate" -d '{}' >/dev/null

# ---- wraithd ----------------------------------------------------------------
# Started before the coordinator so we can derive addresses up-front
# (BIP86 + the fee-collection address). The coordinator needs the
# fee address at boot or /inputs returns 503.
step "starting wraithd"
WRAITHD_SOCKET="$WRAITH_SOCK" \
WRAITHD_NETWORK=regtest \
WRAITHD_GHOST_PAY="$GHOST_PAY_URL" \
WRAITHD_GSP="$GSP_URL" \
WRAITHD_GHOST_PAY_INTERNAL_AUTH="$INTERNAL_SECRET" \
WRAITHD_WALLETS_DIR="$DATADIR/wallets" \
"$BIN/wraithd" \
    >"$DATADIR/wraithd.log" 2>&1 &
WRAITHD_PID=$!
sleep 2
WRAITH() { WRAITHD_SOCKET="$WRAITH_SOCK" "$BIN/wraith" --no-spawn "$@"; }

# ---- wallet + addresses -----------------------------------------------------
step "creating wallet"
WRAITH wallet create mixwallet <<< 'pass1234' >/dev/null
WRAITH wallet select mixwallet

# Fee-collection address goes at a high BIP86 index so it doesn't
# collide with the participant addresses or the mix outputs.
FEE_ADDR=$(WRAITH --json light receive --index 999 \
    | jq -r '.LightReceive.address // .address')
echo "fee-collection address: $FEE_ADDR"

# Derive one funded receive address per participant (indices 0..N-1)
# and one fresh mix-output address per participant (indices 100..N-1+100).
# The mix-output addresses MUST be distinct from the input addresses
# so chain analysts can't link inputs→outputs by address reuse.
declare -a INPUT_ADDRS
declare -a MIX_OUT_ADDRS
for i in $(seq 0 $((N-1))); do
    addr=$(WRAITH --json light receive --index "$i" | jq -r '.LightReceive.address // .address')
    INPUT_ADDRS[$i]="$addr"
    mix=$(WRAITH --json light receive --index "$((100+i))" | jq -r '.LightReceive.address // .address')
    MIX_OUT_ADDRS[$i]="$mix"
    echo "participant $i: input=${INPUT_ADDRS[$i]} mix-out=${MIX_OUT_ADDRS[$i]}"
done

# ---- wraith-coordinator -----------------------------------------------------
# --ghostd-url so the assembled tx is broadcast to bitcoind for real
# (no --mock-broadcaster). Participation needs no escrow at all now:
# registration proves control of the input and a coin that disrupts a
# round goes into cooldown (#699). (demo note —
# safe on regtest, refused on mainnet by the binary).
step "starting wraith-coordinator (real broadcast, no bonds)"
# --fill-window-secs 30 collapses the 5-minute Filling window so the
# session locks ~30s after creation instead of waiting LITE_FILL_WINDOW_SECS
# (300s). 30s is the smallest value that's still robustly larger than
# the wallet's IPC + HTTP overhead per /find_or_create call across 5
# parallel-staggered mix runs (worst case ~5s with system jitter).
# Mainnet refuses this override — see the binary's CLI gate.
"$BIN/wraith-coordinator" \
    --listen 127.0.0.1:9100 \
    --network regtest \
    --fee-address "$FEE_ADDR" \
    --fill-window-secs 30 \
    --ghostd-url "$GHOSTD_RPC_URL" \
    --ghostd-user demo \
    --ghostd-pass demo \
    >"$DATADIR/coordinator.log" 2>&1 &
COORD_PID=$!
sleep 2

# ---- fund the 5 input UTXOs ------------------------------------------------
# Each participant needs EXACTLY the seat price: denom (100,000) + their
# mining-fee share + their service-fee share. Rounds have no change output
# (#698), so an over-funded UTXO is refused — fund to the satoshi.
# The coordinator publishes the figure as `mix_seat_price_sats` in
# /api/v1/pool/discover; 101,596 is that value for the 100k tier.
SEAT_PRICE=$(curl -s "http://127.0.0.1:9100/api/v1/pool/discover" \
    | jq -r '[.tiers[] | select(.id == "100k_sats")][0].mix_seat_price_sats')
[ -n "$SEAT_PRICE" ] && [ "$SEAT_PRICE" != "null" ] \
    || { echo "coordinator did not publish mix_seat_price_sats"; exit 1; }
SEAT_PRICE_BTC=$(awk -v s="$SEAT_PRICE" 'BEGIN { printf "%.8f", s / 100000000 }')
step "funding 5 input UTXOs at exactly $SEAT_PRICE sats each"
declare -a FUND_TXIDS
for i in $(seq 0 $((N-1))); do
    txid=$($BCLI -rpcwallet=demo sendtoaddress "${INPUT_ADDRS[$i]}" "$SEAT_PRICE_BTC")
    FUND_TXIDS[$i]="$txid"
    echo "  participant $i funded: $txid"
done
$BCLI -rpcwallet=demo generatetoaddress 6 "$DEMO_ADDR" >/dev/null
echo "mined 6 confirmations"

# ---- discover the funded UTXOs via the L1 scanner ---------------------------
# Use the wallet's own scanner so we get the scriptPubKey + matching
# vout for each funded address. The coordinator scans bitcoind on
# its own — this query is just to thread the UTXO details into the
# mix run requests.
step "scanning L1 for funded UTXOs"
SCAN_JSON=$(WRAITH --json light l1-utxos --scan-max-index $((N+1)))
echo "$SCAN_JSON" | jq '.LightL1Utxos.utxos // .utxos'

declare -a UTXO_VOUTS
declare -a UTXO_SPKS
for i in $(seq 0 $((N-1))); do
    addr="${INPUT_ADDRS[$i]}"
    entry=$(echo "$SCAN_JSON" \
        | jq --arg a "$addr" '(.LightL1Utxos.utxos // .utxos) | map(select(.address == $a)) | .[0]')
    if [ -z "$entry" ] || [ "$entry" = "null" ]; then
        echo "FAIL: scanner did not see UTXO at $addr (participant $i)" >&2
        exit 1
    fi
    UTXO_VOUTS[$i]=$(echo "$entry" | jq '.vout')
    UTXO_SPKS[$i]=$(echo "$entry" | jq -r '.scriptpubkey_hex')
done

# ---- run 5 fully-parallel mix calls ----------------------------------------
# Each `wraith mix run` blocks until the round broadcasts (or
# fails). All 5 calls hit /find_or_create concurrently and
# converge on a single coordinator session — the registry's
# find_or_create_open primitive holds the lock across the
# find-and-create so simultaneous calls can't split into
# separate sessions.
step "running $N parallel mixes"
declare -a MIX_PIDS
for i in $(seq 0 $((N-1))); do
    (
        WRAITH --json mix run \
            --coordinator "$COORD_URL" \
            --tier 100k_sats \
            --ghost-id "participant_$i" \
            --utxo "${FUND_TXIDS[$i]}:${UTXO_VOUTS[$i]}" \
            --utxo-value "$SEAT_PRICE" \
            --utxo-scriptpubkey "${UTXO_SPKS[$i]}" \
            --mix-output-address "${MIX_OUT_ADDRS[$i]}" \
            --bip86-index "$i" \
            > "$DATADIR/mix-$i.out" 2>&1
    ) &
    MIX_PIDS[$i]=$!
done
echo "waiting for $N mix runs to complete..."
for i in $(seq 0 $((N-1))); do
    if wait "${MIX_PIDS[$i]}"; then
        echo "  participant $i: ok"
    else
        echo "  participant $i: FAILED — see $DATADIR/mix-$i.out" >&2
        cat "$DATADIR/mix-$i.out" >&2
    fi
done

# ---- assertions -------------------------------------------------------------
step "extracting broadcast txid from each participant"
declare -a BROADCAST_TXIDS
for i in $(seq 0 $((N-1))); do
    txid=$(jq -r '.WraithMixCompleted.broadcast_txid // .broadcast_txid // empty' \
        < "$DATADIR/mix-$i.out")
    if [ -z "$txid" ]; then
        echo "FAIL: participant $i did not return a broadcast_txid" >&2
        cat "$DATADIR/mix-$i.out" >&2
        exit 1
    fi
    BROADCAST_TXIDS[$i]="$txid"
    echo "  participant $i broadcast: $txid"
done

# All 5 must report the SAME broadcast txid — they share one tx.
FIRST_TXID="${BROADCAST_TXIDS[0]}"
for i in $(seq 0 $((N-1))); do
    if [ "${BROADCAST_TXIDS[$i]}" != "$FIRST_TXID" ]; then
        echo "FAIL: participants returned different broadcast_txids" >&2
        echo "  participant 0: $FIRST_TXID" >&2
        echo "  participant $i: ${BROADCAST_TXIDS[$i]}" >&2
        exit 1
    fi
done
echo "  PASS: all $N participants share one broadcast tx ($FIRST_TXID)"

# Mine + verify the tx is on chain with the expected shape.
step "mining + verifying the CoinJoin tx on chain"
$BCLI -rpcwallet=demo generatetoaddress 1 "$DEMO_ADDR" >/dev/null
TX=$($BCLI getrawtransaction "$FIRST_TXID" 1)
N_INPUTS=$(echo "$TX" | jq '.vin | length')
N_OUTPUTS=$(echo "$TX" | jq '.vout | length')
if [ "$N_INPUTS" -ne "$N" ]; then
    echo "FAIL: tx has $N_INPUTS inputs, expected $N" >&2
    exit 1
fi
echo "  PASS: tx has $N inputs"

# Outputs: N denom-sized (100k each), plus change outputs and
# the coordinator's service-fee output. Total ≥ N+1.
if [ "$N_OUTPUTS" -lt "$((N+1))" ]; then
    echo "FAIL: tx has $N_OUTPUTS outputs, expected ≥ $((N+1))" >&2
    exit 1
fi
echo "  PASS: tx has $N_OUTPUTS outputs (≥ N+1)"

# Count denom-sized outputs (exactly 100,000 sats / 0.001 BTC each).
N_DENOMS=$(echo "$TX" | jq '[.vout[] | select(.value == 0.001)] | length')
if [ "$N_DENOMS" -ne "$N" ]; then
    echo "FAIL: $N_DENOMS denom-sized outputs, expected $N" >&2
    echo "$TX" | jq '.vout' >&2
    exit 1
fi
echo "  PASS: $N_DENOMS denom-sized outputs (100,000 sats each)"

# Each mix-output address appears exactly once in the outputs.
for i in $(seq 0 $((N-1))); do
    addr="${MIX_OUT_ADDRS[$i]}"
    found=$(echo "$TX" | jq --arg a "$addr" '[.vout[] | select(.scriptPubKey.address == $a)] | length')
    if [ "$found" -ne 1 ]; then
        echo "FAIL: participant $i mix-output $addr appears $found times, expected 1" >&2
        exit 1
    fi
done
echo "  PASS: every participant's mix-output landed at its declared address"

echo
echo "=== WRAITH MIX DEMO COMPLETE ==="
echo "broadcast_txid: $FIRST_TXID"
echo "$N participants, $N denom-sized outputs at $N distinct addresses"
echo "no input→output linkage on chain — chain analysts see a CoinJoin"
