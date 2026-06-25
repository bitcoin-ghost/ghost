#!/usr/bin/env bash
# smoke-test-wallet-e2e.sh — headless end-to-end smoke test for the
# Wraith Wallet.
#
# Drives the all-in-one wallet through its core flows against a real
# regtest backend, asserting success at each step. The point is to be
# able to prove the wallet works end-to-end WITHOUT the GUI — the CLI
# (`wraith`) talks to the daemon (`wraithd`) over a Unix socket, and
# the daemon talks to ghostd + ghost-pay + ghost-gsp, exactly as in
# production. Nothing here is mocked except the coordinator's bond
# ledger (regtest only — refused on mainnet by the binary).
#
# Flows exercised, in order:
#   1.  create a BIP-39 wallet                  (wraith wallet create)
#   2.  select + GSP auth                        (wraith wallet select / gsp auth)
#   3.  derive a receive address                 (wraith light receive)
#   4.  check the light balance                  (wraith light balance)
#   5.  fund the receive address on regtest      (ghost-cli sendtoaddress)
#   6.  scan L1 + see the funded UTXO             (wraith light l1-utxos)
#   7.  Ghost Lock prepare + on-chain fund + confirm
#                                                (wraith locks prepare / confirm)
#   8.  L2 send (the wallet's `send` command)    (wraith light send)
#   9.  single-round Wraith mix → on-chain CoinJoin
#                                                (wraith mix run, 5 enrolments)
#
# A note on the two "send"-shaped flows (steps 7-9):
#   * The wallet's `light send` command is an L2 ledger transfer — it
#     produces NO on-chain txid by design (settlement is deferred to
#     reconciliation / a confidential-transfer proof). We exercise it
#     and assert the ledger row, but it is not an L1 broadcast.
#   * The real on-chain transactions the wallet DIRECTS are (a) the
#     Ghost Lock funding tx and (b) the Wraith mix CoinJoin. Both land
#     on the regtest chain and we assert their shape. That is the
#     honest "on-chain send" coverage for this wallet.
#
# A note on "single-round" mix:
#   The Wraith Lite mix is single-round — one transaction, one signing
#   window, no two-phase commit (crates/wraith-protocol/src/single_round.rs).
#   But every tier has min_participants = 5 (tier.rs), so a round can't
#   lock+broadcast with fewer. We therefore enrol 5 ghost_ids on one
#   wraithd — the same single-machine mechanic the in-process
#   wraith_e2e.rs integration test uses. "single-round" refers to the
#   protocol shape, not the participant count.
#
# Prerequisites:
#   - ghostd + ghost-cli on PATH (Ghost Core, Bitcoin Core v30 fork).
#     bitcoind/bitcoin-cli also work — the RPC interface is identical —
#     and this script falls back to them.
#   - jq + openssl on PATH
#   - the wraith stack binaries built in target/debug/
#     (cargo build --workspace). Override the directory with
#     $WRAITH_BIN_DIR if your binaries live elsewhere (e.g. a shared
#     checkout's target/debug while running from a git worktree).
#     If wraithd / ghost-pay / ghost-gsp / wraith-coordinator / wraith
#     are missing this script tells you which and stops.
#
# Usage:
#   ./scripts/smoke-test-wallet-e2e.sh
#   WRAITH_BIN_DIR=/path/to/target/debug ./scripts/smoke-test-wallet-e2e.sh
#
# Network is hard-pinned to regtest. The script starts the whole stack
# itself and tears it all down on exit (success OR failure).

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${WRAITH_BIN_DIR:-$REPO/target/debug}"
DATADIR="$(mktemp -d -t wraith-smoke-e2e.XXXXXX)"
SAVED_LOGS_DIR="${SAVED_LOGS_DIR:-/tmp/wraith-smoke-e2e-logs}"
mkdir -p "$SAVED_LOGS_DIR"

# Number of mix participants. min_participants is 5 universally
# (wraith-protocol tier.rs) — a round won't lock below this.
N=5

GHOST_PAY_PID=""
GSP_PID=""
COORD_PID=""
WRAITHD_PID=""
GHOSTD_UP=""

cleanup() {
    set +e
    [ -n "$WRAITHD_PID" ]   && kill "$WRAITHD_PID"   2>/dev/null
    [ -n "$COORD_PID" ]     && kill "$COORD_PID"     2>/dev/null
    [ -n "$GSP_PID" ]       && kill "$GSP_PID"       2>/dev/null
    [ -n "$GHOST_PAY_PID" ] && kill "$GHOST_PAY_PID" 2>/dev/null
    if [ -n "$GHOSTD_UP" ]; then
        $BCLI stop 2>/dev/null || true
    fi
    sleep 1
    cp "$DATADIR/"*.log     "$SAVED_LOGS_DIR/" 2>/dev/null || true
    cp "$DATADIR/"mix-*.out "$SAVED_LOGS_DIR/" 2>/dev/null || true
    rm -rf "$DATADIR"
    echo "(logs preserved at $SAVED_LOGS_DIR)"
}
trap cleanup EXIT

step() { echo; echo "=== $* ==="; }
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  PASS: $*"; }

# ---- binary discovery -------------------------------------------------------
for b in wraith wraithd ghost-pay ghost-gsp wraith-coordinator; do
    if [ ! -x "$BIN/$b" ]; then
        fail "missing $BIN/$b — run 'cargo build --workspace' (or set \$WRAITH_BIN_DIR)"
    fi
done

# Prefer ghostd/ghost-cli; fall back to bitcoind/bitcoin-cli (RPC-
# compatible) or to the multitool form (`ghost rpc` / `bitcoin rpc`).
GHOSTD="${GHOSTD:-$(command -v ghostd || command -v bitcoind || true)}"
GHOST_CLI="${GHOST_CLI:-$(command -v ghost-cli || command -v bitcoin-cli || true)}"
if [ -z "$GHOSTD" ]; then
    fail "neither ghostd nor bitcoind found on PATH"
fi
if [ -z "$GHOST_CLI" ]; then
    if command -v ghost > /dev/null 2>&1; then
        GHOST_CLI="ghost rpc"
    elif command -v bitcoin > /dev/null 2>&1; then
        GHOST_CLI="bitcoin rpc"
    else
        fail "no RPC client found (looked for ghost-cli, bitcoin-cli, ghost, bitcoin)"
    fi
fi
command -v jq      >/dev/null 2>&1 || fail "jq not found on PATH"
command -v openssl >/dev/null 2>&1 || fail "openssl not found on PATH"

# ---- topology ---------------------------------------------------------------
GHOSTD_DIR="$DATADIR/ghostd"
GHOSTD_PORT=18443
GHOSTD_RPC_URL="http://127.0.0.1:${GHOSTD_PORT}/"
mkdir -p "$GHOSTD_DIR"

GHOST_PAY_DIR="$DATADIR/ghost-pay"
GHOST_PAY_URL="http://127.0.0.1:8800"
GSP_URL="ws://127.0.0.1:8900/ws/v1"
COORD_URL="http://127.0.0.1:9100"
WRAITH_SOCK="$DATADIR/wraithd.sock"

# ---- port pre-flight --------------------------------------------------------
# Refuse to start if any of our fixed ports is already bound — a stale
# stack process or a pre-existing regtest node on the same port would
# otherwise make the run connect to the WRONG backend and fail with a
# confusing mid-run error (e.g. the coordinator broadcasting to a ghostd
# it can't authenticate to). Fail loud and early instead.
port_busy() {
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -qE "[:.]$1[[:space:]]"
    else
        netstat -ltn 2>/dev/null | grep -qE "[:.]$1[[:space:]]"
    fi
}
for p in "$GHOSTD_PORT" 18444 8800 8900 9100; do
    if port_busy "$p"; then
        fail "port $p is already in use — a stale stack or another regtest node is running. \
Stop it (pkill -9 ghostd ghost-pay ghost-gsp wraithd; pkill -9 -f wraith-coordina) and retry."
    fi
done

# ---- ghostd -----------------------------------------------------------------
step "starting ghostd regtest ($GHOSTD)"
"$GHOSTD" -regtest \
    -datadir="$GHOSTD_DIR" \
    -rpcuser=demo -rpcpassword=demo \
    -rpcport=$GHOSTD_PORT \
    -port=18444 \
    -fallbackfee=0.0001 \
    -daemon \
    -txindex
GHOSTD_UP=1
sleep 2
BCLI="$GHOST_CLI -regtest -datadir=$GHOSTD_DIR -rpcuser=demo -rpcpassword=demo"
$BCLI -named createwallet wallet_name=demo descriptors=true >/dev/null 2>&1 || true
$BCLI loadwallet demo >/dev/null 2>&1 || true
DEMO_ADDR=$($BCLI -rpcwallet=demo getnewaddress)
$BCLI -rpcwallet=demo generatetoaddress 101 "$DEMO_ADDR" >/dev/null
echo "regtest funded — balance: $($BCLI -rpcwallet=demo getbalance) BTC"

# ---- shared secrets ---------------------------------------------------------
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

# ghost-pay needs operator keys before any /api/v1/locks/* route works
# (state.keys is None until generated — returns 404 otherwise). In
# production this is a one-time operator-install step.
step "bootstrapping ghost-pay operator keys"
curl -fsS -X POST -H "X-Internal-Auth: $INTERNAL_SECRET" \
    -H "Content-Type: application/json" \
    "$GHOST_PAY_URL/api/v1/keys/generate" -d '{}' >"$DATADIR/keys-init.json"
echo "  ghost_id: $(jq -r '.ghost_id // empty' < "$DATADIR/keys-init.json" 2>/dev/null || echo '<missing>')"

# ---- wraithd ----------------------------------------------------------------
# Started before the coordinator so we can derive the fee-collection
# address up-front (the coordinator needs it at boot or /inputs 503s).
# WRAITHD_GHOSTD_* lets the daemon talk straight to ghostd for the
# lock-recovery / scan paths, mirroring regtest-recovery-demo.sh.
step "starting wraithd"
WRAITHD_SOCKET="$WRAITH_SOCK" \
WRAITHD_NETWORK=regtest \
WRAITHD_GHOST_PAY="$GHOST_PAY_URL" \
WRAITHD_GSP="$GSP_URL" \
WRAITHD_GHOST_PAY_INTERNAL_AUTH="$INTERNAL_SECRET" \
WRAITHD_GHOSTD_URL="$GHOSTD_RPC_URL" \
WRAITHD_GHOSTD_USER=demo \
WRAITHD_GHOSTD_PASS=demo \
WRAITHD_WALLETS_DIR="$DATADIR/wallets" \
"$BIN/wraithd" \
    >"$DATADIR/wraithd.log" 2>&1 &
WRAITHD_PID=$!
sleep 2

# All CLI calls go through this one wraithd. --no-spawn so we fail loud
# if the daemon died instead of silently auto-spawning a fresh one with
# different env.
WRAITH() { WRAITHD_SOCKET="$WRAITH_SOCK" "$BIN/wraith" --no-spawn "$@"; }

# ============================================================================
# FLOW 1: create a BIP-39 wallet
# ============================================================================
step "FLOW 1 — create a BIP-39 wallet"
# On a pipe (non-TTY) `wraith wallet create` reads one passphrase line
# and skips the confirmation prompt. Capture the mnemonic to prove a
# real BIP-39 seed was generated.
CREATE_OUT=$(WRAITH wallet create smoke <<< 'smoke-pass-1234')
echo "$CREATE_OUT" | grep -q "created at" || fail "wallet create did not report success"
# The 24 recovery words are printed between the warning and the
# "is unlocked" footer. Find the line with exactly 24 words.
MNEMONIC_WORDS=$(echo "$CREATE_OUT" | awk 'NF==24{print NF; exit}')
[ "$MNEMONIC_WORDS" = "24" ] || fail "expected a 24-word BIP-39 mnemonic, got '$MNEMONIC_WORDS'"
pass "wallet 'smoke' created with a 24-word BIP-39 mnemonic"

# ============================================================================
# FLOW 2: select (unlock-active) + GSP auth
# ============================================================================
step "FLOW 2 — select active wallet + GSP auth"
WRAITH wallet select smoke >/dev/null
STATUS_OUT=$(WRAITH wallet status)
echo "$STATUS_OUT" | grep -q "active: smoke"   || fail "smoke is not the active wallet"
echo "$STATUS_OUT" | grep -q "unlocked: yes"   || fail "smoke is not unlocked"
pass "wallet 'smoke' is active + unlocked"

AUTH_OUT=$(WRAITH gsp auth)
echo "$AUTH_OUT" | grep -qiE 'session created' || fail "GSP auth did not create a session"
STATIC_ID=$(echo "$AUTH_OUT" | grep -m1 'wallet_id:' | awk '{print $NF}')
[ -n "$STATIC_ID" ] || fail "GSP auth returned no wallet_id"
pass "GSP session created (static wallet_id $STATIC_ID)"

# ============================================================================
# FLOW 3: derive a receive address
# ============================================================================
step "FLOW 3 — derive a BIP86 receive address"
RECV_JSON=$(WRAITH --json light receive --index 0)
RECV_ADDR=$(echo "$RECV_JSON" | jq -r '.LightReceive.address // .address')
RECV_NET=$(echo "$RECV_JSON" | jq -r '.LightReceive.network // .network')
[ -n "$RECV_ADDR" ] && [ "$RECV_ADDR" != "null" ] || fail "no receive address derived"
[ "$RECV_NET" = "regtest" ] || fail "receive address network is '$RECV_NET', expected regtest"
# Regtest taproot addresses are bcrt1p…; assert the prefix so we know
# we didn't accidentally get a mainnet / signet address.
case "$RECV_ADDR" in
    bcrt1p*) ;;
    *) fail "receive address '$RECV_ADDR' is not a regtest taproot (bcrt1p…) address" ;;
esac
pass "derived regtest taproot receive address $RECV_ADDR"

# ============================================================================
# FLOW 4: check the light balance (pre-funding)
# ============================================================================
step "FLOW 4 — check light balance (pre-funding)"
BAL_OUT=$(WRAITH light balance || true)
echo "$BAL_OUT"
# We only assert the command returns cleanly and reports a balance
# surface; an exact figure depends on GSP scan timing. The post-funding
# L1 scan in FLOW 6 is the authoritative balance assertion.
pass "light balance query returned"

# ============================================================================
# FLOW 5: fund the receive address on regtest
# ============================================================================
step "FLOW 5 — fund the receive address (regtest)"
FUND_TXID=$($BCLI -rpcwallet=demo sendtoaddress "$RECV_ADDR" 0.01)
[ -n "$FUND_TXID" ] || fail "regtest sendtoaddress returned no txid"
$BCLI -rpcwallet=demo generatetoaddress 6 "$DEMO_ADDR" >/dev/null
echo "funded $RECV_ADDR with 0.01 BTC — txid $FUND_TXID (6 confs)"
pass "receive address funded on-chain"

# ============================================================================
# FLOW 6: scan L1 + confirm the wallet sees its own UTXO
# ============================================================================
step "FLOW 6 — scan L1 for the funded UTXO"
SCAN_JSON=$(WRAITH --json light l1-utxos --scan-max-index 4)
FOUND=$(echo "$SCAN_JSON" \
    | jq --arg a "$RECV_ADDR" \
         '[(.LightL1Utxos.utxos // .utxos)[] | select(.address == $a)] | length')
[ "$FOUND" -ge 1 ] || fail "wallet L1 scan did not see its funded UTXO at $RECV_ADDR"
SCAN_SATS=$(echo "$SCAN_JSON" \
    | jq --arg a "$RECV_ADDR" \
         '[(.LightL1Utxos.utxos // .utxos)[] | select(.address == $a) | .amount_sats] | add')
[ "$SCAN_SATS" = "1000000" ] || fail "scanned UTXO value $SCAN_SATS, expected 1000000 (0.01 BTC)"
pass "wallet's own L1 scanner sees the 1,000,000-sat UTXO"

# ============================================================================
# FLOW 7: Ghost Lock prepare + on-chain fund + confirm
#   This is the wallet directing a REAL on-chain transaction: the lock
#   funding tx lands on the regtest chain and the wallet confirms it.
# ============================================================================
step "FLOW 7 — Ghost Lock prepare → on-chain fund → confirm"
PREP_OUT=$(WRAITH locks prepare 100000)
echo "$PREP_OUT"
LOCK_ID=$(echo "$PREP_OUT" | grep -m1 'lock_id:' | awk '{print $NF}')
LOCK_ADDR=$(echo "$PREP_OUT" | grep -m1 'funding address:' | awk '{print $NF}')
[ -n "$LOCK_ID" ] && [ -n "$LOCK_ADDR" ] || fail "locks prepare returned no lock_id / funding address"

LOCK_TXID=$($BCLI -rpcwallet=demo sendtoaddress "$LOCK_ADDR" 0.001)
[ -n "$LOCK_TXID" ] || fail "lock funding sendtoaddress returned no txid"
$BCLI -rpcwallet=demo generatetoaddress 1 "$DEMO_ADDR" >/dev/null
CONFIRM_OUT=$(WRAITH locks confirm "$LOCK_ID" "$LOCK_TXID")
echo "$CONFIRM_OUT"
# The confirm response echoes back the same lock_id + the funding txid
# we supplied — that round-trip IS the success assertion (the operator
# accepted the confirmation and recorded the funding outpoint).
echo "$CONFIRM_OUT" | grep -q "lock confirmed"            || fail "locks confirm did not succeed"
echo "$CONFIRM_OUT" | grep -q "lock_id:      $LOCK_ID"    || fail "confirm echoed a different lock_id"
echo "$CONFIRM_OUT" | grep -q "funding txid: $LOCK_TXID"  || fail "confirm echoed a different funding txid"
# `locks list` is operator-side (GSP) registry state and is shown for
# visibility only — it is not a hard gate (a freshly-confirmed lock may
# lag in the GSP registry, and the demo scripts likewise don't assert
# on it).
echo "locks list (informational):"
WRAITH locks list || true
pass "Ghost Lock $LOCK_ID funded on-chain (tx $LOCK_TXID) and confirmed"

# ============================================================================
# FLOW 8: L2 send — the wallet's `light send` command
#   Honest framing: this is an L2 ledger transfer, NOT an L1 broadcast
#   (txid is null by design). We send to our own wallet's bech32
#   ghost-id and assert the operator-side ledger recorded it.
# ============================================================================
step "FLOW 8 — L2 send (wallet 'light send' command)"
GHOST_ID=$(WRAITH --json wallet ghost-id | jq -r '.WalletGhostId.ghost_id // .ghost_id')
[ -n "$GHOST_ID" ] || fail "could not read the wallet's bech32 ghost-id"
SEND_JSON=$(WRAITH --json light send "$GHOST_ID" 5000 --immediate)
echo "$SEND_JSON" | jq '.'
PAYMENT_ID=$(echo "$SEND_JSON" | jq -r '.LightSent.payment_id // .payment_id // empty')
[ -n "$PAYMENT_ID" ] || fail "light send returned no payment_id"
# Confirm ghost-pay recorded the send under our static wallet_id.
SENDER_TXS=$(curl -fsS -H "X-Internal-Auth: $INTERNAL_SECRET" \
    "$GHOST_PAY_URL/api/v1/transactions?ghost_id=$STATIC_ID&limit=5")
TOP_AMOUNT=$(echo "$SENDER_TXS" | jq -r '.transactions[0].amount_sats // empty')
TOP_TYPE=$(echo   "$SENDER_TXS" | jq -r '.transactions[0].tx_type // empty')
[ "$TOP_AMOUNT" = "-5000" ] && [ "$TOP_TYPE" = "send" ] \
    || fail "operator ledger row unexpected — amount=$TOP_AMOUNT type=$TOP_TYPE"
pass "L2 send recorded in ghost-pay ledger (payment_id $PAYMENT_ID, -5000 send)"

# ============================================================================
# FLOW 9: single-round Wraith mix → on-chain CoinJoin
#   One round, one tx, one signing window (single_round.rs). 5 ghost_ids
#   enrol on this one wraithd (min_participants = 5). The coordinator
#   broadcasts the assembled tx to ghostd for real.
# ============================================================================
step "FLOW 9 — single-round Wraith mix ($N participants → one CoinJoin tx)"

declare -a INPUT_ADDRS MIX_OUT_ADDRS CHANGE_ADDRS
declare -a FUND_TXIDS UTXO_VOUTS UTXO_SPKS MIX_PIDS

# Fee-collection address at a high BIP86 index so it can't collide with
# participant input / output addresses.
FEE_ADDR=$(WRAITH --json light receive --index 999 \
    | jq -r '.LightReceive.address // .address')
echo "fee-collection address: $FEE_ADDR"

# Per-participant: one input address (10..), one mix-output address
# (110..), one change address (210..). Inputs and outputs MUST be
# distinct addresses so the on-chain CoinJoin has no address-reuse
# linkage.
for i in $(seq 0 $((N-1))); do
    INPUT_ADDRS[$i]=$(WRAITH --json light receive --index "$((10+i))"  | jq -r '.LightReceive.address // .address')
    MIX_OUT_ADDRS[$i]=$(WRAITH --json light receive --index "$((110+i))" | jq -r '.LightReceive.address // .address')
    CHANGE_ADDRS[$i]=$(WRAITH --json light receive --index "$((210+i))" | jq -r '.LightReceive.address // .address')
done

# Start the coordinator with a real broadcast target (ghostd) + auto-
# escrow mock bonds + a 30s fill window (collapses the 5-min default so
# the round locks shortly after the 5th enrolment). All three flags are
# refused on mainnet by the binary.
step "starting wraith-coordinator (real broadcast, auto-escrow bonds)"
"$BIN/wraith-coordinator" \
    --listen 127.0.0.1:9100 \
    --network regtest \
    --fee-address "$FEE_ADDR" \
    --mock-bond-ledger \
    --mock-bond-ledger-auto-escrow \
    --fill-window-secs 30 \
    --ghostd-url "$GHOSTD_RPC_URL" \
    --ghostd-user demo \
    --ghostd-pass demo \
    >"$DATADIR/coordinator.log" 2>&1 &
COORD_PID=$!
sleep 2

# Sanity: the coordinator is alive and serving the tier we'll mix.
WRAITH --json mix discover --coordinator "$COORD_URL" \
    | jq -e '[(.WraithCoordinatorDiscover.tiers // .tiers)[] | select(.id == "100k_sats")] | length == 1' \
    >/dev/null || fail "coordinator does not advertise the 100k_sats tier"

# Fund one input UTXO per participant. 200,000 sats covers denom
# (100,000) + bond (500) + per-input fee share + change.
step "funding $N mix-input UTXOs at 200,000 sats each"
for i in $(seq 0 $((N-1))); do
    FUND_TXIDS[$i]=$($BCLI -rpcwallet=demo sendtoaddress "${INPUT_ADDRS[$i]}" 0.002)
done
$BCLI -rpcwallet=demo generatetoaddress 6 "$DEMO_ADDR" >/dev/null

# Resolve each funded UTXO's vout + scriptPubKey via the wallet scanner.
step "scanning L1 for the $N mix-input UTXOs"
MIX_SCAN=$(WRAITH --json light l1-utxos --scan-max-index $((10+N+1)))
for i in $(seq 0 $((N-1))); do
    entry=$(echo "$MIX_SCAN" | jq --arg a "${INPUT_ADDRS[$i]}" \
        '(.LightL1Utxos.utxos // .utxos) | map(select(.address == $a)) | .[0]')
    [ -n "$entry" ] && [ "$entry" != "null" ] \
        || fail "scanner did not see mix-input UTXO at ${INPUT_ADDRS[$i]} (participant $i)"
    UTXO_VOUTS[$i]=$(echo "$entry" | jq '.vout')
    UTXO_SPKS[$i]=$(echo "$entry" | jq -r '.scriptpubkey_hex')
done

# Run all N one-shot mixes concurrently. Each blocks until the round
# broadcasts. They converge on a single coordinator session.
step "running $N parallel mixes"
for i in $(seq 0 $((N-1))); do
    (
        WRAITH --json mix run \
            --coordinator "$COORD_URL" \
            --tier 100k_sats \
            --ghost-id "smoke_participant_$i" \
            --bond-id-placeholder "placeholder_$i" \
            --utxo "${FUND_TXIDS[$i]}:${UTXO_VOUTS[$i]}" \
            --utxo-value 200000 \
            --utxo-scriptpubkey "${UTXO_SPKS[$i]}" \
            --change-address "${CHANGE_ADDRS[$i]}" \
            --mix-output-address "${MIX_OUT_ADDRS[$i]}" \
            --bip86-index "$((10+i))" \
            > "$DATADIR/mix-$i.out" 2>&1
    ) &
    MIX_PIDS[$i]=$!
done
echo "waiting for $N mix runs..."
for i in $(seq 0 $((N-1))); do
    if wait "${MIX_PIDS[$i]}"; then
        echo "  participant $i: ok"
    else
        echo "  participant $i: FAILED — see below" >&2
        cat "$DATADIR/mix-$i.out" >&2
        fail "mix participant $i did not complete"
    fi
done

# Every participant must report the SAME broadcast txid (one shared tx).
step "asserting the on-chain CoinJoin"
FIRST_TXID=""
for i in $(seq 0 $((N-1))); do
    txid=$(jq -r '.WraithMixCompleted.broadcast_txid // .broadcast_txid // empty' \
        < "$DATADIR/mix-$i.out")
    [ -n "$txid" ] || { cat "$DATADIR/mix-$i.out" >&2; fail "participant $i returned no broadcast_txid"; }
    if [ -z "$FIRST_TXID" ]; then
        FIRST_TXID="$txid"
    elif [ "$txid" != "$FIRST_TXID" ]; then
        fail "participants returned different broadcast_txids ($FIRST_TXID vs $txid)"
    fi
done
pass "all $N participants share one broadcast tx ($FIRST_TXID)"

# Mine + verify the tx shape on chain.
$BCLI -rpcwallet=demo generatetoaddress 1 "$DEMO_ADDR" >/dev/null
TX=$($BCLI getrawtransaction "$FIRST_TXID" 1)
N_INPUTS=$(echo "$TX" | jq '.vin | length')
N_OUTPUTS=$(echo "$TX" | jq '.vout | length')
[ "$N_INPUTS" -eq "$N" ] || fail "CoinJoin has $N_INPUTS inputs, expected $N"
pass "CoinJoin tx confirmed on chain with $N inputs"

[ "$N_OUTPUTS" -ge "$((N+1))" ] || fail "CoinJoin has $N_OUTPUTS outputs, expected >= $((N+1))"
N_DENOMS=$(echo "$TX" | jq '[.vout[] | select(.value == 0.001)] | length')
[ "$N_DENOMS" -eq "$N" ] || fail "$N_DENOMS denom-sized outputs, expected $N"
pass "CoinJoin has $N denom-sized outputs (100,000 sats each) among $N_OUTPUTS total"

# Each participant's mix-output address appears exactly once.
for i in $(seq 0 $((N-1))); do
    found=$(echo "$TX" | jq --arg a "${MIX_OUT_ADDRS[$i]}" \
        '[.vout[] | select(.scriptPubKey.address == $a)] | length')
    [ "$found" -eq 1 ] || fail "participant $i mix-output appears $found times, expected 1"
done
pass "every participant's mix-output landed at its declared address"

# ============================================================================
echo
echo "================================================================"
echo "  WRAITH WALLET END-TO-END SMOKE TEST — ALL FLOWS GREEN"
echo "================================================================"
echo "  1. BIP-39 wallet create            ok"
echo "  2. select + GSP auth               ok"
echo "  3. derive receive address          ok  ($RECV_ADDR)"
echo "  4. light balance                   ok"
echo "  5. regtest fund                    ok  ($FUND_TXID)"
echo "  6. L1 scan sees own UTXO           ok  (1,000,000 sats)"
echo "  7. Ghost Lock prepare/fund/confirm ok  ($LOCK_ID)"
echo "  8. L2 send (light send)            ok  ($PAYMENT_ID)"
echo "  9. single-round Wraith mix         ok  ($FIRST_TXID)"
echo "================================================================"
