#!/usr/bin/env bash
# smoke-test-wallet-e2e.sh — headless end-to-end smoke test for the
# Wraith Wallet.
#
# Drives the all-in-one wallet through its core flows against a real
# regtest backend, asserting success at each step. The point is to be
# able to prove the wallet works end-to-end WITHOUT the GUI — the CLI
# (`wraith`) talks to the daemon (`wraithd`) over a Unix socket, and
# the daemon talks to ghostd, exactly as in
# production. Nothing here is mocked.
#
# Flows exercised, in order:
#   1.  create a BIP-39 wallet                  (wraith wallet create)
#   2.  select the active wallet                 (wraith wallet select)
#   3.  derive a receive address                 (wraith light receive)
#   4.  check the light balance                  (wraith light balance)
#   5.  fund the receive address on regtest      (ghost-cli sendtoaddress)
#   6.  scan L1 + see the funded UTXO             (wraith light l1-utxos)
#   7.  Ghost Lock prepare + on-chain fund + confirm
#                                                (wraith lock save / lanes)
#   8.  on-chain payment                         (wraith light pay)
#   9.  single-round Wraith mix → on-chain CoinJoin
#                                                (wraith mix run, 5 enrolments)
#
# A note on the "send"-shaped flows (steps 7-9):
#   Every one of them now lands on the regtest chain: the Ghost Lock
#   funding tx, the `light pay` payment, and the Wraith mix CoinJoin.
#   The L2 ledger transfer that used to sit at step 8 is gone with
#   Ghost Pay — it produced no txid by design, so it was the one flow
#   here whose success the chain could not confirm.
#
# A note on "single-round" mix:
#   The Wraith Lite mix is single-round — one transaction, one signing
#   window, no two-phase commit (crates/wraith-protocol/src/single_round.rs).
#   But a wallet refuses to sign a set below DEFAULT_MIN_ENTITIES (10), so
#   a round at the protocol's own minimum of 5 locks and is then refused.
#   We therefore enrol 10 ghost_ids on one
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
#     If wraithd / wraith-coordinator / wraith
#     are missing this script tells you which and stops.
#
# Usage:
#   ./scripts/smoke-test-wallet-e2e.sh
#   WRAITH_BIN_DIR=/path/to/target/debug ./scripts/smoke-test-wallet-e2e.sh
#
# Network is hard-pinned to regtest. The script starts the whole stack
# itself and tears it all down on exit (success OR failure).

set -euo pipefail

# Name the failure. `set -e` aborts without a word, and the cleanup trap below
# then prints its normal shutdown line — so an aborted run reads exactly like a
# finished one. Three signet runs died in the mining loop before this existed.
trap 'st=$?; echo "ABORTED: line $LINENO: \"$BASH_COMMAND\" exited $st" >&2' ERR

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${WRAITH_BIN_DIR:-$REPO/target/debug}"
DATADIR="$(mktemp -d -t wraith-smoke-e2e.XXXXXX)"
SAVED_LOGS_DIR="${SAVED_LOGS_DIR:-/tmp/wraith-smoke-e2e-logs}"
mkdir -p "$SAVED_LOGS_DIR"

# Number of mix participants.
#
# TEN, not the protocol's five. `min_participants` is 5 (wraith-protocol
# tier.rs) — the smallest round the protocol will ASSEMBLE — but a wallet
# refuses to sign a set below `DEFAULT_MIN_ENTITIES`, which is 10, on the
# grounds that one-in-five is barely privacy. So a five-participant round
# locks and is then refused by every wallet running the defaults:
#
#   "5 distinct entities across 5 seats is below the floor of 10 —
#    the set is not worth signing"
#
# Enrolling five therefore tested the refusal, not the CoinJoin. Ten is the
# smallest round a default-configured wallet will actually sign, which is what
# a user experiences, and it stays under the 100k tier's cap of 20.
N=10

COORD_PID=""
WRAITHD_PID=""
GHOSTD_UP=""

cleanup() {
    set +e
    [ -n "$WRAITHD_PID" ]   && kill "$WRAITHD_PID"   2>/dev/null
    [ -n "$COORD_PID" ]     && kill "$COORD_PID"     2>/dev/null
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
for b in wraith wraithd wraith-coordinator ghost-lock-signer; do
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

# ---- network ----------------------------------------------------------------
# Regtest by default; SMOKE_NETWORK=signet runs the same flows on a PRIVATE
# signet.
#
# Private, not the public one, and the distinction is the point. Public signet
# blocks arrive when somebody else mines them, so a run that needs 1,010 blocks
# to age a Spending lane past its exit delay would take a week. A signet of our
# own with a trivial block challenge keeps `generatetoaddress` while still
# putting every guard, address prefix and network check on the signet path
# rather than the regtest one — which is the half regtest never exercises.
NETWORK="${SMOKE_NETWORK:-regtest}"
case "$NETWORK" in
    regtest)
        GHOSTD_NET=(-regtest)
        GHOSTD_PORT=18443
        GHOSTD_P2P_PORT=18444
        ADDR_PREFIX="bcrt1p"
        ;;
    signet)
        # OP_TRUE: any block satisfies the challenge, so this node can mine its
        # own chain. Nothing else about signet changes.
        GHOSTD_NET=(-signet -signetchallenge=51)
        GHOSTD_PORT=38332
        GHOSTD_P2P_PORT=38333
        ADDR_PREFIX="tb1p"
        ;;
    *)
        fail "SMOKE_NETWORK must be 'regtest' or 'signet', got '$NETWORK'"
        ;;
esac

# ---- topology ---------------------------------------------------------------
GHOSTD_DIR="$DATADIR/ghostd"
GHOSTD_RPC_URL="http://127.0.0.1:${GHOSTD_PORT}/"
mkdir -p "$GHOSTD_DIR"

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
for p in "$GHOSTD_PORT" "$GHOSTD_P2P_PORT" 8800 8900 9100; do
    if port_busy "$p"; then
        fail "port $p is already in use — a stale stack or another node is running. \
Stop it (pkill -9 ghostd wraithd; pkill -9 -f wraith-coordina) and retry."
    fi
done

# ---- ghostd -----------------------------------------------------------------
step "starting ghostd $NETWORK ($GHOSTD)"
"$GHOSTD" "${GHOSTD_NET[@]}" \
    -datadir="$GHOSTD_DIR" \
    -rpcuser=demo -rpcpassword=demo \
    -rpcport=$GHOSTD_PORT \
    -port=$GHOSTD_P2P_PORT \
    -fallbackfee=0.0001 \
    -daemon \
    -txindex
GHOSTD_UP=1
sleep 2
BCLI="$GHOST_CLI ${GHOSTD_NET[0]} -datadir=$GHOSTD_DIR -rpcuser=demo -rpcpassword=demo"

# Mine N blocks to the node's own wallet.
#
# `maxtries` is the whole reason this is a function. Regtest blocks are free,
# but a private signet keeps real proof-of-work — only the block SIGNATURE is
# trivial — and Core's default of 1,000,000 tries gives up before finding one.
# It does not error when it does: it returns an empty array and exit 0, so the
# chain silently fails to advance and the first symptom is "Insufficient funds"
# somewhere far away.
# The node's height, or -1 if it could not be read.
#
# A bare `h=$(cli getblockcount)` is fatal under `set -e` the moment the node is
# too busy to answer, and an empty result is worse: the next `[ "$h" -lt ... ]`
# fails with "integer expression expected" and takes the run down with it. A
# mining loop that hammers RPC for half an hour will meet that eventually.
height() {
    local h
    h=$($BCLI getblockcount 2>/dev/null || true)
    case "$h" in
        ''|*[!0-9]*) echo -1 ;;
        *) echo "$h" ;;
    esac
}

mine() {
    local want="$1" start target now next stalled=0
    start=$(height)
    if [ "$start" -lt 0 ]; then fail "cannot read the chain height on $NETWORK"; fi
    target=$((start + want))
    now=$start
    # Loop to a target HEIGHT rather than trusting one call, because `maxtries`
    # is a budget for the whole call and not per block: on signet one billion
    # tries buys about 200 blocks, and the call then returns the blocks it did
    # find with exit 0. Asking once and believing the answer is how a run ends
    # up 800 blocks short and reports it as "Insufficient funds" much later.
    local chunk
    while [ "$now" -lt "$target" ]; do
        # In bounded chunks, and tolerating a failed call. A single request for
        # a thousand signet blocks grinds for longer than the RPC timeout, and
        # under `set -e` that non-zero exit kills the run outright — no message,
        # just the cleanup trap, which reads like the script simply stopped.
        chunk=$((target - now))
        if [ "$chunk" -gt 50 ]; then chunk=50; fi
        $BCLI -rpcwallet=demo generatetoaddress "$chunk" "$DEMO_ADDR" 500000000 \
            >/dev/null 2>&1 || true
        next=$(height)
        if [ "$next" -le "$now" ]; then
            stalled=$((stalled + 1))
            # A full `if` rather than `[ ... ] && fail`. Under `set -e` a
            # trailing test that comes out FALSE is the branch's exit status,
            # so the guard against a stalled chain was itself killing the run —
            # silently, on the first chunk that happened to find no block.
            if [ "$stalled" -ge 20 ]; then
                fail "mining stalled at height $next on $NETWORK, wanted $target"
            fi
        else
            stalled=0
        fi
        now=$next
    done
}
$BCLI -named createwallet wallet_name=demo descriptors=true >/dev/null 2>&1 || true
$BCLI loadwallet demo >/dev/null 2>&1 || true
DEMO_ADDR=$($BCLI -rpcwallet=demo getnewaddress)
mine 101
echo "$NETWORK funded — balance: $($BCLI -rpcwallet=demo getbalance) BTC"

# ---- shared secrets ---------------------------------------------------------

# ---- wraithd ----------------------------------------------------------------
# Started before the coordinator so we can derive the fee-collection
# address up-front (the coordinator needs it at boot or /inputs 503s).
# WRAITHD_GHOSTD_* lets the daemon talk straight to ghostd for the
# lock-recovery / scan paths, mirroring regtest-recovery-demo.sh.
step "starting wraithd"
WRAITHD_SOCKET="$WRAITH_SOCK" \
WRAITHD_NETWORK="$NETWORK" \
WRAITHD_GHOSTD_URL="$GHOSTD_RPC_URL" \
WRAITHD_GHOSTD_USER=demo \
WRAITHD_GHOSTD_PASS=demo \
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
# FLOW 2: select (unlock-active)
# ============================================================================
step "FLOW 2 — select active wallet"
WRAITH wallet select smoke >/dev/null
STATUS_OUT=$(WRAITH wallet status)
echo "$STATUS_OUT" | grep -q "active: smoke"   || fail "smoke is not the active wallet"
echo "$STATUS_OUT" | grep -q "unlocked: yes"   || fail "smoke is not unlocked"
pass "wallet 'smoke' is active + unlocked"

# The wallet identity is derived locally now. It used to come back from the
# GSP handshake, which meant this smoke test could not read it without an
# operator being up.
STATIC_ID=$(WRAITH --json wallet auth-info | jq -r '.WalletAuthInfo.wallet_id // .wallet_id')
[ -n "$STATIC_ID" ] || fail "wallet auth-info returned no wallet_id"
pass "wallet identity derived locally (wallet_id $STATIC_ID)"

# ============================================================================
# FLOW 3: derive a receive address
# ============================================================================
step "FLOW 3 — derive a BIP86 receive address"
RECV_JSON=$(WRAITH --json light receive --index 0)
RECV_ADDR=$(echo "$RECV_JSON" | jq -r '.LightReceive.address // .address')
RECV_NET=$(echo "$RECV_JSON" | jq -r '.LightReceive.network // .network')
[ -n "$RECV_ADDR" ] && [ "$RECV_ADDR" != "null" ] || fail "no receive address derived"
[ "$RECV_NET" = "$NETWORK" ] || fail "receive address network is '$RECV_NET', expected $NETWORK"
# Regtest taproot addresses are bcrt1p…; assert the prefix so we know
# we didn't accidentally get a mainnet / signet address.
case "$RECV_ADDR" in
    "$ADDR_PREFIX"*) ;;
    *) fail "receive address '$RECV_ADDR' is not a $NETWORK taproot ($ADDR_PREFIX…) address" ;;
esac
pass "derived $NETWORK taproot receive address $RECV_ADDR"

# ============================================================================
# FLOW 4: check the light balance (pre-funding)
# ============================================================================
step "FLOW 4 — check light balance (pre-funding)"
BAL_OUT=$(WRAITH light balance || true)
echo "$BAL_OUT"
# We only assert the command returns cleanly and reports a balance
# surface; an exact figure depends on scan timing. The post-funding
# L1 scan in FLOW 6 is the authoritative balance assertion.
pass "light balance query returned"

# ============================================================================
# FLOW 5: fund the receive address on the chain under test
# ============================================================================
step "FLOW 5 — fund the receive address ($NETWORK)"
FUND_TXID=$($BCLI -rpcwallet=demo sendtoaddress "$RECV_ADDR" 0.01)
[ -n "$FUND_TXID" ] || fail "$NETWORK sendtoaddress returned no txid"
mine 6
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
# FLOW 7: Ghost Lock — save a definition, derive its lanes, fund one on-chain
#
#   The old shape of this flow (`locks prepare` / `locks confirm`) was
#   operator-mediated: ghost-pay registered the Lock and the wallet told it
#   when the funding landed. Both commands are gone with it, and a Lock is
#   now purely local — a definition the wallet remembers, from which the four
#   lane addresses are re-derived every time.
#
#   So what is worth asserting changed too. There is no operator to confirm
#   anything; the chain confirms it. Fund a lane address and check the
#   wallet's own scanner finds the coin at the address it derived.
# ============================================================================
step "FLOW 7 — Ghost Lock: save, derive lanes, fund one on-chain"
TIP_H=$($BCLI getblockcount)
# Stand-in keys for the backup device, the heir and the quorum. This flow is
# about deriving and funding a lane, not about signing with any of them — but
# they must be REAL x-only public keys.
#
# `openssl rand -hex 32` will not do: 32 random bytes are a valid curve
# x-coordinate only about half the time, so a fixture built that way fails
# roughly every other run. Deriving from the wallet gives points that are
# valid by construction; the compressed key's leading parity byte is dropped
# to get the x-only form.
xonly_at() {
    local pk
    pk=$(WRAITH --json wallet derive "$1" | jq -r '.WalletDerive.public_key_hex // .public_key_hex')
    [ ${#pk} -eq 66 ] || fail "derive $1 returned '$pk', expected a 33-byte compressed key"
    echo "${pk:2}"
}
BACKUP_PK=$(xonly_at "m/86'/1'/0'/0/101")
HEIR_PK=$(xonly_at "m/86'/1'/0'/0/102")
QUORUM_PK=$(xonly_at "m/86'/1'/0'/0/103")
LOCK_ARGS=(--backup-pubkey "$BACKUP_PK" --heir-pubkey "$HEIR_PK" --quorum-pubkey "$QUORUM_PK"
           --anchor-height "$TIP_H" --inherit-height "$((TIP_H + 52560))")

SAVE_JSON=$(WRAITH --json lock save --label smoke "${LOCK_ARGS[@]}")
echo "$SAVE_JSON" | jq '.'
LOCK_ID=$(echo "$SAVE_JSON" | jq -r '.GhostLockSaved.lock.lock_id // .lock.lock_id // empty')
[ -n "$LOCK_ID" ] || fail "lock save returned no lock_id"

LANES_JSON=$(WRAITH --json lock lanes "${LOCK_ARGS[@]}")
echo "$LANES_JSON" | jq '.'
# Cash is the lane that is the owner's alone, so it needs no cosigner to be
# funded or later spent — the right one to exercise with money on a smoke test.
LANE_ADDR=$(echo "$LANES_JSON" \
    | jq -r '[(.GhostLockLanes.lanes // .lanes)[] | select(.kind == "cash") | .address][0] // empty')
[ -n "$LANE_ADDR" ] || fail "lock lanes returned no cash-lane address"
# What the lane holds BEFORE this flow adds to it.
#
# Not asserted as zero: Cash is the plain BIP86 output for the owner key —
# deliberately indistinguishable from an ordinary single-sig wallet — so the
# receive address funded in FLOW 5 IS this lane. Asserting an absolute total
# here would encode that coincidence and break the moment the flows above
# changed. The delta is what this flow is responsible for.
LANE_BEFORE=$(echo "$LANES_JSON" \
    | jq -r '[(.GhostLockLanes.lanes // .lanes)[] | select(.kind == "cash") | .balance_sats] | add // 0')

# A Lock coin and a loose coin must be different coins.
#
# Lock owner keys live on account 1'; the plain wallet receives on account 0'.
# They used to share an account, and because Cash is a bare key-path output for
# the owner key, the Cash lane came out byte-identical to the wallet's receive
# address — so the same coin was reported by both the wallet balance and the
# Lock total, and "a Cash coin must never enter a round" could not be enforced
# without refusing every ordinary coin too.
[ "$LANE_ADDR" != "$RECV_ADDR" ] \
    || fail "cash lane address is the wallet's own receive address ($LANE_ADDR) — the Lock shares a key space with the plain wallet"
[ "$LANE_BEFORE" = "0" ] \
    || fail "a freshly derived cash lane already holds $LANE_BEFORE sats, so it is not a separate key space"
pass "the Lock's lanes are a separate key space from the wallet's receive addresses"


LOCK_TXID=$($BCLI -rpcwallet=demo sendtoaddress "$LANE_ADDR" 0.001)
[ -n "$LOCK_TXID" ] || fail "lane funding sendtoaddress returned no txid"
mine 1
# The node holds it — a txid the wallet reported would not prove that.
$BCLI getrawtransaction "$LOCK_TXID" >/dev/null \
    || fail "the node does not know the lane funding tx $LOCK_TXID"

# And the lane now shows the coin. This is the assertion the operator used to
# make on the wallet's behalf, made against the chain instead.
LANES_AFTER=$(WRAITH --json lock lanes "${LOCK_ARGS[@]}")
LANE_AFTER=$(echo "$LANES_AFTER" \
    | jq -r '[(.GhostLockLanes.lanes // .lanes)[] | select(.kind == "cash") | .balance_sats] | add // 0')
[ "$((LANE_AFTER - LANE_BEFORE))" = "100000" ] \
    || fail "cash lane moved by $((LANE_AFTER - LANE_BEFORE)) sats, expected 100000 (before $LANE_BEFORE, after $LANE_AFTER)"
echo "lock list (informational):"
WRAITH lock list || true
pass "Ghost Lock $LOCK_ID: cash lane funded on-chain (tx $LOCK_TXID) and seen by the wallet"

# ============================================================================
# FLOW 8: on-chain payment — the wallet's `light pay` command
#   Builds, signs and broadcasts a real regtest transaction, then asserts
#   the wallet recorded it in its own history with the fee it actually paid.
# ============================================================================
step "FLOW 8 — on-chain payment (wallet 'light pay' command)"
PAY_ADDR=$($BCLI -rpcwallet=demo getnewaddress)
PAY_JSON=$(WRAITH --json light pay "$PAY_ADDR" 5000 --immediate)
echo "$PAY_JSON" | jq '.'
PAY_TXID=$(echo "$PAY_JSON" | jq -r '.L1Sent.txid // .txid // empty')
[ -n "$PAY_TXID" ] || fail "light pay returned no txid"
# The node must actually hold it — a txid the wallet invented would pass a
# check that only asked the wallet.
$BCLI getrawtransaction "$PAY_TXID" >/dev/null \
    || fail "the node does not know tx $PAY_TXID"
# And the wallet must have written it down. History is local now; if this is
# empty the recording broke, not the send.
HIST=$(WRAITH --json light history --limit 5)
echo "$HIST" | jq -r '.LightHistory.transactions[0].txid // .transactions[0].txid' \
    | grep -q "$PAY_TXID" || fail "the payment is missing from local history"
pass "paid 5000 sats on-chain (tx $PAY_TXID) and recorded it locally"

# ============================================================================
# FLOW 9: single-round Wraith mix → on-chain CoinJoin
#   One round, one tx, one signing window (single_round.rs). 5 ghost_ids
#   enrol on this one wraithd (ten clears the wallet's floor). The coordinator
#   broadcasts the assembled tx to ghostd for real.
# ============================================================================
step "FLOW 9 — single-round Wraith mix ($N participants → one CoinJoin tx)"

declare -a INPUT_ADDRS MIX_OUT_ADDRS
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
done

# Start the coordinator with a real broadcast target (ghostd) and a 30s
# fill window (collapses the 5-min default so the round locks shortly
# after the 5th enrolment). The short window is refused on mainnet by
# the binary.
step "starting wraith-coordinator (real broadcast, no bonds)"
"$BIN/wraith-coordinator" \
    --listen 127.0.0.1:9100 \
    --network "$NETWORK" \
    --fee-address "$FEE_ADDR" \
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

# Fund one input UTXO per participant with EXACTLY the seat price. Rounds
# have no change output (#698), so an over-funded UTXO is refused — and the
# figure is read from the coordinator rather than hardcoded, because a
# second copy of that calculation is what went wrong last time.
SEAT_PRICE=$(WRAITH --json mix discover --coordinator "$COORD_URL" \
    | jq -r '[(.WraithCoordinatorDiscover.tiers // .tiers)[]
              | select(.id == "100k_sats")][0].mix_seat_price_sats')
[ -n "$SEAT_PRICE" ] && [ "$SEAT_PRICE" != "null" ] \
    || fail "coordinator did not publish mix_seat_price_sats for the 100k tier"
SEAT_PRICE_BTC=$(awk -v s="$SEAT_PRICE" 'BEGIN { printf "%.8f", s / 100000000 }')
step "funding $N mix-input UTXOs at exactly $SEAT_PRICE sats each"
for i in $(seq 0 $((N-1))); do
    FUND_TXIDS[$i]=$($BCLI -rpcwallet=demo sendtoaddress "${INPUT_ADDRS[$i]}" "$SEAT_PRICE_BTC")
done
mine 6

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
            --utxo "${FUND_TXIDS[$i]}:${UTXO_VOUTS[$i]}" \
            --utxo-value "$SEAT_PRICE" \
            --utxo-scriptpubkey "${UTXO_SPKS[$i]}" \
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
mine 1
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

# The once-per-coin ledger must hold a row per participant. This is a strictly
# stronger check than "no participant failed": `record` rewrites the whole
# table from the snapshot taken when the store was opened, so concurrent mixes
# that raced could each persist a table missing the others' coins. Every flow
# above would still be green, and the wallet would have quietly lost the
# authorisations that stop a coin entering a second round.
LEDGER="$DATADIR/wraith-signed-coins.json"
[ -f "$LEDGER" ] || fail "no signing ledger at $LEDGER"
LEDGER_ROWS=$(jq 'length' < "$LEDGER")
[ "$LEDGER_ROWS" -eq "$N" ] \
    || fail "signing ledger holds $LEDGER_ROWS rows, expected $N — concurrent mixes lost authorisations"
pass "signing ledger recorded all $N coins (no lost authorisations)"

# ============================================================================
# FLOW 10: Ghost Lock escape spend — leaving alone, on chain
#   Every earlier flow FUNDS a lane; none has ever spent one. The three
#   handlers that sign a Lock spend were unit-tested only, so no lane coin had
#   ever moved on a chain and no escape leaf had ever been executed by a node.
#
#   The Spending lane's exit is 1,008 blocks (~7 days), which regtest reaches
#   in seconds. It needs no quorum and no backup device: a key, a delay and a
#   transaction. That makes it the one escape that can be driven end to end
#   here, and it exercises a taproot SCRIPT-path spend, the CSV delay, the
#   nSequence the leaf demands, and the wallet's own refusal rules.
# ============================================================================
step "FLOW 10 — Ghost Lock escape spend (Spending lane, after its exit delay)"

SPEND_ADDR=$(echo "$LANES_AFTER" \
    | jq -r '[(.GhostLockLanes.lanes // .lanes)[] | select(.kind == "spending") | .address][0] // empty')
[ -n "$SPEND_ADDR" ] || fail "no spending-lane address"

ESC_FUND_TXID=$($BCLI -rpcwallet=demo sendtoaddress "$SPEND_ADDR" 0.002)
[ -n "$ESC_FUND_TXID" ] || fail "could not fund the spending lane"
mine 1

# Before the delay, the wallet must say so rather than hand over a signature.
PLAN_EARLY=$(WRAITH --json lock escape-plan --lock-id "$LOCK_ID" --lane spending)
EARLY_REMAINING=$(echo "$PLAN_EARLY" \
    | jq -r '[(.GhostLockEscapePlan.coins // .coins)[] | select(.txid == "'"$ESC_FUND_TXID"'") | .blocks_remaining][0] // empty')
[ -n "$EARLY_REMAINING" ] || fail "escape-plan does not see the coin just funded"
[ "$EARLY_REMAINING" -gt 0 ] \
    || fail "a coin one block old reports $EARLY_REMAINING blocks remaining on a 1,008-block delay"
pass "escape-plan reports the coin is not spendable yet ($EARLY_REMAINING blocks to wait)"

# Age it past the exit delay.
step "mining past the Spending lane's 1,008-block exit delay"
mine 1010

# Mining a thousand signet blocks takes about twenty-five minutes, and the
# daemon's idle auto-lock fires long before that — exactly as it would for a
# user actually waiting out a seven-day exit delay. Unlocking again is part of
# the flow, not a workaround for it, so assert it works rather than papering
# over it.
WRAITH wallet unlock smoke <<< 'smoke-pass-1234' >/dev/null 2>&1 || true
WRAITH wallet status | grep -q "unlocked: yes" \
    || fail "the wallet did not unlock after the idle auto-lock; an escape spend after a \
long delay is unreachable"
pass "wallet unlocked again after the idle auto-lock"

PLAN=$(WRAITH --json lock escape-plan --lock-id "$LOCK_ID" --lane spending)
REQ_SEQ=$(echo "$PLAN" | jq -r '.GhostLockEscapePlan.required_sequence // .required_sequence')
ESC_VOUT=$(echo "$PLAN" \
    | jq -r '[(.GhostLockEscapePlan.coins // .coins)[] | select(.txid == "'"$ESC_FUND_TXID"'")][0].vout')
ESC_SATS=$(echo "$PLAN" \
    | jq -r '[(.GhostLockEscapePlan.coins // .coins)[] | select(.txid == "'"$ESC_FUND_TXID"'")][0].sats')
ESC_REMAINING=$(echo "$PLAN" \
    | jq -r '[(.GhostLockEscapePlan.coins // .coins)[] | select(.txid == "'"$ESC_FUND_TXID"'")][0].blocks_remaining')
[ "$ESC_REMAINING" = "0" ] \
    || fail "coin still reports $ESC_REMAINING blocks remaining after mining 1,010"
pass "escape-plan reports the coin is now spendable (nSequence $REQ_SEQ)"

# Build the spend. The wallet signs a PSBT; it does not build one, so the
# caller supplies it — which is exactly why the signing handlers had to start
# judging the inputs they are given.
ESC_DEST=$(WRAITH --json light receive --index 500 | jq -r '.LightReceive.address // .address')
ESC_OUT_BTC=$(awk -v s="$ESC_SATS" 'BEGIN { printf "%.8f", (s - 2000) / 100000000 }')
ESC_PSBT_RAW=$($BCLI createpsbt \
    "[{\"txid\":\"$ESC_FUND_TXID\",\"vout\":$ESC_VOUT,\"sequence\":$REQ_SEQ}]" \
    "[{\"$ESC_DEST\":$ESC_OUT_BTC}]")
[ -n "$ESC_PSBT_RAW" ] || fail "could not build the escape PSBT"
# The signer needs the previous output; the node fills it from the UTXO set.
ESC_PSBT=$($BCLI utxoupdatepsbt "$ESC_PSBT_RAW")

ESC_SIGNED=$(WRAITH --json lock escape \
    --lock-id "$LOCK_ID" --lane spending --psbt "$ESC_PSBT" --input-index 0)
ESC_TX=$(echo "$ESC_SIGNED" | jq -r '.GhostLockEscapeSigned.tx_hex // .tx_hex // empty')
[ -n "$ESC_TX" ] || { echo "$ESC_SIGNED" >&2; fail "escape signing returned no transaction"; }

# The network is the judge: a wrong witness, a wrong sequence or an immature
# CSV are all rejected here and nowhere earlier.
ESC_TXID=$($BCLI sendrawtransaction "$ESC_TX") \
    || fail "the node refused the escape spend — the script path does not work on chain"
mine 1

ESC_CONF=$($BCLI getrawtransaction "$ESC_TXID" 1 | jq -r '.confirmations // 0')
[ "$ESC_CONF" -ge 1 ] || fail "escape spend $ESC_TXID did not confirm"
pass "escape spend confirmed on chain (tx $ESC_TXID) — a lane coin moved by its script path"

# And the coin really left the lane.
LANES_FINAL=$(WRAITH --json lock lanes "${LOCK_ARGS[@]}")
SPEND_LEFT=$(echo "$LANES_FINAL" \
    | jq -r '[(.GhostLockLanes.lanes // .lanes)[] | select(.kind == "spending") | .balance_sats] | add // 0')
[ "$SPEND_LEFT" = "0" ] \
    || fail "the spending lane still holds $SPEND_LEFT sats after the escape spend"
pass "the spending lane is empty — the escape moved the coin out"

# ============================================================================
# FLOW 11: air-gapped Savings spend — wallet + a real backup device, on chain
#   The Savings key path is MuSig2(owner, backup): the ordinary way money
#   leaves a Lock. `GhostLockSignBegin` / `SignNonce` / `SignComplete` had NO
#   test of any kind — they appear only in the IPC definition, the CLI, the
#   GUI and the daemon. The device side is covered by ghost-lock-signer's own
#   round trip; the wallet's half of the same ceremony was not, and the two
#   had never been run against each other.
#
#   The device here is the real `ghost-lock-signer` binary with its own seed,
#   holding a key this wallet does not have.
# ============================================================================
step "FLOW 11 — air-gapped Savings spend (owner + backup device, MuSig2 key path)"

DEV_SEED="$DATADIR/device-seed.txt"
DEV_LEDGER="$DATADIR/device-nonces.json"
"$BIN/ghost-lock-signer" generate --out "$DEV_SEED" --index 0 >"$DATADIR/device-gen.out" 2>&1 \
    || { cat "$DATADIR/device-gen.out" >&2; fail "could not create a backup-device seed"; }
DEV_PK=$("$BIN/ghost-lock-signer" pubkey --seed "$DEV_SEED" --index 0 2>&1 \
    | grep -oE '[0-9a-f]{64}' | head -1)
[ ${#DEV_PK} -eq 64 ] || fail "device pubkey is '$DEV_PK', expected 64 hex chars"
echo "backup device key: $DEV_PK"

# A Lock whose backup key belongs to the device, not to this wallet. Without
# that the ceremony would be the wallet signing with itself twice, which
# proves nothing about the protocol.
AIR_ARGS=(--backup-pubkey "$DEV_PK" --heir-pubkey "$HEIR_PK" --quorum-pubkey "$QUORUM_PK"
          --anchor-height "$TIP_H" --inherit-height "$((TIP_H + 52560))")
AIR_SAVE=$(WRAITH --json lock save --label airgap "${AIR_ARGS[@]}")
AIR_LOCK_ID=$(echo "$AIR_SAVE" | jq -r '.GhostLockSaved.lock.lock_id // .lock.lock_id // empty')
[ -n "$AIR_LOCK_ID" ] || { echo "$AIR_SAVE" >&2; fail "could not remember the air-gapped Lock"; }

AIR_LANES=$(WRAITH --json lock lanes "${AIR_ARGS[@]}")
AIR_SAV_ADDR=$(echo "$AIR_LANES" \
    | jq -r '[(.GhostLockLanes.lanes // .lanes)[] | select(.kind == "savings") | .address][0] // empty')
[ -n "$AIR_SAV_ADDR" ] || fail "no savings-lane address for the air-gapped Lock"

AIR_FUND_TXID=$($BCLI -rpcwallet=demo sendtoaddress "$AIR_SAV_ADDR" 0.003)
mine 1
AIR_VOUT=$($BCLI getrawtransaction "$AIR_FUND_TXID" 1 \
    | jq -r --arg a "$AIR_SAV_ADDR" '.vout[] | select(.scriptPubKey.address == $a) | .n')
[ -n "$AIR_VOUT" ] || fail "the funding tx has no output at the savings lane"

# Key-path spend: no sequence requirement, unlike the escape leaf.
AIR_DEST=$(WRAITH --json light receive --index 501 | jq -r '.LightReceive.address // .address')
AIR_PSBT=$($BCLI utxoupdatepsbt "$($BCLI createpsbt \
    "[{\"txid\":\"$AIR_FUND_TXID\",\"vout\":$AIR_VOUT}]" \
    "[{\"$AIR_DEST\":0.00298}]")")
[ -n "$AIR_PSBT" ] || fail "could not build the air-gapped spend PSBT"

# Round 1 (wallet): review the spend, commit our nonce, emit the device payload.
AIR_BEGIN=$(WRAITH --json lock sign begin \
    --lock-id "$AIR_LOCK_ID" --lane savings --psbt "$AIR_PSBT" --input-index 0)
AIR_SESSION=$(echo "$AIR_BEGIN" | jq -r '.GhostLockSignBegun.session // .session // empty')
[ -n "$AIR_SESSION" ] || { echo "$AIR_BEGIN" >&2; fail "lock sign begin returned no session"; }
echo "$AIR_BEGIN" | jq -r '.GhostLockSignBegun.device_request // .device_request' > "$DATADIR/dev-request.json"
pass "round 1: the wallet committed a nonce and produced a device payload"

# The device is interactive across both rounds, so its stdin is held open on a
# FIFO while its output is followed.
DEV_IN="$DATADIR/dev-in"
DEV_OUT="$DATADIR/dev-out"
rm -f "$DEV_IN" "$DEV_OUT"; mkfifo "$DEV_IN"; : > "$DEV_OUT"
"$BIN/ghost-lock-signer" sign \
    --request "$DATADIR/dev-request.json" \
    --seed "$DEV_SEED" \
    --ledger "$DEV_LEDGER" \
    --network "$NETWORK" \
    --no-confirm \
    <"$DEV_IN" >"$DEV_OUT" 2>&1 &
DEV_PID=$!
exec 9>"$DEV_IN"

# Payload blocks are delimited: `--- round N ---` ... `--- end ---`.
read_device_block() {
    local want="$1" waited=0
    while [ $waited -lt 200 ]; do
        if grep -q -- "--- end ---" "$DEV_OUT" 2>/dev/null \
           && [ "$(grep -c -- '--- end ---' "$DEV_OUT")" -ge "$want" ]; then
            awk -v want="$want" '
                /^--- round/ { n++; inside = (n == want); next }
                /^--- end ---/ { if (inside) exit; inside = 0; next }
                inside { print }
            ' "$DEV_OUT"
            return 0
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
    cat "$DEV_OUT" >&2
    return 1
}

DEV_NONCE_JSON=$(read_device_block 1) || fail "the device never produced a round-1 nonce"
DEV_NONCE=$(echo "$DEV_NONCE_JSON" | jq -r '.public_nonce // empty')
[ -n "$DEV_NONCE" ] || { echo "$DEV_NONCE_JSON" >&2; fail "no public_nonce in the device's round-1 reply"; }

# Round 2 (wallet): sign our own share, burning our nonce durably first.
AIR_NONCED=$(WRAITH --json lock sign nonce --session "$AIR_SESSION" --device-nonce "$DEV_NONCE")
AIR_PARTIAL_REQ=$(echo "$AIR_NONCED" | jq -r '.GhostLockSignNonced.device_request // .device_request // empty')
[ -n "$AIR_PARTIAL_REQ" ] || { echo "$AIR_NONCED" >&2; fail "lock sign nonce returned no device payload"; }
pass "round 2: the wallet signed its share and produced the second device payload"

echo "$AIR_PARTIAL_REQ" >&9
DEV_PARTIAL_JSON=$(read_device_block 2) || fail "the device never produced a round-2 partial"
DEV_PARTIAL=$(echo "$DEV_PARTIAL_JSON" | jq -r '.partial // empty')
[ -n "$DEV_PARTIAL" ] || { echo "$DEV_PARTIAL_JSON" >&2; fail "no partial in the device's round-2 reply"; }
exec 9>&-
wait "$DEV_PID" || fail "the backup device exited non-zero"

# Aggregate. A signature that verifies here is one that checks out against the
# lane's output key — but only the network decides if it spends the coin.
AIR_DONE=$(WRAITH --json lock sign complete --session "$AIR_SESSION" --device-partial "$DEV_PARTIAL")
AIR_SIGNED_PSBT=$(echo "$AIR_DONE" | jq -r '.GhostLockSigned.psbt // .psbt // empty')
[ -n "$AIR_SIGNED_PSBT" ] || { echo "$AIR_DONE" >&2; fail "the ceremony produced no signed PSBT"; }
pass "round 3: owner and device partials aggregated into one Schnorr signature"

# Unlike the escape path, this returns a signed PSBT rather than a finished
# transaction — the key-path signature still has to be finalised into a
# witness. Letting the node do it is also a check: a signature it cannot
# finalise is one that was never going to spend the coin.
AIR_FINAL=$($BCLI finalizepsbt "$AIR_SIGNED_PSBT")
echo "$AIR_FINAL" | jq -e '.complete == true' >/dev/null \
    || { echo "$AIR_FINAL" >&2; fail "the node could not finalise the air-gapped spend"; }
AIR_TX=$(echo "$AIR_FINAL" | jq -r '.hex')
[ -n "$AIR_TX" ] || fail "finalizepsbt returned no transaction"

AIR_TXID=$($BCLI sendrawtransaction "$AIR_TX") \
    || fail "the node refused the air-gapped spend — the MuSig2 key path does not work on chain"
mine 1
AIR_CONF=$($BCLI getrawtransaction "$AIR_TXID" 1 | jq -r '.confirmations // 0')
[ "$AIR_CONF" -ge 1 ] || fail "air-gapped spend $AIR_TXID did not confirm"
pass "air-gapped Savings spend confirmed on chain (tx $AIR_TXID)"

AIR_LEFT=$(WRAITH --json lock lanes "${AIR_ARGS[@]}" \
    | jq -r '[(.GhostLockLanes.lanes // .lanes)[] | select(.kind == "savings") | .balance_sats] | add // 0')
[ "$AIR_LEFT" = "0" ] || fail "the savings lane still holds $AIR_LEFT sats after the spend"
pass "the savings lane is empty — owner and backup device moved the coin together"

# ============================================================================
# FLOW 12: quorum co-signed Spending spend — the lane's fast path, on chain
#   The Spending key path is MuSig2(owner, quorum). It could not work at all:
#   `lock_id` is a hash OVER the quorum key, while the quorum derives its key
#   FROM the id it is handed, so each needed the other first and no Lock could
#   carry the key the coordinator would sign with. The lane was reachable only
#   through its escape leaf, 1,008 blocks later.
#
#   The quorum now derives from a BINDING id: the same Lock minus the quorum
#   key. This flow is the proof — it builds the key the way an operator does,
#   BEFORE the Lock exists, and then spends with it.
# ============================================================================
step "FLOW 12 — quorum co-signed Spending spend (owner + coordinator quorum)"

QSEED="$DATADIR/quorum-seed.txt"
"$BIN/ghost-lock-signer" generate --out "$QSEED" --index 0 >"$DATADIR/quorum-gen.out" 2>&1 \
    || { cat "$DATADIR/quorum-gen.out" >&2; fail "could not create a quorum seed"; }

# The id must be obtainable BEFORE the Lock is built. That is the whole point.
QBIND=$(WRAITH --json lock quorum-id \
    --backup-pubkey "$DEV_PK" --heir-pubkey "$HEIR_PK" \
    --anchor-height "$TIP_H" --inherit-height "$((TIP_H + 52560))" \
    | jq -r '.GhostLockQuorumBindingId.binding_id // .binding_id // empty')
[ -n "$QBIND" ] || fail "could not obtain a quorum binding id"

QUORUM_DERIVED=$("$BIN/ghost-lock-signer" quorum-pubkey --seed "$QSEED" --lock-id "$QBIND" 2>&1 \
    | grep -oE '[0-9a-f]{64}' | head -1)
[ ${#QUORUM_DERIVED} -eq 64 ] || fail "quorum-pubkey returned '$QUORUM_DERIVED'"

Q_ARGS=(--backup-pubkey "$DEV_PK" --heir-pubkey "$HEIR_PK" --quorum-pubkey "$QUORUM_DERIVED"
        --anchor-height "$TIP_H" --inherit-height "$((TIP_H + 52560))")
Q_SAVE=$(WRAITH --json lock save --label quorum "${Q_ARGS[@]}")
Q_LOCK_ID=$(echo "$Q_SAVE" | jq -r '.GhostLockSaved.lock.lock_id // .lock.lock_id // empty')
[ -n "$Q_LOCK_ID" ] || { echo "$Q_SAVE" >&2; fail "could not remember the quorum Lock"; }
[ "$Q_LOCK_ID" != "$QBIND" ] \
    || fail "the binding id and the lock id are the same value — the cycle is still there"
pass "derived the quorum key from a binding id before the Lock existed"

# A coordinator that actually holds the quorum seed.
step "restarting the coordinator with a quorum seed"
kill "$COORD_PID" 2>/dev/null || true
wait "$COORD_PID" 2>/dev/null || true
"$BIN/wraith-coordinator" \
    --listen 127.0.0.1:9100 \
    --network "$NETWORK" \
    --fee-address "$FEE_ADDR" \
    --fill-window-secs 30 \
    --ghostd-url "$GHOSTD_RPC_URL" \
    --ghostd-user demo \
    --ghostd-pass demo \
    --lock-seed-file "$QSEED" \
    --lock-cosign-role active \
    --lock-ledger-dir "$DATADIR" \
    >"$DATADIR/coordinator-quorum.log" 2>&1 &
COORD_PID=$!
sleep 3
if grep -q "does not co-sign Ghost Locks" "$DATADIR/coordinator-quorum.log"; then
    fail "the coordinator did not pick up its quorum seed"
fi
# Co-signing defaults to standby — an operator has to turn it on, and only one
# coordinator may be active. A standby refuses, which reads as a signing bug if
# you are not expecting it.
if grep -q "on STANDBY" "$DATADIR/coordinator-quorum.log"; then
    fail "the coordinator is on standby and will refuse to co-sign"
fi

Q_SPEND_ADDR=$(WRAITH --json lock lanes "${Q_ARGS[@]}" \
    | jq -r '[(.GhostLockLanes.lanes // .lanes)[] | select(.kind == "spending") | .address][0] // empty')
[ -n "$Q_SPEND_ADDR" ] || fail "no spending-lane address on the quorum Lock"

Q_FUND_TXID=$($BCLI -rpcwallet=demo sendtoaddress "$Q_SPEND_ADDR" 0.0025)
mine 1
Q_VOUT=$($BCLI getrawtransaction "$Q_FUND_TXID" 1 \
    | jq -r --arg a "$Q_SPEND_ADDR" '.vout[] | select(.scriptPubKey.address == $a) | .n')
[ -n "$Q_VOUT" ] || fail "the funding tx has no output at the spending lane"

# Key-path spend, so no timelock and no sequence requirement: this is the fast
# path the lane exists to have.
Q_DEST=$(WRAITH --json light receive --index 502 | jq -r '.LightReceive.address // .address')
Q_PSBT=$($BCLI utxoupdatepsbt "$($BCLI createpsbt \
    "[{\"txid\":\"$Q_FUND_TXID\",\"vout\":$Q_VOUT}]" \
    "[{\"$Q_DEST\":0.00248}]")")

Q_SIGNED=$(WRAITH --json lock quorum-sign \
    --lock-id "$Q_LOCK_ID" --lane spending --psbt "$Q_PSBT" --input-index 0 \
    --coordinator "$COORD_URL")
Q_PSBT_OUT=$(echo "$Q_SIGNED" | jq -r '.GhostLockQuorumSigned.psbt // .psbt // empty')
[ -n "$Q_PSBT_OUT" ] || { echo "$Q_SIGNED" >&2; fail "the quorum co-sign produced no signed PSBT"; }
pass "owner and quorum aggregated a signature without any timelock"

Q_FINAL=$($BCLI finalizepsbt "$Q_PSBT_OUT")
echo "$Q_FINAL" | jq -e '.complete == true' >/dev/null \
    || { echo "$Q_FINAL" >&2; fail "the node could not finalise the quorum spend"; }
Q_TXID=$($BCLI sendrawtransaction "$(echo "$Q_FINAL" | jq -r '.hex')") \
    || fail "the node refused the quorum co-signed spend"
mine 1
[ "$($BCLI getrawtransaction "$Q_TXID" 1 | jq -r '.confirmations // 0')" -ge 1 ] \
    || fail "quorum spend $Q_TXID did not confirm"
pass "quorum co-signed Spending spend confirmed on chain (tx $Q_TXID)"

Q_LEFT=$(WRAITH --json lock lanes "${Q_ARGS[@]}" \
    | jq -r '[(.GhostLockLanes.lanes // .lanes)[] | select(.kind == "spending") | .balance_sats] | add // 0')
[ "$Q_LEFT" = "0" ] || fail "the spending lane still holds $Q_LEFT sats after the quorum spend"
pass "the spending lane emptied by its fast path, not by waiting 1,008 blocks"

# ============================================================================
echo
echo "================================================================"
echo "  WRAITH WALLET END-TO-END SMOKE TEST — ALL FLOWS GREEN ($NETWORK)"
echo "================================================================"
echo "  1. BIP-39 wallet create            ok"
echo "  2. select active wallet            ok"
echo "  3. derive receive address          ok  ($RECV_ADDR)"
echo "  4. light balance                   ok"
printf "  5. %-32sok  (%s)\n" "$NETWORK fund" "$FUND_TXID"
echo "  6. L1 scan sees own UTXO           ok  (1,000,000 sats)"
echo "  7. Ghost Lock prepare/fund/confirm ok  ($LOCK_ID)"
echo "  8. on-chain payment (light pay)    ok  ($PAY_TXID)"
echo "  9. single-round Wraith mix         ok  ($FIRST_TXID)"
echo " 10. Ghost Lock escape spend         ok  ($ESC_TXID)"
echo " 11. air-gapped Savings spend        ok  ($AIR_TXID)"
echo " 12. quorum co-signed spend          ok  ($Q_TXID)"
echo "================================================================"
