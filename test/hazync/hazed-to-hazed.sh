#!/usr/bin/env bash
# Two hazed nodes, talking to each other, on regtest.
#
# A hazed node serves GHOST_STRIPPED_BLOCK to any peer advertising NODE_GHOST_HAZE, so two hazed
# nodes exercise the whole path — serve, transfer, receive — without touching mainnet. Regtest keeps
# it to seconds rather than the minutes a mainnet sync costs.
#
# WHAT THIS IS FOR. The receive path decides what a node may do with structural data from a peer,
# and that decision cannot be tested with one node. It answers a question the documentation and the
# code disagree about: whether a hazed node can actually sync from another hazed node.
#
# Usage: GHOSTD=/path/to/ghostd ./test/hazync/hazed-to-hazed.sh
set -uo pipefail

GHOSTD="${GHOSTD:-}"
[ -x "$GHOSTD" ] || { echo "set GHOSTD=<path to ghostd>" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 2; }

pass=0; fail=0
ok(){  echo "  ok    $1"; pass=$((pass+1)); }
bad(){ echo "  FAIL  $1"; fail=$((fail+1)); }
note(){ echo "  --    $1"; }

DD_A=$(mktemp -d); DD_B=$(mktemp -d)
PID_A=""; PID_B=""
# ⚠ With -listen=1 the node also binds 127.0.0.1:<port+1> for the Tor onion listener, so an RPC port
# adjacent to the P2P port collides and the node exits with "Failed to listen on any port".
P2P_A=19444; RPC_A=19999; RPC_B=19998
cleanup(){
    [ -n "$PID_B" ] && { kill "$PID_B" 2>/dev/null; wait "$PID_B" 2>/dev/null; }
    [ -n "$PID_A" ] && { kill "$PID_A" 2>/dev/null; wait "$PID_A" 2>/dev/null; }
    rm -rf "$DD_A" "$DD_B"
}
trap cleanup EXIT

rpc(){ # rpc <port> <body>
    curl -s --max-time 60 --user t:t --data-binary "$2" \
        -H 'content-type: text/plain;' "http://127.0.0.1:$1/" 2>/dev/null
}
jq_(){ python3 -c "import sys,json
try: r=json.load(sys.stdin)['result']
except Exception: print('none'); sys.exit()
if r is None: print('none'); sys.exit()
$1"; }
height(){ rpc "$1" '{"jsonrpc":"1.0","id":"t","method":"getblockchaininfo","params":[]}' | jq_ "print(r['blocks'])"; }

wait_rpc(){ for i in $(seq 1 60); do [ "$(height "$1")" != "none" ] && return 0; sleep 1; done; return 1; }

echo "Ghost Haze — hazed node syncing from a hazed node (regtest)"

# ── node A: hazed, with a chain ────────────────────────────────────────────────────────────────
"$GHOSTD" -regtest -datadir="$DD_A" -printtoconsole=1 -server=1 -hazemode=hazed \
    -port=$P2P_A -rpcport=$RPC_A -rpcuser=t -rpcpassword=t -listen=1 -discover=0 \
    >"$DD_A/debug.out" 2>&1 &
PID_A=$!
wait_rpc $RPC_A || { bad "node A never started"; tail -10 "$DD_A/debug.out" | sed 's/^/    /'; echo; echo "passed $pass, failed $fail"; exit 1; }
ok "node A started (hazed, regtest)"

# A fixed P2WPKH regtest address (BIP173 test vector key), so this needs no wallet build.
ADDR="bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
rpc $RPC_A "{\"jsonrpc\":\"1.0\",\"id\":\"t\",\"method\":\"generatetoaddress\",\"params\":[120,\"$ADDR\"]}" >/dev/null
HA=$(height $RPC_A)
[ "${HA:-0}" -ge 100 ] 2>/dev/null \
    && ok "node A mined to height $HA" \
    || { bad "node A did not mine (height $HA) — no wallet, or generatetoaddress failed"
         tail -6 "$DD_A/debug.out" | sed 's/^/    /'; echo; echo "passed $pass, failed $fail"; exit 1; }

grep -q "Ghost Exorcism initialized in HAZED mode" "$DD_A/debug.out" \
    && ok "node A is hazed — it holds only stripped storage to serve" \
    || bad "node A is not hazed; this tests nothing"

# ── node B: hazed, empty, pointed at A ─────────────────────────────────────────────────────────
"$GHOSTD" -regtest -datadir="$DD_B" -printtoconsole=1 -server=1 -hazemode=hazed \
    -rpcport=$RPC_B -rpcuser=t -rpcpassword=t -listen=0 -discover=0 \
    -connect=127.0.0.1:$P2P_A \
    >"$DD_B/debug.out" 2>&1 &
PID_B=$!
wait_rpc $RPC_B || { bad "node B never started"; tail -10 "$DD_B/debug.out" | sed 's/^/    /'; echo; echo "passed $pass, failed $fail"; exit 1; }
ok "node B started (hazed, empty) and pointed at A"

# Give them time to handshake, exchange headers, and attempt block transfer.
for i in $(seq 1 60); do
    HB=$(height $RPC_B)
    [ "${HB:-0}" -ge "$HA" ] 2>/dev/null && break
    sleep 1
done
HB=$(height $RPC_B)

PEERS=$(rpc $RPC_B '{"jsonrpc":"1.0","id":"t","method":"getpeerinfo","params":[]}' | jq_ "print(len(r))")
[ "${PEERS:-0}" -ge 1 ] 2>/dev/null \
    && ok "node B is connected to A ($PEERS peer)" \
    || bad "node B never connected to A"

HEADERS_B=$(rpc $RPC_B '{"jsonrpc":"1.0","id":"t","method":"getblockchaininfo","params":[]}' | jq_ "print(r['headers'])")
[ "${HEADERS_B:-0}" -ge "$HA" ] 2>/dev/null \
    && ok "node B received A's headers (to $HEADERS_B) — the peering works" \
    || bad "node B did not get headers from A (got $HEADERS_B)"

# ── the actual question ────────────────────────────────────────────────────────────────────────
echo
echo "  === did stripped blocks transfer, and could B use them? ==="
# grep -c already prints 0 and exits 1 when nothing matches, so `|| echo 0` appends a second zero.
SERVED=$(grep -c "served stripped block" "$DD_A/debug.out" 2>/dev/null; true)
RECVD=$(grep -c "received stripped block" "$DD_B/debug.out" 2>/dev/null; true)
REFUSED=$(grep -c "stripped data cannot be used to extend it" "$DD_B/debug.out" 2>/dev/null; true)
NO_NETWORK=$(grep -c "not advertising NODE_NETWORK" "$DD_A/debug.out" 2>/dev/null; true)
note "A served $SERVED, B received $RECVD, B refused-as-extension $REFUSED"
note "A height $HA, B height $HB"

# The finding this test exists to record. A hazed node cannot serve full blocks and so does not
# advertise NODE_NETWORK; block download will not select such a peer, so the stripped-block serving
# path is never even reached. Hazed sync does not fail validation — it never starts.
if [ "${RECVD:-0}" -gt 0 ]; then
    note "stripped blocks transferred ($RECVD)"
else
    ok "no stripped blocks transferred — B never asked, because A cannot advertise NODE_NETWORK"
fi
[ "${NO_NETWORK:-0}" -gt 0 ] \
    && ok "node A declines NODE_NETWORK, which is why nothing requests blocks from it" \
    || note "node A did advertise NODE_NETWORK — the reasoning above needs rechecking"

# The load-bearing conclusion: a hazed node cannot sync another hazed node, and no protocol change
# fixes it, because NEITHER PARTY HOLDS THE FULL BLOCK. The data the receiver needs does not exist
# anywhere in the exchange. Fast sync from a hazed peer is G4's job — adopt a proven UTXO set — not
# this path's.
[ "${HB:-0}" -eq 0 ] 2>/dev/null \
    && ok "node B synced NO blocks from a hazed peer — the documented expectation is wrong" \
    || note "node B reached height $HB, which contradicts the analysis and wants investigating"

# B must NOT have advanced its chain on stripped data. Whether it refuses them or simply cannot use
# them, the tip must not move on blocks whose scriptPubKeys were rewritten.
if [ "${HB:-0}" -gt 0 ] 2>/dev/null && [ "${RECVD:-0}" -gt 0 ]; then
    bad "node B advanced to height $HB using stripped blocks — UTXO construction from stripped data is unsound"
else
    ok "node B did not advance its chain on stripped data (height $HB)"
fi

# And it must not have died trying.
kill -0 "$PID_B" 2>/dev/null \
    && ok "node B is still alive" \
    || bad "node B died while handling stripped blocks"
grep -q "A fatal internal error" "$DD_B/debug.out" \
    && bad "node B hit a fatal internal error" \
    || ok "no fatal error on node B"

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
