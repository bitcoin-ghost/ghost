#!/usr/bin/env bash
# End-to-end adoption of a proven UTXO set, against the real mainnet header chain.
#
# WHY THIS NEEDS THE NETWORK, and why that is not avoidable. Adoption requires the proof's base
# block to already be in this node's headers chain, and the Hazync guest compiles
# CChainParams::Main(), so there is no regtest proof to use instead. Offline, every case stops at
# the headers check — which is what test/hazync/adversarial-adoption.sh asserts, deliberately. This
# script is the other half: the cases that can only be reached with headers in hand.
#
# It does NOT download the chain. Headers sync, adoption, and a restart; blocks below the base are
# never fetched, which is the entire point of the exercise.
#
# ⚠ Core pre-synchronises the whole header chain before committing ANY of it, so `headers` reads 0
# for several minutes and then jumps. Adoption cannot happen during that window. Budget ~5 minutes
# for the first run; restarts are fast because the header index is already on disk.
#
# Usage: GHOSTD=/path/to/ghostd ./test/hazync/adoption-live.sh <artefact-dir>
#   artefact-dir needs: fold_8.snark, dump_h8.bin
set -uo pipefail

GHOSTD="${GHOSTD:-}"
ART="${1:-}"
PORT="${RPCPORT:-18906}"
[ -x "$GHOSTD" ] || { echo "set GHOSTD=<path to ghostd>" >&2; exit 2; }
[ -d "$ART" ]    || { echo "usage: $0 <artefact-dir>" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 2; }

pass=0; fail=0
ok(){   echo "  ok    $1"; pass=$((pass+1)); }
bad(){  echo "  FAIL  $1"; fail=$((fail+1)); }
check(){ # check <name> <expected> <actual>
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

DD=$(mktemp -d)
PID=""
cleanup(){ [ -n "$PID" ] && { kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; }; rm -rf "$DD"; }
trap cleanup EXIT

ARMED=(-hazyncadopt=1 -hazyncproof="$ART/fold_8.snark" -hazyncutxo="$ART/dump_h8.bin")

rpc(){ curl -s --max-time 30 --user t:t --data-binary "$1" \
        -H 'content-type: text/plain;' "http://127.0.0.1:$PORT/" 2>/dev/null; }
# A null result means the node is still warming up, or the call legitimately found nothing (gettxout
# on a missing coin). Both collapse to 'none' rather than a traceback, so that genuine errors stay
# visible instead of being lost among expected ones.
jq_(){ python3 -c "import sys,json
try: r=json.load(sys.stdin)['result']
except Exception: print('none'); sys.exit()
if r is None: print('none'); sys.exit()
$1"; }

start(){ # start <logfile> <args...>
    local log="$1"; shift
    "$GHOSTD" -datadir="$DD" -printtoconsole=1 -server=1 -listen=0 -maxconnections=8 \
        -rpcport="$PORT" -rpcuser=t -rpcpassword=t "$@" >"$log" 2>&1 &
    PID=$!
}
stop(){ [ -n "$PID" ] && { kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; }; PID=""; }

# blocks + whether the node says it is standing on the proof
state(){ rpc '{"jsonrpc":"1.0","id":"t","method":"getblockchaininfo","params":[]}' \
    | jq_ "print(r['blocks'], r.get('hazync',{}).get('actedon'))"; }

echo "Hazync adoption — live, against the real header chain"

# ── run 1: sync headers, then adopt ────────────────────────────────────────────────────────────
start "$DD/run1.log" "${ARMED[@]}"
H=-1
for i in $(seq 1 600); do
    H=$(rpc '{"jsonrpc":"1.0","id":"t","method":"getblockchaininfo","params":[]}' \
        | jq_ "print(r['headers'])")
    [ "${H:--1}" -gt 8 ] 2>/dev/null && break
    sleep 1
done
if ! [ "${H:--1}" -gt 8 ] 2>/dev/null; then
    bad "headers never passed the proven height (got '$H') — no peers?"
    echo "passed $pass, failed $fail"; exit 1
fi
ok "headers reached $H (pre-sync completed)"

ADOPT=$(rpc '{"jsonrpc":"1.0","id":"t","method":"hazyncadoptsnapshot","params":[]}')
check "adoption loads exactly the proven number of coins" "8" \
    "$(printf '%s' "$ADOPT" | jq_ "print(r['coins_loaded'])")"
check "adoption bases the chainstate on the proven tip" \
    "00000000408c48f847aa786c2268fc3e6ec2af68e8468a34a28c61b7f1de0dc6" \
    "$(printf '%s' "$ADOPT" | jq_ "print(r['tip_hash'])")"
check "the node is now at the proven height, and says it acted on the proof" "8 True" "$(state)"

# The set must be the proven one, not merely the right size: a coin inside the proof's range is
# present, and the first coin past it is absent. Both, because either alone is weak.
check "a coin from inside the proven range is in the chainstate (block 1 coinbase)" "50.0 True" \
    "$(rpc '{"jsonrpc":"1.0","id":"t","method":"gettxout","params":["0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",0]}' \
        | jq_ "print(r['value'], r['coinbase']) if r else print('none')")"
check "the first coin PAST the proven range is absent (block 9 coinbase)" "none" \
    "$(rpc '{"jsonrpc":"1.0","id":"t","method":"gettxout","params":["0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9",0]}' \
        | jq_ "print('none' if r is None else 'present')")"

grep -q "disabling background IBD" "$DD/run1.log" \
    && ok "background validation was disabled, not left to re-download the chain" \
    || bad "background IBD was not disabled"
stop

# ── run 2: restart WITH the proof ──────────────────────────────────────────────────────────────
#
# ⚠ This is the case that caught a real abort. Reporting SUCCESS from
# MaybeCompleteSnapshotValidation made node/chainstate.cpp PROMOTE the snapshot to an ordinary
# chainstate, which discards the marker that bootstraps m_chain_tx_count at the base; the base then
# never enters setBlockIndexCandidates and the node died in PruneBlockIndexCandidates. A restart
# that merely "starts" is not enough to assert — it has to come back up ON the adopted chainstate.
start "$DD/run2.log" "${ARMED[@]}"
R="none"
for i in $(seq 1 120); do R=$(state); [ "$R" != "none" ] && break; sleep 1; done
check "restarting with the proof comes back up on the adopted chainstate" "8 True" "$R"
grep -q "nothing to complete" "$DD/run2.log" \
    && ok "the snapshot is not promoted — the chain below the base was never validated here" \
    || bad "expected the completion path to decline to promote the snapshot"
stop

# ── run 3: restart WITHOUT the proof ───────────────────────────────────────────────────────────
#
# The exemption is re-earned on every start, never read back from disk as a settled fact. A node
# that adopted yesterday and lost its proof must stop and say so, not carry on serving a chainstate
# it can no longer justify.
start "$DD/run3.log"
sleep 25
stop
grep -q "Assumeutxo data not found for the given blockhash" "$DD/run3.log" \
    && ok "restarting without the proof is refused, with the reason stated" \
    || bad "expected a stated refusal when the proof is absent"
grep -q "restart with the same -hazyncadopt" "$DD/run3.log" \
    && ok "the refusal names the remedy" \
    || bad "the refusal does not tell the operator how to recover"
# Asserted as an absence: the danger is not a noisy failure, it is a quiet success.
if grep -qE "successfully activated snapshot|ADOPTED the proven" "$DD/run3.log"; then
    bad "the node came up on the adopted chainstate WITHOUT the proof"
else
    ok "the node did not come up on the adopted chainstate without the proof"
fi

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
