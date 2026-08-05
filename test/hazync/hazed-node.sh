#!/usr/bin/env bash
# Exercise Ghost Haze against a real hazed mainnet node.
#
# WHY THIS IS NOT A UNIT TEST. Everything here needs a node that is genuinely hazed — one where
# exorcism is active from the first block, so what lands on disk is the stripped form and nothing
# else. The unit fixtures cannot produce that: they always have a chain tip, and a CChain cannot be
# emptied through its public interface, so the startup state a fresh hazed node passes through is not
# constructible in them.
#
# That gap was not academic. It hid a bug that made a fresh hazed node forget the GENESIS block and
# fail to start, while every unit test passed. Case 2 below is the regression test for it.
#
# Syncs a few thousand blocks from mainnet, so it needs network and a few minutes. It never touches
# the fleet: outbound Bitcoin P2P only, no listening socket beyond a localhost RPC port, and a
# throwaway datadir.
#
# Usage: GHOSTD=/path/to/ghostd ./test/hazync/hazed-node.sh [target-height]
set -uo pipefail

GHOSTD="${GHOSTD:-}"
TARGET="${1:-3000}"
PORT="${RPCPORT:-18913}"
[ -x "$GHOSTD" ] || { echo "set GHOSTD=<path to ghostd>" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 2; }

pass=0; fail=0
ok(){  echo "  ok    $1"; pass=$((pass+1)); }
bad(){ echo "  FAIL  $1"; fail=$((fail+1)); }

DD=$(mktemp -d)
PID=""
cleanup(){ [ -n "$PID" ] && { kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; }; rm -rf "$DD"; }
trap cleanup EXIT

rpc(){ curl -s --max-time 60 --user t:t --data-binary "$1" \
        -H 'content-type: text/plain;' "http://127.0.0.1:$PORT/" 2>/dev/null; }
jq_(){ python3 -c "import sys,json
try: r=json.load(sys.stdin)['result']
except Exception: print('none'); sys.exit()
if r is None: print('none'); sys.exit()
$1"; }

start(){ # start <logfile>
    "$GHOSTD" -datadir="$DD" -printtoconsole=1 -server=1 -listen=0 -maxconnections=12 \
        -rpcport="$PORT" -rpcuser=t -rpcpassword=t -hazemode=hazed "${@:2}" >"$1" 2>&1 &
    PID=$!
}
stop(){ [ -n "$PID" ] && { kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; }; PID=""; }

height(){ rpc '{"jsonrpc":"1.0","id":"t","method":"getblockchaininfo","params":[]}' | jq_ "print(r['blocks'])"; }

wait_for_height(){ # wait_for_height <target> <seconds>
    local want="$1" limit="$2" h
    for i in $(seq 1 "$limit"); do
        h=$(height)
        [ "${h:-none}" != "none" ] && [ "$h" -ge "$want" ] 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

echo "Ghost Haze — live hazed mainnet node"

# ── 1. it starts, and it is actually hazed ─────────────────────────────────────────────────────
start "$DD/run1.log"
if ! wait_for_height "$TARGET" 1800; then
    bad "never reached height $TARGET — no peers, or the node did not start"
    echo "  last lines:"; tail -15 "$DD/run1.log" | sed 's/^/    /'
    echo; echo "passed $pass, failed $fail"; exit 1
fi
ok "synced to height $(height)"

grep -q "Ghost Exorcism initialized in HAZED mode" "$DD/run1.log" \
    && ok "exorcism is active — hazeable content never reaches disk" \
    || bad "node is not in hazed mode; nothing below tests what it claims to"

# The point of the mode: structural storage only.
if ls "$DD/blocks"/gsb*.dat >/dev/null 2>&1; then
    ok "blocks are stored in stripped (gsb) form"
else
    bad "no gsb files — the node did not write stripped storage"
fi
# The size of blk00000.dat proves nothing: block files are preallocated in 16 MiB chunks and are
# XOR-obfuscated, so an empty one is neither small nor zero-filled. Ask the node instead — a stripped
# block cannot be served as a full block, and genesis can, because it is written whole.
GEN_HASH=$(rpc '{"jsonrpc":"1.0","id":"t","method":"getblockhash","params":[0]}' | jq_ "print(r)")
MID_HASH=$(rpc '{"jsonrpc":"1.0","id":"t","method":"getblockhash","params":[1000]}' | jq_ "print(r)")
GEN_READ=$(rpc "{\"jsonrpc\":\"1.0\",\"id\":\"t\",\"method\":\"getblock\",\"params\":[\"$GEN_HASH\"]}")
MID_READ=$(rpc "{\"jsonrpc\":\"1.0\",\"id\":\"t\",\"method\":\"getblock\",\"params\":[\"$MID_HASH\"]}")

printf '%s' "$GEN_READ" | grep -q '"error":null' \
    && ok "genesis is readable as a full block (it is written whole, by design)" \
    || bad "genesis cannot be read as a full block — a hazed node cannot connect its own first block"

# A hazed node DOES serve block 1000 — as the structural form, which is the documented behaviour.
# What must be true is that what comes back has no scriptSig, because the payload really is gone.
printf '%s' "$MID_READ" | grep -q '"error":null' \
    && ok "block 1000 is served (as the structural form, which is what a hazed node offers)" \
    || bad "block 1000 could not be served at all"

CB=$(rpc "{\"jsonrpc\":\"1.0\",\"id\":\"t\",\"method\":\"getblock\",\"params\":[\"$MID_HASH\",2]}" \
     | jq_ "print(r['tx'][0]['vin'][0].get('coinbase',''))")
[ -z "$CB" ] || [ "$CB" = "none" ] \
    && ok "and its coinbase scriptSig is empty — the payload really was destroyed" \
    || bad "block 1000's coinbase scriptSig survived: $CB"

# ── 2. REGRESSION: a fresh hazed node must never forget genesis ────────────────────────────────
#
# Two bugs met here, both fatal on a fresh hazed node and neither visible to the unit tests.
#
# Genesis was being MARKED stripped although it is written whole — the flag followed "is haze on"
# rather than which writer ran — so the read path looked for its payload in the gsb sequence while it
# sat in blk. And the startup pass that forgets unconnectable stripped blocks ran before any
# chainstate had a tip, where nothing looks connected, so it condemned genesis itself.
#
# Assert on the block, not merely on the absence of a log line, so a reworded message cannot make
# this pass silently.
if grep -q "Forgetting stripped block .* (0)" "$DD/run1.log"; then
    bad "genesis was forgotten at startup — a fresh hazed node cannot start"
else
    ok "genesis was not forgotten at startup"
fi
GEN=$(rpc '{"jsonrpc":"1.0","id":"t","method":"getblockhash","params":[0]}' | jq_ "print(r)")
[ "$GEN" = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" ] \
    && ok "genesis is present and correct" \
    || bad "genesis is missing or wrong ($GEN)"

# ── 3. it restarts ─────────────────────────────────────────────────────────────────────────────
#
# The #542 case. A hazed node writes a block's stripped form before connecting it, so stopping in
# that window leaves storage that cannot satisfy a connect. It must forget those and carry on, not
# die reading a gsb offset out of a blk file.
BEFORE=$(height)
stop
start "$DD/run2.log"
if wait_for_height 1 300; then
    ok "restarted after being killed mid-sync (was at $BEFORE, resumed at $(height))"
else
    bad "did not come back up after a restart"
    tail -15 "$DD/run2.log" | sed 's/^/    /'
fi
grep -q "Block magic mismatch" "$DD/run2.log" \
    && bad "restart hit a block magic mismatch — reading gsb data as a full block" \
    || ok "no block magic mismatch on restart"

# ── 4. it can undo its own stripped history ────────────────────────────────────────────────────
#
# Disconnecting reads no scriptSig and no witness, so this must work from stripped storage alone.
TIP=$(rpc '{"jsonrpc":"1.0","id":"t","method":"getbestblockhash","params":[]}' | jq_ "print(r)")
INV=$(rpc "{\"jsonrpc\":\"1.0\",\"id\":\"t\",\"method\":\"invalidateblock\",\"params\":[\"$TIP\"]}")
if printf '%s' "$INV" | grep -q '"error":null'; then
    AFTER=$(rpc '{"jsonrpc":"1.0","id":"t","method":"getbestblockhash","params":[]}' | jq_ "print(r)")
    [ "$AFTER" != "$TIP" ] \
        && ok "disconnected a block from stripped storage (tip moved back)" \
        || bad "invalidateblock reported success but the tip did not move"

    # ── 5. and come back to the branch it abandoned ────────────────────────────────────────────
    #
    # Reconnecting needs what stripping destroyed, so the node must re-fetch rather than shut down.
    rpc "{\"jsonrpc\":\"1.0\",\"id\":\"t\",\"method\":\"reconsiderblock\",\"params\":[\"$TIP\"]}" >/dev/null
    sleep 20
    if [ "$(height)" != "none" ]; then
        ok "still alive after being asked to reconnect a stripped block"
    else
        bad "node died reconnecting a stripped block"
    fi
else
    bad "invalidateblock failed: $(printf '%s' "$INV" | head -c 200)"
fi

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
