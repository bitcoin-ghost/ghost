#!/usr/bin/env bash
# Adversarial cases for adopting a Hazync proof (hazync#31, #42).
#
# WRITTEN BEFORE ADOPTION EXISTS, deliberately. That creates one hazard worth naming: while nothing
# can be adopted, every case below is refused anyway, so a test that only asserted "was refused"
# would pass without exercising anything and would keep passing if adoption later accepted the lot.
#
# So each case asserts the SPECIFIC REASON. A proof rejected for being unanchored must say so, not
# merely fail. That is what makes these still bite once adoption lands: the reason is the assertion,
# not the refusal.
#
# Usage: GHOSTD=/path/to/ghostd ./test/hazync/adversarial-adoption.sh <artefact-dir>
#   artefact-dir needs: fold_8.snark, neg500.snark, fold_8_bitflip.snark, dump_h8.bin, dump_h8_bad.bin
set -uo pipefail

GHOSTD="${GHOSTD:-}"
ART="${1:-}"
[ -x "$GHOSTD" ] || { echo "set GHOSTD=<path to ghostd>" >&2; exit 2; }
[ -d "$ART" ]    || { echo "usage: $0 <artefact-dir>" >&2; exit 2; }

pass=0; fail=0
run() { # run <name> <expect-substring> <args...>
    local name="$1" expect="$2"; shift 2
    local dd; dd=$(mktemp -d)
    local log="$dd/out.log"
    timeout 8 "$GHOSTD" -datadir="$dd" -connect=0 -printtoconsole=1 "$@" >"$log" 2>&1
    if grep -qF -- "$expect" "$log"; then
        echo "  ok    $name"; pass=$((pass+1))
    else
        echo "  FAIL  $name"
        echo "        expected substring: $expect"
        echo "        hazync lines were:"
        grep -i hazync "$log" | sed 's/^/          /' | head -4
        fail=$((fail+1))
    fi
    rm -rf "$dd"
}

echo "Hazync adoption — adversarial cases"

# --- the control. Without it every refusal below could be refusing everything. ---
run "CONTROL a genuine genesis-anchored proof verifies" \
    "proof VERIFIED against guest" \
    -hazyncproof="$ART/fold_8.snark"

run "CONTROL a matching dump is recognised as the proven set" \
    "MATCHES the proven set" \
    -hazyncproof="$ART/fold_8.snark" -hazyncutxo="$ART/dump_h8.bin"

# --- #31's four: each must be refused, and must say WHY ---
run "a valid but NON-GENESIS-ANCHORED proof is refused as unanchored" \
    "NOT genesis-anchored" \
    -hazyncproof="$ART/neg500.snark"

run "a bit-flipped proof is refused as invalid, not merely unparsable" \
    "REJECTED" \
    -hazyncproof="$ART/fold_8_bitflip.snark"

# A proof for another chain, and one under another guest id, cannot be produced here: the guest
# compiles CChainParams::Main(), so a testnet/regtest proof needs a different guest and therefore a
# different image id — which is the same case as the guest-id check. That check is covered by
# rebuilding with a mismatched pin, exercised separately; see the B1 notes. Recorded rather than
# silently omitted, so the gap is visible.

# --- dump binding: the set must be tied to the proof, not merely well-formed ---
run "a tampered dump is refused against a genuine proof" \
    "UTXO SET DOES NOT MATCH THE PROOF" \
    -hazyncproof="$ART/fold_8.snark" -hazyncutxo="$ART/dump_h8_bad.bin"

run_absent() { # run_absent <name> <forbidden-substring> <args...>
    local name="$1" forbidden="$2"; shift 2
    local dd; dd=$(mktemp -d)
    timeout 8 "$GHOSTD" -datadir="$dd" -connect=0 -printtoconsole=1 "$@" >"$dd/out.log" 2>&1
    if grep -qF -- "$forbidden" "$dd/out.log"; then
        echo "  FAIL  $name (found forbidden: $forbidden)"; fail=$((fail+1))
    else
        echo "  ok    $name"; pass=$((pass+1))
    fi
    rm -rf "$dd"
}

# A dump alone must never be treated as proven. Asserted as an ABSENCE, because there is no message
# to match — and an empty expected-substring would make `grep -F ""` match anything, i.e. a check
# that cannot fail.
run_absent "a dump without a proof is never called proven" \
    "MATCHES the proven set" \
    -hazyncutxo="$ART/dump_h8.bin"

# --- the snapshot must never describe an unproven set ---
snapdir=$(mktemp -d)
run "no snapshot is written when the dump does not match" \
    "UTXO SET DOES NOT MATCH THE PROOF" \
    -hazyncproof="$ART/fold_8.snark" -hazyncutxo="$ART/dump_h8_bad.bin" \
    -hazyncsnapshotout="$snapdir/must_not_exist.dat"
if [ -e "$snapdir/must_not_exist.dat" ]; then
    echo "  FAIL  a snapshot was written from a dump that failed the proof check"; fail=$((fail+1))
else
    echo "  ok    no snapshot file was produced from an unproven set"; pass=$((pass+1))
fi
rm -rf "$snapdir"

# --- adoption: what must be true before a proven set may become the chainstate ---
#
# ⚠ SCOPE. These cases assert the GATES, not a successful adoption. Adopting needs the base block to
# already be in the node's headers chain, and these runs use -connect=0 with a fresh datadir, so the
# headers chain is genesis alone. A positive end-to-end adoption therefore needs a proof at a height
# this node can sync headers to, i.e. the GPU spend — that is B4, and it is recorded as outstanding
# rather than quietly approximated here. What IS reachable offline is every refusal, and the last
# case below reaches the headers check itself, which is the final gate before coins are admitted.

run "an unarmed node says plainly that it did not act on the proof" \
    "NOT ACTED ON" \
    -hazyncproof="$ART/fold_8.snark" -hazyncutxo="$ART/dump_h8.bin"

run "arming without a proof disarms, and says so" \
    "Adoption is DISARMED" \
    -hazyncadopt=1

run "arming with a proof but no dump is refused: a proof alone names no set" \
    "requires -hazyncutxo" \
    -hazyncadopt=1 -hazyncproof="$ART/fold_8.snark"

run "arming with a dump that is not the proven set is refused" \
    "is not the set the proof commits to" \
    -hazyncadopt=1 -hazyncproof="$ART/fold_8.snark" -hazyncutxo="$ART/dump_h8_bad.bin"

# The reason the proof was refused is asserted above; what this asserts is the CONSEQUENCE. An
# operator who asked to adopt and got only a proof-level complaint has not been told that adoption
# is off, and the two are separately worth failing on.
run "a refused proof disarms adoption, and says so" \
    "Adoption is DISARMED" \
    -hazyncadopt=1 -hazyncproof="$ART/neg500.snark" -hazyncutxo="$ART/dump_h8.bin"

# The positive control for arming. Without it, every refusal above could be refusing everything, and
# the suite would keep passing if arming were broken outright.
run "CONTROL a genuine proof and matching dump do arm adoption" \
    "ADOPTION ARMED" \
    -hazyncadopt=1 -hazyncproof="$ART/fold_8.snark" -hazyncutxo="$ART/dump_h8.bin"

# Armed is not adopted. Asserted as an absence because the distinction is the whole safety property:
# if arming alone adopted, every case above would have adopted too.
run_absent "arming alone never adopts" \
    "ADOPTED the proven UTXO set" \
    -hazyncadopt=1 -hazyncproof="$ART/fold_8.snark" -hazyncutxo="$ART/dump_h8.bin"

# No chainstate may appear from arming alone, whatever the log says.
adoptdir=$(mktemp -d)
timeout 8 "$GHOSTD" -datadir="$adoptdir" -connect=0 -printtoconsole=1 \
    -hazyncadopt=1 -hazyncproof="$ART/fold_8.snark" -hazyncutxo="$ART/dump_h8.bin" \
    >"$adoptdir/out.log" 2>&1
if find "$adoptdir" -name 'chainstate_snapshot*' -print -quit | grep -q .; then
    echo "  FAIL  arming alone created a snapshot chainstate"; fail=$((fail+1))
else
    echo "  ok    arming alone created no snapshot chainstate"; pass=$((pass+1))
fi
# The temporary snapshot the adoption RPC writes is unlinked as soon as it is opened, so it must
# never be found on disk — including after a run that did not adopt at all.
if [ -e "$adoptdir/hazync_snapshot.tmp" ]; then
    echo "  FAIL  a temporary snapshot file was left behind"; fail=$((fail+1))
else
    echo "  ok    no temporary snapshot file was left behind"; pass=$((pass+1))
fi
rm -rf "$adoptdir"

# --- the adoption RPC itself ---
#
# The cases above stop at startup. These start a node and actually call `hazyncadoptsnapshot`, which
# is the only thing that can adopt — so they are the ones that exercise the trigger rather than its
# preconditions. Nothing here can adopt successfully (no headers), and that is asserted too.
RPCPORT="${RPCPORT:-18899}"
run_rpc() { # run_rpc <name> <expect-substring> <json-body> <args...>
    local name="$1" expect="$2" body="$3"; shift 3
    local dd; dd=$(mktemp -d)
    # $SNAPOUT lets a case ask the node to write a snapshot into its own datadir first.
    local extra=(); [ -n "${SNAPOUT:-}" ] && extra=(-hazyncsnapshotout="$dd/$SNAPOUT")
    "$GHOSTD" -datadir="$dd" -connect=0 -printtoconsole=1 -server=1 \
        -rpcport="$RPCPORT" -rpcuser=t -rpcpassword=t "${extra[@]}" "$@" >"$dd/out.log" 2>&1 &
    local pid=$!
    local out="" i
    for i in $(seq 1 40); do
        out=$(curl -s --max-time 5 --user t:t --data-binary \
            "${body//@DD@/$dd}" \
            -H 'content-type: text/plain;' "http://127.0.0.1:$RPCPORT/" 2>/dev/null)
        # Warming up: the RPC server rejects calls until the node is out of init.
        case "$out" in ""|*"warming up"*|*"Loading"*) sleep 0.5; continue ;; esac
        break
    done
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    if [ -z "$out" ]; then
        # An empty reply is not a pass — it means the call never landed, so the case proved nothing.
        echo "  FAIL  $name (RPC never answered; is another node on port $RPCPORT?)"; fail=$((fail+1))
    elif printf '%s' "$out" | grep -qF -- "$expect"; then
        echo "  ok    $name"; pass=$((pass+1))
    else
        echo "  FAIL  $name"
        echo "        expected substring: $expect"
        echo "        got: $(printf '%s' "$out" | head -c 300)"
        fail=$((fail+1))
    fi
    # Adoption must not have happened in any of these.
    if find "$dd" -name 'chainstate_snapshot*' -print -quit | grep -q .; then
        echo "  FAIL  $name — a snapshot chainstate was created"; fail=$((fail+1))
    fi
    rm -rf "$dd"
}

if ! command -v curl >/dev/null 2>&1; then
    echo "  SKIP  RPC cases (curl not available) — these are NOT counted as passing"
else
    ADOPT_BODY='{"jsonrpc":"1.0","id":"t","method":"hazyncadoptsnapshot","params":[]}'

    run_rpc "the adoption RPC refuses on an unarmed node" \
        "adoption is not armed" "$ADOPT_BODY" \
        -hazyncproof="$ART/fold_8.snark" -hazyncutxo="$ART/dump_h8.bin"

    run_rpc "the adoption RPC refuses when the dump is not the proven set" \
        "is not the set the proof commits to" "$ADOPT_BODY" \
        -hazyncadopt=1 -hazyncproof="$ART/fold_8.snark" -hazyncutxo="$ART/dump_h8_bad.bin"

    # The last gate before coins are admitted: a node that has not seen the base block cannot adopt a
    # set based on it, however good the proof. This is the case that shows the RPC really does reach
    # ActivateSnapshot rather than being stopped by something earlier and looking the same — the
    # message it must produce lives PAST the chainparams gate, so reaching it proves that gate opened.
    run_rpc "a fully armed node still cannot adopt a base block its headers chain lacks" \
        "must appear in the headers chain" "$ADOPT_BODY" \
        -hazyncadopt=1 -hazyncproof="$ART/fold_8.snark" -hazyncutxo="$ART/dump_h8.bin"

    # ── The isolation property, attacked directly ──────────────────────────────────────────────
    # Same node, fully armed, holding a genuine snapshot of the proven set — but reached through
    # `loadtxoutset`, which has no proof behind it. It must be refused at the CHAINPARAMS gate,
    # because height 8 is not an assumeutxo height and loadtxoutset passes no authority.
    #
    # This is the case that would catch the authority being ambient. If ActivateSnapshot read the
    # armed adoption out of module state instead of taking it as an argument, this call would sail
    # through that gate and fail later at the headers check — the same message as the case above.
    # So the two cases are deliberately distinguished by WHICH refusal they get, not whether they
    # are refused: both are refused either way, and only the reason tells them apart.
    SNAPOUT=proven_h8.dat
    run_rpc "loadtxoutset cannot borrow the proof's authority" \
        "not recognized" \
        '{"jsonrpc":"1.0","id":"t","method":"loadtxoutset","params":["@DD@/proven_h8.dat"]}' \
        -hazyncadopt=1 -hazyncproof="$ART/fold_8.snark" -hazyncutxo="$ART/dump_h8.bin"
    unset SNAPOUT
fi

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
