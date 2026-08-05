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

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
