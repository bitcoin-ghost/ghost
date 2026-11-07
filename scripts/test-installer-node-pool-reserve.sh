#!/usr/bin/env bash
#
# Self-test for the installer's node pool block reserve.
#
# ghostd's default block reserve (8,000 WU) has no room for the node pool's coinbase, which runs
# to 22 KB: regtest lost a block at 2.25 KB on a full template. The node pool is the only mode, so
# the installer always writes blockreservedweight=90000 into bitcoin.conf. Asserted here, against
# the installer's OWN text:
#   1. --node-pool, which used to switch the reserve on, is still accepted and does nothing;
#   2. the bitcoin.conf write carries the line exactly once on every network, inside the chain's
#      section on signet and regtest, and the mainnet-only assumevalid only on mainnet;
#   3. the value matches NODE_POOL_BLOCK_RESERVED_WEIGHT in the Rust constants.
#
# Hermetic: the installer is never run; its pieces are extracted and run against a temp file.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${INSTALLER:-$REPO_ROOT/scripts/install-node.sh}"
CONSTANTS="$REPO_ROOT/crates/ghost-common/src/node_pool_constants.rs"
G=/usr/bin/grep
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
is() { if [ "$2" = "$3" ]; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
       else printf "  [BAD] %s\n        wanted: %s\n        got:    %s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }

echo "1. the old flag"
arms="$($G -E '^[[:space:]]+--node-pool\)' "$INSTALLER")"
is "the flag is still parsed" 1 "$(printf '%s\n' "$arms" | $G -c . || true)"
parse() {
    ( CONFIG_FLAGS=0
      eval "while [ \$# -gt 0 ]; do case \"\$1\" in
$arms
        *) shift;;
      esac; done"
      echo "$CONFIG_FLAGS" )
}
is "--node-pool is accepted and is not a config choice" 0 "$(parse --node-pool)"
is "the help names it" 1 "$($G -c '^  --node-pool ' "$INSTALLER" || true)"
is "no NODE_POOL switch is left" 0 "$($G -c 'NODE_POOL=' "$INSTALLER" || true)"

echo "2. the bitcoin.conf write"
step="$(awk '/^RPC_USER="ghostrpc_mainnet"$/{on=1} on{print} on&&/^\} > \/etc\/bitcoin\/bitcoin.conf$/{exit}' "$INSTALLER")"
is "the write step is present" yes "$([ -n "$step" ] && echo yes)"
conf="$TMP/bitcoin.conf"
run_step() {
    # shellcheck disable=SC2034  # read by the extracted step
    ( NETWORK="$1" SIGNET_CHALLENGE="" BITCOIN_PEERS="" ARCHIVE=false SYNC_MODE=ibd RPCPW=pw NP_P2P_PORT="$2" ASSUMEVALID=00ab
      eval "${step//\/etc\/bitcoin\/bitcoin.conf/$conf}" )
}
for n in mainnet:8333 signet:38333 regtest:18444; do
    net="${n%%:*}"; port="${n##*:}"
    run_step "$net" "$port"
    is "$net: one blockreservedweight=90000" 1 "$($G -cx 'blockreservedweight=90000' "$conf" || true)"
    is "$net: P2P port $port" 1 "$($G -cx "port=$port" "$conf" || true)"
    if [ "$net" = mainnet ]; then
        is "mainnet: no chain section" 0 "$($G -c '^chain=\|^\[' "$conf" || true)"
        is "mainnet: assumevalid" 1 "$($G -c '^assumevalid=' "$conf" || true)"
        is "mainnet: rpc user" 1 "$($G -cx 'rpcuser=ghostrpc_mainnet' "$conf" || true)"
    else
        is "$net: chain selected first" "chain=$net" "$(head -1 "$conf")"
        is "$net: settings in the [$net] section" "[$net]" "$(sed -n 2p "$conf")"
        is "$net: no mainnet assumevalid" 0 "$($G -c '^assumevalid=' "$conf" || true)"
        is "$net: rpc user" 1 "$($G -cx "rpcuser=ghostrpc_$net" "$conf" || true)"
    fi
done

echo "3. the value"
shell_value="$(printf '%s\n' "$step" | $G -oE 'blockreservedweight=[0-9]+' | cut -d= -f2)"
rust_value="$($G -oE 'NODE_POOL_BLOCK_RESERVED_WEIGHT: u64 = [0-9_]+' "$CONSTANTS" | $G -oE '[0-9_]+$' | tr -d _)"
is "the installer writes 90000" 90000 "$shell_value"
is "it matches the Rust constant" "$rust_value" "$shell_value"

echo
echo "test-installer-node-pool-reserve: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
