#!/usr/bin/env bash
#
# Self-test for the installer's --node-pool option.
#
# ghostd's default block reserve (8,000 WU) has no room for the node pool's coinbase, which runs
# to 22 KB: regtest lost a block at 2.25 KB on a full template. --node-pool writes
# blockreservedweight=90000 into bitcoin.conf. Asserted here, against the installer's OWN text:
#   1. the default is off, and --node-pool turns it on;
#   2. the write step adds the line only when on, and only once;
#   3. the value matches NODE_POOL_BLOCK_RESERVED_WEIGHT in the Rust constants;
#   4. the write step runs after the truncating write of bitcoin.conf.
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

echo "1. the option"
is "default is off" 1 "$($G -cx 'NODE_POOL="false"' "$INSTALLER" || true)"
arms="$($G -E '^[[:space:]]+--node-pool\)' "$INSTALLER")"
is "the flag is parsed" 1 "$(printf '%s\n' "$arms" | $G -c . || true)"
parse() {
    ( NODE_POOL="false"; CONFIG_FLAGS=0
      eval "while [ \$# -gt 0 ]; do case \"\$1\" in
$arms
        *) shift;;
      esac; done"
      echo "$NODE_POOL $CONFIG_FLAGS" )
}
is "--node-pool turns it on and counts as a config flag" "true 1" "$(parse --node-pool)"
is "no flag leaves it off"                              "false 0" "$(parse --nickname x)"
is "the help names it" 1 "$($G -c '^  --node-pool ' "$INSTALLER" || true)"

echo "2. the write step"
step="$(awk '/^if \[\[ "\$NODE_POOL" == "true" \]\]; then$/{on=1} on{print} on&&/^fi$/{exit}' "$INSTALLER")"
is "the write step is present" yes "$([ -n "$step" ] && echo yes)"
run_step() {
    ( NODE_POOL="$1"
      printf 'server=1\n' > "$TMP/bitcoin.conf"
      eval "${step//\/etc\/bitcoin\/bitcoin.conf/$TMP/bitcoin.conf}"
      $G -c '^blockreservedweight=' "$TMP/bitcoin.conf" || true )
}
is "on: one blockreservedweight line" 1 "$(run_step true)"
is "off: no blockreservedweight line" 0 "$(run_step false)"

echo "3. the value"
shell_value="$(printf '%s\n' "$step" | $G -oE 'blockreservedweight=[0-9]+' | cut -d= -f2)"
rust_value="$($G -oE 'NODE_POOL_BLOCK_RESERVED_WEIGHT: u64 = [0-9_]+' "$CONSTANTS" | $G -oE '[0-9_]+$' | tr -d _)"
is "the installer writes 90000" 90000 "$shell_value"
is "it matches the Rust constant" "$rust_value" "$shell_value"

echo "4. order"
line_of() { $G -nF "$1" "$INSTALLER" | head -1 | cut -d: -f1; }
trunc="$(line_of '} > /etc/bitcoin/bitcoin.conf')"
write="$(line_of 'if [[ "$NODE_POOL" == "true" ]]; then')"
is "the line is appended after bitcoin.conf is written" yes \
   "$([ -n "$trunc" ] && [ -n "$write" ] && [ "$trunc" -lt "$write" ] && echo yes)"

echo
echo "test-installer-node-pool-reserve: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
