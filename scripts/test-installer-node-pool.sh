#!/usr/bin/env bash
#
# Self-test for the installer's node pool pieces (W2.12): the fee address check, the per-network
# defaults, the rendered pool_sv2 config, the preflight lines, the flags and the wizard's prompts.
#
# Hermetic: the installer is never run. Its NODE_POOL_FUNCTIONS block, flag arms and wizard are
# extracted and run here, with the machine (RAM, disk, ports, the Bitcoin node) stood in for.
# bins/pool-sv2/tests/installer_config.rs feeds the rendered config to pool_sv2 itself.
# Variables and stubs below are read by the extracted installer code, which shellcheck cannot see.
# shellcheck disable=SC2034,SC2329
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${INSTALLER:-$REPO_ROOT/scripts/install-node.sh}"
G=/usr/bin/grep
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
is() { if [ "$2" = "$3" ]; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
       else printf "  [BAD] %s\n        wanted: %s\n        got:    %s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }
has() { if printf '%s\n' "$3" | $G -qF -- "$2"; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
        else printf "  [BAD] %s\n        wanted a line with: %s\n        in:\n%s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }
hasnt() { if printf '%s\n' "$3" | $G -qF -- "$2"; then printf "  [BAD] %s\n        unwanted: %s\n" "$1" "$2"; fail=$((fail+1));
          else printf "  [ok ] %s\n" "$1"; pass=$((pass+1)); fi; }

sed -n '/^# >>> NODE_POOL_FUNCTIONS$/,/^# <<< NODE_POOL_FUNCTIONS$/p' "$INSTALLER" > "$TMP/np.sh"
is "the functions block is present" yes "$([ "$(wc -l < "$TMP/np.sh")" -gt 100 ] && echo yes)"
# shellcheck source=/dev/null
source "$TMP/np.sh"

echo "1. fee address"
check() { local out; out="$(set -euo pipefail; np_fee_address_check "$1" "$2")"; echo "$?:$out"; }
# BIP 173 / BIP 350 / base58 vectors.
is "mainnet P2WPKH"      "0:p2wpkh" "$(check bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 mainnet)"
is "uppercase P2WPKH"    "0:p2wpkh" "$(check BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4 mainnet)"
is "mainnet P2WSH"       "0:p2wsh"  "$(check bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3 mainnet)"
is "mainnet P2TR"        "0:p2tr"   "$(check bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0 mainnet)"
is "mainnet P2SH"        "0:p2sh"   "$(check 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy mainnet)"
is "signet P2WSH"        "0:p2wsh"  "$(check tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7 signet)"
is "regtest P2WPKH"      "0:p2wpkh" "$(check bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080 regtest)"
is "testnet P2SH on signet" "0:p2sh" "$(check 2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc signet)"
refused() { case "$1" in 1:*"$2"*) echo refused;; *) echo "$1";; esac; }
is "P2PKH refused"         refused "$(refused "$(check 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 mainnet)" P2PKH)"
is "testnet P2PKH refused" refused "$(refused "$(check mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn signet)" P2PKH)"
is "signet address on mainnet refused" refused \
   "$(refused "$(check tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7 mainnet)" "needs 'bc1")"
is "mainnet address on regtest refused" refused \
   "$(refused "$(check bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 regtest)" "needs 'bcrt1")"
is "mainnet P2SH on signet refused" refused "$(refused "$(check 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy signet)" "another network")"
is "one changed character refused (bech32)" refused \
   "$(refused "$(check bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5 mainnet)" "bad checksum")"
is "one changed character refused (base58)" refused "$(refused "$(check 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLz mainnet)" "bad checksum")"
is "v1 under the bech32 (not bech32m) checksum refused" refused \
   "$(refused "$(check bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut mainnet)" "bad checksum")"
is "witness v2 refused" refused "$(refused "$(check bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs mainnet)" "not P2WPKH")"
is "mixed case refused" refused "$(refused "$(check bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kV8F3T4 mainnet)" "mixed-case")"
is "garbage refused"    refused "$(refused "$(check not-an-address mainnet)" "not a valid address")"
is "empty refused"      refused "$(refused "$(check '' mainnet)" "no address")"
is "unknown network refused" refused "$(refused "$(check bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 testnet)" "unknown network")"

echo "2. network defaults"
np_network_defaults mainnet ibd false
is "mainnet genesis is not published: UNSET" "UNSET 0" "$NP_GENESIS_ANCHOR $NP_GENESIS_HEIGHT"
is "mainnet tier base is the default" "" "$NP_TIER_BASE"
is "mainnet P2P port" 8333 "$NP_P2P_PORT"
np_network_defaults mainnet haze false;  is "haze needs more disk" 250 "$NP_MIN_DISK_GB"
np_network_defaults mainnet ibd true;    is "archive needs the most disk" 800 "$NP_MIN_DISK_GB"
np_network_defaults signet
is "signet genesis is not published: UNSET" UNSET "$NP_GENESIS_ANCHOR"
np_network_defaults regtest
is "regtest genesis is fixed" "8d8cd561340ff83e99410e115619d64ad94516264d3e5cd6a991109c69f1229c" "$NP_GENESIS_ANCHOR"
is "it is sha256 of its name" "$NP_GENESIS_ANCHOR" "$(printf 'GhostNodePool/genesis/regtest' | sha256sum | cut -c1-64)"
is "regtest tier base is its pow limit" 7fffff "${NP_TIER_BASE:0:6}"
is "an unknown network is refused" 1 "$(np_network_defaults testnet; echo $?)"

echo "3. the rendered pool_sv2 config"
render() {
    ( SV2_AUTH_PUB=pub SV2_AUTH_SEC=sec TDP_PUBKEY=tdp APISECRET=secret RPC_USER=u RPCPW=p
      NETWORK="$1" FEE_ADDRESS="$2" RELAY_PORT=8566 RELAY_PEERS="$3"
      np_network_defaults "$NETWORK"
      GENESIS_ANCHOR="${4:-$NP_GENESIS_ANCHOR}" GENESIS_HEIGHT="${5:-$NP_GENESIS_HEIGHT}"
      np_render_pool_config )
}
out="$(render regtest bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080 "a.example:8566 10.0.0.2:9000")"
has "a [node_pool] section"        '[node_pool]' "$out"
has "the fee address"              'fee_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"' "$out"
has "a [node_pool.relay] section"  '[node_pool.relay]' "$out"
has "the relay listens on its port" 'listen = "0.0.0.0:8566"' "$out"
has "the peers, as a TOML list"    'peers = ["a.example:8566", "10.0.0.2:9000"]' "$out"
has "regtest genesis"              'genesis_anchor = "8d8cd561340ff83e99410e115619d64ad94516264d3e5cd6a991109c69f1229c"' "$out"
has "regtest tier base"            'tier_base = "7fffff' "$out"
has "the relay store"              'db_path = "/var/lib/ghost/node-pool.db"' "$out"
has "the relay's network"          'network = "regtest"' "$out"
has "the coinbase_reward_script"   'coinbase_reward_script = "addr(bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080)"' "$out"
hasnt "no placeholder warning on regtest" 'PLACEHOLDER' "$out"
is "the [node_pool] section comes before [node_pool.relay]" yes \
   "$(a=$(printf '%s\n' "$out" | $G -nx '\[node_pool\]' | cut -d: -f1); b=$(printf '%s\n' "$out" | $G -nxF '[node_pool.relay]' | cut -d: -f1); [ "$a" -lt "$b" ] && echo yes)"
out="$(render mainnet bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 "")"
has "mainnet: no peers is an empty list" 'peers = []' "$out"
has "mainnet: the UNSET placeholder"     'genesis_anchor = "UNSET"' "$out"
has "mainnet: marked as a placeholder"   'PLACEHOLDER. No share-chain genesis is published for mainnet' "$out"
has "mainnet: says pool_sv2 refuses"     'REFUSES TO START' "$out"
hasnt "mainnet: no tier_base key"        'tier_base = ' "$out"
out="$(render mainnet bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 "" "ab$(printf 'cd%.0s' {1..31})" 975000)"
has "a given genesis is written"        "genesis_anchor = \"ab$(printf 'cd%.0s' {1..31})\"" "$out"
has "with its height"                   'genesis_btc_height = 975000' "$out"
hasnt "and no placeholder warning"      'PLACEHOLDER' "$out"

echo "4. preflight"
# The machine, stood in for.
MEM=16000; DISK=900; CHAIN=""; declare -A OWNER=(); RESOLVES=yes
pf_mem_mb() { echo "$MEM"; }
pf_disk_free_gb() { echo "$DISK"; }
pf_port_owner() { echo "${OWNER[$1]:-}"; }
pf_bitcoin_chain() { echo "$CHAIN"; }
pf_resolves() { [ "$RESOLVES" = yes ]; }
NETWORK=mainnet SYNC_MODE=ibd ARCHIVE=false RELAY_PORT=8566 RELAY_PEERS="peer.example:8566"
FEE_ADDRESS=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 GENESIS_ANCHOR="ab$(printf 'cd%.0s' {1..31})"
GENESIS_HEIGHT=975000 ALERT_WEBHOOK=https://ntfy.sh
pf() { out="$(np_preflight 2>&1)"; rc=$?; }
pf
is "a good machine passes" 0 "$rc"
has "it says so" "Preflight: passed." "$out"
has "fee address line"   "[PASS] fee address is a valid mainnet P2WPKH address" "$out"
has "RAM line"           "[PASS] RAM: 16000 MB" "$out"
has "disk line"          "[PASS] disk: 900 GB free on /var/lib (needs 60 GB)" "$out"
has "relay port line"    "[PASS] port 8566 is free" "$out"
has "P2P port line"      "[PASS] port 8333 is free" "$out"
has "fresh Bitcoin line" "[PASS] no Bitcoin node yet" "$out"
has "relay firewall line" "[PASS] relay port 8566/tcp will be opened on ufw" "$out"
has "peer line"          "[PASS] relay peer peer.example:8566 resolves" "$out"
has "a mainnet genesis warns" "[WARN] share-chain genesis abcdcdcdcdcdcdcd… is configured on mainnet: pool_sv2 runs mainnet only on the start compiled into it" "$out"
has "webhook line"       "[PASS] alert webhook https://ntfy.sh" "$out"
hasnt "no FAIL line"     "[FAIL]" "$out"

FEE_ADDRESS=1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2; pf
is "a P2PKH fee address fails the preflight" 1 "$rc"
has "with a FAIL line" "[FAIL] fee address '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2': P2PKH is not accepted" "$out"
has "and the verdict" "Preflight: 1 check(s) FAILED. Nothing has been changed." "$out"
FEE_ADDRESS=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4

MEM=3000; pf;  has "too little RAM fails" "[FAIL] RAM: 3000 MB, a mainnet node needs at least 7000 MB" "$out"
MEM=9000; pf;  has "little RAM warns"     "[WARN] RAM: 9000 MB, 15000 MB or more recommended" "$out"
is "a warning alone still passes" 0 "$rc"
MEM=16000
DISK=40; pf;   has "too little disk fails" "[FAIL] disk: 40 GB free on /var/lib, this node (mainnet, sync ibd) needs 60 GB" "$out"
DISK=900
OWNER[8566]=nginx; pf
has "a relay port held by another process fails" "[FAIL] port 8566 is in use by nginx; this node needs it" "$out"
OWNER[8566]=pool_sv2; OWNER[8332]=ghostd; CHAIN=main; pf
has "ports held by this node pass (re-run)" "[PASS] port 8566 is held by this node's pool_sv2 (re-run)" "$out"
has "a re-run's Bitcoin node answers" "[PASS] Bitcoin node answers on 127.0.0.1:8332 (chain main)" "$out"
is "and that passes" 0 "$rc"
CHAIN=signet; pf
has "a Bitcoin node on another chain fails" "[FAIL] Bitcoin node on 127.0.0.1:8332 runs chain 'signet', not mainnet" "$out"
CHAIN=""; OWNER=()
RELAY_PEERS="no-port-here"; pf
has "a malformed peer fails" "[FAIL] relay peer 'no-port-here' is not host:port" "$out"
RELAY_PEERS="gone.example:8566"; RESOLVES=no; pf
has "an unresolvable peer warns" "[WARN] relay peer gone.example:8566 does not resolve now" "$out"
is "and still passes" 0 "$rc"
RELAY_PEERS=""; pf
has "no peers warns" "[WARN] no relay peers given" "$out"
RESOLVES=yes; RELAY_PEERS="peer.example:8566"
GENESIS_ANCHOR=UNSET; pf
has "an unset genesis warns" "[WARN] no share-chain genesis is published for mainnet: pool_sv2 will refuse to start" "$out"
is "and still installs" 0 "$rc"
GENESIS_ANCHOR=xyz; pf
has "a malformed genesis fails" "[FAIL] genesis anchor 'xyz' is not 64 hex characters" "$out"
GENESIS_ANCHOR="$(printf '0%.0s' {1..64})"; pf
has "an all-zero genesis fails" "[FAIL] genesis anchor" "$out"
GENESIS_ANCHOR="ab$(printf 'cd%.0s' {1..31})"
ALERT_WEBHOOK=""; pf
has "no webhook warns" "[WARN] no alert webhook (--alert-webhook): alerts are written disabled" "$out"
ALERT_WEBHOOK="ntfy.sh"; pf
has "a webhook that is not a URL fails" "[FAIL] alert webhook 'ntfy.sh' is not an http(s) URL" "$out"
ALERT_WEBHOOK=https://ntfy.sh
NETWORK=regtest; FEE_ADDRESS=bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080; MEM=2000; DISK=10; pf
is "regtest has small floors" 0 "$rc"
has "a regtest genesis passes" "[PASS] share-chain genesis abcdcdcdcdcdcdcd… at height 975000" "$out"
has "regtest P2P port is checked" "[PASS] port 18444 is free" "$out"
NETWORK=testnet; pf
is "an unknown network fails" 1 "$rc"

echo "5. flags"
arms="$(awk '/^while \[\[ \$# -gt 0 \]\]; do$/{on=1;next} on&&/^  esac$/{exit} on&&!/^  case /' "$INSTALLER" | $G -vE '^\s+-h\|--help|^\s+\*\)')"
parse() {
    ( FEE_ADDRESS="" NETWORK=mainnet RELAY_PEERS="" RELAY_PORT=8566 GENESIS_ANCHOR="" GENESIS_HEIGHT=""
      PREFLIGHT_ONLY=false CONFIG_FLAGS=0 NON_INTERACTIVE=false
      usage() { :; }
      eval "while [[ \$# -gt 0 ]]; do case \"\$1\" in
$arms
        *) echo UNKNOWN; shift;;
      esac; done" 2>/dev/null
      echo "$FEE_ADDRESS|$NETWORK|$RELAY_PEERS|$RELAY_PORT|$GENESIS_ANCHOR|$GENESIS_HEIGHT|$PREFLIGHT_ONLY|$CONFIG_FLAGS" )
}
is "--fee-address"        "x|mainnet||8566|||false|1" "$(parse --fee-address x)"
is "--payout-address is its old name" "y|mainnet||8566|||false|1" "$(parse --payout-address y)"
is "node pool flags" "x|regtest|a:1 b:2|9000|ab|7|true|7" \
   "$(parse --fee-address x --network regtest --relay-peer a:1 --relay-peer b:2 --relay-port 9000 --genesis-anchor ab --genesis-height 7 --preflight-only)"
for gone in --treasury-address --mining-mode --no-public-mining --capability --elder; do
    is "$gone is gone" 0 "$($G -cE "^[[:space:]]+${gone}\)" "$INSTALLER" || true)"
done
is "no treasury prompt is left" 0 "$($G -ciE 'read .*treasury' "$INSTALLER" || true)"

echo "6. the wizard"
wiz="$(awk '/^_trim\(\) /{print} /^prompt_yes_no\(\) \{$/,/^\}$/{print} /^run_wizard\(\) \{$/,/^\}$/{print}' "$INSTALLER")"
wizard() {
    ( log() { :; }; err() { echo "ERR $*"; exit 1; }
      FEE_ADDRESS="" NETWORK=mainnet RELAY_PEERS="" RELAY_PORT=8566 ALERT_WEBHOOK="" ALERT_TOPIC=ghost-node
      SYNC_MODE=ibd POOL_NAME="" REAPER=true ARCHIVE=false TOR=false TOR_MODE=hybrid AUTO_UPDATE=false
      BACKUPS=true NICKNAME=ghost-node
      pool_name_valid() { return 0; }
      eval "$wiz"
      run_wizard >"$TMP/wizard.out" 2>&1
      echo "$NETWORK|$FEE_ADDRESS|$RELAY_PEERS|$ALERT_WEBHOOK|$ALERT_TOPIC" )
}
#                network  bad fee    good fee                                       peers       bad url  url              topic  sync name reaper archive tor auto backups nick proceed
answers="regtest
1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080
a.example:8566
ntfy.sh
https://ntfy.sh
my-topic
1

y
n
n
n
y
node
y"
is "the wizard asks for network, fee address, peers and the alert webhook" \
   "regtest|bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080|a.example:8566|https://ntfy.sh|my-topic" \
   "$(wizard <<<"$answers")"
is "it re-asked after the P2PKH fee address" 1 "$($G -c 'P2PKH is not accepted' "$TMP/wizard.out" 2>/dev/null || true)"
answers_nohook="mainnet
bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4


1

y
n
n
n
y
node
y"
is "the alert webhook is optional" "mainnet|bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4|||ghost-node" "$(wizard <<<"$answers_nohook")"
is "it does not ask for a treasury" 0 "$(printf '%s\n' "$wiz" | $G -ci treasury || true)"

echo "7. validation and re-runs"
validate="$(awk '/^np_hrp "\$NETWORK" >\/dev\/null \|\| err/{on=1} on{print} on&&/^  AUTO_UPDATE="false"$/{getline; print; exit}' "$INSTALLER")"
is "the validation step is present" yes "$([ -n "$validate" ] && echo yes)"
old="$TMP/pool-config.toml"
eval "$($G '^_trim() ' "$INSTALLER")"
validated() {
    ( log() { :; }; err() { echo "ERR $*"; exit 1; }; usage() { :; }
      np_preflight() { echo "PREFLIGHT"; }
      FEE_ADDRESS="$1" NETWORK="${2:-mainnet}" RELAY_PEERS="" RELAY_PORT=8566 GENESIS_ANCHOR="${3:-}"
      GENESIS_HEIGHT="${4:-}" PREFLIGHT_ONLY=true SYNC_MODE=ibd ARCHIVE=false
      eval "${validate//\/etc\/ghost\/pool-config.toml/$old}"
      echo "never" ) 2>&1 | $G -v PREFLIGHT | tr '\n' ' ' | sed 's/ $//'
}
rm -f "$old"
is "a fresh install without a fee address is refused" "ERR --fee-address is required." "$(validated '')"
printf 'coinbase_reward_script = "addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)"\n' > "$old"
validated_vars() {
    ( log() { :; }; err() { echo "ERR $*"; exit 1; }; usage() { :; }; np_preflight() { :; }
      FEE_ADDRESS="" NETWORK=mainnet RELAY_PEERS="" RELAY_PORT=8566 GENESIS_ANCHOR="" GENESIS_HEIGHT=""
      PREFLIGHT_ONLY=false SYNC_MODE=ibd ARCHIVE=false GHOST_VERSION=v9.9.9 AUTO_UPDATE=false
      eval "${validate//\/etc\/ghost\/pool-config.toml/$old}"
      echo "$FEE_ADDRESS|$RELAY_PEERS|$GENESIS_ANCHOR|$GENESIS_HEIGHT" )
}
is "an upgrade from before the node pool takes the old payout address" \
   "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4||UNSET|0" "$(validated_vars)"
printf 'fee_address = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"\npeers = ["a:1", "b:2"]\ngenesis_anchor = "%s"\ngenesis_btc_height = 975000\n' "$(printf 'ab%.0s' {1..32})" > "$old"
is "a re-run keeps the fee address, peers and a set genesis" \
   "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3|a:1 b:2|$(printf 'ab%.0s' {1..32})|975000" "$(validated_vars)"
rm -f "$old"
is "a genesis anchor needs its height" "ERR --genesis-anchor needs --genesis-height: the anchor's Bitcoin height is part of the genesis." \
   "$(validated bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 mainnet "$(printf 'ab%.0s' {1..32})")"
is "--preflight-only exits after the preflight" "" "$(validated bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)"
is "an unknown network is refused" "ERR --network must be mainnet, signet or regtest." "$(validated x testnet)"
pinned() {
    ( log() { echo "LOG $*"; }; err() { echo "ERR $*"; exit 1; }; usage() { :; }; np_preflight() { :; }
      FEE_ADDRESS=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 NETWORK=mainnet RELAY_PEERS="" RELAY_PORT=8566
      GENESIS_ANCHOR="" GENESIS_HEIGHT="" PREFLIGHT_ONLY=false SYNC_MODE=ibd ARCHIVE=false
      GHOST_VERSION="$1" AUTO_UPDATE="$2"
      eval "${validate//\/etc\/ghost\/pool-config.toml/$old}"
      echo "AUTO_UPDATE=$AUTO_UPDATE" ) 2>&1 | tr '\n' ' '
}
has "an unpinned release is refused (latest is the old network's)" "ERR Pin the node pool release to install" "$(pinned '' false)"
has "a pinned release proceeds" "AUTO_UPDATE=false" "$(pinned v9.9.9 false)"
has "--auto-update is turned off, and says so" "not available for node pool nodes yet" "$(pinned v9.9.9 true)"
has "... and is off" "AUTO_UPDATE=false" "$(pinned v9.9.9 true)"
is "the installer no longer tracks the latest release" 0 "$($G -c 'GHOST_VERSION=.*releases/latest' "$INSTALLER" || true)"

echo "8. isolation from the old network"
for ip in 83.136.251.162 85.9.198.212 213.163.207.46 95.111.221.169; do
    is "no old fleet address $ip" 0 "$($G -cF "$ip" "$INSTALLER" || true)"
done
is "pool.toml is written with no mesh seeds" 1 "$($G -cx 'seed_nodes = \[\]' "$INSTALLER" || true)"
is "no SEED_NODES list is left" 0 "$($G -c 'SEED_NODES' "$INSTALLER" || true)"
is "the old mesh ports are not opened" 0 "$($G -cE '^ufw allow (8555|8563|8443)' "$INSTALLER" || true)"
is "they are closed on a re-run" 3 "$($G -cE '^ufw delete allow (8555:8562|8563|8443)/tcp' "$INSTALLER" || true)"

echo
echo "test-installer-node-pool: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
