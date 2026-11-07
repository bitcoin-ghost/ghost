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
is "mainnet genesis is the flag-day start" "a512f0c9378c31fe34160ee6388b62289596e46110d45079eec8eafe8c4c4526 974875" "$NP_GENESIS_ANCHOR $NP_GENESIS_HEIGHT"
is "mainnet table digest" 43e8165e "${NP_TABLE_DIGEST:0:8}"
is "mainnet export digest" cfb62020 "${NP_EXPORT_DIGEST:0:8}"
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
has "mainnet: the published genesis"     'genesis_anchor = "a512f0c9378c31fe34160ee6388b62289596e46110d45079eec8eafe8c4c4526"' "$out"
has "mainnet: at the freeze height"      'genesis_btc_height = 974875' "$out"
hasnt "mainnet: no placeholder warning"  'PLACEHOLDER' "$out"
hasnt "mainnet: no tier_base key"        'tier_base = ' "$out"
out="$(render signet tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx "")"
has "signet: the UNSET placeholder"      'genesis_anchor = "UNSET"' "$out"
has "signet: marked as a placeholder"    'PLACEHOLDER. No share-chain genesis is published for signet' "$out"
has "signet: says pool_sv2 refuses"      'REFUSES TO START' "$out"
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
has "disk line"          "[PASS] disk: 900 GB available on /var/lib (needs 25 GB)" "$out"
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

MEM=2000; pf;  has "too little RAM fails" "[FAIL] RAM: 2000 MB, a mainnet node needs at least 2800 MB" "$out"
MEM=3000; pf;  has "little RAM warns"     "[WARN] RAM: 3000 MB, 3800 MB or more recommended" "$out"
is "a warning alone still passes" 0 "$rc"
MEM=16000
DISK=20; pf;   has "too little disk fails" "[FAIL] disk: 20 GB available on /var/lib (free plus any chain already there), this node (mainnet, sync ibd) needs 25 GB" "$out"
DISK=900
OWNER[8566]=nginx; pf
has "a relay port held by another process fails" "[FAIL] port 8566 is in use by nginx; this node needs it" "$out"
OWNER[8566]=pool_sv2; OWNER[8332]=ghostd; CHAIN=main; pf
has "ports held by this node pass (re-run)" "[PASS] port 8566 is held by this node's pool_sv2 (re-run)" "$out"
has "a re-run's Bitcoin node answers" "[PASS] Bitcoin node answers on 127.0.0.1:8332 (chain main)" "$out"
is "and that passes" 0 "$rc"
# (that branch reads /etc/bitcoin/bitcoin.conf itself, so its message is checked in the source)
is "an RPC port that refuses bitcoin.conf's password says how to repair it" 1 \
   "$($G -c 'does not answer with /etc/bitcoin/bitcoin.conf.s credentials.*sudo systemctl restart ghostd, then re-run' "$INSTALLER" || true)"
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
NETWORK=signet; FEE_ADDRESS=tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7; MEM=8000; DISK=100
SIGNET_CHALLENGE=""; pf
has "signet without a challenge warns it is the public signet" "[WARN] no --signet-challenge: this node joins the public signet" "$out"
is "and passes" 0 "$rc"
SIGNET_CHALLENGE="20$(printf 'ab%.0s' {1..32})7551"; BITCOIN_PEERS="seed.example:38333 10.0.0.2:38333"; pf
has "a custom signet passes" "[PASS] custom signet, challenge 20abababababab" "$out"
has "a Bitcoin peer passes" "[PASS] Bitcoin peer seed.example:38333" "$out"
is "and passes" 0 "$rc"
SIGNET_CHALLENGE="51x"; pf
has "a challenge that is not hex fails" "[FAIL] signet challenge '51x' is not a hex script" "$out"
SIGNET_CHALLENGE="51"; BITCOIN_PEERS="seed.example"; pf
has "a Bitcoin peer without a port fails" "[FAIL] Bitcoin peer 'seed.example' is not host:port" "$out"
NETWORK=regtest; FEE_ADDRESS=bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080; BITCOIN_PEERS=""; pf
has "a challenge off signet fails" "[FAIL] --signet-challenge is for --network signet, not regtest" "$out"
SIGNET_CHALLENGE=""; BITCOIN_PEERS=""

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
      echo "$FEE_ADDRESS|$NETWORK|$RELAY_PEERS|$RELAY_PORT|$GENESIS_ANCHOR|$GENESIS_HEIGHT|$PREFLIGHT_ONLY|$CONFIG_FLAGS${SIGNET_CHALLENGE:+|$SIGNET_CHALLENGE|$BITCOIN_PEERS}" )
}
is "--fee-address"        "x|mainnet||8566|||false|1" "$(parse --fee-address x)"
is "--payout-address is its old name" "y|mainnet||8566|||false|1" "$(parse --payout-address y)"
is "node pool flags" "x|regtest|a:1 b:2|9000|ab|7|true|7" \
   "$(parse --fee-address x --network regtest --relay-peer a:1 --relay-peer b:2 --relay-port 9000 --genesis-anchor ab --genesis-height 7 --preflight-only)"
is "custom signet flags" "x|signet||8566|||false|5|51|s:1 t:2" \
   "$(parse --fee-address x --network signet --signet-challenge 51 --bitcoin-peer s:1 --bitcoin-peer t:2)"
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
validate="$(awk '/^np_hrp "\$NETWORK" >\/dev\/null \|\| err/{on=1} on{print} on&&/^POOL_TARBALL=/{exit}' "$INSTALLER")"
is "the validation step is present" yes "$([ -n "$validate" ] && echo yes)"
old="$TMP/pool-config.toml"
eval "$($G '^_trim() ' "$INSTALLER")"
# The release constants the validation step reads (production values; no test mirror in the env).
unset GHOST_TEST_RELEASE_MIRROR GHOST_TEST_RELEASE_KEY_FP
eval "$($G -E '^(GPG_KEY_FP|RELEASE_KEY_URL|RELEASE_DOWNLOAD_URL|TEST_RELEASE_MIRROR|TEST_RELEASE_KEY_FP)=' "$INSTALLER")"
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
      PREFLIGHT_ONLY=false SYNC_MODE=ibd ARCHIVE=false GHOST_VERSION=np-v9.9.9 AUTO_UPDATE=false
      eval "${validate//\/etc\/ghost\/pool-config.toml/$old}"
      echo "$FEE_ADDRESS|$RELAY_PEERS|$GENESIS_ANCHOR|$GENESIS_HEIGHT" )
}
is "an upgrade from before the node pool takes the old payout address" \
   "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4||a512f0c9378c31fe34160ee6388b62289596e46110d45079eec8eafe8c4c4526|974875" "$(validated_vars)"
printf 'fee_address = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"\npeers = ["a:1", "b:2"]\ngenesis_anchor = "%s"\ngenesis_btc_height = 975000\n' "$(printf 'ab%.0s' {1..32})" > "$old"
is "a re-run keeps the fee address and peers; mainnet's genesis is the published one" \
   "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3|a:1 b:2|a512f0c9378c31fe34160ee6388b62289596e46110d45079eec8eafe8c4c4526|974875" "$(validated_vars)"
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
      echo "AUTO_UPDATE=$AUTO_UPDATE GHOST_VERSION=$GHOST_VERSION TARBALL=$POOL_TARBALL" ) 2>&1 | tr '\n' ' '
}
# The channel itself (np-latest against a release list, the marker, the updater) is
# scripts/test-release-channel.sh; here, only that the install step uses it.
has "an unpinned release is refused (latest is the old network's)" "Name the node pool release to install" "$(pinned '' false)"
has "... and stops the install" "ERR GHOST_VERSION='' refused" "$(pinned '' false)"
has "an exact node pool tag proceeds" "GHOST_VERSION=np-v9.9.9" "$(pinned np-v9.9.9 false)"
has "... and names the node pool tarball" "TARBALL=bitcoin-ghost-np-v9.9.9-x86_64-unknown-linux-gnu.tar.gz" "$(pinned np-v9.9.9 false)"
has "an old-network tag is refused" "ERR GHOST_VERSION='v9.9.9' refused" "$(pinned v9.9.9 false)"
has "... saying why" "v-tags are the old network's" "$(pinned v9.9.9 false)"
has "a bare version is refused" "ERR GHOST_VERSION='1.11.46' refused" "$(pinned 1.11.46 false)"
has "'latest' is refused" "ERR GHOST_VERSION='latest' refused" "$(pinned latest false)"
has "--auto-update stays on: it follows the np- channel" "AUTO_UPDATE=true" "$(pinned np-v9.9.9 true)"
hasnt "... with no warning that it is unavailable" "not available for node pool nodes" "$(pinned np-v9.9.9 true)"
is "the installer never tracks the latest release" 0 "$($G -c 'GHOST_VERSION=.*releases/latest' "$INSTALLER" || true)"
is "the channel marker is written before the updater can be enabled" yes \
   "$(awk '/^cat > \/etc\/ghost\/release-channel /{m=NR} /systemctl enable --now ghost-auto-update.timer/{if(!t)t=NR} END{print (m && t && m<t)?"yes":"no"}' "$INSTALLER")"

echo "7c. a custom signet survives a re-run"
oldbc="$TMP/bitcoin.conf"
signet_vars() {   # CHALLENGE_FLAG PEERS_FLAG: validation against $oldbc, prints challenge|peers
    ( log() { :; }; err() { echo "ERR $*"; exit 1; }; usage() { :; }; np_preflight() { :; }
      FEE_ADDRESS=tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7 NETWORK=signet
      RELAY_PEERS="" RELAY_PORT=8566 GENESIS_ANCHOR="" GENESIS_HEIGHT="" PREFLIGHT_ONLY=false SYNC_MODE=ibd
      ARCHIVE=false GHOST_VERSION=np-v9.9.9 AUTO_UPDATE=false SIGNET_CHALLENGE="$1" BITCOIN_PEERS="$2"
      v="${validate//\/etc\/ghost\/pool-config.toml/$TMP/none}"
      eval "${v//\/etc\/bitcoin\/bitcoin.conf/$oldbc}"
      echo "$SIGNET_CHALLENGE|$BITCOIN_PEERS" ) 2>&1 | tail -1
}
printf 'chain=signet\n[signet]\nserver=1\nsignetchallenge=5175\naddnode=seed:38333\naddnode=10.0.0.9:38333\nprune=550\n' > "$oldbc"
is "a re-run keeps the challenge and the Bitcoin peers" "5175|seed:38333 10.0.0.9:38333" "$(signet_vars '' '')"
is "flags given this time win" "51|x:1" "$(signet_vars 51 x:1)"
rm -f "$oldbc"
is "a fresh install has neither" "|" "$(signet_vars '' '')"
conf_block="$(awk '/^RPC_USER="ghostrpc_mainnet"$/{on=1} on{print} on&&/^} > \/etc\/bitcoin\/bitcoin.conf$/{exit}' "$INSTALLER")"
is "the bitcoin.conf step is present" yes "$([ -n "$conf_block" ] && echo yes)"
written() {   # NETWORK CHALLENGE PEERS: the bitcoin.conf the installer writes
    ( NETWORK="$1" SIGNET_CHALLENGE="$2" BITCOIN_PEERS="$3" ARCHIVE=false SYNC_MODE=ibd RPCPW=pw NP_P2P_PORT=38333
      ASSUMEVALID=00; set -e
      eval "${conf_block//\/etc\/bitcoin\/bitcoin.conf/$TMP/written.conf}"
      cat "$TMP/written.conf" )
}
w="$(written signet 5175 "seed:38333 10.0.0.9:38333")"
has "the challenge is written" "signetchallenge=5175" "$w"
has "each Bitcoin peer is an addnode" "addnode=seed:38333" "$w"
has "... all of them" "addnode=10.0.0.9:38333" "$w"
is "in the [signet] section" "[signet]" "$(printf '%s\n' "$w" | sed -n '2p')"
w="$(written signet '' '')"
hasnt "no challenge: the public signet" "signetchallenge" "$w"
hasnt "no peers: no addnode" "addnode" "$w"
has "and the file is still complete" "blockreservedweight=90000" "$w"

echo "7d. a re-run restarts the node on what it wrote, with the same RPC password"
secrets_block="$(awk '/^log "Generating fresh node secrets"$/{on=1;next} on&&/^if \[\[ -f \/etc\/ghost\/pool.toml \]\]/{exit} on' "$INSTALLER")"
is "the RPC password step is present" yes "$([ -n "$secrets_block" ] && echo yes)"
rpcpw() { ( unset RPCPW; eval "${secrets_block//\/etc\/bitcoin\/bitcoin.conf/$TMP/bc.conf}"; echo "$RPCPW" ); }
pw="$(printf 'ab%.0s' {1..32})"
printf 'chain=signet\n[signet]\nrpcuser=u\nrpcpassword=%s\n' "$pw" > "$TMP/bc.conf"
is "a re-run keeps the RPC password" "$pw" "$(rpcpw)"
rm -f "$TMP/bc.conf"
fresh="$(rpcpw)"
is "a fresh install makes a new one" yes "$([[ "$fresh" =~ ^[0-9a-f]{64}$ && "$fresh" != "$pw" ]] && echo yes)"
start_block="$(awk '/^log "Starting services"$/{on=1;next} on{print} on&&/^systemctl enable --now ghost-mining-gate/{exit}' "$INSTALLER")"
is "the start step is present" yes "$([ -n "$start_block" ] && echo yes)"
started() {   # NODE_WAS_RUNNING: the systemctl calls of the start step, in order
    ( calls=""; systemctl() { calls+="$*;"; }; log() { :; }; NODE_WAS_RUNNING="$1"
      eval "$start_block"; echo "${calls//>\/dev\/null 2>&1/}" )
}
is "a fresh install starts ghostd and the gate, nothing else" \
   "daemon-reload;enable --now ghostd;enable --now ghost-mining-gate;" "$(started false)"
is "a re-run on a running node stops the stack, restarts ghostd, and lets the gate start the rest" \
   "daemon-reload;stop sri-translator sri-pool ghost-mining;restart ghostd;stop ghost-mining-gate;enable --now ghostd;enable --now ghost-mining-gate;" \
   "$(started true)"
was_block="$(awk '/^NODE_WAS_RUNNING=false$/{on=1} on{print} on&&/^done$/{exit}' "$INSTALLER")"
was() { ( systemctl() { [ "$1 $2" = "is-active --quiet" ] && [[ " $ACTIVE " == *" $3 "* ]]; }; ACTIVE="$1"; eval "$was_block"; echo "$NODE_WAS_RUNNING" ); }
is "running: any of the node's units is active" true "$(was "sri-pool")"
is "not running: none is" false "$(was "")"
is "it is read before the installer changes anything" yes \
   "$(awk '/^NODE_WAS_RUNNING=false$/{w=NR} /^apt-get update/{if(!a)a=NR} END{print (w && a && w<a)?"yes":"no"}' "$INSTALLER")"
is "ghostd may take 600 s to flush on stop" 1 "$($G -c '^TimeoutStopSec=600$' "$INSTALLER" || true)"

echo "7a. the test-only release mirror"
TFP=0123456789ABCDEF0123456789ABCDEF01234567
mirrored() {   # NETWORK MIRROR KEY_FP
    ( log() { :; }; err() { echo "ERR $*"; exit 1; }; usage() { :; }; np_preflight() { :; }
      FEE_ADDRESS=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 NETWORK="$1" RELAY_PEERS="" RELAY_PORT=8566
      [ "$1" = signet ] && FEE_ADDRESS=tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7
      GENESIS_ANCHOR="" GENESIS_HEIGHT="" PREFLIGHT_ONLY=false SYNC_MODE=ibd ARCHIVE=false
      GHOST_VERSION=np-v9.9.9 AUTO_UPDATE=false TEST_RELEASE_MIRROR="$2" TEST_RELEASE_KEY_FP="$3"
      eval "${validate//\/etc\/ghost\/pool-config.toml/$TMP/none}"
      echo "$NP_RELEASES_API_URL|$RELEASE_BASE|$RELEASE_KEY_URL|$GPG_KEY_FP" ) 2>/dev/null | tail -1
}
prod_fp="$(sed -nE 's/^GPG_KEY_FP="([0-9A-F]{40})"$/\1/p' "$INSTALLER")"
is "without a mirror: GitHub, the release key" \
   "https://api.github.com/repos/bitcoin-ghost/ghost/releases?per_page=100|https://github.com/bitcoin-ghost/ghost/releases/download/np-v9.9.9|https://get.bitcoinghost.org/ghost-release-key.asc|$prod_fp" \
   "$(mirrored signet '' '')"
is "with a mirror: every URL and the key move to it" \
   "http://m:8/r/releases|http://m:8/r/download/np-v9.9.9|http://m:8/r/release-key.asc|$TFP" \
   "$(mirrored signet http://m:8/r/ "$TFP")"
is "a mirror without its key is refused" "ERR GHOST_TEST_RELEASE_MIRROR and GHOST_TEST_RELEASE_KEY_FP go together (test installs only)." \
   "$(mirrored signet http://m:8/r '')"
is "a key without a mirror is refused" "ERR GHOST_TEST_RELEASE_MIRROR and GHOST_TEST_RELEASE_KEY_FP go together (test installs only)." \
   "$(mirrored signet '' "$TFP")"
is "a mirror on mainnet is refused" "ERR GHOST_TEST_RELEASE_MIRROR is for test installs on signet or regtest, never mainnet." \
   "$(mirrored mainnet http://m:8/r "$TFP")"
is "the release key cannot be the test key" "ERR GHOST_TEST_RELEASE_KEY_FP is the release key: a test mirror is signed with a throwaway key." \
   "$(mirrored regtest http://m:8/r "$prod_fp")"
is "a malformed fingerprint is refused" "ERR GHOST_TEST_RELEASE_KEY_FP must be a 40-hex uppercase fingerprint." \
   "$(mirrored regtest http://m:8/r "${TFP,,}")"
dropin_block="$(awk '/^TEST_MIRROR_DROPIN=/{on=1} on{print} on&&/^fi$/{exit}' "$INSTALLER")"
is "the updater drop-in step is present" yes "$([ -n "$dropin_block" ] && echo yes)"
dropin() {   # MIRROR: runs the step against $TMP/sd, prints the drop-in or "absent"
    ( TEST_RELEASE_MIRROR="$1" NP_RELEASES_API_URL=http://m/releases RELEASE_DOWNLOAD_URL=http://m/download
      RELEASE_KEY_URL=http://m/release-key.asc GPG_KEY_FP="$TFP"
      eval "${dropin_block//\/etc\/systemd\/system/$TMP/sd}" )
    cat "$TMP/sd/ghost-auto-update.service.d/test-release-mirror.conf" 2>/dev/null || echo absent
}
d="$(dropin http://m)"
for v in GHOST_NP_RELEASES_API_URL=http://m/releases GHOST_RELEASE_DOWNLOAD_URL=http://m/download \
         GHOST_RELEASE_KEY_URL=http://m/release-key.asc "GHOST_GPG_KEY_FP=$TFP"; do
    has "a mirror install points the updater at it: ${v%%=*}" "Environment=$v" "$d"
    has "... a variable the updater reads" "${v%%=*}:-" "$($G -F "${v%%=*}:-" "$REPO_ROOT/scripts/ghost-auto-update.sh")"
done
is "a normal re-run removes the drop-in" absent "$(dropin '')"

echo "7b. slot-class sensing reaches pool_sv2"
# The translator must negotiate the Ghost agent extension, or pool_sv2 never sees an SV1 miner's
# user agent and serves every one the smallest class (Phase 3 harness finding D).
tr_ext="$(awk '/^cat > .*translator.*toml/{t=1} t && /^required_extensions = /{print; exit}' "$INSTALLER")"
has "the translator requires the agent extension 0x4748" "0x4748" "$tr_ext"
has "and still the per-miner TLV 0x0002" "0x0002" "$tr_ext"
pool_ext="$($G -m1 -E '^supported_extensions = \[0x0002' "$INSTALLER" || true)"
has "pool_sv2's config supports 0x4748" "0x4748" "$pool_ext"

echo "8. isolation from the old network"
for ip in 83.136.251.162 85.9.198.212 213.163.207.46 95.111.221.169; do
    is "no old fleet address $ip" 0 "$($G -cF "$ip" "$INSTALLER" || true)"
done
is "pool.toml carries no mesh keys" 0 "$($G -cE '^(seed_nodes|noise_enabled) =|^\[network\.p2p\]' "$INSTALLER" || true)"
is "no SEED_NODES list is left" 0 "$($G -c 'SEED_NODES' "$INSTALLER" || true)"
is "the old mesh ports are not opened" 0 "$($G -cE '^ufw allow (8555|8563|8443)' "$INSTALLER" || true)"
is "they are closed on a re-run" 3 "$($G -cE '^ufw delete allow (8555:8562|8563|8443)/tcp' "$INSTALLER" || true)"


echo "9. loopback-only listeners: the template server, verification HTTPS and the dashboard"
is "8442 (TDP) is not opened" 0 "$($G -cE '^ufw allow 8442' "$INSTALLER" || true)"
is "an 8442 rule an older install opened is removed" 1 "$($G -cE '^ufw delete allow 8442/tcp' "$INSTALLER" || true)"
is "ghost-mining's TDP server binds loopback" 1 \
   "$($G -cE '^ExecStart=/opt/ghost/bin/ghost-mining .*--tdp-port 8442 --tdp-bind 127\.0\.0\.1 ' "$INSTALLER" || true)"
is "the dashboard port is never opened" 0 "$($G -cE 'ufw allow .*3000' "$INSTALLER" || true)"
unit="$(cat "$REPO_ROOT/scripts/systemd/ghost-dashboard.service")"
has "the dashboard binds loopback" "Environment=HOSTNAME=127.0.0.1" "$unit"
has "it runs the pinned Node.js, not apt's" "ExecStart=/opt/ghost/node/bin/node server.js" "$unit"
hasnt "it is not ordered after a unit no node has" "ghost-node.service" "$unit"
has "its password comes from a root-only file, not an Environment= line" "EnvironmentFile=-/etc/ghost/dashboard.env" "$unit"
hasnt "no password in the unit" "DASHBOARD_PASSWORD=" "$unit"
# The internal API key: `systemctl show` hands every `Environment=` value to any local user, so the
# key must reach the dashboard through a root-only EnvironmentFile, never an Environment= line.
is "the internal API key is never written as an Environment= line" 0 \
   "$($G -cE 'Environment=INTERNAL_AUTH_KEY' "$INSTALLER" || true)"
auth_block="$(awk '/^install -d -m 0750 \/etc\/systemd\/system\/ghost-dashboard.service.d$/{on=1} on{print} on&&/^chmod 0644 /{exit}' "$INSTALLER")"
has "the drop-in names a root-only key file" "EnvironmentFile=/etc/ghost/dashboard-internal-auth.env" "$auth_block"
has "... written with a 077 umask" "umask 077" "$auth_block"
has "... and mode 600" "chmod 0600 /etc/ghost/dashboard-internal-auth.env" "$auth_block"
k="$TMP/authkey"; mkdir -p "$k/etc/ghost" "$k/etc/systemd/system"
( APISECRET=$(printf 'ab%.0s' $(seq 32))
  b="${auth_block//\/etc\//$k\/etc\/}"; b="${b//chown root:root/:}"
  eval "$b" ) >/dev/null 2>&1
is "a run writes the key file mode 600" 600 "$(stat -c %a "$k/etc/ghost/dashboard-internal-auth.env" 2>/dev/null)"
hasnt "the drop-in itself holds no key" "abab" "$(cat "$k/etc/systemd/system/ghost-dashboard.service.d/internal-auth.conf" 2>/dev/null)"
has "the key file holds the node's secret" "INTERNAL_AUTH_KEY=abab" "$(cat "$k/etc/ghost/dashboard-internal-auth.env" 2>/dev/null)"
pf_dashboard_active() { [ "${DASH_ACTIVE:-no}" = yes ]; }
NETWORK=mainnet; FEE_ADDRESS=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4; SIGNET_CHALLENGE=""; BITCOIN_PEERS=""; pf
has "a free dashboard port passes" "[PASS] port 3000 is free (node dashboard, loopback only)" "$out"
OWNER[3000]=node; DASH_ACTIVE=yes; pf
has "the node's own dashboard on it is a re-run" "[PASS] port 3000 is held by this node's dashboard (re-run)" "$out"
OWNER[3000]=grafana; DASH_ACTIVE=no; pf
has "another program on it only warns" "[WARN] port 3000 is in use by grafana: the node dashboard will not start until it is free" "$out"
is "... and the install goes on" 0 "$rc"
OWNER=()

echo "10. the dashboard and its runtime"
has "libsqlite3-0 is installed explicitly" "libsqlite3-0" "$($G -A3 '^apt-get install -y -qq \\$' "$INSTALLER")"
nv="$(sed -nE 's/^NODEJS_VERSION="(v[0-9]+)\..*/\1/p' "$INSTALLER")"
is "Node.js is pinned to 22 or later" yes "$([[ "${nv#v}" -ge 22 ]] 2>/dev/null && echo yes)"
is "... to an exact version" 1 "$($G -cE '^NODEJS_VERSION="v[0-9]+\.[0-9]+\.[0-9]+"$' "$INSTALLER" || true)"
is "... with its SHA-256" 1 "$($G -cE '^NODEJS_SHA256="[0-9a-f]{64}"$' "$INSTALLER" || true)"
is "... checked before it is unpacked" yes \
   "$(awk '/NODEJS_SHA256\}  \$TMP\/\$NODEJS_TARBALL" \| sha256sum -c/{c=NR} /tar -xzf "\$TMP\/\$NODEJS_TARBALL"/{x=NR} END{print (c && x && c<x)?"yes":"no"}' "$INSTALLER")"
is "the dashboard is fetched after the release signature is verified" yes \
   "$(awk '/VALIDSIG \$\{GPG_KEY_FP\}/{if(!v)v=NR} /curl -fsSLO "\$\{RELEASE_BASE\}\/\$\{DASHBOARD_TARBALL\}"/{d=NR} END{print (v && d && v<d)?"yes":"no"}' "$INSTALLER")"
dl_block="$(awk '/^DASHBOARD_SRC=""$/{on=1} on{print} on&&/^fi$/{exit}' "$INSTALLER")"
is "the dashboard download step is present" yes "$([ -n "$dl_block" ] && echo yes)"
REL="$TMP/rel"; mkdir -p "$REL/stage/ghost-dashboard"; echo 'console.log(1)' > "$REL/stage/ghost-dashboard/server.js"
tar -czf "$REL/bitcoin-ghost-np-v9.9.9-dashboard.tar.gz" -C "$REL/stage" ghost-dashboard
fetched() {   # SUMS: runs the step in a fresh dir with SHA256SUMS.txt = SUMS, prints DASHBOARD_SRC or the error
    local w="$TMP/dl.$RANDOM"; mkdir -p "$w"; printf '%s' "$1" > "$w/SHA256SUMS.txt"
    ( cd "$w"; err() { echo "ERR $*" >&2; exit 1; }; log() { :; }
      curl() { local a="${*: -1}"; cp "$REL/${a##*/}" .; }
      GHOST_VERSION=np-v9.9.9 DASHBOARD_TARBALL=bitcoin-ghost-np-v9.9.9-dashboard.tar.gz RELEASE_BASE=http://m/np-v9.9.9
      eval "${dl_block//\$TMP/$w}" >/dev/null; echo "SRC=${DASHBOARD_SRC#"$w"/}" ) 2>&1 | $G -E '^(SRC=|ERR )' 
}
good="$(cd "$REL" && sha256sum bitcoin-ghost-np-v9.9.9-dashboard.tar.gz)"
is "a dashboard in the signed manifest is installed" "SRC=dashboard/ghost-dashboard" "$(fetched "$good"$'\n')"
has "one whose checksum does not match stops the install" "ERR Checksum verification FAILED for bitcoin-ghost-np-v9.9.9-dashboard.tar.gz." \
   "$(fetched "$(printf '%064d' 0)  bitcoin-ghost-np-v9.9.9-dashboard.tar.gz"$'\n')"
is "a release without one installs the node alone" "SRC=" "$(fetched "$(printf '%064d' 0)  other.tar.gz"$'\n')"
pw_block="$(awk '/^  # The password\. /{on=1} on{print} on&&/^  \[\[ -e "\$DASHBOARD_ENV" \]\]/{exit}' "$INSTALLER")"
is "the password step is present" yes "$([ -n "$pw_block" ] && echo yes)"
password() {   # runs the step against $TMP/pw, prints the note; the env file is left there
    ( chown() { :; }; DASHBOARD_ENV="$TMP/pw/dashboard.env"
      b="${pw_block//\/etc\/systemd\/system\/ghost-dashboard.service.d/$TMP/pw/dropins}"
      eval "$b"; echo "$DASHBOARD_PW_NOTE" )
}
rm -rf "$TMP/pw"; mkdir -p "$TMP/pw/dropins"
note="$(password)"
is "a fresh install generates one" yes "$($G -qE '^DASHBOARD_PASSWORD=[0-9a-f]{32}$' "$TMP/pw/dashboard.env" && echo yes)"
is "... readable by root only" 600 "$(stat -c %a "$TMP/pw/dashboard.env")"
has "... and says where it is, not what it is" "sudo grep DASHBOARD_PASSWORD $TMP/pw/dashboard.env" "$note"
hasnt "... the value never in the note" "$(sed -n 's/^DASHBOARD_PASSWORD=//p' "$TMP/pw/dashboard.env")" "$note"
sed -i 's/^DASHBOARD_PASSWORD=.*/DASHBOARD_PASSWORD=my own choice/' "$TMP/pw/dashboard.env"
password >/dev/null
is "a re-run keeps it, changed by hand or not" "DASHBOARD_PASSWORD=my own choice" "$($G '^DASHBOARD_PASSWORD=' "$TMP/pw/dashboard.env")"
rm -f "$TMP/pw/dashboard.env"; printf '[Service]\nEnvironment=DASHBOARD_PASSWORD=x\n' > "$TMP/pw/dropins/override.conf"
note="$(password)"
is "an operator's own drop-in password is kept and no file is written" absent "$([ -e "$TMP/pw/dashboard.env" ] && echo present || echo absent)"
has "... and the note says so" "your own" "$note"
is "the dashboard is restarted on a re-run" 1 "$($G -c '^  systemctl restart ghost-dashboard ' "$INSTALLER" || true)"
is "nothing prints the dashboard password" 0 "$($G -cE 'echo.*\$\(?(sed|grep|cat)[^|]*dashboard\.env|cat .*dashboard\.env' "$INSTALLER" || true)"


echo "11. the translator assigns tier difficulties"
tcfg="$(sed -n '/^cat > \/etc\/ghost\/translator-config.toml <<EOF$/,/^EOF$/p' "$INSTALLER")"
is "the translator config is found" yes "$([ -n "$tcfg" ] && echo yes)"
is "quantise_to_tiers is on, once" 1 "$(printf '%s\n' "$tcfg" | $G -cx 'quantise_to_tiers = true' || true)"
is "inside [downstream_difficulty_config]" "[downstream_difficulty_config]" \
   "$(printf '%s\n' "$tcfg" | sed -n '1,/^quantise_to_tiers = true$/p' | $G -E '^\[' | tail -1)"
echo
echo "test-installer-node-pool: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
