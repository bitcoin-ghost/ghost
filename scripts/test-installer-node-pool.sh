#!/usr/bin/env bash
#
# Self-test for the installer's Ghost Solo pieces: the payout address check, the per-network
# defaults, the rendered pool_sv2 config ([solo]), the preflight lines, the flags (--peer-node,
# --submit-node, --submit-auth), the wizard's prompts, re-runs, the found-block credentials, the
# mempool policy, the stratum ports and the firewall.
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
has() { if $G -qF -- "$2" <<<"$3"; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
        else printf "  [BAD] %s\n        wanted a line with: %s\n        in:\n%s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }
like() { if $G -qE -- "$2" <<<"$3"; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
         else printf "  [BAD] %s\n        wanted /%s/ in: %s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }
hasnt() { if $G -qF -- "$2" <<<"$3"; then printf "  [BAD] %s\n        unwanted: %s\n" "$1" "$2"; fail=$((fail+1));
          else printf "  [ok ] %s\n" "$1"; pass=$((pass+1)); fi; }

sed -n '/^# >>> NODE_POOL_FUNCTIONS$/,/^# <<< NODE_POOL_FUNCTIONS$/p' "$INSTALLER" > "$TMP/np.sh"
is "the functions block is present" yes "$([ "$(wc -l < "$TMP/np.sh")" -gt 100 ] && echo yes)"
# shellcheck source=/dev/null
source "$TMP/np.sh"

echo "1. payout address (a miner's username; pool_sv2's payee classes)"
check() { local out; out="$(set -euo pipefail; np_payout_address_check "$1" "$2")"; echo "$?:$out"; }
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
is "mainnet P2P port" 8333 "$NP_P2P_PORT"
is "mainnet RAM floors (measured on vm8)" "2800 3800" "$NP_MIN_RAM_MB $NP_WARN_RAM_MB"
is "mainnet pruned disk floor" 25 "$NP_MIN_DISK_GB"
np_network_defaults mainnet haze false;  is "haze needs more disk" 250 "$NP_MIN_DISK_GB"
np_network_defaults mainnet ibd true;    is "archive needs the most disk" 800 "$NP_MIN_DISK_GB"
np_network_defaults signet;  is "signet P2P port" 38333 "$NP_P2P_PORT"
np_network_defaults regtest; is "regtest P2P port" 18444 "$NP_P2P_PORT"
is "an unknown network is refused" 1 "$(np_network_defaults testnet; echo $?)"
is "no share-chain genesis is left" 0 "$($G -cE 'NP_GENESIS_ANCHOR|NP_TIER_BASE|NP_TABLE_DIGEST|NP_EXPORT_DIGEST' "$TMP/np.sh" || true)"
is "dbcache under 4 GB" 450 "$(np_dbcache 3900)"
is "dbcache from 4 GB" 1024 "$(np_dbcache 4096)"
is "dbcache when the RAM cannot be read" 450 "$(np_dbcache '')"
is "a found-block target host:port becomes a URL" "http://10.0.0.2:8332" "$(np_submit_url 10.0.0.2:8332)"
is "a name works too" "http://b.example:8332" "$(np_submit_url b.example:8332)"
is "an https URL is kept (trailing slash dropped)" "https://b.example:8443" "$(np_submit_url https://b.example:8443/)"
is "no port is refused" 1 "$(np_submit_url b.example >/dev/null; echo $?)"
is "a path is refused" 1 "$(np_submit_url http://b.example:8332/wallet >/dev/null; echo $?)"
is "credentials in the URL are refused" 1 "$(np_submit_url http://u:p@b.example:8332 >/dev/null; echo $?)"
is "port 0 is refused" 1 "$(np_submit_url b.example:0 >/dev/null; echo $?)"
is "the host of a target" "10.0.0.2" "$(np_url_host http://10.0.0.2:8332)"
is "the host of a host:port" "b.example" "$(np_url_host b.example:8332)"

echo "3. the rendered pool_sv2 config"
render() {   # NETWORK SUBMIT_NODES AUTH_READY
    ( SV2_AUTH_PUB=pub SV2_AUTH_SEC=sec TDP_PUBKEY=tdp APISECRET=secret
      NETWORK="$1" SUBMIT_NODES="$2" SUBMIT_AUTH_READY="${3:-false}"
      set -u; np_render_pool_config )
}
out="$(render mainnet "http://10.0.0.2:8332 https://b.example:8443" true)"
has "a [solo] section"                  '[solo]' "$out"
is "exactly one"                        1 "$(printf '%s\n' "$out" | $G -cx '\[solo\]' || true)"
has "its network"                       'network = "mainnet"' "$out"
has "its state directory"               'state_dir = "/var/lib/ghost/solo"' "$out"
has "the found-block targets, as a TOML list" 'submit_rpc = ["http://10.0.0.2:8332", "https://b.example:8443"]' "$out"
has "their credentials file"            'submit_rpc_auth_file = "/etc/ghost/solo-submit-rpc.auth"' "$out"
has "both SV1 ports"                    'sv1_ports = [3333, 4444]' "$out"
has "the SV2 port"                      'listen_address = "0.0.0.0:34255"' "$out"
has "the group channel pays the treasury script" 'coinbase_reward_script = "raw(00144191423ac78d3054875d18b4dd1a8f306da23f9d)"' "$out"
is "the treasury script is ghost_common::solo's" yes \
   "$(rust="$(sed -n '/^pub const TREASURY_SCRIPT/,/^\];/p' "$REPO_ROOT/crates/ghost-common/src/solo.rs" | $G -oE '0x[0-9a-f]{2}' | sed 's/0x//' | tr -d '\n')"
      [ -n "$rust" ] && [ "$rust" = 00144191423ac78d3054875d18b4dd1a8f306da23f9d ] && echo yes)"
has "the template provider"             '[template_provider_type.Sv2Tp]' "$out"
is "[solo] is a section of its own, before the template provider" yes \
   "$(a=$(printf '%s\n' "$out" | $G -nx '\[solo\]' | cut -d: -f1); b=$(printf '%s\n' "$out" | $G -nxF '[template_provider_type.Sv2Tp]' | cut -d: -f1); [ "$a" -lt "$b" ] && echo yes)"
for gone in '[node_pool]' '[node_pool.relay]' 'fee_address' 'genesis_anchor' 'tier_base' 'node-pool.db' 'peers = ' 'addr('; do
    hasnt "no $gone" "$gone" "$out"
done
out="$(render regtest "http://10.0.0.2:18443" false)"
has "regtest: its network"              'network = "regtest"' "$out"
has "no credentials file yet: the targets are still written" 'submit_rpc = ["http://10.0.0.2:18443"]' "$out"
has "... and the file is NOT named (pool_sv2 refuses to start on one it cannot read)" '# submit_rpc_auth_file = ' "$out"
is "... not even once uncommented" 0 "$(printf '%s\n' "$out" | $G -c '^submit_rpc_auth_file' || true)"
out="$(render signet "")"
has "one node: an empty target list"    'submit_rpc = []' "$out"
is "... and no credentials file named" 0 "$(printf '%s\n' "$out" | $G -c '^submit_rpc_auth_file' || true)"
has "signet: its network"               'network = "signet"' "$out"
out="$( ( SV2_AUTH_PUB=pub SV2_AUTH_SEC=sec TDP_PUBKEY=tdp APISECRET=secret NETWORK=mainnet; unset SUBMIT_NODES SUBMIT_AUTH_READY
          set -u; np_render_pool_config ) 2>&1 )"
has "renders with SUBMIT_NODES unset (as installer_config.rs runs it)" 'submit_rpc = []' "$out"

echo "4. preflight"
# The machine, stood in for.
MEM=16000; DISK=900; CHAIN=""; declare -A OWNER=(); RESOLVES=yes
pf_mem_mb() { echo "$MEM"; }
pf_disk_free_gb() { echo "$DISK"; }
pf_port_owner() { echo "${OWNER[$1]:-}"; }
pf_bitcoin_chain() { echo "$CHAIN"; }
pf_resolves() { [ "$RESOLVES" = yes ]; }
NETWORK=mainnet SYNC_MODE=ibd ARCHIVE=false SIGNET_CHALLENGE="" BITCOIN_PEERS="10.0.0.2:8333"
SUBMIT_NODES="http://10.0.0.2:8332" RPC_ALLOW="10.0.0.2" SUBMIT_AUTH="u:p" SUBMIT_AUTH_PRESENT=false
ALERT_WEBHOOK=https://ntfy.sh
pf() { out="$(np_preflight 2>&1)"; rc=$?; }
pf
is "a good machine passes" 0 "$rc"
has "it says so" "Preflight: passed." "$out"
has "RAM line"           "[PASS] RAM: 16000 MB (ghostd dbcache=1024)" "$out"
has "disk line"          "[PASS] disk: 900 GB available on /var/lib (needs 25 GB)" "$out"
for p in 8333 8332 8080 8442 3333 4444 34255 9090; do
    has "port $p is checked" "[PASS] port $p is free" "$out"
done
hasnt "the relay port is not checked" "port 8566" "$out"
has "fresh Bitcoin line" "[PASS] no Bitcoin node yet" "$out"
has "the other node is a Bitcoin peer" "[PASS] Bitcoin peer 10.0.0.2:8333" "$out"
has "found blocks also go to it" "[PASS] found blocks also go to http://10.0.0.2:8332" "$out"
has "its credentials are given" "[PASS] found-block credentials given" "$out"
has "it may reach this node's RPC" "[PASS] the other node 10.0.0.2 may reach this node's Bitcoin RPC (8332, that address only)" "$out"
has "webhook line"       "[PASS] alert webhook https://ntfy.sh" "$out"
hasnt "no FAIL line"     "[FAIL]" "$out"
for gone in "fee address" "relay" "genesis"; do hasnt "no $gone line" "$gone" "$out"; done

SUBMIT_AUTH=""; SUBMIT_AUTH_PRESENT=true; pf
has "credentials kept from an earlier run" "[PASS] found-block credentials kept from /etc/ghost/solo-submit-rpc.auth" "$out"
SUBMIT_AUTH_PRESENT=false; pf
has "no credentials at all warns" "[WARN] no --submit-auth: the other node refuses found blocks" "$out"
is "... and still installs" 0 "$rc"
SUBMIT_AUTH="no-colon"; pf
has "credentials that are not user:password fail" "[FAIL] --submit-auth must be user:password" "$out"
SUBMIT_AUTH="u:p"
SUBMIT_NODES="b.example"; pf
has "a target without a port fails" "[FAIL] found-block target 'b.example' is not host:port or an http(s)://host:port URL" "$out"
SUBMIT_NODES="http://gone.example:8332"; RESOLVES=no; pf
has "an unresolvable target warns" "[WARN] found-block target http://gone.example:8332 does not resolve now" "$out"
is "and still passes" 0 "$rc"
RESOLVES=yes; SUBMIT_NODES=""; RPC_ALLOW=""; pf
has "one node alone warns" "[WARN] no other node (--peer-node): found blocks are submitted to this node's ghostd only" "$out"
hasnt "... and asks for no credentials" "submit-auth" "$out"
is "... and installs" 0 "$rc"
RPC_ALLOW="peer.example"; pf
has "a peer that did not resolve to an address fails (no rpcallowip for a name)" "[FAIL] 'peer.example' is not an IPv4 address" "$out"
RPC_ALLOW=""; SUBMIT_NODES="http://10.0.0.2:8332"; RPC_ALLOW="10.0.0.2"

MEM=2000; pf;  has "too little RAM fails" "[FAIL] RAM: 2000 MB, a mainnet node needs at least 2800 MB" "$out"
MEM=3000; pf;  has "little RAM warns, with the smaller dbcache" "[WARN] RAM: 3000 MB, 3800 MB or more recommended (ghostd gets dbcache=450)" "$out"
is "a warning alone still passes" 0 "$rc"
MEM=16000
DISK=20; pf;   has "too little disk fails" "[FAIL] disk: 20 GB available on /var/lib (free plus any chain already there), this node (mainnet, sync ibd) needs 25 GB" "$out"
DISK=900
OWNER[4444]=nginx; pf
has "the farm port held by another process fails" "[FAIL] port 4444 is in use by nginx; this node needs it" "$out"
OWNER[4444]=translator_sv2; OWNER[8332]=ghostd; CHAIN=main; pf
has "ports held by this node pass (re-run)" "[PASS] port 4444 is held by this node's translator_sv2 (re-run)" "$out"
has "a re-run's Bitcoin node answers" "[PASS] Bitcoin node answers on 127.0.0.1:8332 (chain main)" "$out"
is "and that passes" 0 "$rc"
is "an RPC port that refuses bitcoin.conf's password says how to repair it" 1 \
   "$($G -c 'does not answer with /etc/bitcoin/bitcoin.conf.s credentials.*sudo systemctl restart ghostd, then re-run' "$INSTALLER" || true)"
CHAIN=signet; pf
has "a Bitcoin node on another chain fails" "[FAIL] Bitcoin node on 127.0.0.1:8332 runs chain 'signet', not mainnet" "$out"
CHAIN=""; OWNER=()
ALERT_WEBHOOK=""; pf
has "no webhook warns" "[WARN] no alert webhook (--alert-webhook): alerts are written disabled" "$out"
ALERT_WEBHOOK="ntfy.sh"; pf
has "a webhook that is not a URL fails" "[FAIL] alert webhook 'ntfy.sh' is not an http(s) URL" "$out"
ALERT_WEBHOOK=https://ntfy.sh
NETWORK=regtest; MEM=2000; DISK=10; BITCOIN_PEERS=""; pf
is "regtest has small floors" 0 "$rc"
has "regtest P2P port is checked" "[PASS] port 18444 is free" "$out"
NETWORK=testnet; pf
is "an unknown network fails" 1 "$rc"
NETWORK=signet; MEM=8000; DISK=100
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
NETWORK=regtest; BITCOIN_PEERS=""; pf
has "a challenge off signet fails" "[FAIL] --signet-challenge is for --network signet, not regtest" "$out"
SIGNET_CHALLENGE=""; BITCOIN_PEERS=""; NETWORK=mainnet

echo "5. flags"
arms="$(awk '/^while \[\[ \$# -gt 0 \]\]; do$/{on=1;next} on&&/^  esac$/{exit} on&&!/^  case /' "$INSTALLER" | $G -vE '^\s+-h\|--help|^\s+\*\)')"
parse() {
    ( NETWORK=mainnet PEER_NODES="" SUBMIT_FLAGS="" SUBMIT_AUTH="" BITCOIN_PEERS="" REAPER=false
      PREFLIGHT_ONLY=false CONFIG_FLAGS=0 NON_INTERACTIVE=false
      usage() { :; }
      eval "while [[ \$# -gt 0 ]]; do case \"\$1\" in
$arms
        *) echo UNKNOWN; shift;;
      esac; done" 2>/dev/null
      echo "$NETWORK|$PEER_NODES|$SUBMIT_FLAGS|$SUBMIT_AUTH|$BITCOIN_PEERS|$REAPER|$PREFLIGHT_ONLY|$CONFIG_FLAGS${SIGNET_CHALLENGE:+|$SIGNET_CHALLENGE}" )
}
is "--peer-node, repeatable" "mainnet|10.0.0.2 b.example||||false|false|2" "$(parse --peer-node 10.0.0.2 --peer-node b.example)"
is "--submit-node, repeatable" "mainnet||a:8332 http://b:8332|||false|false|2" "$(parse --submit-node a:8332 --submit-node http://b:8332)"
is "--submit-auth" "mainnet|||u:p||false|false|1" "$(parse --submit-auth u:p)"
is "--bitcoin-peer still works, repeatable" "mainnet||||s:1 t:2|false|false|2" "$(parse --bitcoin-peer s:1 --bitcoin-peer t:2)"
is "--reaper turns the reaper on" "mainnet|||||true|false|1" "$(parse --reaper)"
is "--no-reaper is still accepted" "mainnet|||||false|false|1" "$(parse --no-reaper)"
is "--network and --preflight-only" "regtest|||||false|true|1" "$(parse --network regtest --preflight-only)"
is "custom signet flags" "signet||||s:1|false|false|3|51" "$(parse --network signet --signet-challenge 51 --bitcoin-peer s:1)"
is "--fee-address and --payout-address are accepted and ignored" "mainnet|||||false|false|2" "$(parse --fee-address bc1q --payout-address x)"
has "... with a note saying why" "is ignored: every fee goes to the miner who finds the block" \
   "$( ( usage() { :; }; CONFIG_FLAGS=0; set -- --fee-address x; eval "while [[ \$# -gt 0 ]]; do case \"\$1\" in
$arms
        *) shift;; esac; done" ) 2>&1 )"
for gone in --relay-port --relay-peer --genesis-anchor --genesis-height --genesis-export --lister --no-lister \
            --lister-table-digest --lister-genesis-export --lister-export-digest --treasury-address --mining-mode; do
    is "$gone is gone" UNKNOWN "$(parse "$gone" x | head -1)"
done
is "no treasury prompt is left" 0 "$($G -ciE 'read .*treasury' "$INSTALLER" || true)"
is "--fee-address is no longer required" 0 "$($G -c 'fee-address is required' "$INSTALLER" || true)"

echo "6. the wizard"
wiz="$(awk '/^_trim\(\) /{print} /^prompt_yes_no\(\) \{$/,/^\}$/{print} /^run_wizard\(\) \{$/,/^\}$/{print}' "$INSTALLER")"
wizard() {
    ( log() { :; }; err() { echo "ERR $*"; exit 1; }
      NETWORK=mainnet PEER_NODES="" SUBMIT_AUTH="" ALERT_WEBHOOK="" ALERT_TOPIC=ghost-node
      SYNC_MODE=ibd POOL_NAME="" REAPER=false ARCHIVE=false TOR=false TOR_MODE=hybrid AUTO_UPDATE=false
      BACKUPS=true NICKNAME=ghost-node
      pool_name_valid() { return 0; }
      eval "$wiz"
      run_wizard >"$TMP/wizard.out" 2>&1
      echo "$NETWORK|$PEER_NODES|$SUBMIT_AUTH|$ALERT_WEBHOOK|$ALERT_TOPIC|$REAPER" )
}
#        network  peer       its auth  bad url  url              topic  sync name reaper archive tor auto backups nick proceed
answers="regtest
10.0.0.2
ghostrpc_regtest:pw
ntfy.sh
https://ntfy.sh
my-topic
1

n
n
n
n
y
node
y"
is "the wizard asks for network, the other node, its credentials and the alert webhook" \
   "regtest|10.0.0.2|ghostrpc_regtest:pw|https://ntfy.sh|my-topic|false" "$(wizard <<<"$answers")"
hasnt "it does not echo the credentials" "ghostrpc_regtest:pw" "$(cat "$TMP/wizard.out")"
answers_alone="mainnet



1






y"
is "the other node and the webhook are optional; the reaper defaults to off" "mainnet||||ghost-node|false" "$(wizard <<<"$answers_alone")"
is "it does not ask for a fee address" 0 "$(printf '%s\n' "$wiz" | $G -ciE 'read .*fee' || true)"
is "it does not ask for relay peers" 0 "$(printf '%s\n' "$wiz" | $G -ciE 'relay' || true)"
is "it does not ask for a treasury" 0 "$(printf '%s\n' "$wiz" | $G -ci treasury || true)"

echo "7. validation and re-runs"
validate="$(awk '/^np_hrp "\$NETWORK" >\/dev\/null \|\| err/{on=1} on{print} on&&/^POOL_TARBALL=/{exit}' "$INSTALLER")"
is "the validation step is present" yes "$([ -n "$validate" ] && echo yes)"
old="$TMP/pool-config.toml"; oldbc="$TMP/bitcoin.conf"; auth="$TMP/solo-submit-rpc.auth"; oldnode="$TMP/pool.toml"
eval "$($G '^_trim() ' "$INSTALLER")"
# The release constants the validation step reads (production values; no test mirror in the env).
unset GHOST_TEST_RELEASE_MIRROR GHOST_TEST_RELEASE_KEY_FP
eval "$($G -E '^(GPG_KEY_FP|RELEASE_KEY_URL|RELEASE_DOWNLOAD_URL|TEST_RELEASE_MIRROR|TEST_RELEASE_KEY_FP)=' "$INSTALLER")"
pf_resolve_ip() { case "$1" in b.example) echo 192.0.2.7;; *.invalid) ;; *) echo "$1";; esac; }
localize() { local v="${1//\/etc\/ghost\/pool-config.toml/$old}"; v="${v//\/etc\/bitcoin\/bitcoin.conf/$oldbc}"; v="${v//\/etc\/ghost\/pool.toml/$oldnode}"; printf '%s' "${v//\/etc\/ghost\/solo-submit-rpc.auth/$auth}"; }
validated_vars() {   # PEER_NODES SUBMIT_FLAGS BITCOIN_PEERS [NETWORK]
    ( log() { :; }; err() { echo "ERR $*"; exit 1; }; usage() { :; }; np_preflight() { :; }
      NETWORK="${4:-mainnet}" PEER_NODES="$1" SUBMIT_FLAGS="$2" BITCOIN_PEERS="$3" RPC_ALLOW="" SUBMIT_AUTH=""
      SIGNET_CHALLENGE="" ALERT_WEBHOOK="${ALERT_WEBHOOK:-}" ALERT_TOPIC="${ALERT_TOPIC:-}" PREFLIGHT_ONLY=false SYNC_MODE=ibd ARCHIVE=false GHOST_VERSION=np-v9.9.9 AUTO_UPDATE=false
      eval "$(localize "$validate")"
      echo "$BITCOIN_PEERS|$SUBMIT_NODES|$RPC_ALLOW|$SUBMIT_AUTH_PRESENT|${OLD_RELAY_PORT:-}" ) 2>&1 | tail -1
}
rm -f "$old" "$oldbc" "$auth"
is "a fresh install with nothing: one node" "|||false|" "$(validated_vars '' '' '')"
is "--peer-node IP: addnode, found-block target and RPC allow" "10.0.0.2:8333|http://10.0.0.2:8332|10.0.0.2|false|" \
   "$(validated_vars 10.0.0.2 '' '')"
is "--peer-node name: its address is allowed in" "b.example:8333|http://b.example:8332|192.0.2.7|false|" \
   "$(validated_vars b.example '' '')"
is "--peer-node on signet: the network's P2P port" "10.0.0.2:38333|http://10.0.0.2:8332|10.0.0.2|false|" \
   "$(validated_vars 10.0.0.2 '' '' signet)"
is "--peer-node with --submit-node and --bitcoin-peer: all of them, each once" \
   "s:1 10.0.0.2:8333|http://c:8332 http://10.0.0.2:8332|10.0.0.2|false|" \
   "$(validated_vars "10.0.0.2 10.0.0.2" "c:8332 10.0.0.2:8332" "s:1")"
is "a malformed --submit-node is kept for the preflight to name" "|nope||false|" "$(validated_vars '' nope '')"
is "a --peer-node with a port is refused" \
   "ERR --peer-node takes a host (an IP address or a name), not '10.0.0.2:8333': the ports are the network's." \
   "$(validated_vars 10.0.0.2:8333 '' '')"
printf 'submit_rpc = ["http://10.0.0.2:8332"]\nsubmit_rpc_auth_file = "/etc/ghost/solo-submit-rpc.auth"\n' > "$old"
printf 'rpcallowip=127.0.0.1\nrpcallowip=10.0.0.2\naddnode=10.0.0.2:8333\nprune=550\n' > "$oldbc"
echo 'u:p' > "$auth"
is "a re-run keeps the other node: addnode, targets, RPC allow and credentials" "10.0.0.2:8333|http://10.0.0.2:8332|10.0.0.2|true|" \
   "$(validated_vars '' '' '')"
is "flags given this time win" "10.0.0.9:8333|http://10.0.0.9:8332|10.0.0.9|true|" "$(validated_vars 10.0.0.9 '' '')"
is "--bitcoin-peer alone replaces the peers, keeps the targets and the allow-list" "s:1|http://10.0.0.2:8332|10.0.0.2|true|" \
   "$(validated_vars '' '' s:1)"
printf '[node_pool]\nfee_address = "bc1q"\n[node_pool.relay]\nlisten = "0.0.0.0:9566"\npeers = ["a:1"]\n' > "$old"
rm -f "$oldbc" "$auth"
is "an upgrade from the node pool: its relay port is noted (to close it), its peers are not targets" "|||false|9566" \
   "$(validated_vars '' '' '')"
rm -f "$old"
# Alerts on a re-run (2026-11-08): pool.toml is rewritten every run, so the channel the last install
# or the dashboard set must be kept, and no node may sit on the old shared public topic.
alerts_vars() {   # ALERT_WEBHOOK ALERT_TOPIC
    ( log() { :; }; err() { echo "ERR $*"; exit 1; }; usage() { :; }; np_preflight() { :; }
      NETWORK=mainnet PEER_NODES="" SUBMIT_FLAGS="" BITCOIN_PEERS="" RPC_ALLOW="" SUBMIT_AUTH=""
      SIGNET_CHALLENGE="" PREFLIGHT_ONLY=false SYNC_MODE=ibd ARCHIVE=false GHOST_VERSION=np-v9.9.9 AUTO_UPDATE=false
      ALERT_WEBHOOK="$1" ALERT_TOPIC="$2"
      eval "$(localize "$validate")"
      echo "$ALERT_WEBHOOK|$ALERT_TOPIC" ) 2>&1 | tail -1
}
push_toml() { printf '[alerts]\nenabled = true\n\n[alerts.channels.push]\nenabled = true\nwebhook_url = "%s"\ntopic = "%s"\n\n[other]\ntopic = "not-this"\n' "$1" "$2" > "$oldnode"; }
rm -f "$oldnode"
is "no webhook and no earlier install: alerts stay off" "|" "$(alerts_vars '' '')"
like "a webhook with no topic gets a random private topic, never a shared one" '^https://ntfy\.sh\|ghostpool-[0-9a-f]{12}$' "$(alerts_vars https://ntfy.sh '')"
is "a webhook and a topic given are used as given" "https://n.example|mine" "$(alerts_vars https://n.example mine)"
push_toml https://ntfy.sh ghostpool-0123456789ab
is "a re-run without flags keeps the webhook and topic the last install wrote" "https://ntfy.sh|ghostpool-0123456789ab" "$(alerts_vars '' '')"
is "... and a topic given this time wins" "https://ntfy.sh|other" "$(alerts_vars '' other)"
push_toml https://ntfy.sh ghost-node
like "a re-run on the old shared topic 'ghost-node' moves to a random one" '^https://ntfy\.sh\|ghostpool-[0-9a-f]{12}$' "$(alerts_vars '' '')"
rm -f "$oldnode"
validated() {
    ( log() { :; }; err() { echo "ERR $*"; exit 1; }; usage() { :; }
      np_preflight() { echo "PREFLIGHT"; }
      NETWORK="${1:-mainnet}" PEER_NODES="" SUBMIT_FLAGS="" BITCOIN_PEERS="" RPC_ALLOW="" SUBMIT_AUTH=""
      SIGNET_CHALLENGE="" ALERT_WEBHOOK="${ALERT_WEBHOOK:-}" ALERT_TOPIC="${ALERT_TOPIC:-}" PREFLIGHT_ONLY=true SYNC_MODE=ibd ARCHIVE=false
      eval "$(localize "$validate")"
      echo "never" ) 2>&1 | $G -v PREFLIGHT | tr '\n' ' ' | sed 's/ $//'
}
is "a fresh install needs no address at all" "" "$(validated)"
is "--preflight-only exits after the preflight" "" "$(validated mainnet)"
is "an unknown network is refused" "ERR --network must be mainnet, signet or regtest." "$(validated testnet)"
pinned() {
    ( log() { echo "LOG $*"; }; err() { echo "ERR $*"; exit 1; }; usage() { :; }; np_preflight() { :; }
      NETWORK=mainnet PEER_NODES="" SUBMIT_FLAGS="" BITCOIN_PEERS="" RPC_ALLOW="" SUBMIT_AUTH=""
      SIGNET_CHALLENGE="" ALERT_WEBHOOK="${ALERT_WEBHOOK:-}" ALERT_TOPIC="${ALERT_TOPIC:-}" PREFLIGHT_ONLY=false SYNC_MODE=ibd ARCHIVE=false
      GHOST_VERSION="$1" AUTO_UPDATE="$2"
      eval "$(localize "$validate")"
      echo "AUTO_UPDATE=$AUTO_UPDATE GHOST_VERSION=$GHOST_VERSION TARBALL=$POOL_TARBALL" ) 2>&1 | tr '\n' ' '
}
# The channel itself (np-latest against a release list, the marker, the updater) is
# scripts/test-release-channel.sh; here, only that the install step uses it.
is "an unset GHOST_VERSION means np-latest (the published one-liner names none)" "np-latest" \
   "$(env -u GHOST_VERSION bash -c "$($G -m1 '^GHOST_VERSION=' "$INSTALLER")"'; echo "$GHOST_VERSION"')"
has "an unpinned release is refused (latest is the old network's)" "Name the Ghost Pool release to install" "$(pinned '' false)"
has "... and stops the install" "ERR GHOST_VERSION='' refused" "$(pinned '' false)"
has "an exact tag of the channel proceeds" "GHOST_VERSION=np-v9.9.9" "$(pinned np-v9.9.9 false)"
has "... and names its tarball" "TARBALL=bitcoin-ghost-np-v9.9.9-x86_64-unknown-linux-gnu.tar.gz" "$(pinned np-v9.9.9 false)"
has "an old-network tag is refused" "ERR GHOST_VERSION='v9.9.9' refused" "$(pinned v9.9.9 false)"
has "... saying why" "v-tags are the old network's" "$(pinned v9.9.9 false)"
has "a bare version is refused" "ERR GHOST_VERSION='1.11.46' refused" "$(pinned 1.11.46 false)"
has "'latest' is refused" "ERR GHOST_VERSION='latest' refused" "$(pinned latest false)"
has "--auto-update stays on: it follows the np- channel" "AUTO_UPDATE=true" "$(pinned np-v9.9.9 true)"
is "the installer never tracks the latest release" 0 "$($G -c 'GHOST_VERSION=.*releases/latest' "$INSTALLER" || true)"
is "the channel marker is written before the updater can be enabled" yes \
   "$(awk '/^cat > \/etc\/ghost\/release-channel /{m=NR} /systemctl enable --now ghost-auto-update.timer/{if(!t)t=NR} END{print (m && t && m<t)?"yes":"no"}' "$INSTALLER")"

echo "7c. a custom signet survives a re-run"
signet_vars() {   # CHALLENGE_FLAG PEERS_FLAG: validation against $oldbc, prints challenge|peers
    ( log() { :; }; err() { echo "ERR $*"; exit 1; }; usage() { :; }; np_preflight() { :; }
      NETWORK=signet PEER_NODES="" SUBMIT_FLAGS="" RPC_ALLOW="" SUBMIT_AUTH="" PREFLIGHT_ONLY=false SYNC_MODE=ibd
      ARCHIVE=false GHOST_VERSION=np-v9.9.9 AUTO_UPDATE=false SIGNET_CHALLENGE="$1" BITCOIN_PEERS="$2" ALERT_WEBHOOK="" ALERT_TOPIC=""
      eval "$(localize "$validate")"
      echo "$SIGNET_CHALLENGE|$BITCOIN_PEERS" ) 2>&1 | tail -1
}
printf 'chain=signet\n[signet]\nserver=1\nsignetchallenge=5175\naddnode=seed:38333\naddnode=10.0.0.9:38333\nprune=550\n' > "$oldbc"
is "a re-run keeps the challenge and the Bitcoin peers" "5175|seed:38333 10.0.0.9:38333" "$(signet_vars '' '')"
is "flags given this time win" "51|x:1" "$(signet_vars 51 x:1)"
rm -f "$oldbc"
is "a fresh install has neither" "|" "$(signet_vars '' '')"
conf_block="$(awk '/^RPC_USER="ghostrpc_mainnet"$/{on=1} on{print} on&&/^} > \/etc\/bitcoin\/bitcoin.conf$/{exit}' "$INSTALLER")"
is "the bitcoin.conf step is present" yes "$([ -n "$conf_block" ] && echo yes)"
written() {   # NETWORK CHALLENGE PEERS [RPC_ALLOW]: the bitcoin.conf the installer writes
    ( NETWORK="$1" SIGNET_CHALLENGE="$2" BITCOIN_PEERS="$3" RPC_ALLOW="${4:-}" ARCHIVE=false SYNC_MODE=ibd RPCPW=pw
      NP_P2P_PORT=38333 ASSUMEVALID=00; pf_mem_mb() { echo 8000; }; set -e
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
is "no peers: no addnode" 0 "$(printf '%s\n' "$w" | $G -c '^addnode=' || true)"
has "and the file is still complete" "blockreservedweight=" "$w"
w="$(written mainnet '' '10.0.0.2:8333' 10.0.0.2)"
has "the other node: an addnode" "addnode=10.0.0.2:8333" "$w"
has "... and allowed to reach RPC" "rpcallowip=10.0.0.2" "$w"

echo "7d. a re-run restarts the node on what it wrote, with the same RPC password"
secrets_block="$(awk '/^log "Generating fresh node secrets"$/{on=1;next} on&&/^if \[\[ -f \/etc\/ghost\/pool.toml \]\]/{exit} on' "$INSTALLER")"
is "the RPC password step is present" yes "$([ -n "$secrets_block" ] && echo yes)"
rpcpw() { ( unset RPCPW; eval "${secrets_block//\/etc\/bitcoin\/bitcoin.conf/$TMP/bc.conf}"; echo "$RPCPW" ); }
pw="$(printf 'ab%.0s' {1..32})"
printf 'chain=signet\n[signet]\nrpcuser=u\nrpcpassword=%s\n' "$pw" > "$TMP/bc.conf"
is "a re-run keeps the RPC password (the other node's --submit-auth stays valid)" "$pw" "$(rpcpw)"
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

echo "7e. the found-block credentials"
auth_step="$(awk '/^if \[\[ -n "\$SUBMIT_AUTH" \]\]; then$/{on=1} on{print} on&&/^np_render_pool_config > \/etc\/ghost\/pool-config.toml$/{exit}' "$INSTALLER")"
is "the credentials step is present" yes "$([ -n "$auth_step" ] && echo yes)"
creds() {   # SUBMIT_AUTH SUBMIT_NODES: runs the step against $TMP/cr, prints READY|mode|content
    ( chown() { :; }; log() { echo "LOG $*" >> "$TMP/cr/log"; }
      np_render_pool_config() { echo "rendered READY=$SUBMIT_AUTH_READY"; }
      SUBMIT_AUTH="$1" SUBMIT_NODES="$2" SUBMIT_AUTH_FILE="$TMP/cr/solo-submit-rpc.auth"
      b="${auth_step//\/etc\/ghost\/pool-config.toml/$TMP/cr/pool-config.toml}"
      eval "$b"
      printf '%s|%s|%s' "$SUBMIT_AUTH_READY" "$(stat -c %a "$SUBMIT_AUTH_FILE" 2>/dev/null || echo none)" \
        "$($G -v '^#' "$SUBMIT_AUTH_FILE" 2>/dev/null)" )
}
rm -rf "$TMP/cr"; mkdir -p "$TMP/cr"
is "--submit-auth writes the file root-only, one user:password line" "true|600|ghostrpc_mainnet:pw" "$(creds ghostrpc_mainnet:pw http://10.0.0.2:8332)"
has "... the config is rendered after it, naming it" "rendered READY=true" "$(cat "$TMP/cr/pool-config.toml")"
printf 'http://10.0.0.2:8332 a:b\n' > "$TMP/cr/solo-submit-rpc.auth"; chmod 644 "$TMP/cr/solo-submit-rpc.auth"
is "a re-run without it keeps the file (edited by hand), and makes it 600" "true|600|http://10.0.0.2:8332 a:b" "$(creds '' http://10.0.0.2:8332)"
rm -f "$TMP/cr/solo-submit-rpc.auth" "$TMP/cr/log"
is "targets with no credentials: no file, not named" "false|none|" "$(creds '' http://10.0.0.2:8332)"
has "... and the install says the other node refuses them" "the other node refuses them" "$(cat "$TMP/cr/log")"
is "nothing prints the credentials (only the root-only file gets them)" 0 \
   "$($G -E '(echo|log|printf|warn|err) ' "$INSTALLER" | sed -E 's/-[nz] "\$SUBMIT_AUTH"//g' | $G -vF '> "${SUBMIT_AUTH_FILE}.tmp"' \
      | $G -cE '\$\{?SUBMIT_AUTH([^_A-Z]|$)' || true)"
is "... the file write is the one use" 1 "$($G -cF '"$SUBMIT_AUTH" > "${SUBMIT_AUTH_FILE}.tmp"' "$INSTALLER" || true)"
has "the file format is the one pool_sv2 parses (submit_rpc.rs)" 'http://10.0.0.2:8332 user:password' \
   "$(cat "$REPO_ROOT/bins/pool-sv2/src/lib/submit_rpc.rs")"
has "... and the installer documents it" '#     http://10.0.0.2:8332 user:password' "$(cat "$INSTALLER")"
has "... at the path pool_sv2's docs name" 'submit_rpc_auth_file = "/etc/ghost/solo-submit-rpc.auth"' \
   "$(cat "$REPO_ROOT/bins/pool-sv2/src/lib/config.rs")"
echo "7a. the test-only release mirror"
TFP=0123456789ABCDEF0123456789ABCDEF01234567
mirrored() {   # NETWORK MIRROR KEY_FP
    ( log() { :; }; err() { echo "ERR $*"; exit 1; }; usage() { :; }; np_preflight() { :; }
      NETWORK="$1" PEER_NODES="" SUBMIT_FLAGS="" BITCOIN_PEERS="" RPC_ALLOW="" SUBMIT_AUTH=""
      SIGNET_CHALLENGE="" ALERT_WEBHOOK="${ALERT_WEBHOOK:-}" ALERT_TOPIC="${ALERT_TOPIC:-}" PREFLIGHT_ONLY=false SYNC_MODE=ibd ARCHIVE=false
      GHOST_VERSION=np-v9.9.9 AUTO_UPDATE=false TEST_RELEASE_MIRROR="$2" TEST_RELEASE_KEY_FP="$3"
      eval "$(localize "$validate")"
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
NETWORK=mainnet; SIGNET_CHALLENGE=""; BITCOIN_PEERS=""; rm -f "$old" "$oldbc" "$auth"; pf
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


echo "11. the translator: both SV1 tiers, plain vardiff"
tcfg="$(sed -n '/^cat > \/etc\/ghost\/translator-config.toml <<EOF$/,/^EOF$/p' "$INSTALLER")"
is "the translator config is found" yes "$([ -n "$tcfg" ] && echo yes)"
is "quantise_to_tiers is off, once" 1 "$(printf '%s\n' "$tcfg" | $G -cx 'quantise_to_tiers = false' || true)"
is "... never on" 0 "$(printf '%s\n' "$tcfg" | $G -cx 'quantise_to_tiers = true' || true)"
has "small miners on 3333" "downstream_port = 3333" "$tcfg"
has "the farm tier block is emitted" '${FARM_TIER_BLOCK}' "$tcfg"
farm="$(awk '/^FARM_TIER_BLOCK="\[farm_tier\]$/{on=1} on{print} on&&/"$/{exit}' "$INSTALLER")"
has "... on 4444" "port = 4444" "$farm"
is "... unconditionally (no flag or mode turns it off)" 1 "$($G -c '^FARM_TIER_BLOCK=' "$INSTALLER" || true)"
has "ghost-mining advertises the farm port" "farm_port = 4444" "$(sed -n '/^cat > \/etc\/ghost\/pool.toml <<EOF$/,/^EOF$/p' "$INSTALLER")"
hasnt "no fee address as the translator's identity" 'FEE_ADDRESS' "$tcfg"

echo "12. the firewall"
fw="$(awk '/^log "Configuring firewall"$/{on=1} on{print} on&&/^ufw --force enable/{exit}' "$INSTALLER")"
reconcile="$(cat "$REPO_ROOT/scripts/reconcile-mining-firewall.sh")"
is "the firewall step is present" yes "$([ -n "$fw" ] && echo yes)"
has "ssh first" 'ufw allow 22/tcp' "$fw"
has "Bitcoin P2P (8333 on mainnet)" 'ufw allow "${NP_P2P_PORT}/tcp"' "$fw"
has "the ghost API" 'ufw allow 8080/tcp' "$fw"
has "Stratum 3333 and 34255 (reconcile)" 'PORTS=(3333 34255)' "$reconcile"
has "the farm tier 4444 (reconcile)" 'ufw allow 4444/tcp' "$reconcile"
is "the reconcile is installed and applied" 2 "$($G -cE '^(systemctl enable --now ghost-mining-firewall.path|/opt/ghost/bin/reconcile-mining-firewall.sh )' "$INSTALLER" || true)"
is "the relay port is never opened" 0 "$($G -cE '^ufw allow .*(8566|RELAY_PORT)' "$INSTALLER" || true)"
firewall_calls() {   # RPC_ALLOW OLD_RELAY_PORT: the ufw calls of the firewall step
    ( calls=""; ufw() { calls+="$*;"; }; log() { :; }; eval "$(declare -f np_uniq 2>/dev/null || $G '^np_uniq() ' "$INSTALLER")"
      NP_P2P_PORT=8333 TOR=false TOR_MODE=hybrid RPC_ALLOW="$1" OLD_RELAY_PORT="$2"
      eval "$fw"; echo "${calls//>\/dev\/null 2>&1/}" )
}
c="$(firewall_calls '' '')"
has "a re-run closes the relay port 8566" "delete allow 8566/tcp" "$c"
is "no RPC rule without another node" 0 "$(printf '%s' "$c" | $G -c '8332' || true)"
c="$(firewall_calls '10.0.0.2 10.0.0.3' 9566)"
has "a relay port an older config moved is closed too" "delete allow 9566/tcp" "$c"
has "... and 8566 still" "delete allow 8566/tcp" "$c"
has "the other node may reach RPC, from its address alone" "allow proto tcp from 10.0.0.2 to any port 8332" "$c"
has "... each of them" "allow proto tcp from 10.0.0.3 to any port 8332" "$c"
is "8332 is never opened to everyone" 0 "$($G -cE '^ufw allow 8332' "$INSTALLER" || true)"
has "the old mesh stays closed" "delete allow 8555:8562/tcp" "$c"

echo "13. the standard mempool policy"
reaper_line="$($G -E '^REAPER="(true|false)"' "$INSTALLER")"
is "the reaper is off by default" 'REAPER="false"' "$reaper_line"
rf="$(awk '/^REAPER_FLAGS=/{print} /^\[\[ "\$REAPER" == "true" \]\] && REAPER_FLAGS=/{print}' "$INSTALLER")"
flags() { ( REAPER="$1"; eval "$rf"; echo "$REAPER_FLAGS" ); }
is "off: ghostd is told so explicitly (its own default is ON)" "-ghostreaper=disabled" "$(flags false)"
has "--reaper: the detectors are on" "-ghostreaper=enabled" "$(flags true)"
has "the unit carries the flags" 'ExecStart=/opt/ghost/bin/ghostd -conf=/etc/bitcoin/bitcoin.conf -datadir=/var/lib/bitcoin ${REAPER_FLAGS}' "$(cat "$INSTALLER")"
ptoml="$(sed -n '/^cat > \/etc\/ghost\/pool.toml <<EOF$/,/^EOF$/p' "$INSTALLER")"
has "the template policy is full_open (no tier filter)" 'profile = "full_open"' "$ptoml"
has "ghost-mining's reaper follows the flag" 'enabled = ${REAPER}' "$ptoml"
has "ghostd's master switch defaults to enabled, which is why it is written" 'GetArg("-ghostreaper", "enabled")' \
   "$(cat "$REPO_ROOT/ghost-core/src/node/mempool_args.cpp" 2>/dev/null)"

echo "14. what the node pool left: nothing of it is written"
# (An older install's lister is removed: scripts/test-installer-lister.sh.)
for gone in '--np-import-genesis' 'ghost-lister.service <<' 'cat > /etc/ghost/lister.env' '[node_pool.relay]' 'fee_address =' \
            'genesis_anchor' 'GENESIS_STATUS' 'LISTER_STATUS' 'RELAY_PEERS'; do
    is "no $gone" 0 "$($G -cF -- "$gone" "$INSTALLER" || true)"
done

echo "15. the summary"
summary="$(awk '/^NODE_ID="\$\(sudo -u ghost/{on=1} on{print}' "$INSTALLER")"
is "the summary step is present" yes "$([ -n "$summary" ] && echo yes)"
shown() {   # SUBMIT_NODES SUBMIT_AUTH_READY: the summary as printed
    ( sudo() { :; }; systemctl() { echo inactive; }
      PUBIP=203.0.113.5 NETWORK=mainnet SV2_AUTH_PUB=9bAuthKey BITCOIN_CHECK="[PASS] ok" ALERT_WEBHOOK=""
      DASHBOARD_SRC="" GHOST_VERSION=np-v9.9.9 BITCOIN_PEERS="" SUBMIT_NODES="$1" SUBMIT_AUTH_READY="$2"
      eval "$summary" )
}
s="$(shown http://10.0.0.2:8332 true)"
has "it names the product"            "✅ Ghost Pool installed (mainnet)." "$s"
has "the payout rule"                  "pays it the subsidy and every fee, less 0.5% of the subsidy" "$s"
has "the help names it too" "Ghost Pool — installer" "$(sed -n '/^usage() {$/,/^}$/p' "$INSTALLER")"
is "no 'Ghost Solo' is left (the product is Ghost Pool)" 0 "$($G -ci 'Ghost Solo' "$INSTALLER" || true)"
has "the SV1 line for small miners"   "stratum+tcp://203.0.113.5:3333" "$s"
has "the SV1 line for the farm tier"  "stratum+tcp://203.0.113.5:4444" "$s"
has "the SV2 line with its authority key" "203.0.113.5:34255                 SV2, authority key 9bAuthKey" "$s"
has "the username is the miner's address" "username: their own Bitcoin address" "$s"
has "the other node"                  "found blocks also go to http://10.0.0.2:8332" "$s"
has "how to pair the other node"      "--peer-node 203.0.113.5" "$s"
for gone in Genesis Lister Relay "Fee address"; do hasnt "no $gone line" "$gone" "$s"; done
hasnt "no password in it" "rpcpassword=" "$(printf '%s\n' "$s" | $G -v "sudo grep")"
s="$(shown http://10.0.0.2:8332 false)"
has "targets without credentials say so" "NO credentials yet" "$s"
s="$(shown '' false)"
has "one node alone says so" "none (--peer-node <the other node>)" "$s"

echo "16. the auto-updater no longer waits for relay peers"
UPDATER="$REPO_ROOT/scripts/ghost-auto-update.sh"
is "no peer_count read" 0 "$($G -c '"peer_count"' "$UPDATER" || true)"
is "no PEERS_BEFORE" 0 "$($G -c 'PEERS_BEFORE' "$UPDATER" || true)"
has "it checks that ghost-mining answers /health" 'block_height' "$(sed -n '/^read_node_height() {$/,/^}$/p' "$UPDATER")"

echo
echo "test-installer-node-pool: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
