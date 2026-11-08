#!/usr/bin/env bash
#
# Ghost Pool — one-command installer (a solo mining pool node).
#
#   curl -sSL https://get.bitcoinghost.org | sudo bash -s -- --alert-webhook https://ntfy.sh
#
# Stands up a Ghost Pool node on Ubuntu: ghostd + ghost-mining + the SV2 stratum stack (pool_sv2
# and the SV1 translator). Ghost Pool is a solo mining pool: no accounts, no sign-up. A miner's
# username is its own Bitcoin address, and a block it finds pays it directly in the coinbase: the
# subsidy and every fee, less 0.5% of the subsidy to the treasury (compiled into pool_sv2). There is
# no share chain, relay, ledger, fee address or lister. Every per-node secret is generated fresh on
# this machine and never leaves it.
#
# Two nodes (A and B) back each other up: each sends every block its miners find to the other as
# well as to its own ghostd, and each keeps a direct Bitcoin connection to the other so a block
# reaches the network from both at once. On each node, once both are installed:
#
#   sudo bash install-node.sh --peer-node <the other node's IP> --submit-auth <its user:password>
#
# --peer-node sets `addnode=<ip>:8333` (the Bitcoin P2P link) and the found-block target
# `http://<ip>:8332` ([solo] submit_rpc in /etc/ghost/pool-config.toml), and lets that IP reach
# this node's Bitcoin RPC (rpcallowip, plus a ufw rule for that address only). The other node's RPC
# credentials are its /etc/bitcoin/bitcoin.conf `rpcuser`/`rpcpassword`.
#
# Found-block credentials file (what pool_sv2 reads, `[solo] submit_rpc_auth_file`):
#   /etc/ghost/solo-submit-rpc.auth, root:root 0600. One entry a line, `#` comments allowed:
#     http://10.0.0.2:8332 user:password    # for that node only
#     user:password                          # for every node without its own line
#   --submit-auth <user:password> writes the second form; a re-run without it keeps the file.
#   (Also GHOST_SUBMIT_AUTH=<user:password> in the environment, so it stays out of `ps`.)
#
# Derived from the verified provisioning of mainnet-5.
set -euo pipefail

# ─────────────────────────── network constants ───────────────────────────────
# ⛔ GHOST_VERSION names a release of this channel: `np-latest` (the newest published np-vX.Y.Z)
# or an exact `np-v…` tag. These releases have their own channel in the same GitHub repository:
# tags `np-v*`, published as pre-releases, so they are never the repository's `latest`. `latest`
# is the old network's, and its tags (v1.11.x) are refused here. Unset means `np-latest`, so
# `curl -sSL https://get.bitcoinghost.org | sudo bash` installs the newest Ghost Pool release: this
# installer can only ever resolve np- tags, never `releases/latest`. It used to refuse without one,
# which made the published one-liner fail at its first step (2026-11-08). The tarball is
# GPG-verified below regardless. RELEASE_BASE and POOL_TARBALL are set once the tag is resolved.
GHOST_VERSION="${GHOST_VERSION:-np-latest}"
# Signed release artefacts (GPG: defenwycke release key).
GPG_KEY_FP="777FE81F8CC077FD3D08055E852C2B3190F5B928"
# ghostd now ships INSIDE the signed release tarball (same SHA256SUMS + GPG chain
# as ghost-mining), so it can never drift from the release version and
# needs no separate checksum pin — its integrity rides the tarball signature we
# already verify below. GHOSTD_URL is an OPTIONAL, unverified escape hatch (empty
# by default) for transition/testing only; leave it unset in production so ghostd
# comes out of the verified tarball.
GHOSTD_URL="${GHOSTD_URL:-}"
RELEASE_KEY_URL="https://get.bitcoinghost.org/ghost-release-key.asc"
# Release assets live at <this>/<tag>/<asset>.
RELEASE_DOWNLOAD_URL="https://github.com/bitcoin-ghost/ghost/releases/download"
# ⛔ TEST ONLY: a local release mirror signed with a throwaway key, for rehearsing an install
# end to end (see test_release_mirror below). Both must be set; refused on mainnet. Never set
# either for a real node.
TEST_RELEASE_MIRROR="${GHOST_TEST_RELEASE_MIRROR:-}"
TEST_RELEASE_KEY_FP="${GHOST_TEST_RELEASE_KEY_FP:-}"
# ⛔ No old-network peers. The old network's eight nodes keep running `main`, and the two must never
# talk: a seed list here used to name the old fleet, so every install dialled its mesh. ghost-mining
# no longer runs the old mesh at all, and the old mesh ports stay closed (below).
# assumevalid checkpoint (speeds signature validation; does NOT skip download).
ASSUMEVALID="000000000000000000010538edbfd2d5b809a33dd83f284aeea41c6d0d96968a"

# ─────────────────────────────── defaults ────────────────────────────────────
NETWORK="mainnet"          # mainnet | signet | regtest
# A custom signet (`signetchallenge`, hex) and Bitcoin peers to dial (`addnode`, host:port). On a
# two-node setup the other node is one of these (--peer-node adds it); without a challenge
# `--network signet` is the public signet.
SIGNET_CHALLENGE=""
BITCOIN_PEERS=""
# Other nodes every found block is also sent to (`[solo] submit_rpc`), space-separated
# http(s)://host:port URLs; --submit-node host:port and --peer-node add to it.
SUBMIT_NODES=""
# Addresses allowed to reach this node's Bitcoin RPC besides 127.0.0.1 (the other node, so it can
# submit the blocks its miners find here). --peer-node adds its host's address.
RPC_ALLOW=""
# The other nodes' RPC credentials (`user:password`), for /etc/ghost/solo-submit-rpc.auth.
SUBMIT_AUTH="${GHOST_SUBMIT_AUTH:-}"
PREFLIGHT_ONLY="false"
ALERT_WEBHOOK=""
# Empty = keep the topic a previous install wrote, else a random one (see the re-run block). Never a
# fixed default: ntfy topics are public by name, so every node sharing one told strangers about it.
ALERT_TOPIC=""
NICKNAME="ghost-node"
SYNC_MODE="ibd"            # ibd (trustless, default) | haze (IRREVERSIBLE)
# Optional custom pool name. Empty = fall back to the default coinbase tag
# "GHOST PublicPool" (nothing written to pool.toml). When set it becomes the block coinbase
# scriptsig tag "- G H O S T - <name>", visible on explorers. ASCII, <=30 chars.
POOL_NAME=""
# ⛔ The Reaper is OFF by default on a solo node. A block propagates fastest when every peer can
# rebuild it from its own mempool (compact blocks): a template built from Bitcoin Core's standard
# policy is one they can, and a filtered mempool is not what they hold. ghostd's Reaper defaults to
# ON when no flag says otherwise, so the unit says `-ghostreaper=disabled` explicitly. --reaper
# turns it on (spam filtering, at the cost of templates peers have to fetch more of).
REAPER="false"
ARCHIVE="false"
# Tor. OFF by default — a plain clearnet install is completely unchanged.
#   hybrid   (--tor)      reach outbound peers via Tor AND stay reachable on
#                         clearnet 8333, plus publish an ephemeral v3 onion.
#   tor-only (--tor-only) route everything over Tor, disable clearnet
#                         (onlynet=onion) and close 8333.
# --no-tor pins it off. TOR_MODE only matters when TOR is "true".
TOR="false"
TOR_MODE="hybrid"
# Automatic updates. OFF by default — a node NEVER self-upgrades unless the
# operator explicitly opts in (here, or later via the dashboard toggle). The
# updater verifies the GPG release signature before applying anything.
AUTO_UPDATE="false"
BACKUPS="true"

usage() {
  cat <<EOF
Ghost Pool — installer (a solo mining pool node)

A solo mining pool: miners connect with their Bitcoin address as the username, and a block a
miner finds pays it the subsidy and every fee, less 0.5% of the subsidy to the treasury.
Nothing is required: run it with no flags on a terminal for a guided setup.

Network:
  --network <name>            mainnet | signet | regtest           (default: mainnet)
  --signet-challenge <hex>    signet only: a custom signet's challenge script (signetchallenge).
                                Default: the public signet.
  --preflight-only            Run the preflight checks and exit; change nothing.

Two nodes (the other node backs this one up; run the same on it, pointing back here):
  --peer-node <host>          The other node: addnode=<host>:8333 (a direct Bitcoin link, so a
                                block found on either reaches the network from both), found
                                blocks also sent to http://<host>:8332, and that host allowed
                                to reach this node's Bitcoin RPC (rpcallowip + a ufw rule for
                                it alone). Repeat for more. Keep that link private (a VPN or a
                                private network): the RPC password crosses it.
  --submit-auth <user:pass>   The other node's Bitcoin RPC credentials (its bitcoin.conf
                                rpcuser/rpcpassword), written root-only to
                                /etc/ghost/solo-submit-rpc.auth. Or GHOST_SUBMIT_AUTH=... in
                                the environment. A re-run without it keeps the file.
  --bitcoin-peer <host:port>  A Bitcoin peer for ghostd to dial (addnode); repeat for more.
                                --peer-node adds the other node here.
  --submit-node <host:port>   Another Bitcoin node's RPC that every found block is also sent
                                to (submitblock), without the addnode or rpcallowip that
                                --peer-node adds; repeat for more. http(s):// URLs work too.

Strongly recommended:
  --alert-webhook <url>       Push endpoint for node alerts (e.g. https://ntfy.sh). Without
                                this, alerts are DISABLED and every detector — low disk,
                                node offline, behind tip, restart loop … — fires into nothing.
  --alert-topic <name>        Push topic                        (default: ghost-node)

Options:
  --nickname <name>           Display name of this node       (default: ghost-node)
  --pool-name <name>          Custom pool name shown in the block coinbase as
                                '- G H O S T - <name>' on explorers. ASCII only,
                                max 30 chars. Distinct from --nickname (the node's
                                display name). Default tag: "GHOST PublicPool".
  --sync <mode>               ibd | haze                      (default: ibd)
                                ibd  — full trustless sync + prune (recommended)
                                haze — strips block data, ~195GB, FAST but
                                       IRREVERSIBLE. You can never serve raw
                                       blocks or go archive without a full resync.
  --reaper                    Run the mempool reaper (spam filter). Off by default: blocks
                                built from the standard policy propagate fastest.
  --no-reaper                 Don't run the mempool reaper    (default)
  --archive                   Full archive node (~720GB)
  --tor                       Route over Tor (hybrid): outbound peers via Tor +
                                publish an onion, still reachable on clearnet 8333
  --tor-only                  Route over Tor ONLY: no clearnet (onlynet=onion),
                                close 8333 (implies --tor)
  --no-tor                    Never use Tor                   (default)
  --auto-update               Automatically apply newer SIGNED releases of this channel (off
                                by default). Follows the np- channel only, never the old
                                network's releases. Verifies the GPG signature and the
                                tarball checksum before swapping any binary; health-checks
                                and rolls back on failure. Checked every 6h.
  --no-auto-update            Never auto-update                (default)
  --backups                   Nightly local database backups at 03:00 UTC,
                                kept 7 days in /var/backups/ghost/db   (default)
  --no-backups                No nightly backups. They can be switched on later:
                                sudo systemctl enable --now ghost-backup.timer
  --fee-address, --payout-address <address>
                              Accepted and ignored: fees go to the miner who finds the block.
  --node-pool                 Accepted and ignored.
  --non-interactive           Never prompt; use flags/defaults only (for scripts)
  -h, --help                  This help.

Removing the node:
  --uninstall                 Stop and remove the node's services, timers, binaries, dashboard,
                                firewall rules (22/tcp stays), sudoers files and release channel.
                                KEEPS its data: the chain, node.key, miner statistics, the
                                configs and the backups; installing again reuses them. Asks for
                                confirmation. Also removes what an older (node pool) install left:
                                the lister and its user, and the relay's firewall rule.
  --purge                     With --uninstall: delete that data too. Cannot be undone.
  --yes                       With --uninstall: do not ask (for scripts).

Environment:
  GHOST_VERSION=<release>     np-latest (the default: the newest Ghost Pool release) or an
                                exact np-v<x.y.z> tag. Old-network tags (v1.11.x) are refused.

Miners connect to:
  stratum+tcp://<this node>:3333   SV1, small miners (Bitaxe, NerdAxe)
  stratum+tcp://<this node>:4444   SV1, the farm tier (S19/S21-class, rented hashrate)
  <this node>:34255                SV2 (Noise; the authority key is printed at the end)
  Username: <your Bitcoin address>[.<worker>] (P2SH, P2WPKH, P2WSH or P2TR). Password: anything.

Every install runs a preflight first (RAM, disk, ports, Bitcoin node, peers); a failed check
stops it before anything is changed.

The node dashboard is installed with the node and listens on 127.0.0.1:3000 only (reach it
through an SSH tunnel). Its password is in /etc/ghost/dashboard.env (root-only).

Re-running the installer on a node keeps its identity, keys and settings (peers, found-block
targets and their credentials), and restarts the node (and the dashboard) on what it wrote.
EOF
}

# ─────────────────────────────── arg parse ───────────────────────────────────
# CONFIG_FLAGS counts how many config-setting flags were passed. The interactive
# wizard runs ONLY when none were given (and stdin is a TTY and --non-interactive
# was not passed); otherwise the script behaves exactly as the flag interface
# always has.
CONFIG_FLAGS=0
NON_INTERACTIVE="false"
UNINSTALL="false"
PURGE="false"
ASSUME_YES="false"
while [[ $# -gt 0 ]]; do
  case "$1" in
    # Fees go to the miner who finds the block now. Kept so an old command line still runs.
    --fee-address|--payout-address) shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1))
                      echo "NOTE: --fee-address/--payout-address is ignored: every fee goes to the miner who finds the block." >&2;;
    --network)        NETWORK="$2"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --signet-challenge) SIGNET_CHALLENGE="$2"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --bitcoin-peer)   BITCOIN_PEERS="${BITCOIN_PEERS:+$BITCOIN_PEERS }$2"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --peer-node)      PEER_NODES="${PEER_NODES:+$PEER_NODES }$2"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --submit-node)    SUBMIT_FLAGS="${SUBMIT_FLAGS:+$SUBMIT_FLAGS }$2"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --submit-auth)    SUBMIT_AUTH="$2"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --preflight-only) PREFLIGHT_ONLY="true"; shift;;
    --alert-webhook)  ALERT_WEBHOOK="$2"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --alert-topic)    ALERT_TOPIC="$2"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --nickname)       NICKNAME="$2"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --pool-name)      POOL_NAME="${2:-}"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --sync)           SYNC_MODE="$2"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --reaper)         REAPER="true"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --no-reaper)      REAPER="false"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --archive)        ARCHIVE="true"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --tor)            TOR="true"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --tor-only)       TOR="true"; TOR_MODE="tor-only"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --no-tor)         TOR="false"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --auto-update)    AUTO_UPDATE="true"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --no-auto-update) AUTO_UPDATE="false"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --backups)        BACKUPS="true"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --no-backups)     BACKUPS="false"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --node-pool)      shift;;   # kept so old command lines still run
    --non-interactive) NON_INTERACTIVE="true"; shift;;
    --uninstall)      UNINSTALL="true"; shift;;
    --purge)          PURGE="true"; shift;;
    --yes)            ASSUME_YES="true"; shift;;
    -h|--help)        usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done
PEER_NODES="${PEER_NODES:-}"
SUBMIT_FLAGS="${SUBMIT_FLAGS:-}"

err() { echo "ERROR: $*" >&2; exit 1; }
log() { echo -e "\033[36m==>\033[0m $*"; }

# >>> NODE_POOL_FUNCTIONS
# The Ghost Pool pieces of this installer: the payout address check, per-network defaults, the
# pool_sv2 config and the preflight. Kept between these two markers (whose name is older than
# Ghost Pool) and free of side effects (they only print), because two tests run them straight out
# of this file:
#   scripts/test-installer-node-pool.sh       the shell-level checks, preflight lines included
#   bins/pool-sv2/tests/installer_config.rs   pool_sv2 parses the rendered config, and agrees with
#                                             np_payout_address_check on every address class
# Edit them here; both tests read this file, not a copy.

# Network → bech32 human-readable part. Signet and regtest share testnet's P2SH version byte.
np_hrp() {
  case "$1" in
    mainnet) echo bc;; signet) echo tb;; regtest) echo bcrt;;
    *) return 1;;
  esac
}
np_p2sh_version() { case "$1" in mainnet) echo 5;; signet|regtest) echo 196;; *) return 1;; esac; }

NP_B32_CHARSET="qpzry9x8gf2tvdw0s3jn54khce6mua7l"
NP_B58_ALPHABET="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# BIP 173 checksum over a list of 5-bit values.
np_bech32_polymod() {
  local chk=1 v b i
  local -a g=(0x3b6a57b2 0x26508e6d 0x1ea119fa 0x3d4233dd 0x2a1462b3)
  for v in "$@"; do
    b=$((chk >> 25))
    chk=$(( ((chk & 0x1ffffff) << 5) ^ v ))
    for i in 0 1 2 3 4; do
      if (( (b >> i) & 1 )); then chk=$((chk ^ g[i])); fi
    done
  done
  echo "$chk"
}

# Double SHA-256 of a hex string, as hex.
np_sha256d_hex() {
  local h
  h="$(printf '%b' "$(sed 's/../\\x&/g' <<<"$1")" | sha256sum | cut -c1-64)"
  printf '%b' "$(sed 's/../\\x&/g' <<<"$h")" | sha256sum | cut -c1-64
}

# np_payout_address_check ADDRESS NETWORK
# Succeeds, printing the class (p2sh, p2wpkh, p2wsh, p2tr), when ADDRESS is a valid address of
# NETWORK in one of the four payee classes pool_sv2 accepts as a miner's username
# (Solo::payee_for_identity). Otherwise fails, printing why. Checksums are verified.
# installer_config.rs checks it agrees with pool_sv2 on every address class.
np_payout_address_check() {
  local a="$1" net="$2" hrp
  hrp="$(np_hrp "$net")" || { echo "unknown network '$net'"; return 1; }
  [[ -n "$a" ]] || { echo "no address given"; return 1; }
  local lower="${a,,}"
  if [[ "$lower" =~ ^([a-z]+)1([qpzry9x8gf2tvdw0s3jn54khce6mua7l]+)$ ]]; then
    [[ "$a" == "$lower" || "$a" == "${a^^}" ]] || { echo "mixed-case bech32 is invalid"; return 1; }
    (( ${#a} <= 90 )) || { echo "too long for a bech32 address"; return 1; }
    local got="${BASH_REMATCH[1]}" data="${BASH_REMATCH[2]}"
    if [[ "$got" != "$hrp" ]]; then
      echo "is a '${got}1…' address; a ${net} node needs '${hrp}1…'"
      return 1
    fi
    (( ${#data} >= 8 )) || { echo "too short for a segwit address"; return 1; }
    local -a vals=() exp=()
    local i c pre
    for (( i = 0; i < ${#data}; i++ )); do
      c="${data:i:1}"; pre="${NP_B32_CHARSET%%"$c"*}"; vals+=("${#pre}")
    done
    for (( i = 0; i < ${#hrp}; i++ )); do exp+=("$(( $(printf '%d' "'${hrp:i:1}") >> 5 ))"); done
    exp+=(0)
    for (( i = 0; i < ${#hrp}; i++ )); do exp+=("$(( $(printf '%d' "'${hrp:i:1}") & 31 ))"); done
    local chk ver="${vals[0]}"
    chk="$(np_bech32_polymod "${exp[@]}" "${vals[@]}")"
    if (( ver == 0 )); then
      (( chk == 1 )) || { echo "bad checksum"; return 1; }
    else
      (( chk == 0x2bc830a3 )) || { echo "bad checksum"; return 1; }
    fi
    # Witness program: 5-bit groups to bytes, no padding allowed beyond 4 zero bits.
    local acc=0 bits=0 n=0 j
    for (( j = 1; j < ${#vals[@]} - 6; j++ )); do
      acc=$(( ((acc << 5) | vals[j]) & 0xfff ))
      bits=$((bits + 5))
      if (( bits >= 8 )); then bits=$((bits - 8)); n=$((n + 1)); fi
    done
    if (( bits >= 5 || (acc & (2 ** bits - 1)) != 0 )); then echo "bad padding"; return 1; fi
    case "$ver:$n" in
      0:20) echo p2wpkh;;
      0:32) echo p2wsh;;
      1:32) echo p2tr;;
      *) echo "witness v${ver} with a ${n}-byte program is not P2WPKH, P2WSH or P2TR"; return 1;;
    esac
    return 0
  fi
  if [[ "$a" =~ ^[1-9A-HJ-NP-Za-km-z]{25,35}$ ]]; then
    local -a bytes=()
    local k carry pre2 z=0
    for (( i = 0; i < ${#a}; i++ )); do
      c="${a:i:1}"; pre2="${NP_B58_ALPHABET%%"$c"*}"; carry="${#pre2}"
      for (( k = ${#bytes[@]} - 1; k >= 0; k-- )); do
        carry=$(( carry + bytes[k] * 58 )); bytes[k]=$(( carry & 255 )); carry=$(( carry >> 8 ))
      done
      while (( carry > 0 )); do bytes=("$(( carry & 255 ))" "${bytes[@]}"); carry=$(( carry >> 8 )); done
    done
    while [[ "${a:z:1}" == 1 ]]; do bytes=(0 "${bytes[@]}"); z=$((z + 1)); done
    (( ${#bytes[@]} == 25 )) || { echo "not a valid address"; return 1; }
    local hex="" sum
    for (( i = 0; i < 21; i++ )); do hex+="$(printf '%02x' "${bytes[i]}")"; done
    sum="$(np_sha256d_hex "$hex")"
    [[ "${sum:0:8}" == "$(printf '%02x%02x%02x%02x' "${bytes[@]:21:4}")" ]] \
      || { echo "bad checksum"; return 1; }
    case "${bytes[0]}" in
      0|111) echo "P2PKH is not accepted (only P2SH, P2WPKH, P2WSH and P2TR)"; return 1;;
    esac
    if (( bytes[0] != $(np_p2sh_version "$net") )); then
      if (( bytes[0] == 5 || bytes[0] == 196 )); then
        echo "is a P2SH address of another network than ${net}"
      else
        echo "not a valid address"
      fi
      return 1
    fi
    echo p2sh
    return 0
  fi
  echo "not a valid address"
  return 1
}

# Per-network defaults. Sets:
#   NP_P2P_PORT              ghostd's P2P port (the network's own default)
#   NP_MIN_RAM_MB / NP_WARN_RAM_MB, NP_MIN_DISK_GB   the preflight's floors
#
# Mainnet floors, measured on vm8 (2026-11-07, pruned): the whole stack used 1.46 GB, and ghostd's
# RSS reached 2.2 GB with dbcache=1024; under 4 GB of RAM ghostd is given dbcache=450
# (np_dbcache). Disk: the pruned chain state is about 12 GB; 25 GB counts a chain already there.
np_network_defaults() {
  local net="$1" sync="${2:-ibd}" archive="${3:-false}"
  case "$net" in
    mainnet)
      NP_P2P_PORT=8333; NP_MIN_RAM_MB=2800; NP_WARN_RAM_MB=3800
      if [[ "$archive" == "true" ]]; then NP_MIN_DISK_GB=800
      elif [[ "$sync" == "haze" ]]; then NP_MIN_DISK_GB=250
      else NP_MIN_DISK_GB=25; fi;;
    signet)
      NP_P2P_PORT=38333; NP_MIN_RAM_MB=3500; NP_WARN_RAM_MB=7000; NP_MIN_DISK_GB=30;;
    regtest)
      NP_P2P_PORT=18444; NP_MIN_RAM_MB=1500; NP_WARN_RAM_MB=3500; NP_MIN_DISK_GB=5;;
    *) return 1;;
  esac
}

# np_dbcache MEM_MB: ghostd's dbcache for a machine with MEM_MB of RAM. 1024 from 4 GB up; 450
# (Bitcoin Core's default) below, or when the RAM could not be read: ghostd's RSS reached 2.2 GB
# at 1024 on vm8, which leaves too little of a 3 GB machine for the rest of the stack.
np_dbcache() {
  if [[ "${1:-}" =~ ^[0-9]+$ ]] && (( $1 >= 4096 )); then echo 1024; else echo 450; fi
}

# np_submit_url ENTRY: a found-block target as the URL pool_sv2 takes (`[solo] submit_rpc`).
# host:port becomes http://host:port; an http(s)://host:port URL is kept. Fails on anything else
# (a path, credentials in the URL, no port).
np_submit_url() {
  local e="${1%/}"
  if [[ "$e" =~ ^(https?://)?[A-Za-z0-9._-]+:([0-9]{1,5})$ ]] \
     && (( BASH_REMATCH[2] > 0 && BASH_REMATCH[2] < 65536 )); then
    [[ -n "${BASH_REMATCH[1]}" ]] || e="http://${e}"
    echo "$e"; return 0
  fi
  return 1
}

# np_render_pool_config: the whole pool_sv2 config, on stdout. Reads
#   SV2_AUTH_PUB SV2_AUTH_SEC TDP_PUBKEY APISECRET NETWORK
#   SUBMIT_NODES (space-separated http(s):// URLs; may be unset)
#   SUBMIT_AUTH_READY (true when /etc/ghost/solo-submit-rpc.auth exists; may be unset). The file
#     is named only then: pool_sv2 refuses to start on a credentials file it cannot read.
np_render_pool_config() {
  local submit="" u auth_line
  for u in ${SUBMIT_NODES:-}; do submit+="${submit:+, }\"${u}\""; done
  auth_line="# submit_rpc_auth_file = \"/etc/ghost/solo-submit-rpc.auth\""
  [[ -n "$submit" && "${SUBMIT_AUTH_READY:-false}" == true ]] \
    && auth_line="submit_rpc_auth_file = \"/etc/ghost/solo-submit-rpc.auth\""
  cat <<EOF
# Ghost Pool (SV2). Generated by install-node.sh.
#
# ghost-mining (TDP :8442) -> pool_sv2 (SV2 :34255) -> translator (SV1 :3333, :4444) -> miners

# Per-node SV2 authority keypair (Ed25519/secp256k1, generated fresh at install).
authority_public_key = "${SV2_AUTH_PUB}"
authority_secret_key = "${SV2_AUTH_SEC}"
cert_validity_sec = 3600

# Listen for SV2 miners/translators.
listen_address = "0.0.0.0:34255"

# Required by the SV2 config, but not what blocks pay: every miner's job pays the treasury and
# that miner ([solo] below). This script is only the group channel's, whose job is never sent. It
# is the treasury's (bc1qgxg5ywk835c9fp6arz6d6x50xpk6y0ualt900k), the same on every network.
coinbase_reward_script = "raw(00144191423ac78d3054875d18b4dd1a8f306da23f9d)"

# Pool identification. pool_signature is kept in step with ghost-mining's coinbase
# tag by update-pool-signature.sh (sri-pool ExecStartPre); this is the fallback
# until ghost-mining has written its coinbase_tag file.
server_id = 1
pool_signature = "- G H O S T -"

# Difficulty settings
shares_per_minute = 6.0
share_batch_size = 1

# Protocol extensions — the Ghost per-miner TLV extension (0x0002) and the Ghost agent extension
# (0x4748), which binds a channel the translator opened on subscribe to the miner's address once
# it authorises. (pool_sv2 also adds 0x4748 by itself; it is listed so the pairing is visible and
# checked.)
supported_extensions = [0x0002, 0x4748]
required_extensions = []

# Monitoring endpoint (localhost; the translator readiness gate polls it).
monitoring_address = "127.0.0.1:9090"

# Native share accounting into ghost-mining.
#
# \`secret\` is mandatory (H-13) and must match ghost-mining's [network] internal_api_secret —
# the same value written into pool.toml. ghost-mining requires an HMAC on every share batch:
# loopback alone authorised any process on the box to write to it.
[share_webhook]
url = "http://127.0.0.1:8080/api/internal/shares"
secret = "${APISECRET}"
batch_size = 1
batch_timeout_ms = 2000
max_retries = 3

# Bounds on concurrent downstream connections (#994).
#
# ⛔ Commented out = the built-in defaults apply, NOT unlimited. Uncomment only to override.
#   max_downstream_connections   default 512
#   max_connections_per_ip       default 64
# A value of 0 is clamped to 1 rather than honoured.
# max_downstream_connections = 512
# max_connections_per_ip = 64

# GHOST POOL. Every job pays, in its coinbase: the treasury exactly subsidy / 200, the miner whose
# username (its Bitcoin address) opened the channel the rest (subsidy - subsidy / 200 + every fee),
# and the witness commitment. Nothing else.
[solo]
# mainnet, signet or regtest: the subsidy schedule and which addresses miners may use.
network = "${NETWORK}"
# Where miner-stats.json and blocks-found.json are kept across restarts.
state_dir = "/var/lib/ghost/solo"
# Other Bitcoin nodes every found block is also sent to (submitblock), in parallel, after the
# local node: the other node of a two-node setup (install-node.sh --peer-node / --submit-node).
submit_rpc = [${submit}]
# Their credentials, root-only: one \`user:password\` (every node) or \`http://host:port
# user:password\` (that node) a line. Never in this file, never logged.
${auth_line}
# The translator's SV1 ports, shown by /api/v1/pool/status (3333 small miners, 4444 farm tier).
sv1_ports = [3333, 4444]

# Template provider — this node's own ghost-mining TDP server. public_key is the
# TDP authority key derived from node.key.
[template_provider_type.Sv2Tp]
address = "127.0.0.1:8442"
public_key = "${TDP_PUBKEY}"
EOF
}

# ── preflight ───────────────────────────────────────────────────────────────────
# One line per check: PASS, WARN (installs anyway) or FAIL (stops before anything is changed).
# The probes are functions so a test can stand in for the machine.
PF_FAILS=0
pf_line() {
  local status="$1"; shift
  printf '  [%s] %s\n' "$status" "$*"
  [[ "$status" == FAIL ]] && PF_FAILS=$((PF_FAILS + 1))
  return 0
}
pf_mem_mb() { awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null || true; }
# Space, in GB, the chain can use on the filesystem that holds it: free space plus a chain
# already in /var/lib/bitcoin (a re-run or a machine that already runs a Bitcoin node keeps it).
pf_disk_free_gb() {
  local d=/var/lib free have=0
  free="$(df -Pk "$d" 2>/dev/null | awk 'NR == 2 {print $4}')" || true
  [[ -n "$free" ]] || return 0
  if [[ -d /var/lib/bitcoin ]]; then have="$(du -sk /var/lib/bitcoin 2>/dev/null | awk '{print $1}')"; fi
  echo $(( (free + ${have:-0}) / 1048576 ))
}
# The process listening on a TCP port, or nothing when the port is free.
pf_port_owner() {
  ss -Hltnp "sport = :$1" 2>/dev/null | head -1 | sed -nE 's/.*users:\(\("([^"]+)".*/\1/p;t;s/.+/unknown/p' || true
}
# getblockchaininfo's chain, or nothing when no node answers.
pf_bitcoin_chain() {
  local conf=/etc/bitcoin/bitcoin.conf user pw
  [[ -r "$conf" ]] || return 0
  user="$(grep -m1 '^rpcuser=' "$conf" | cut -d= -f2-)"
  pw="$(grep -m1 '^rpcpassword=' "$conf" | cut -d= -f2-)"
  curl -s --max-time 8 --user "${user}:${pw}" \
    --data '{"jsonrpc":"1.0","id":"preflight","method":"getblockchaininfo","params":[]}' \
    http://127.0.0.1:8332/ 2>/dev/null | grep -oE '"chain":[[:space:]]*"[a-z0-9]+"' | grep -oE '"[a-z0-9]+"$' | tr -d '"' || true
}
pf_resolves() { getent hosts "$1" >/dev/null 2>&1; }
# The address a host resolves to (itself when it is one), or nothing. IPv4 first.
pf_resolve_ip() {
  if [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then echo "$1"; return 0; fi
  getent ahostsv4 "$1" 2>/dev/null | awk 'NR == 1 {print $1}' || true
}
# The host of a found-block target (host:port or http(s)://host:port).
np_url_host() { local h="${1#*://}"; echo "${h%:*}"; }
pf_dashboard_active() { systemctl is-active --quiet ghost-dashboard 2>/dev/null; }
# The chain name bitcoind reports for a network.
np_core_chain() { case "$1" in mainnet) echo main;; signet) echo signet;; regtest) echo regtest;; esac; }

# np_preflight: every check, then a verdict. Reads NETWORK SYNC_MODE ARCHIVE SIGNET_CHALLENGE
# BITCOIN_PEERS SUBMIT_NODES RPC_ALLOW SUBMIT_AUTH SUBMIT_AUTH_PRESENT ALERT_WEBHOOK. Returns
# non-zero when any check FAILed.
np_preflight() {
  PF_FAILS=0
  np_network_defaults "$NETWORK" "$SYNC_MODE" "$ARCHIVE" || { pf_line FAIL "network '$NETWORK' is not mainnet, signet or regtest"; return 1; }
  local mem disk p owner chain
  echo "Preflight (${NETWORK}):"

  mem="$(pf_mem_mb)"
  if [[ -z "$mem" ]]; then pf_line WARN "RAM: could not be read"
  elif (( mem < NP_MIN_RAM_MB )); then pf_line FAIL "RAM: ${mem} MB, a ${NETWORK} node needs at least ${NP_MIN_RAM_MB} MB"
  elif (( mem < NP_WARN_RAM_MB )); then pf_line WARN "RAM: ${mem} MB, ${NP_WARN_RAM_MB} MB or more recommended (ghostd gets dbcache=$(np_dbcache "$mem"))"
  else pf_line PASS "RAM: ${mem} MB (ghostd dbcache=$(np_dbcache "$mem"))"; fi

  disk="$(pf_disk_free_gb)"
  if [[ -z "$disk" ]]; then pf_line WARN "disk: free space on /var/lib could not be read"
  elif (( disk < NP_MIN_DISK_GB )); then pf_line FAIL "disk: ${disk} GB available on /var/lib (free plus any chain already there), this node (${NETWORK}, sync ${SYNC_MODE}$([[ "$ARCHIVE" == true ]] && echo ", archive")) needs ${NP_MIN_DISK_GB} GB"
  else pf_line PASS "disk: ${disk} GB available on /var/lib (needs ${NP_MIN_DISK_GB} GB)"; fi

  # Ports this node listens on. Held by one of the node's own processes is a re-run, not a clash.
  for p in "$NP_P2P_PORT" 8332 8080 8442 3333 4444 34255 9090; do
    owner="$(pf_port_owner "$p")"
    case "$owner" in
      "") pf_line PASS "port ${p} is free";;
      ghostd|ghost-mining|ghost-pool|pool_sv2|translator_sv2) pf_line PASS "port ${p} is held by this node's ${owner} (re-run)";;
      *) pf_line FAIL "port ${p} is in use by ${owner}; this node needs it";;
    esac
  done

  # The dashboard's loopback port. Someone else on it only keeps the dashboard down, not the node.
  owner="$(pf_port_owner 3000)"
  if [[ -z "$owner" ]]; then pf_line PASS "port 3000 is free (node dashboard, loopback only)"
  elif pf_dashboard_active; then pf_line PASS "port 3000 is held by this node's dashboard (re-run)"
  else pf_line WARN "port 3000 is in use by ${owner}: the node dashboard will not start until it is free"; fi

  # The Bitcoin node. A re-run talks to the one already installed; a fresh install has none yet.
  chain="$(pf_bitcoin_chain)"
  if [[ -n "$chain" ]]; then
    if [[ "$chain" == "$(np_core_chain "$NETWORK")" ]]; then
      pf_line PASS "Bitcoin node answers on 127.0.0.1:8332 (chain ${chain})"
    else
      pf_line FAIL "Bitcoin node on 127.0.0.1:8332 runs chain '${chain}', not ${NETWORK}"
    fi
  elif [[ -r /etc/bitcoin/bitcoin.conf ]] && [[ -n "$(pf_port_owner 8332)" ]]; then
    pf_line FAIL "Bitcoin RPC port 8332 is listening but does not answer with /etc/bitcoin/bitcoin.conf's credentials (a re-run by an older installer changed the password under a running ghostd: sudo systemctl restart ghostd, then re-run)"
  else
    pf_line PASS "no Bitcoin node yet: ghostd is installed and checked again once started"
  fi

  # ghostd's chain: a custom signet's challenge, and Bitcoin peers to dial.
  if [[ -n "${SIGNET_CHALLENGE:-}" ]]; then
    if [[ "$NETWORK" != signet ]]; then
      pf_line FAIL "--signet-challenge is for --network signet, not ${NETWORK}"
    elif [[ "$SIGNET_CHALLENGE" =~ ^([0-9a-fA-F]{2}){1,520}$ ]]; then
      pf_line PASS "custom signet, challenge ${SIGNET_CHALLENGE:0:16}…"
    else
      pf_line FAIL "signet challenge '${SIGNET_CHALLENGE}' is not a hex script"
    fi
  elif [[ "$NETWORK" == signet ]]; then
    pf_line WARN "no --signet-challenge: this node joins the public signet"
  fi
  for p in ${BITCOIN_PEERS:-}; do
    if [[ "$p" =~ ^([^[:space:]=]+):([0-9]{1,5})$ ]] && (( BASH_REMATCH[2] > 0 && BASH_REMATCH[2] < 65536 )); then
      pf_line PASS "Bitcoin peer ${p}"
    else
      pf_line FAIL "Bitcoin peer '${p}' is not host:port"
    fi
  done

  # The other node: where found blocks are also sent, and who may reach this node's RPC.
  if [[ -z "${SUBMIT_NODES:-}" ]]; then
    pf_line WARN "no other node (--peer-node): found blocks are submitted to this node's ghostd only"
  else
    for p in $SUBMIT_NODES; do
      if np_submit_url "$p" >/dev/null; then
        if pf_resolves "$(np_url_host "$p")"; then pf_line PASS "found blocks also go to ${p}"
        else pf_line WARN "found-block target ${p} does not resolve now"; fi
      else
        pf_line FAIL "found-block target '${p}' is not host:port or an http(s)://host:port URL"
      fi
    done
    if [[ -n "${SUBMIT_AUTH:-}" ]]; then
      if [[ "$SUBMIT_AUTH" =~ ^[^[:space:]:#]+:[^[:space:]#]+$ ]]; then
        pf_line PASS "found-block credentials given (written root-only to /etc/ghost/solo-submit-rpc.auth)"
      else
        pf_line FAIL "--submit-auth must be user:password (no spaces or #)"
      fi
    elif [[ "${SUBMIT_AUTH_PRESENT:-false}" == true ]]; then
      pf_line PASS "found-block credentials kept from /etc/ghost/solo-submit-rpc.auth"
    else
      pf_line WARN "no --submit-auth: the other node refuses found blocks until /etc/ghost/solo-submit-rpc.auth holds its RPC user:password"
    fi
  fi
  for p in ${RPC_ALLOW:-}; do
    if [[ "$p" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
      pf_line PASS "the other node ${p} may reach this node's Bitcoin RPC (8332, that address only)"
    else
      pf_line FAIL "'${p}' is not an IPv4 address: --peer-node needs a host that resolves to one"
    fi
  done

  if [[ -z "$ALERT_WEBHOOK" ]]; then
    pf_line WARN "no alert webhook (--alert-webhook): alerts are written disabled"
  elif [[ "$ALERT_WEBHOOK" =~ ^https?://[^[:space:]\"]+$ ]]; then
    pf_line PASS "alert webhook ${ALERT_WEBHOOK}"
  else
    pf_line FAIL "alert webhook '${ALERT_WEBHOOK}' is not an http(s) URL"
  fi

  if (( PF_FAILS > 0 )); then
    echo "Preflight: ${PF_FAILS} check(s) FAILED. Nothing has been changed."
    return 1
  fi
  echo "Preflight: passed."
}

# >>> NP_RELEASE_CHANNEL
# The node pool release channel. Node pool releases are tagged `np-vMAJOR.MINOR.PATCH` and are
# published as GitHub PRE-releases, so GitHub can never make one the repository's `latest`: the
# old network's nodes resolve `releases/latest` and must never be handed a node pool build. A node
# pool node therefore never asks for `latest`; it lists the releases and picks the newest
# `np-v` tag itself. The same block is in scripts/install-node.sh, which resolves
# GHOST_VERSION=np-latest with it; scripts/test-release-channel.sh keeps the copies identical.
NP_RELEASES_API_URL="${GHOST_NP_RELEASES_API_URL:-https://api.github.com/repos/bitcoin-ghost/ghost/releases?per_page=100}"
# The marker the node pool installer writes. Present and saying `node-pool`: this node follows the
# np- channel. Absent: an install from before the channel existed, which keeps the old channel.
# Anything else is refused, never guessed.
NP_CHANNEL_FILE="${GHOST_RELEASE_CHANNEL_FILE:-/etc/ghost/release-channel}"

# np_tag_ok TAG — an exact node pool release tag, final or with a suffix (np-v1.2.3-rc1).
np_tag_ok() { [[ "$1" =~ ^np-v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; }
# np_tag_final TAG — a final node pool release: the only kind np-latest ever picks.
np_tag_final() { [[ "$1" =~ ^np-v[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

# np_latest_tag — reads a GitHub "list releases" JSON array on stdin and prints the highest final
# np- tag of a PUBLISHED release. Drafts, tags of any other shape (the old network's v1.11.x,
# np-v…-rc1) and anything else are skipped. Exit 1 when there is none, 2 when the JSON does not
# have the shape this expects (each release carries one tag_name and one draft), so a changed API
# fails closed instead of picking something. The prerelease flag is not used: every node pool
# release carries it, which is what keeps them out of `latest`.
np_latest_tag() {
  local tok key val tag="" draft="" cands=""
  while IFS= read -r tok; do
    key="${tok#\"}"; key="${key%%\"*}"
    val="${tok#*:}"; val="${val#"${val%%[![:space:]]*}"}"; val="${val//\"/}"
    case "$key" in
      tag_name) [[ -z "$tag" ]] || return 2; tag="$val" ;;
      draft)    [[ -z "$draft" ]] || return 2; draft="$val" ;;
    esac
    if [[ -n "$tag" && -n "$draft" ]]; then
      if [[ "$draft" == false ]] && np_tag_final "$tag"; then cands+="${tag#np-v}"$'\n'; fi
      tag=""; draft=""
    fi
  done < <(grep -oE '"(tag_name|draft)"[[:space:]]*:[[:space:]]*("[^"]*"|true|false)' || true)
  [[ -z "$tag" && -z "$draft" ]] || return 2
  [[ -n "$cands" ]] || return 1
  echo "np-v$(printf '%s' "$cands" | sort -V | tail -1)"
}

# np_channel — prints this node's release channel: `node-pool` or `old-network`. Fails, printing
# why on stderr, when the marker exists but says anything else.
np_channel() {
  [[ -e "$NP_CHANNEL_FILE" ]] || { echo old-network; return 0; }
  local v
  v="$(grep -vE '^[[:space:]]*(#|$)' "$NP_CHANNEL_FILE" 2>/dev/null | head -1 | tr -d '[:space:]')"
  [[ "$v" == node-pool ]] || { echo "release channel marker $NP_CHANNEL_FILE says '${v}', expected 'node-pool'" >&2; return 1; }
  echo node-pool
}
# <<< NP_RELEASE_CHANNEL

# np_resolve_release SPEC — prints the node pool release tag to install for GHOST_VERSION=SPEC:
# `np-latest` resolves to the newest published np-vX.Y.Z (never `releases/latest`, which is the
# old network's), an exact np- tag is taken as given. Anything else fails, saying why.
np_resolve_release() {
  local spec="$1" json tag rc=0
  case "$spec" in
    "")
      echo "Name the Ghost Pool release to install: GHOST_VERSION=np-latest (or an exact np-v<x.y.z> tag). The latest GitHub release is the old network's and is never installed." >&2
      return 1 ;;
    np-latest)
      json="$(curl -fsSL --max-time 30 "$NP_RELEASES_API_URL" 2>/dev/null)" \
        || { echo "GHOST_VERSION=np-latest: could not fetch the release list from $NP_RELEASES_API_URL" >&2; return 1; }
      tag="$(np_latest_tag <<<"$json")" || rc=$?
      case "$rc" in
        0) echo "$tag" ;;
        1) echo "GHOST_VERSION=np-latest: no Ghost Pool release (np-v<x.y.z>) is published yet" >&2; return 1 ;;
        *) echo "GHOST_VERSION=np-latest: the release list is not in the expected shape — refusing to pick one" >&2; return 1 ;;
      esac ;;
    *)
      if np_tag_ok "$spec"; then echo "$spec"; return 0; fi
      echo "GHOST_VERSION=$spec is not a Ghost Pool release. Ghost Pool releases are tagged np-v<x.y.z>; v-tags are the old network's. Use GHOST_VERSION=np-latest or an exact np- tag." >&2
      return 1 ;;
  esac
}

# <<< NODE_POOL_FUNCTIONS

# is_core_rpc_client PATH — true only if PATH is the Ghost Core RPC client (#1028).
# Two programs have been called `ghost-cli`: the Core RPC client, which is what the name means
# on every node and in every runbook, and the Rust administration tool, which release tarballs
# up to v1.11.45 shipped under that name (it is `ghost-admin` from then on). A file name in a
# tarball therefore proves nothing, so ask the binary. The admin tool answers `-version` with
# a usage error on stderr; a binary that hangs is cut off and refused.
is_core_rpc_client() {
  [[ -f "$1" && -x "$1" ]] || return 1
  local out
  out="$(timeout "${CLI_IDENTITY_TIMEOUT:-10}" "$1" -version 2>/dev/null)" || return 1
  [[ "${out%%$'\n'*}" == *"RPC client"* ]]
}

# Strip leading/trailing whitespace (mirrors the dashboard wizard's .trim()).
_trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }

# Validate a custom pool name against the SAME rules as the dashboard wizard:
# printable ASCII (0x20–0x7E) only, max 30 characters after trimming. Returns 0
# if the trimmed name is acceptable, non-zero otherwise. (An empty name is
# "invalid" here; callers treat empty as "use the default" before calling this.)
pool_name_valid() {
  local n; n="$(_trim "$1")"
  [[ -n "$n" ]] || return 1
  (( ${#n} <= 30 )) || return 1
  LC_ALL=C grep -qE '^[ -~]+$' <<<"$n"
}

# Set to "true" by the wizard so the post-wizard validation below doesn't ask the
# haze confirmation a second time (the wizard already collected it).
WIZARD_RAN="false"

# Yes/No prompt with a default. Echoes "true" or "false" so the caller can assign
# it straight into REAPER / ARCHIVE. The read prompt
# goes to stderr, so it stays visible inside $(...) capture; only the echoed
# answer is captured. `|| true` keeps an EOF (Ctrl-D) from tripping `set -e`.
prompt_yes_no() {
  local question="$1" default="$2" answer hint="[y/N]"
  [[ "$default" == "Y" ]] && hint="[Y/n]"
  read -rp "$question $hint " answer || true
  answer="${answer:-$default}"
  case "${answer,,}" in
    y|yes) echo "true";;
    n|no)  echo "false";;
    *)     [[ "$default" == "Y" ]] && echo "true" || echo "false";;
  esac
}

# Interactive first-run wizard. Collects the SAME variables the flag interface
# sets (NETWORK, PEER_NODES, SUBMIT_AUTH, ALERT_WEBHOOK, SYNC_MODE, POOL_NAME, REAPER,
# ARCHIVE, NICKNAME); the rest of the installer is unchanged. Only ever runs with no
# config flags, on a TTY, without --non-interactive.
run_wizard() {
  echo
  log "Ghost Pool — guided setup"
  echo "This installs a Ghost Pool node (ghostd + ghost-mining + the SV2 stratum stack): a solo"
  echo "mining pool whose miners use their Bitcoin address as the username and are paid the whole"
  echo "block they find (less 0.5% of the subsidy). Press Enter to accept each [default]."
  echo

  # Network.
  local nw
  read -rp "Network: mainnet, signet or regtest [mainnet]: " nw || true
  nw="$(_trim "${nw:-mainnet}")"
  case "$nw" in mainnet|signet|regtest) NETWORK="$nw";; *) echo "  Unrecognised — using mainnet."; NETWORK="mainnet";; esac

  # The other node (optional).
  echo
  echo "The other node (optional): a second Ghost Pool node this one backs up and is backed up by."
  echo "Found blocks go to both nodes, and the two keep a direct Bitcoin connection. Install both,"
  echo "then give each the other's address. Keep the link between them private (VPN or LAN)."
  local pn_host
  read -rp "Other node's IP or hostname [none]: " pn_host || true
  PEER_NODES="$(_trim "$pn_host")"
  if [[ -n "$PEER_NODES" ]]; then
    echo "  Its Bitcoin RPC credentials: on that node, sudo grep -E '^rpc(user|password)=' /etc/bitcoin/bitcoin.conf"
    local su
    read -rsp "  Its rpcuser:rpcpassword [leave blank to add later]: " su || true
    echo
    SUBMIT_AUTH="$(_trim "$su")"
  fi

  # Alert webhook (optional, but without it every detector fires into nothing).
  echo
  echo "Alert webhook (optional): an ntfy-style push endpoint, e.g. https://ntfy.sh. Without one,"
  echo "alerts are written disabled and low disk, node offline, restart loops … reach nobody."
  local wh
  while :; do
    read -rp "Alert webhook URL [none]: " wh || wh=""
    wh="$(_trim "$wh")"
    if [[ -z "$wh" ]]; then ALERT_WEBHOOK=""; break; fi
    if [[ "$wh" =~ ^https?://[^[:space:]\"]+$ ]]; then
      ALERT_WEBHOOK="$wh"
      local tp
      read -rp "Alert topic [${ALERT_TOPIC:-a random, private one}]: " tp || true
      tp="$(_trim "$tp")"; [[ -n "$tp" ]] && ALERT_TOPIC="$tp"
      break
    fi
    echo "  ✗ Must be an http:// or https:// URL. Try again (or leave blank)."
  done

  # Sync mode.
  echo
  echo "Block download / sync method:"
  echo "  1) ibd   full trustless sync — validates every block (hours up to ~a day). RECOMMENDED."
  echo "  2) haze  IRREVERSIBLE — strips block data (~195GB, fast). Can never serve raw blocks or"
  echo "           become an archive node afterwards without a full resync."
  local sync_choice
  read -rp "Choose 1 or 2 [1]: " sync_choice || true
  sync_choice="${sync_choice:-1}"
  case "$sync_choice" in
    1|ibd)  SYNC_MODE="ibd";;
    2|haze)
      SYNC_MODE="haze"
      echo
      echo -e "\033[33mWARNING\033[0m: haze strips block data IRREVERSIBLY."
      local hc
      read -rp "  Type 'yes' to confirm haze (anything else uses ibd): " hc || true
      if [[ "$hc" != "yes" ]]; then
        echo "  Not confirmed — falling back to ibd."; SYNC_MODE="ibd"
      fi
      ;;
    *) echo "  Unrecognised choice — using ibd."; SYNC_MODE="ibd";;
  esac

  # Optional custom pool name (the coinbase tag). Blank = the default tag
  # "GHOST PublicPool". Validated/re-prompted to match the dashboard.
  POOL_NAME=""
  echo
  echo "Pool name (optional) — shown in the block coinbase as '- G H O S T - <name>'"
  echo "on block explorers. ASCII only, max 30 characters. Leave blank for the default."
  while :; do
    local pn
    read -rp "Pool name [none]: " pn || true
    pn="$(_trim "$pn")"
    [[ -z "$pn" ]] && { POOL_NAME=""; break; }
    if pool_name_valid "$pn"; then POOL_NAME="$pn"; break; fi
    echo "  ✗ Must be printable ASCII and at most 30 characters. Try again (or leave blank)."
  done

  # ghostd options.
  echo
  echo "Node options:"
  REAPER="$(prompt_yes_no "  Run the mempool reaper — filters spam/inscriptions (blocks then propagate slower)?" N)"
  ARCHIVE="$(prompt_yes_no "  Run as a full archive node — ~720GB disk?" N)"

  # Tor. Off by default. Hybrid keeps clearnet reachability AND adds an onion;
  # tor-only routes everything over Tor and drops clearnet.
  echo
  echo "Privacy:"
  TOR="$(prompt_yes_no "  Route this node over Tor (adds an onion service)?" N)"
  if [[ "$TOR" == "true" ]]; then
    if [[ "$(prompt_yes_no "    Tor-only? (N = hybrid: reachable on clearnet AND via onion)" N)" == "true" ]]; then
      TOR_MODE="tor-only"
    else
      TOR_MODE="hybrid"
    fi
  fi

  # Automatic updates. Off by default — explicit opt-in only. Every applied
  # update verifies the GPG release signature before swapping any binary.
  echo
  echo "Maintenance:"
  AUTO_UPDATE="$(prompt_yes_no "  Enable automatic updates? (verifies GPG signature before applying)" N)"
  BACKUPS="$(prompt_yes_no "  Back up the node database every night? (local copies, kept 7 days)" Y)"

  # Nickname.
  echo
  local nn
  read -rp "Node nickname [ghost-node]: " nn || true
  NICKNAME="${nn:-ghost-node}"

  # Summary + final confirmation before anything destructive happens.
  echo
  log "Summary of your choices"
  echo "  Network        : $NETWORK"
  echo "  Other node     : ${PEER_NODES:-none}$([[ -n "$PEER_NODES" && -z "$SUBMIT_AUTH" ]] && echo "  (no RPC credentials yet)")"
  echo "  Alert webhook  : ${ALERT_WEBHOOK:-none (alerts disabled)}"
  echo "  Sync mode      : $SYNC_MODE"
  [[ -n "$POOL_NAME" ]] && echo "  Pool name      : $POOL_NAME  (coinbase: - G H O S T - $POOL_NAME)"
  echo "  Reaper         : $REAPER"
  echo "  Archive node   : $ARCHIVE"
  echo "  Tor            : $([[ "$TOR" == "true" ]] && echo "$TOR_MODE" || echo "off")"
  echo "  Auto-update    : $AUTO_UPDATE"
  echo "  Backups        : $BACKUPS"
  echo "  Nickname       : $NICKNAME"
  echo
  local proceed
  proceed="$(prompt_yes_no "Proceed with installation?" Y)"
  [[ "$proceed" == "true" ]] || err "Aborted by user."
  WIZARD_RAN="true"
  echo
}

[[ $EUID -eq 0 ]] || err "Run as root (sudo)."

# >>> NP_UNINSTALL
# --uninstall: take the node off this machine and keep its data; --purge takes the data too.
# Removed: every unit, timer and drop-in this installer writes, /opt/ghost (binaries, helper
# scripts, the dashboard and its Node.js runtime), the firewall rules it opened (22/tcp stays, so
# ssh keeps working, and ufw stays enabled), its sudoers files, the release channel marker, the
# installed-version file, the auto-update opt-in and the journald drop-in. What an older (node
# pool) install left goes too: the lister's unit (ghost-lister.service), and with --purge its
# user (ghost-audit), its state (/var/lib/ghost-audit) and the relay's store
# (/var/lib/ghost/node-pool.db), as well as its relay port's firewall rule.
# Kept unless --purge: the chain (/var/lib/bitcoin), the node's state (/var/lib/ghost: miner
# statistics and found blocks), node.key and ghost-mining's database (/home/ghost/.ghost), the
# configs that carry the node's keys and settings (/etc/ghost, /etc/bitcoin), the nightly backups
# (/var/backups/ghost, /var/lib/ghost-backup) and the ghost user. Installing again over what was
# kept reuses the node's identity, keys and peers, as a re-run does.
# Kept between these markers so scripts/test-installer-uninstall.sh can run it against a throwaway
# root (UNINSTALL_ROOT) with systemctl, ufw and userdel stood in for.
UNINSTALL_ROOT="${UNINSTALL_ROOT:-}"
NP_UNITS=(ghost-dashboard.service sri-translator.service sri-pool.service ghost-mining.service
  ghost-mining-gate.service ghostd.service ghost-auto-update.timer ghost-auto-update.service
  ghost-restart-watch.timer ghost-restart-watch.service ghost-backup.timer ghost-backup.service
  ghost-mining-firewall.path ghost-mining-firewall.service ghost-lister.service)
NP_UNIT_DROPINS=(ghost-dashboard.service.d ghost-mining.service.d ghost-auto-update.service.d)
NP_DATA=(/var/lib/bitcoin /var/lib/ghost /home/ghost /etc/ghost /etc/bitcoin /var/backups/ghost
  /var/lib/ghost-backup /var/lib/ghost-audit)
NP_REMOVED_FILES=(/etc/sudoers.d/ghost-autoupdate /etc/sudoers.d/ghost-backup-offsite
  /etc/ghost/release-channel /etc/ghost/version /etc/ghost/auto-update.conf
  /etc/systemd/journald.conf.d/10-ghost.conf)

# The TCP ports this installer opens: the Bitcoin P2P port as configured (all three networks' P2P
# defaults when the config is gone), the API and the stratum ports; and those an older install
# opened: the node pool relay's (as its config named it, 8566 by default) and 8442, opened before
# the TDP server moved to loopback. Never 22.
np_opened_ports() {
  local r="$UNINSTALL_ROOT" p2p relay
  p2p="$(sed -nE 's/^port=([0-9]+)$/\1/p' "$r/etc/bitcoin/bitcoin.conf" 2>/dev/null | head -1)"
  relay="$(sed -nE 's/^listen = "[^"]*:([0-9]+)"$/\1/p' "$r/etc/ghost/pool-config.toml" 2>/dev/null | head -1)"
  if [[ -n "$p2p" ]]; then echo "$p2p"; else printf '%s\n' 8333 38333 18444; fi
  printf '%s\n' "${relay:-8566}" 8080 3333 34255 4444 8442
}

# The other nodes allowed to reach this node's Bitcoin RPC (bitcoin.conf rpcallowip, loopback
# aside): each has a ufw rule for 8332 from that address alone (--peer-node).
np_rpc_allowed() {
  sed -nE 's/^rpcallowip=([^[:space:]]+)$/\1/p' "$UNINSTALL_ROOT/etc/bitcoin/bitcoin.conf" 2>/dev/null \
    | { /usr/bin/grep -vxE '127\.0\.0\.1(/32)?|::1' || true; }
}

np_uninstall() {
  local r="$UNINSTALL_ROOT" u p f d answer word=uninstall
  [[ "$PURGE" == true ]] && word=purge
  echo "This removes the Ghost Pool node from this machine: its services, timers, binaries"
  echo "(/opt/ghost), dashboard, firewall rules (except 22/tcp), sudoers files and release channel."
  if [[ "$PURGE" == true ]]; then
    echo "--purge: it ALSO DELETES the node's data, which cannot be undone:"
    for d in "${NP_DATA[@]}"; do echo "    $d"; done
    echo "  node.key (the node's identity) and the found-block record are in there. Back them up first."
  else
    echo "The node's data is kept: the chain, node.key, the miner statistics, the configs and the backups."
  fi
  if [[ "$ASSUME_YES" != true ]]; then
    # Never `read` stdin: under `curl … | sudo bash` stdin is this script (see --sync haze).
    { true </dev/tty; } 2>/dev/null || err "--uninstall needs confirmation and there is no terminal to ask. Re-run with --yes."
    read -rp "Type '${word}' to continue: " answer </dev/tty || answer=""
    [[ "$answer" == "$word" ]] || err "Aborted. Nothing was changed."
  fi

  log "Stopping and removing the node's services"
  for u in "${NP_UNITS[@]}"; do
    systemctl disable --now "$u" >/dev/null 2>&1 || true
  done
  for u in "${NP_UNITS[@]}"; do rm -f "$r/etc/systemd/system/$u"; done
  for d in "${NP_UNIT_DROPINS[@]}"; do rm -rf "$r/etc/systemd/system/$d"; done
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed >/dev/null 2>&1 || true

  log "Removing /opt/ghost (binaries, helper scripts, dashboard, Node.js runtime)"
  rm -rf "$r/opt/ghost"

  log "Removing the firewall rules the installer opened (22/tcp is left open)"
  for p in $(np_opened_ports | sort -un); do
    ufw delete allow "${p}/tcp" >/dev/null 2>&1 || true
  done
  for p in $(np_rpc_allowed); do
    ufw delete allow proto tcp from "$p" to any port 8332 >/dev/null 2>&1 || true
  done

  log "Removing sudoers files, the release channel, the version and auto-update files"
  for f in "${NP_REMOVED_FILES[@]}"; do rm -f "$r$f"; done

  if [[ "$PURGE" == true ]]; then
    log "Purging the node's data"
    for d in "${NP_DATA[@]}"; do rm -rf "$r$d"; done
    if id ghost >/dev/null 2>&1; then userdel ghost >/dev/null 2>&1 || true; fi
    if id ghost-audit >/dev/null 2>&1; then userdel ghost-audit >/dev/null 2>&1 || true; fi
    echo
    echo "  Ghost Pool node removed, data included. Nothing of it is left in:"
    for d in "${NP_DATA[@]}"; do echo "    $d"; done
  else
    echo
    echo "  Ghost Pool node removed. Kept (installing again reuses all of it):"
    for d in "${NP_DATA[@]}"; do
      [[ -e "$r$d" ]] || continue
      printf '    %-22s %6s  %s\n' "$d" "$(du -sh "$r$d" 2>/dev/null | cut -f1)" "$(np_kept_what "$d")"
    done
    echo "  Also kept: the ghost user, ufw (enabled, 22/tcp open), and the apt packages it installed."
    echo "  To delete the data as well: re-run with --uninstall --purge."
  fi
}

np_kept_what() {
  case "$1" in
    /var/lib/bitcoin)      echo "the chain (ghostd's data directory)";;
    /var/lib/ghost)        echo "solo/ (miner statistics, found blocks); node-pool.db if an older install left one";;
    /home/ghost)           echo ".ghost/node.key (node identity), ghost-mining's database";;
    /etc/ghost)            echo "pool.toml, pool-config.toml (SV2 key, found-block targets), solo-submit-rpc.auth, dashboard.env, dashboard-internal-auth.env";;
    /etc/bitcoin)          echo "bitcoin.conf (RPC password, signet challenge, peers)";;
    /var/backups/ghost)    echo "nightly database backups";;
    /var/lib/ghost-backup) echo "off-node backup key and status";;
    /var/lib/ghost-audit)  echo "an older install's lister state";;
  esac
}
# <<< NP_UNINSTALL

if [[ "$UNINSTALL" == true ]]; then
  np_uninstall
  exit 0
fi
[[ "$PURGE" != true ]] || err "--purge goes with --uninstall."

# Enter the wizard ONLY with no config flags, an interactive terminal, and no
# --non-interactive. Otherwise fall straight through to the flag/validation path
# exactly as before.
if [[ "$CONFIG_FLAGS" -eq 0 && "$NON_INTERACTIVE" != "true" && -t 0 ]]; then
  run_wizard
fi

np_hrp "$NETWORK" >/dev/null || err "--network must be mainnet, signet or regtest."
np_network_defaults "$NETWORK" "$SYNC_MODE" "$ARCHIVE"
# A re-run keeps what the last install wrote when no flag says otherwise: the found-block targets
# live only in pool_sv2's config, their credentials in their own file, and a custom signet's
# challenge, the Bitcoin peers and the RPC allow-list in bitcoin.conf, which is rewritten on every
# run. Losing the challenge would move the node to the public signet, a different chain.
OLD_POOL_CONFIG=/etc/ghost/pool-config.toml
OLD_BITCOIN_CONF=/etc/bitcoin/bitcoin.conf
SUBMIT_AUTH_FILE=/etc/ghost/solo-submit-rpc.auth
old_key() { [[ -r "$OLD_POOL_CONFIG" ]] && sed -nE "s/^${1}[[:space:]]*=[[:space:]]*(.*)$/\1/p" "$OLD_POOL_CONFIG" | head -1 || true; }
# Words of a list, each once, in order.
np_uniq() { local w out="" seen=" "; for w in $1; do [[ "$seen" == *" $w "* ]] && continue; seen+="$w "; out+="${out:+ }$w"; done; echo "$out"; }
# The relay port an older (node pool) install opened, closed on the firewall below.
OLD_RELAY_PORT="$(sed -nE 's/^listen = "[^"]*:([0-9]+)"$/\1/p' "$OLD_POOL_CONFIG" 2>/dev/null | head -1 || true)"
if [[ -z "$SIGNET_CHALLENGE" && "$NETWORK" == signet && -r "$OLD_BITCOIN_CONF" ]]; then
  SIGNET_CHALLENGE="$(sed -nE 's/^signetchallenge=([0-9a-fA-F]+)$/\1/p' "$OLD_BITCOIN_CONF" | head -1)"
  [[ -n "$SIGNET_CHALLENGE" ]] && log "Keeping the custom signet challenge from ${OLD_BITCOIN_CONF}"
fi
if [[ -z "$BITCOIN_PEERS" && -z "$PEER_NODES" && -r "$OLD_BITCOIN_CONF" ]]; then
  BITCOIN_PEERS="$(sed -nE 's/^addnode=(.+)$/\1/p' "$OLD_BITCOIN_CONF" | paste -sd' ' -)"
fi
if [[ -z "$SUBMIT_FLAGS" && -z "$PEER_NODES" ]]; then
  SUBMIT_FLAGS="$(_trim "$(old_key submit_rpc | tr -d '[]",')")"
  [[ -n "$SUBMIT_FLAGS" ]] && log "Keeping the found-block targets from ${OLD_POOL_CONFIG}: ${SUBMIT_FLAGS}"
fi
# Alerts: pool.toml is rewritten on every run, so a re-run without --alert-webhook used to write
# alerts DISABLED on a node that had them. Keep the channel the last install (or the dashboard)
# configured. A topic is never shared: ntfy topics are public by name, and the old fixed default
# `ghost-node` put every node's alerts on one topic anyone could read (2026-11-08).
OLD_NODE_CONFIG=/etc/ghost/pool.toml
old_push() { [[ -r "$OLD_NODE_CONFIG" ]] && sed -nE "/^\[alerts\.channels\.push\]/,/^\[/s/^${1}[[:space:]]*=[[:space:]]*\"([^\"]*)\".*$/\1/p" "$OLD_NODE_CONFIG" | head -1 || true; }
if [[ -z "$ALERT_WEBHOOK" ]]; then
  ALERT_WEBHOOK="$(old_push webhook_url)"
  [[ -n "$ALERT_WEBHOOK" ]] && log "Keeping the alert webhook from ${OLD_NODE_CONFIG}"
fi
if [[ -n "$ALERT_WEBHOOK" && -z "$ALERT_TOPIC" ]]; then
  ALERT_TOPIC="$(old_push topic)"
  [[ "$ALERT_TOPIC" == ghost-node ]] && ALERT_TOPIC=""
  [[ -n "$ALERT_TOPIC" ]] || ALERT_TOPIC="ghostpool-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
fi
if [[ -z "$PEER_NODES" && -r "$OLD_BITCOIN_CONF" ]]; then
  RPC_ALLOW="$(sed -nE 's/^rpcallowip=([^[:space:]]+)$/\1/p' "$OLD_BITCOIN_CONF" | { /usr/bin/grep -vxE '127\.0\.0\.1(/32)?|::1' || true; } | paste -sd' ' -)"
fi
# --peer-node HOST: the other node. A Bitcoin link to its P2P port, its RPC as a found-block
# target, and its address allowed to reach this node's RPC (so it can send its blocks here).
for h in $PEER_NODES; do
  [[ "$h" =~ ^[A-Za-z0-9._-]+$ ]] || err "--peer-node takes a host (an IP address or a name), not '${h}': the ports are the network's."
  BITCOIN_PEERS+=" ${h}:${NP_P2P_PORT}"
  SUBMIT_FLAGS+=" ${h}:8332"
  peer_ip="$(pf_resolve_ip "$h")"
  RPC_ALLOW+=" ${peer_ip:-$h}"
done
BITCOIN_PEERS="$(np_uniq "$BITCOIN_PEERS")"
RPC_ALLOW="$(np_uniq "$RPC_ALLOW")"
SUBMIT_NODES=""
for e in $SUBMIT_FLAGS; do
  # A malformed entry is kept as given, for the preflight to name.
  u="$(np_submit_url "$e")" || u="$e"
  SUBMIT_NODES+=" $u"
done
SUBMIT_NODES="$(np_uniq "$SUBMIT_NODES")"
SUBMIT_AUTH="$(_trim "${SUBMIT_AUTH:-}")"
SUBMIT_AUTH_PRESENT=false
[[ -s "$SUBMIT_AUTH_FILE" ]] && SUBMIT_AUTH_PRESENT=true

# ⛔ Preflight, before anything on this machine is changed. A FAIL stops the install here.
np_preflight || err "Preflight failed — fix the FAIL lines above and re-run."
[[ "$PREFLIGHT_ONLY" == "true" ]] && exit 0

# ⛔ TEST ONLY: install from a local release mirror instead of GitHub. The mirror is laid out as
# release-node-pool.yml publishes, under one URL M:
#   M/releases                       the release list (GitHub's "list releases" JSON)
#   M/download/<tag>/<asset>         bitcoin-ghost-<tag>-x86_64-unknown-linux-gnu.tar.gz,
#                                    SHA256SUMS.txt, SHA256SUMS.txt.asc
#   M/release-key.asc                the throwaway public key that signed SHA256SUMS.txt
# and is verified exactly as a real release is, against GHOST_TEST_RELEASE_KEY_FP instead of the
# release key. The node's updater is pointed at the same mirror (a drop-in, below), so the rehearsal
# covers automatic updates too. Both variables or neither; never on mainnet.
if [[ -n "$TEST_RELEASE_MIRROR" || -n "$TEST_RELEASE_KEY_FP" ]]; then
  [[ -n "$TEST_RELEASE_MIRROR" && -n "$TEST_RELEASE_KEY_FP" ]] \
    || err "GHOST_TEST_RELEASE_MIRROR and GHOST_TEST_RELEASE_KEY_FP go together (test installs only)."
  [[ "$NETWORK" != mainnet ]] || err "GHOST_TEST_RELEASE_MIRROR is for test installs on signet or regtest, never mainnet."
  [[ "$TEST_RELEASE_KEY_FP" =~ ^[0-9A-F]{40}$ ]] || err "GHOST_TEST_RELEASE_KEY_FP must be a 40-hex uppercase fingerprint."
  [[ "$TEST_RELEASE_KEY_FP" != "$GPG_KEY_FP" ]] || err "GHOST_TEST_RELEASE_KEY_FP is the release key: a test mirror is signed with a throwaway key."
  TEST_RELEASE_MIRROR="${TEST_RELEASE_MIRROR%/}"
  NP_RELEASES_API_URL="${TEST_RELEASE_MIRROR}/releases"
  RELEASE_DOWNLOAD_URL="${TEST_RELEASE_MIRROR}/download"
  RELEASE_KEY_URL="${TEST_RELEASE_MIRROR}/release-key.asc"
  GPG_KEY_FP="$TEST_RELEASE_KEY_FP"
  echo -e "\033[33mWARNING\033[0m: TEST RELEASE MIRROR ${TEST_RELEASE_MIRROR}, verified against ${GPG_KEY_FP}."
  echo "         This node installs and updates from a test mirror, not from real releases."
fi

# The node pool release channel: np-latest or an exact np- tag, never an old-network tag.
GHOST_VERSION_SPEC="$GHOST_VERSION"
GHOST_VERSION="$(np_resolve_release "$GHOST_VERSION_SPEC")" || err "GHOST_VERSION='${GHOST_VERSION_SPEC}' refused (see above)."
[[ "$GHOST_VERSION_SPEC" == "$GHOST_VERSION" ]] || log "GHOST_VERSION=${GHOST_VERSION_SPEC} resolved to ${GHOST_VERSION}"
RELEASE_BASE="${RELEASE_DOWNLOAD_URL}/${GHOST_VERSION}"
POOL_TARBALL="bitcoin-ghost-${GHOST_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
DASHBOARD_TARBALL="bitcoin-ghost-${GHOST_VERSION}-dashboard.tar.gz"
# Automatic updates follow the same channel: the updater reads /etc/ghost/release-channel
# (written below) and picks the newest np- release, never the old network's `releases/latest`.

# The [alerts] block. ⛔ Written with `enabled` reflecting whether a channel was actually given:
# a section that says `enabled = true` with nowhere to deliver is worse than an honest false,
# because it reads as configured (#985). ghost-mining warns loudly at every start in either case.
# ⚠ AlertsConfig carries #[serde(deny_unknown_fields)] — these key names must match config.rs.
if [[ -n "$ALERT_WEBHOOK" ]]; then
  ALERTS_BLOCK=$(cat <<ALERTS
[alerts]
enabled = true

[alerts.channels.push]
enabled = true
webhook_url = "${ALERT_WEBHOOK}"
topic = "${ALERT_TOPIC}"
ALERTS
)
else
  ALERTS_BLOCK=$(cat <<'ALERTS'
# ⛔ NO ALERT DELIVERY IS CONFIGURED. Fourteen detectors are wired and every one of them will
# fire into nothing. Re-run the installer with --alert-webhook, or set a channel below and flip
# `enabled` to true. ghost-mining warns about this at every start until you do.
[alerts]
enabled = false

# [alerts.channels.push]
# enabled = true
# webhook_url = "https://ntfy.sh"
# topic = "ghost-node"
ALERTS
)
fi

[[ "$(uname -m)" == "x86_64" ]] || err "Only x86_64 is supported by this installer right now."
case "$SYNC_MODE" in ibd) ;;
  haze) if [[ "$WIZARD_RAN" != "true" ]]; then
          echo -e "\033[33mWARNING\033[0m: --sync haze strips block data IRREVERSIBLY. This node can never";
          echo "         serve raw blocks or become an archive node without a full resync.";
          # ⛔ Never `read` stdin here: under `curl … | sudo bash` stdin IS this script, so the
          # prompt swallowed the next line of the installer as its answer. Ask the terminal; with
          # no terminal, --non-interactive is the operator saying they have read this.
          if [[ "$NON_INTERACTIVE" == "true" ]]; then
            echo "         --non-interactive given: continuing."
          elif { true </dev/tty; } 2>/dev/null; then
            read -rp "         Type 'yes' to continue: " c </dev/tty || c=""
            [[ "$c" == "yes" ]] || err "Aborted."
          else
            err "--sync haze needs confirmation and there is no terminal to ask. Re-run with --non-interactive to confirm."
          fi
        fi;;
  *) err "--sync must be ibd or haze.";;
esac

# Normalise / validate an optional custom pool name. The wizard validates
# interactively and re-prompts; this central check catches the flag path
# (--pool-name) and mirrors the dashboard wizard's rules exactly (printable
# ASCII, <=30 chars after trimming) so the installer and dashboard agree on the
# resulting coinbase tag. Empty = use the mode default (nothing written).
if [[ -n "$POOL_NAME" ]]; then
  if pool_name_valid "$POOL_NAME"; then
    POOL_NAME="$(_trim "$POOL_NAME")"
  else
    err "--pool-name must be printable ASCII (no control characters) and at most 30 characters."
  fi
fi

# A re-run on a node that is running: noted before anything changes, so the node is restarted on
# the new binaries and configs at the end (section 11). Nothing else here restarts it.
NODE_WAS_RUNNING=false
for u in ghostd ghost-mining sri-pool sri-translator; do
  systemctl is-active --quiet "$u" 2>/dev/null && NODE_WAS_RUNNING=true
done

# ────────────────────────────── 1. packages ──────────────────────────────────
log "Installing dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  libevent-2.1-7 libevent-extra-2.1-7 libevent-pthreads-2.1-7 libevent-openssl-2.1-7 \
  libzmq5 libsqlite3-0 ca-certificates ufw openssl curl gnupg tar >/dev/null
# Tor — only when routing over Tor. DEBIAN_FRONTEND is already exported above.
if [[ "$TOR" == "true" ]]; then
  log "Installing Tor"
  apt-get install -y -qq tor >/dev/null
fi

# ─────────────────────────── 2. user + layout ────────────────────────────────
log "Creating ghost user and directories"
id ghost >/dev/null 2>&1 || useradd -r -m -d /home/ghost -s /bin/bash ghost
mkdir -p /opt/ghost/bin /etc/ghost /etc/bitcoin /var/lib/bitcoin /var/lib/ghost /home/ghost/.ghost/data

# Grant the operator read access to the service journals so that
# `journalctl -u ghost-mining` works without sudo. When installed via `sudo bash`,
# $SUDO_USER is the human who invoked it; add them to systemd-journal (a
# read-only group). Root operators already see everything; a non-root sudo user
# would otherwise get empty output and mistake it for "no logs".
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && id "$SUDO_USER" >/dev/null 2>&1; then
  usermod -aG systemd-journal "$SUDO_USER" 2>/dev/null \
    && log "Granted ${SUDO_USER} journal read access (takes effect on next login; use 'sudo journalctl' until then)"
fi

# Persistent journal. Without /var/log/journal, `Storage=auto` keeps the journal in
# /run/log/journal — tmpfs — which means it is capped at 10% of RAM and, more to the
# point, is DESTROYED on every reboot and on any journald restart.
#
# That is not a theoretical loss. While diagnosing an hourly OOM kill, each kill wiped
# the run-up to the previous one, and the cause took four wrong guesses to find because
# the evidence was being deleted by the thing under investigation. Measured retention on
# the fleet was ~3-4.5 hours, which cannot show a daily pattern at all.
#
# Limits are set explicitly rather than inherited: the SystemMaxUse default is 10% of the
# filesystem, which on a large disk would let the journal grow into space the node needs.
log "Enabling persistent journald storage"
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/10-ghost.conf <<'EOF'
# Bitcoin Ghost — journal retention. Written by install-node.sh.
#
# Persistent so the journal survives the restart of whatever is being diagnosed,
# and long enough to see a daily pattern rather than only the last few hours.
[Journal]
Storage=persistent
SystemMaxUse=2G
SystemKeepFree=1G
MaxRetentionSec=2week
EOF
if systemctl restart systemd-journald >/dev/null 2>&1; then
  log "Journal is now persistent (2G cap, 2 week retention)"
else
  log "WARNING: could not restart systemd-journald; journal may still be volatile"
fi

# ─────────────────────── 3. download + verify binaries ───────────────────────
log "Downloading and verifying binaries (${GHOST_VERSION})"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
curl -fsSLO "${RELEASE_BASE}/${POOL_TARBALL}"
curl -fsSLO "${RELEASE_BASE}/SHA256SUMS.txt"
curl -fsSLO "${RELEASE_BASE}/SHA256SUMS.txt.asc"
# Verify the GPG signature over the checksums, then the checksum of our tarball. In a keyring of
# its own, as the updater does, so root's keyring is never given an ultimately trusted key.
export GNUPGHOME="$TMP/gnupg"; mkdir -m 700 "$GNUPGHOME"
curl -fsSL "$RELEASE_KEY_URL" 2>/dev/null | gpg --quiet --import 2>/dev/null || true
# Mark the pinned key trusted so gpg doesn't emit a (cosmetic) web-of-trust warning.
echo "${GPG_KEY_FP}:6:" | gpg --quiet --import-ownertrust 2>/dev/null || true
# Verify via status-fd and require VALIDSIG to be EXACTLY our pinned key — this is
# stronger than "Good signature from <name>" (which any imported key satisfies).
if gpg --status-fd=1 --verify SHA256SUMS.txt.asc SHA256SUMS.txt 2>/dev/null | grep -q "VALIDSIG ${GPG_KEY_FP}"; then
  echo "  ✓ release signature verified (key ${GPG_KEY_FP})"
else
  err "Release signature verification FAILED (expected signing key ${GPG_KEY_FP})."
fi
grep " ${POOL_TARBALL}\$" SHA256SUMS.txt | sha256sum -c - || err "Checksum verification FAILED for ${POOL_TARBALL}."
unset GNUPGHOME
# The node dashboard ships in the same release, covered by the same signed SHA256SUMS.txt. A
# release without it (none before the node pool dashboard was packaged) installs the node alone.
DASHBOARD_SRC=""
if grep -q " ${DASHBOARD_TARBALL}\$" SHA256SUMS.txt; then
  curl -fsSLO "${RELEASE_BASE}/${DASHBOARD_TARBALL}"
  grep " ${DASHBOARD_TARBALL}\$" SHA256SUMS.txt | sha256sum -c - || err "Checksum verification FAILED for ${DASHBOARD_TARBALL}."
  mkdir -p "$TMP/dashboard"
  tar -xzf "$DASHBOARD_TARBALL" -C "$TMP/dashboard"
  [[ -f "$TMP/dashboard/ghost-dashboard/server.js" ]] || err "${DASHBOARD_TARBALL} does not carry ghost-dashboard/server.js."
  DASHBOARD_SRC="$TMP/dashboard/ghost-dashboard"
else
  log "${GHOST_VERSION} ships no node dashboard (${DASHBOARD_TARBALL}) — installing the node without it"
fi
tar -xzf "$POOL_TARBALL"
# The node binary was `ghost-pool` up to and including v1.11.44 (#1018). A release that old is
# refused rather than installed under the new name: that binary restarts itself and reads its own
# journal as `ghost-pool`, a unit this installer does not create, so the dashboard's restart and
# log pages would fail on a node that otherwise looked healthy.
NODE_BIN_SRC="$(find . -name ghost-mining -type f | head -1)"
[ -n "$NODE_BIN_SRC" ] || err "Release ${GHOST_VERSION:-} does not contain ghost-mining — it predates the rename from ghost-pool. This installer needs a newer release."
install -m755 -o root -g root "$NODE_BIN_SRC" /opt/ghost/bin/ghost-mining
# ghost-cli (the ghostd RPC client, like bitcoin-cli) ships in the same signed
# tarball. Install it so operators can query their node's ghostd directly — it is
# not required for ghost-mining operation (ghost-mining talks to ghostd over RPC/ZMQ),
# but without it a node has no CLI to inspect its own daemon.
#
# Releases up to v1.11.45 carry the Rust administration tool under this name instead
# (#1028), so the binary is asked what it is before it is given the RPC client's path.
# The admin tool is installed as ghost-admin, whichever name the release used for it.
cli_bin="$(find . -name ghost-cli -type f | head -1)"
admin_bin="$(find . -name ghost-admin -type f | head -1)"
if [[ -n "$cli_bin" ]] && is_core_rpc_client "$cli_bin"; then
  install -m755 -o root -g root "$cli_bin" /opt/ghost/bin/ghost-cli
else
  [[ -n "$admin_bin" ]] || admin_bin="$cli_bin"
  log "${GHOST_VERSION} does not ship the ghostd RPC client — no ghost-cli installed. Query ghostd over RPC on 127.0.0.1:8332 until a newer release is out."
fi
if [[ -n "$admin_bin" ]]; then
  install -m755 -o root -g root "$admin_bin" /opt/ghost/bin/ghost-admin
fi
# ghost-audit (`ghost-audit check`: a miner's check that a node's jobs pay the treasury and the
# miner, and nothing else) ships in the release. Installed on every node; nothing runs it.
audit_bin="$(find . -name ghost-audit -type f | head -1)"
if [[ -n "$audit_bin" ]]; then
  install -m755 -o root -g root "$audit_bin" /opt/ghost/bin/ghost-audit
fi
# The miner-facing SV2 stratum stack ships in the SAME signed tarball. Without
# these two binaries a node has ghost-mining's Template Distribution Protocol
# running but nothing for miners to connect to, so it can run yet never
# serve a single hasher. translator_sv2 accepts Stratum V1 miners (e.g. BitAxe)
# and translates to SV2; pool_sv2 is the SV2 pool that bridges those miners to
# ghost-mining's TDP. Both are ALWAYS installed (a v1 node download must be a
# complete, miner-ready node); whether the ports are exposed is decided later by
# the mining-mode firewall reconcile.
translator_bin="$(find . -name translator_sv2 -type f | head -1)"
[[ -n "$translator_bin" ]] || err "translator_sv2 was not found in ${POOL_TARBALL}. This installer requires a release that bundles the SV2 stratum stack (translator_sv2 + pool_sv2). Upgrade GHOST_VERSION."
install -m755 -o root -g root "$translator_bin" /opt/ghost/bin/translator_sv2
pool_sv2_bin="$(find . -name pool_sv2 -type f | head -1)"
[[ -n "$pool_sv2_bin" ]] || err "pool_sv2 was not found in ${POOL_TARBALL}. This installer requires a release that bundles the SV2 stratum stack (translator_sv2 + pool_sv2). Upgrade GHOST_VERSION."
install -m755 -o root -g root "$pool_sv2_bin" /opt/ghost/bin/pool_sv2
# ghostd ships in the SAME signed tarball we just GPG- + checksum-verified, so it
# is installed straight from the extracted tree exactly like ghost-mining — its
# integrity is covered by the release signature, with no separate download or
# checksum pin to rot. GHOSTD_URL, if the operator explicitly set it, is an
# unverified override for transition/testing.
if [[ -n "$GHOSTD_URL" ]]; then
  log "Fetching ghostd from override URL ${GHOSTD_URL} (UNVERIFIED override path)"
  curl -fsSL "$GHOSTD_URL" -o ghostd || err "Could not download ghostd from ${GHOSTD_URL}."
  install -m755 -o root -g root ghostd /opt/ghost/bin/ghostd
else
  GHOSTD_BIN="$(find . -name ghostd -type f | head -1)"
  [[ -n "$GHOSTD_BIN" ]] || err "ghostd was not found in ${POOL_TARBALL}. This installer requires a release that bundles ghostd (the first unified build onward). Upgrade GHOST_VERSION, or set GHOSTD_URL to override."
  install -m755 -o root -g root "$GHOSTD_BIN" /opt/ghost/bin/ghostd
fi
cd /

# ─────────────────────────── 4. fresh secrets ────────────────────────────────
log "Generating fresh node secrets"
# The RPC password is kept across a re-run like the secrets below. A fresh one every run left the
# running ghostd on the old password while bitcoin.conf, and so every tool and check that reads
# it (ghost-cli, the boot gate, the updater's health check), carried the new one.
if [[ -f /etc/bitcoin/bitcoin.conf ]] && grep -qE '^rpcpassword=[0-9a-fA-F]{64}$' /etc/bitcoin/bitcoin.conf; then
  RPCPW="$(sed -nE 's/^rpcpassword=([0-9a-fA-F]{64})$/\1/p' /etc/bitcoin/bitcoin.conf | head -1)"
fi
[[ -n "${RPCPW:-}" ]] || RPCPW="$(openssl rand -hex 32)"
# internal_api_secret: the shared HMAC secret between ghost-mining and the node
# dashboard. Generate ONCE and REUSE any existing value on re-runs, so an
# upgrade/re-provision never rotates it out from under the dashboard (a rotated
# secret 401s every internal dashboard request).
# share-once pattern below. Change B (after pool.toml is written) mirrors this
# same value into the dashboard's INTERNAL_AUTH_KEY so the two can never drift.
if [[ -f /etc/ghost/pool.toml ]] && grep -qE '^internal_api_secret[[:space:]]*=' /etc/ghost/pool.toml; then
  APISECRET="$(sed -nE 's/^internal_api_secret[[:space:]]*=[[:space:]]*"([0-9a-fA-F]{64})".*/\1/p' /etc/ghost/pool.toml | head -1)"
fi
[[ -n "${APISECRET:-}" ]] || APISECRET="$(openssl rand -hex 32)"
# Kept across a re-run, like the secret above: a fresh one every run would quietly re-key a node
# whose operator only meant to change a flag.
if [[ -f /etc/ghost/pool.toml ]] && grep -qE '^signing_key[[:space:]]*=' /etc/ghost/pool.toml; then
  SIGNKEY="$(sed -nE 's/^signing_key[[:space:]]*=[[:space:]]*"([0-9a-fA-F]{64})".*/\1/p' /etc/ghost/pool.toml | head -1)"
fi
[[ -n "${SIGNKEY:-}" ]] || SIGNKEY="$(openssl rand -hex 32)"
PUBIP="$(curl -fsSL https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"

# ───────────────────────── 5. ghostd config (sync) ───────────────────────────
log "Writing /etc/bitcoin/bitcoin.conf (${NETWORK}, sync mode: ${SYNC_MODE})"
# Mainnet is written at the top level, as it always was. Signet and regtest select their chain and
# put every setting in that chain's section, where Core applies the network-specific ones (ports,
# rpcbind); RPC stays on 8332 on every network so nothing downstream changes.
RPC_USER="ghostrpc_mainnet"
[[ "$NETWORK" == mainnet ]] || RPC_USER="ghostrpc_${NETWORK}"
# dbcache by RAM: 1024 from 4 GB up, 450 below (np_dbcache).
DBCACHE="$(np_dbcache "$(pf_mem_mb)")"
# RPC is loopback-only unless another node is allowed in (--peer-node): then it listens on every
# interface and Core refuses anyone but loopback and those addresses (rpcallowip); the firewall
# opens 8332 to those addresses alone (below).
RPC_BIND="127.0.0.1"
[[ -n "$RPC_ALLOW" ]] && RPC_BIND="0.0.0.0"
{
  if [[ "$NETWORK" != mainnet ]]; then
    echo "chain=${NETWORK}"
    echo "[${NETWORK}]"
  fi
  echo "server=1"
  echo "listen=1"
  if [[ "$ARCHIVE" == "true" ]]; then echo "hazemode=FullArchive"
  elif [[ "$SYNC_MODE" == "haze" ]]; then echo "hazemode=Hazed"
  else echo "prune=550"; fi
  cat <<EOF
rpcuser=${RPC_USER}
rpcpassword=${RPCPW}
rpcallowip=127.0.0.1
rpcbind=${RPC_BIND}
rpcport=8332
port=${NP_P2P_PORT}
zmqpubhashblock=tcp://127.0.0.1:28332
zmqpubhashtx=tcp://127.0.0.1:28333
zmqpubsequence=tcp://127.0.0.1:28334
# 1024 from 4 GB of RAM up, Core's 450 below: ghostd's RSS reached 2.2 GB at 1024 (vm8, 2026-11-07).
dbcache=${DBCACHE}
# 125 is kept on a solo node, not raised. A found block reaches the network through this node's
# outbound peers and the other node (addnode, a direct link that relays it as a compact block at
# once), not through inbound count; more inbound peers cost memory on a 3-4 GB machine and buy
# no propagation for the blocks found here.
#
# Core's default is 125. This was 50, which sounds merely conservative but is not: Core
# reserves the outbound slots, so 50 leaves roughly 40 inbound, and a settled node sits at
# ~39 of them. The node is then FULL, and a full node REFUSES new peers — including
# crawlers, which then record it as unreachable and drop it from public listings. The fleet
# vanished from node directories for exactly this reason while every node was healthy,
# listening on 0.0.0.0:8333 and externally reachable.
#
# It also means the node contributes far less relay capacity than the hardware allows.
#
# Raise this only with the box's memory in mind. ghost-mining already holds a large working
# set on the smaller nodes (#417/#418), and connections are not free.
maxconnections=125
fallbackfee=0.00001
EOF
  # The assumevalid block is a mainnet block.
  [[ "$NETWORK" == mainnet ]] && echo "assumevalid=${ASSUMEVALID}"
  [[ -n "$SIGNET_CHALLENGE" ]] && echo "signetchallenge=${SIGNET_CHALLENGE}"
  for p in $RPC_ALLOW; do echo "rpcallowip=${p}"; done
  # The other node (--peer-node) and any --bitcoin-peer: a standing connection each.
  for p in $BITCOIN_PEERS; do echo "addnode=${p}"; done
  # ghost_common::solo::BLOCK_RESERVED_WEIGHT, Bitcoin Core's default: the weight getblocktemplate
  # leaves for the header, the transaction count and the coinbase. ghost-mining trims a template
  # to fit a coinbase of MAX_COINBASE_BYTES (1,000 B, 4,376 WU with the header); a solo coinbase is
  # under 300 B. The node pool's 90,000 left about 2% of every block empty of fee-paying
  # transactions. test-installer-node-pool-reserve.sh holds this to the Rust constant.
  echo "blockreservedweight=8000"
} > /etc/bitcoin/bitcoin.conf

# Tor wiring. `listen=1` is already written above; here we add the onion service
# (listenonion), the control-port endpoint ghostd uses to create/rotate it
# (torcontrol), and outbound peering via Tor's SOCKS proxy (proxy). tor-only also
# disables clearnet so the node ONLY talks over the onion network. bitcoin.conf
# is rewritten from scratch on every run (truncating `>` above), so appending
# here never duplicates lines across re-runs.
if [[ "$TOR" == "true" ]]; then
  {
    echo "listenonion=1"
    echo "torcontrol=127.0.0.1:9051"
    echo "proxy=127.0.0.1:9050"
    [[ "$TOR_MODE" == "tor-only" ]] && echo "onlynet=onion"
  } >> /etc/bitcoin/bitcoin.conf
fi

# ─────────────────────── 5b. Tor service provisioning ────────────────────────
# Configure Tor's control port (cookie-authenticated) so ghostd can publish its
# ephemeral v3 onion, and grant the ghostd-running user access to the cookie.
if [[ "$TOR" == "true" ]]; then
  log "Configuring Tor (mode: ${TOR_MODE})"
  # Idempotent append — the ControlPort line is our sentinel, so re-running the
  # installer never duplicates the block in /etc/tor/torrc.
  if ! grep -qE '^[[:space:]]*ControlPort[[:space:]]+9051([[:space:]]|$)' /etc/tor/torrc 2>/dev/null; then
    cat >> /etc/tor/torrc <<'TORRC'

# Added by Bitcoin Ghost installer — ghostd onion-service control access.
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
TORRC
  fi
  # ghostd runs as the `ghost` user (see ghostd.service `User=ghost` below); it
  # must be in the debian-tor group to read the control-auth cookie.
  usermod -aG debian-tor ghost
  systemctl enable tor >/dev/null 2>&1 || true
  systemctl restart tor
fi

# ─────────────────────────── 6. pool config ──────────────────────────────────
log "Writing /etc/ghost/pool.toml"

# Every node is a public Ghost Pool node, so there is no mining_mode to write. Configs from older
# installs that still carry [network] mining_mode / private_mining_password / solo_payout_address,
# [pool] treasury_address / min_payout_sats / payout_interval_blocks / node_payout_address /
# share_shard / shard_*, or a [coordinator] section still load: those keys are read and ignored.
#
# Tell peers about the farm listener (farm_port in [network] below).
#
# The listener itself is the translator's ([farm_tier] port, emitted below); this is
# ghost-mining's advertisement of it. They are separate processes, so the port is
# duplicated — `scripts/check-stratum-config-agreement.sh` keeps the two in step, because a node
# advertising a port it does not listen on turns a routing decision into a dropped connection.
#
# Without this the listener is open and nobody is told, which is why farm routing has been inert
# since #494 shipped (#495).
# Build the [pool] block body. The section header itself is always written (the config struct
# requires it); the optional custom pool_name is the only line it carries, and only when set.
# POOL_NAME is already trimmed + validated (printable ASCII, <=30); we still
# TOML-escape backslash and double-quote so the written basic string round-trips
# to exactly the name the dashboard would store (and thus the same coinbase tag).
POOL_IDENTITY_BLOCK=""
if [[ -n "$POOL_NAME" ]]; then
  POOL_NAME_ESCAPED="${POOL_NAME//\\/\\\\}"
  POOL_NAME_ESCAPED="${POOL_NAME_ESCAPED//\"/\\\"}"
  POOL_IDENTITY_BLOCK="pool_name = \"${POOL_NAME_ESCAPED}\""
fi
cat > /etc/ghost/pool.toml <<EOF
[identity]
key_path = "/home/ghost/.ghost/node.key"
display_name = "${NICKNAME}"

[bitcoin]
rpc_host = "127.0.0.1"
rpc_port = 8332
rpc_user = "${RPC_USER}"
rpc_password = "${RPCPW}"
network = "${NETWORK}"
zmq_hashblock = "tcp://127.0.0.1:28332"
zmq_hashtx = "tcp://127.0.0.1:28333"

[network]
internal_api_secret = "${APISECRET}"
signing_key = "${SIGNKEY}"
public_address = "${PUBIP}"
sv2_port = 34255
sv1_port = 3333
http_port = 8080
max_miners = 1000
farm_port = 4444
# No mesh. The other node of a two-node setup is in bitcoin.conf (addnode) and
# /etc/ghost/pool-config.toml ([solo] submit_rpc).

# The standard policy: every tier ghostd's mempool holds is one a template may use, as in Bitcoin
# Core. full_open emits no -ghostpolicy flags (the tier gate is inert), so this node's templates
# are built from the same mempool its peers hold, and its blocks reach them as compact blocks
# they can rebuild without asking for transactions.
[policy]
profile = "full_open"

[storage]
db_path = "/home/ghost/.ghost/data"
wal_mode = true
archive_mode = ${ARCHIVE}
prune_height = 0

[pool]
${POOL_IDENTITY_BLOCK}

${ALERTS_BLOCK}

# NOTE (#760): the keys removed from the blocks above and below were read by NOTHING. There is no
# \`#[serde(deny_unknown_fields)]\` on NodeConfig, so they parsed, were discarded, and produced no
# warning — while reading, to anyone opening the file, exactly like settings that were in force:
#
#   pool.treasury_fee_percent      no such field on PoolConfig; the split is a constant
#   reaper.mode                    no such field on ReaperSettings; the controls are reject_*
#
# The whole [tdp] section went with them. TDP is configured on the COMMAND LINE, not in this file:
# the unit runs \`--tdp-enabled --tdp-port 8442\`, and \`main.rs\` sets \`tdp_config.port =
# args.tdp_port\`. Putting \`port = 8442\` here looked like configuration and did nothing, so editing
# it and restarting changed nothing, silently.

[reaper]
enabled = ${REAPER}
EOF

# Change B: mirror internal_api_secret into the dashboard's INTERNAL_AUTH_KEY so
# the dashboard always signs internal requests with the SAME secret ghost-mining
# validates against. Written as a root-only systemd drop-in in a file SEPARATE
# from the dashboard's DASHBOARD_PASSWORD override, so rewriting the auth key
# never clobbers the password (or vice-versa). The dashboard may be installed
# out-of-band; systemd applies the drop-in as soon as ghost-dashboard.service
# exists. Because $APISECRET is pinned to pool.toml's existing value (Change A),
# a re-run refreshes this file to the SAME value — the two can never drift.
#
# ⛔ The key lives in a root-only EnvironmentFile, never in an `Environment=` line: systemd hands
# `Environment=` values to any local user (`systemctl show ghost-dashboard -p Environment`), and
# the file mode of the drop-in does not change that. The drop-in names only the file's path.
install -d -m 0750 /etc/systemd/system/ghost-dashboard.service.d
install -d -m 0755 /etc/ghost
( umask 077
  printf 'INTERNAL_AUTH_KEY=%s\n' "${APISECRET}" > /etc/ghost/dashboard-internal-auth.env )
chown root:root /etc/ghost/dashboard-internal-auth.env
chmod 0600 /etc/ghost/dashboard-internal-auth.env
cat > /etc/systemd/system/ghost-dashboard.service.d/internal-auth.conf <<'EOF'
[Service]
EnvironmentFile=/etc/ghost/dashboard-internal-auth.env
EOF
chmod 0644 /etc/systemd/system/ghost-dashboard.service.d/internal-auth.conf
systemctl daemon-reload 2>/dev/null || true
# If the dashboard is already running, restart it to pick up the aligned key
# (safe: the dashboard is non-consensus). No-op when the unit isn't installed.
systemctl is-active --quiet ghost-dashboard 2>/dev/null && systemctl restart ghost-dashboard || true

# H-11: configs with secrets must be 0600.
chown ghost:ghost /etc/bitcoin/bitcoin.conf /etc/ghost/pool.toml
chmod 600 /etc/bitcoin/bitcoin.conf /etc/ghost/pool.toml
chown -R ghost:ghost /home/ghost /var/lib/ghost /var/lib/bitcoin

# ─────────────────────────── 7. node identity ────────────────────────────────
# ⛔ NEVER regenerate an identity that already exists (#985). node.key is not a cache: node_id
# derives from it, and its first 32 bytes ARE the TDP authority secret. `--generate-identity` does
# not recover an identity, it mints a DIFFERENT node — and nothing backs this file up. Re-running an installer is the most natural operator reflex there is (to
# upgrade, to repair a config, after a failed first attempt), and it used to destroy the one
# artefact that cannot be recreated. Note this script already preserves internal_api_secret across
# re-runs, so idempotency was considered for a regenerable value and not for the irreplaceable one.
if [[ -s /home/ghost/.ghost/node.key ]]; then
  log "Node identity already present — keeping it (node.key is irreplaceable; not regenerating)"
  sudo -u ghost /opt/ghost/bin/ghost-mining --config /etc/ghost/pool.toml --show-identity 2>&1 \
    | grep -iE "Node ID" || true
else
  log "Generating node identity"
  sudo -u ghost /opt/ghost/bin/ghost-mining --config /etc/ghost/pool.toml --generate-identity 2>&1 | grep -iE "Node ID" || true
fi

# ───────────────────── 7b. SV2 stratum stack config ──────────────────────────
# Generate the miner-facing SV2 config the same way ghost-mining's pool.toml is
# generated above: everything per-node is derived on THIS machine, and no
# identity or secret from any other node is ever baked in.
#
# Data path:  BitAxe (SV1) -> translator_sv2 (:3333) -> pool_sv2 (SV2 :34255)
#             -> ghost-mining TDP (:8442) -> ghostd
#
# Two keys tie the stack together, both minted here:
#   • The SV2 pool AUTHORITY keypair (Noise static identity that pool_sv2 presents
#     on :34255). It is generated FRESH per node — a public installer must never
#     ship a shared secret, or anyone could impersonate a node's SV2 endpoint to
#     its miners. The translator pins the matching public half as its upstream
#     authority_pubkey.
#   • ghost-mining's TDP authority PUBLIC key, which pool_sv2 must pin to trust this
#     node's own template server. ghost-mining derives it from the first 32 bytes of
#     the node identity key (node.key), so we derive the identical value here from
#     the same file rather than having to scrape it from ghost-mining's logs (which
#     only appear once ghost-mining is running, hours later after the sync gate).
log "Configuring SV2 stratum stack (translator + pool)"
NODE_KEY_FILE="/home/ghost/.ghost/node.key"
[[ -s "$NODE_KEY_FILE" ]] || err "Node identity key ${NODE_KEY_FILE} was not generated — cannot configure the SV2 pool."

# ghost-mining's TDP authority public key, derived from THIS node's node.key exactly
# as ghost-mining does at runtime (identical base58 secp256k1 encoding).
TDP_PUBKEY="$(/opt/ghost/bin/pool_sv2 --tdp-pubkey-from-keyfile "$NODE_KEY_FILE" 2>/dev/null)" \
  || err "Failed to derive the TDP authority public key. The installed pool_sv2 lacks --tdp-pubkey-from-keyfile; use a release that bundles the SV2 keygen support."
[[ -n "$TDP_PUBKEY" ]] || err "Derived TDP authority public key is empty."

# Per-node SV2 pool authority keypair (base58 secp256k1, the format pool-config.toml expects).
# Printed as two TOML lines; we split out each half. ⛔ Reused on a re-run: SV2 miners pin the
# authority PUBLIC key, so a fresh pair every run would cut off every SV2 miner on this node.
if [[ -f /etc/ghost/pool-config.toml ]] \
   && grep -qE '^authority_public_key *= *"[^"]+"$' /etc/ghost/pool-config.toml \
   && grep -qE '^authority_secret_key *= *"[^"]+"$' /etc/ghost/pool-config.toml; then
  SV2_KEYPAIR="$(grep -E '^authority_(public|secret)_key *= *"' /etc/ghost/pool-config.toml)"
  log "Keeping the existing SV2 pool authority keypair"
else
  SV2_KEYPAIR="$(/opt/ghost/bin/pool_sv2 --generate-key 2>/dev/null)" \
    || err "Failed to generate the SV2 pool authority keypair. The installed pool_sv2 lacks --generate-key; use a release that bundles the SV2 keygen support."
fi
SV2_AUTH_PUB="$(sed -n 's/^authority_public_key *= *"\(.*\)"$/\1/p' <<<"$SV2_KEYPAIR")"
SV2_AUTH_SEC="$(sed -n 's/^authority_secret_key *= *"\(.*\)"$/\1/p' <<<"$SV2_KEYPAIR")"
[[ -n "$SV2_AUTH_PUB" && -n "$SV2_AUTH_SEC" ]] || err "Could not parse the generated SV2 authority keypair."

# Tell the node its OWN authority key, so /api/v1/mining/status advertises the key this
# node's pool_sv2 actually presents. pool.toml was written earlier — before the keypair
# existed — so it is patched here rather than templated above.
#
# There is no default to fall back on and there must not be one: an SV2 miner that pins a
# wrong key cannot reach this pool, but WOULD authenticate anyone holding the secret half
# of whatever key it was told to trust (#516). Unset, the API says `null`, which is the
# honest answer.
if grep -q '^sv2_authority_public_key' /etc/ghost/pool.toml; then
  sed -i "s|^sv2_authority_public_key.*|sv2_authority_public_key = \"${SV2_AUTH_PUB}\"|" /etc/ghost/pool.toml
else
  sed -i "/^\[network\]/a sv2_authority_public_key = \"${SV2_AUTH_PUB}\"" /etc/ghost/pool.toml
fi
grep -q "^sv2_authority_public_key = \"${SV2_AUTH_PUB}\"$" /etc/ghost/pool.toml \
  || err "Failed to record the SV2 authority public key in pool.toml."

# Farm/rental tier (#410). Every node is public, so every node runs it;
# `reconcile-mining-firewall.sh` opens 4444 unconditionally to match.
FARM_TIER_BLOCK="[farm_tier]
port = 4444
min_individual_miner_hashrate = 100_000_000_000_000.0  # ~232,827 starting difficulty
hobby_max_individual_miner_hashrate = 50_000_000_000_000.0"

# translator_sv2 — accepts SV1 miners on :3333 (and the farm tier on :4444) and forwards SV2 to
# the local pool. Each SV1 miner authorises as <its own address>[.<worker>]: that address is what
# its jobs pay.
cat > /etc/ghost/translator-config.toml <<EOF
# Bitcoin Ghost — SRI Translator (Stratum V1 -> V2). Generated by install-node.sh.
#
# miners (SV1) -> translator (:3333, farm tier :4444) -> pool_sv2 (SV2 :34255) -> ghost-mining (TDP)

# Listen for SV1 miners (standard stratum port)
downstream_address = "0.0.0.0"
downstream_port = 3333

# Protocol version
max_supported_version = 2
min_supported_version = 2

# Extranonce size for downstream miners (CGminer max 8, min 2).
# Must be >= 7: rented-hashrate marketplaces subdivide extranonce2 across their
# fan-out connections and reject a pool that advertises less. Braiins requires 7.
downstream_extranonce2_size = 8

# The translator's own upstream identity, not a payee: a Ghost Pool miner authorises as
# <its own address>[.<worker>], and that address is what its jobs pay. A username with no
# address is refused by pool_sv2.
user_identity = "ghost_miner"

# Each miner gets its own upstream channel (per-miner share attribution).
aggregate_channels = false

# Open the upstream channel on mining.subscribe rather than mining.authorize, so serialising
# clients (proxies, rented-hashrate marketplaces) get the real extranonce in the subscribe
# response instead of a placeholder that makes every share they build invalid.
# ROLLOUT GATE, default false: pool_sv2 must understand a provisional channel identity on
# every node before this is turned on anywhere.
# ⚠ The rollout gate is SATISFIED and this is now ON. \`pool_sv2\` understands a provisional
# channel identity on every node (fleet-wide since #783/#784/#785, all eight verified), so the
# ordering hazard above is spent.
#
# It must stay \`true\` here or a freshly provisioned node gets the pre-#783 behaviour: a
# serialising client (a proxy, or a rented-hashrate marketplace like Braiins) is answered with
# an 8-byte placeholder extranonce while the real prefix is 12, builds a 4-byte-short coinbase,
# and has EVERY share rejected. \`mining.set_extranonce\` cannot rescue it — that is an optional
# extension those clients never negotiate.
# A Ghost Pool job pays its miner, so pool_sv2 builds none for a channel opened on subscribe
# until the miner authorises: the translator then binds the channel to the miner's
# <address>.<worker> (an UpdateChannel carrying the Ghost payee TLV, extension 0x4748, required
# below). Pipelining miners authorise within the debounce and open on authorize as before.
open_channel_on_subscribe = true

# Protocol extensions — the Ghost per-miner TLV extension (0x0002), and the Ghost agent extension
# (0x4748), which carries the payee binding above. Without 0x4748 a channel opened on subscribe
# is never bound to its miner and is given no job.
supported_extensions = []
required_extensions = [0x0002, 0x4748]

# Monitoring endpoint
monitoring_address = "0.0.0.0:9092"

# Difficulty configuration for SV1 miners
[downstream_difficulty_config]
# Hobby-tier floor: 1 TH/s -> starting difficulty ~2,328.
#
# Was 10 TH/s (~23,283), which is a bar set for a machine 10x larger than anything that
# actually connects here. Measured on a live Bitaxe Gamma: its ASIC finds results averaging
# 688 difficulty and peaking around 1,386, so at a 23,283 floor it had to get ~34x luckier
# than its typical result to submit ANYTHING. It found a share about every 267s, which left
# AxeOS estimating hashrate from two or three samples and displaying 26 TH/s for a 1.13 TH/s
# machine — the operator reasonably read that as a broken miner.
#
# The control group is bitaxe4, which reaches pool_sv2 directly at difficulty 2,215 and reads
# stable and truthful on the same hardware class.
#
# Payout is unaffected: it is proportional to work, and a share's work IS its difficulty, so
# the same hashrate earns the same at any floor. The cost is share VOLUME (~10x more rows,
# each gossiped to 8 nodes), which is why large miners belong on the farm tier (:4444) rather
# than here.
min_individual_miner_hashrate = 1_000_000_000_000.0
shares_per_minute = 6.0
enable_vardiff = true
# Off: power-of-two difficulty tiers were the share chain's. A solo pool credits no shares, so
# plain vardiff targets are right.
quantise_to_tiers = false
# ⛔ REMOVED: \`idle_timeout_secs\`. It was set here and by install-node.sh, documented as
# "disconnect miners with no shares" — and NO Rust struct reads it. \`TranslatorConfig\` carries no
# \`deny_unknown_fields\`, so it parsed, was discarded, and produced no warning, while reading to
# anyone opening this file exactly like a setting that was in force.
#
# ⚠ There is NO idle-miner reaper. A connection that opens a channel and then goes quiet holds
# its socket indefinitely. The only reaper is CHANNELLESS_REAP_TIMEOUT (120s) in sv1_server.rs,
# which catches scanners that never open a channel at all. Adding a real one is a behavioural
# change to the component serving live miners and wants its own change, not a config line.

# Keepalive interval for downstream miners (seconds)
job_keepalive_interval_secs = 60

# Upstream SV2 pool (local pool_sv2). authority_pubkey pins the pool's freshly
# generated authority key so the two ends of the Noise handshake agree.
[[upstreams]]
address = "127.0.0.1"
port = 34255
authority_pubkey = "${SV2_AUTH_PUB}"

# ── Port tiers (#410) ─────────────────────────────────────────────────────────
# One difficulty cannot serve both a 500 GH/s bitaxe and a 1 PH/s rented order.
# Sized for the bitaxe, a large order floods the pool for minutes while vardiff
# ramps (it caps corrections above 1000% to x3-x5 per 60s tick) and marketplaces
# reject the pool. Sized for the order, a bitaxe finds a share every ~200s and
# looks dead — which is what made the dashboard flap after the floor was raised.
#
# Uncomment to run a SECOND listener for farm/rental traffic. The hobby tier keeps
# \`downstream_port\`, so every miner already pointed here stays put and nobody has
# to be told to move; only large miners need the new port advertised to them.
#
# BEFORE ENABLING: open the farm port on the firewall and the load balancer on
# every node. A port that is advertised but unreachable is worse than no port.
#
# 4444 is a conventional stratum alternate and was verified free on every node. 6666 was
# considered and rejected: it is IRC-associated and blocked by default on some ISPs,
# corporate firewalls and AV suites, which is a poor property for the port you hand to a
# paying customer.
#
# The farm floor of ~232,827 is not a guess. avalonQ, a ~95 TH/s miner, vardiffed itself to
# 233,672 on this fleet without prompting — the pool has already measured the right starting
# difficulty for that size of miner, so the tier simply starts there instead of climbing.
#
# \`hobby_max_individual_miner_hashrate\` only logs a warning when a miner on the
# hobby port measures above it. It is a CAPACITY control, not anti-fraud: payout
# is proportional to work and a share's work IS its difficulty, so the same
# hashrate earns the same on either port. A large miner on the hobby port is not
# taking anything from anyone — it just costs this node ~20x the share
# validation, bandwidth and database writes.
#
# Enabled on every node (operator decision, 2026-07-27; every node is now a public node
# pool node), with a matching 4444 firewall rule.
${FARM_TIER_BLOCK}

[load_balancer]
ghost_pool_url = "127.0.0.1:8080"
poll_interval_secs = 30
EOF

# pool_sv2 — SV2 pool bridging miners/translators to ghost-mining's TDP, and Ghost Pool: every
# miner's job pays the treasury and that miner, and found blocks also go to the other node.
# Holds the secret half of the authority keypair, so this file is 0600 root-only. Rendered by
# np_render_pool_config (above), which bins/pool-sv2/tests/installer_config.rs feeds to
# pool_sv2's own config loader. An older install's [node_pool] section is not written again.
#
# The other nodes' RPC credentials ([solo] submit_rpc_auth_file) first, root-only like the config:
# pool_sv2 runs as root, and the file is never logged. --submit-auth replaces it; a re-run without
# it keeps it as it is (edited by hand or not). ⛔ The config names the file only when it exists:
# pool_sv2 refuses to start on a credentials file it cannot read, and a pool that does not start
# mines nothing, where one without credentials only has its blocks refused by the other node.
if [[ -n "$SUBMIT_AUTH" ]]; then
  ( umask 077
    printf '# The other nodes'"'"' Bitcoin RPC credentials, for found blocks ([solo] submit_rpc). Written by\n# install-node.sh --submit-auth. One `user:password` (every node) or `http://host:port user:password`\n# (that node) a line. Then: sudo systemctl restart sri-pool\n%s\n' \
      "$SUBMIT_AUTH" > "${SUBMIT_AUTH_FILE}.tmp" )
  mv -f "${SUBMIT_AUTH_FILE}.tmp" "$SUBMIT_AUTH_FILE"
fi
SUBMIT_AUTH_READY=false
if [[ -e "$SUBMIT_AUTH_FILE" ]]; then
  chown root:root "$SUBMIT_AUTH_FILE"
  chmod 600 "$SUBMIT_AUTH_FILE"
  SUBMIT_AUTH_READY=true
elif [[ -n "$SUBMIT_NODES" ]]; then
  log "WARNING: found blocks also go to ${SUBMIT_NODES}, with no credentials (${SUBMIT_AUTH_FILE} is missing):"
  log "         the other node refuses them. Re-run with --submit-auth <its rpcuser:rpcpassword>."
fi
np_render_pool_config > /etc/ghost/pool-config.toml
# Miner statistics and found blocks ([solo] state_dir). pool_sv2 runs as root.
install -d -m 0755 -o root -g root /var/lib/ghost/solo

# update-pool-signature.sh keeps pool_signature in sync with ghost-mining's coinbase
# tag (written by ghost-mining at startup to ~/.ghost/coinbase_tag). Runs as the
# sri-pool ExecStartPre (root) before each pool_sv2 start.
cat > /opt/ghost/bin/update-pool-signature.sh <<'EOF'
#!/bin/bash
# Sync pool_sv2's pool_signature with ghost-mining's current coinbase tag.
TAG=$(cat /home/ghost/.ghost/coinbase_tag 2>/dev/null || echo "- G H O S T -")
sed -i "s/^pool_signature = .*/pool_signature = \"${TAG}\"/" /etc/ghost/pool-config.toml
EOF
chmod 755 /opt/ghost/bin/update-pool-signature.sh
chown root:root /opt/ghost/bin/update-pool-signature.sh

# Permissions: the pool config carries the authority SECRET, so root-only 0600
# (pool_sv2 + its ExecStartPre run as root). The translator config has no secret
# (public authority key + public payout address) and is read by the ghost user.
chown root:root /etc/ghost/pool-config.toml
chmod 600 /etc/ghost/pool-config.toml
chown ghost:ghost /etc/ghost/translator-config.toml
chmod 644 /etc/ghost/translator-config.toml

# ───────────────────────── 8. sync gate (auto) ───────────────────────────────
# Start ghost-mining only AFTER ghostd finishes its initial sync. An unsynced node
# participating in checkpoint consensus just spams "wrong proposer" and can't
# vote — so we gate it. On a normal reboot ghostd is already synced, so the gate
# returns almost immediately.
log "Installing sync gate"
# Inlined copy of scripts/ops/fleet-files/wait-for-ghostd-sync.sh, kept byte-identical by
# scripts/check-inlined-copies.sh. It used to be a shorter variant of it, which is how the
# fleet came to run three versions of this file (#759).
cat > /opt/ghost/bin/wait-for-ghostd-sync.sh <<'WAIT_FOR_GHOSTD_SYNC_EOF'
#!/usr/bin/env bash
#
# Deployed to /opt/ghost/bin/wait-for-ghostd-sync.sh — the ExecStart of
# ghost-mining-gate.service. ghost-mining is disabled at boot; this gate is what
# starts it, once ghostd reports it has left initial block download. Starting
# ghost-mining against a syncing ghostd is what the gate exists to prevent.
#
# This file is the canonical copy (#759). It used to exist only on the fleet, in
# three variants that no repo file governed.
#
# Ghost Pay is retired: the gate starts nothing for it. A host that still has a
# ghost-pay unit keeps it exactly as it is — not started here, not stopped.
#
# The gate owns the stratum stack's start too (#1020). `sri-pool.service` used to carry
# `Wants=ghost-mining.service`, which made systemd start the node whenever sri-pool started —
# at boot, and on the installer's first `enable --now sri-pool`. So the node came up ahead of
# this script every time, and on a fresh install it joined the live mesh at chain height 0 and
# broadcast an MPC contribution while this script was still printing "waiting". sri-pool and
# sri-translator now order themselves after the node without pulling it in, are not enabled at
# boot, and are started here, after the node, once ghostd is synced.
#
# Change this file, then run scripts/ops/deploy-fleet-file.sh to converge the
# fleet. check-fleet-uniformity.sh fails if any node drifts from what is here.
set -u
# Overridable so scripts/test-boot-gate.sh can run this against a throwaway directory.
CONF="${GHOST_BITCOIN_CONF:-/etc/bitcoin/bitcoin.conf}"
UNIT_DIR="${GHOST_UNIT_DIR:-/etc/systemd/system}"
RPCUSER=$(grep -m1 '^rpcuser=' "$CONF" | cut -d= -f2-)
RPCPW=$(grep -m1 '^rpcpassword=' "$CONF" | cut -d= -f2-)
echo "[ghost-mining-gate] waiting for ghostd to finish initial sync..."
while true; do
  RESP=$(curl -s --max-time 8 --user "$RPCUSER:$RPCPW" \
    --data '{"jsonrpc":"1.0","method":"getblockchaininfo","params":[]}' \
    http://127.0.0.1:8332/ 2>/dev/null)
  IBD=$(echo "$RESP" | grep -oE '"initialblockdownload":[[:space:]]*(true|false)' | grep -oE 'true|false')
  if [ "$IBD" = "false" ]; then
    # The node unit was `ghost-pool` until #1018, and this file reaches a node separately from
    # that rename — deploy-fleet-file.sh before it, or the unit switch before this. Start
    # whichever the node has, so neither order leaves a node that does not mine after a reboot.
    UNIT=ghost-mining
    [ -e "$UNIT_DIR/ghost-mining.service" ] || UNIT=ghost-pool
    echo "[ghost-mining-gate] ghostd synced — starting $UNIT"
    # Without the node there is nothing for the stratum stack to serve; it would only restart
    # in a loop. Fail instead, so the unit shows as failed (and is retried where it has Restart=).
    systemctl start "$UNIT" || { echo "[ghost-mining-gate] $UNIT did not start"; exit 1; }
    rc=0
    for SVC in sri-pool sri-translator; do
      [ -f "$UNIT_DIR/$SVC.service" ] || continue
      echo "[ghost-mining-gate] starting $SVC"
      if ! systemctl start "$SVC"; then
        echo "[ghost-mining-gate] $SVC did not start"
        rc=1
      fi
    done
    exit "$rc"
  fi
  sleep 30
done
WAIT_FOR_GHOSTD_SYNC_EOF
chmod 755 /opt/ghost/bin/wait-for-ghostd-sync.sh
cat > /etc/systemd/system/ghost-mining-gate.service <<'EOF'
[Unit]
Description=Ghost Mining sync gate (starts ghost-mining once ghostd is synced)
After=ghostd.service network-online.target
Wants=network-online.target
[Service]
# Type=simple so the installer's `systemctl start` returns immediately — a
# blocking oneshot would hang the install for the hours-long initial sync.
Type=simple
ExecStart=/opt/ghost/bin/wait-for-ghostd-sync.sh
Restart=on-failure
RestartSec=30
[Install]
WantedBy=multi-user.target
EOF
# Ghost Pay is retired. A re-run on a host that still has its unit leaves the unit exactly as it
# is: neither the gate nor the auto-updater starts, health-checks, stops or swaps it any more. Its
# database (which may hold funds) stays in the nightly backup.
if [[ -e /etc/systemd/system/ghost-pay.service ]]; then
    log "ghost-pay.service found — Ghost Pay is retired; the unit is left as it is (not started, checked or updated)"
fi

# ─────────────────────────── 9. systemd units ────────────────────────────────
log "Installing systemd units"
# ⛔ -ghostreaper=disabled is written, not left out: ghostd's Reaper defaults to ENABLED, so a unit
# with no Reaper flag runs every detector and the node's mempool (and templates) drift from the
# standard policy its peers run. Off by default on a solo node (see REAPER above); --reaper.
REAPER_FLAGS="-ghostreaper=disabled"
[[ "$REAPER" == "true" ]] && REAPER_FLAGS="-ghostreaper=enabled -ghostreaper-rejectinscription=1 -ghostreaper-rejectdropstuffing=1 -ghostreaper-rejectfakepubkey=1 -ghostreaper-rejectannex=1 -ghostreaper-rejectopreturn=1 -ghostreaper-rejectrunestone=1 -ghostreaper-maxopreturn=82 -ghostreaper-mindropsize=76"
# Order ghostd after tor when Tor is enabled, so the control port is up before
# ghostd tries to publish its onion. Empty otherwise → unit byte-identical.
GHOSTD_AFTER=""
[[ "$TOR" == "true" ]] && GHOSTD_AFTER=" tor.service"
cat > /etc/systemd/system/ghostd.service <<EOF
[Unit]
Description=Ghost Bitcoin Core (${NETWORK})
After=network-online.target${GHOSTD_AFTER}
Wants=network-online.target
[Service]
Type=simple
User=ghost
Group=ghost
ExecStart=/opt/ghost/bin/ghostd -conf=/etc/bitcoin/bitcoin.conf -datadir=/var/lib/bitcoin ${REAPER_FLAGS}
Restart=on-failure
RestartSec=30
# Core flushes its chainstate on stop, which can outlast systemd's default 90 s; a SIGKILL there
# costs a reindex. Bitcoin Core's own unit allows 600 s.
TimeoutStopSec=600
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/ghost-mining.service <<EOF
[Unit]
Description=Ghost Mining node
After=network-online.target ghostd.service
Wants=network-online.target
[Service]
Type=simple
User=ghost
Group=ghost
WorkingDirectory=/var/lib/ghost
ExecStart=/opt/ghost/bin/ghost-mining --config /etc/ghost/pool.toml --tdp-enabled --tdp-port 8442 --tdp-bind 127.0.0.1 --stratum-port 3333
Environment=RUST_LOG=info
Restart=on-failure
RestartSec=15
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF

# The zk trusted-setup anchor drop-in is gone with zk; remove it from a node installed before.
rm -f /etc/systemd/system/ghost-mining.service.d/genesis-anchor.conf
mkdir -p /etc/systemd/system/ghost-mining.service.d

# Journal access — the dashboard Logs console reads the OTHER node binaries'
# logs (ghostd / dashboard / SV2 stack) out of the systemd journal
# via journalctl, which requires membership of the `systemd-journal` group.
# Written as a drop-in (merged with the base unit) so it can ship to existing nodes without rewriting the whole unit; the
# later `systemctl daemon-reload` picks it up and it takes effect on the next
# ghost-mining restart. ghost-mining's own logs come from its in-process ring buffer
# and need no privilege.
cat > /etc/systemd/system/ghost-mining.service.d/journal-access.conf <<EOF
[Service]
SupplementaryGroups=systemd-journal
EOF

# SV2 stratum stack units. sri-pool bridges ghost-mining's TDP to SV2 miners; the
# translator fronts it for SV1 miners. sri-pool runs as root (it rewrites its own
# pool_signature via update-pool-signature.sh before each start); the translator
# runs as the unprivileged ghost user. Neither is enabled at boot or started by
# this installer: ghost-mining-gate starts them, after ghost-mining, once ghostd is
# synced (#1020). These are installed in EVERY mining mode so any node can serve
# miners; the firewall (below) decides whether the ports are reachable from off-box.
# Canonical source: config/sri/sri-pool.service — kept byte-identical by
# scripts/check-inlined-copies.sh, which is why this heredoc has a named marker.
cat > /etc/systemd/system/sri-pool.service <<'SRI_POOL_SERVICE_EOF'
[Unit]
Description=SRI Pool (SV2) - Ghost Network
# Ordering only, deliberately no `Wants=ghost-mining.service` (#1020). With it, starting this
# unit started the node, so the node came up ahead of ghost-mining-gate at every boot and on a
# fresh install joined the mesh at chain height 0. The gate starts the node and then this unit;
# neither this unit nor sri-translator is enabled at boot.
After=network.target ghost-mining.service
[Service]
Type=simple
User=root
Group=root
ExecStartPre=/opt/ghost/bin/update-pool-signature.sh
ExecStart=/opt/ghost/bin/pool_sv2 --config /etc/ghost/pool-config.toml
# `debug` here made sri-pool ~30x louder than it needs to be and evicted the journal
# (#903): on the loudest node it left 4.1 days of history against the other nodes' full
# two weeks. The mining message handler stays at debug because those
# OpenExtendedMiningChannel / CloseChannel lines are what diagnose channel faults --
# they are what pinned down #898.
Environment=RUST_LOG=info,pool_sv2::channel_manager::mining_message_handler=debug,pool_sv2::share_webhook=debug
# ⛔ pool_sv2 holds the world-open SV2 miner port (:34255) and was the ONLY one of the four units
# without this, so it inherited the default SOFT limit of 1024 while ghostd, ghost-mining and
# sri-translator all set 65536.
#
# MEASURED on the live fleet before this line existed:
#   sri-pool    LimitNOFILE 524288  soft 1024
#   ghost-mining  LimitNOFILE 65536   soft 65536
#
# A process is bounded by its SOFT limit unless it raises it itself, so the miner-facing process
# capped near 1,000 descriptors against a configured ceiling of 1,000 miners — and a miner
# connection costs more than one fd. ⚠ Note `capacity.rs` derives its ceiling from `getrlimit` in
# GHOST-POOL, which holds almost no miner sockets, so the capacity model never saw this.
LimitNOFILE=65536
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
SRI_POOL_SERVICE_EOF
cat > /etc/systemd/system/sri-translator.service <<'EOF'
[Unit]
Description=SRI Translator (SV1 to SV2) - Ghost Network
After=network.target sri-pool.service
Wants=sri-pool.service
[Service]
Type=simple
User=ghost
Group=ghost
# Readiness gate: wait for pool_sv2's monitoring API to answer, then a short
# settle for the first template, before connecting upstream — avoids the
# CouldNotInitiateSystem self-restart churn when started before pool_sv2 is ready.
ExecStartPre=/bin/sh -c 'i=0; while [ $i -lt 30 ]; do /usr/bin/curl -sf -m2 http://127.0.0.1:9090/api/v1/clients >/dev/null 2>&1 && { sleep 10; exit 0; }; sleep 2; i=$((i+1)); done; exit 0'
ExecStart=/opt/ghost/bin/translator_sv2 --config /etc/ghost/translator-config.toml
Restart=always
RestartSec=5
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF

# ─────────────────────────────── 9. firewall ─────────────────────────────────
log "Configuring firewall"
ufw allow 22/tcp        >/dev/null 2>&1   # ssh FIRST so we don't lock out
ufw allow "${NP_P2P_PORT}/tcp" >/dev/null 2>&1   # bitcoin P2P
ufw allow 8080/tcp      >/dev/null 2>&1   # ghost API (miner pages: /api/v1/miner/<address>)
# The other node's found blocks: Bitcoin RPC (8332) from its address alone (--peer-node). Nobody
# else reaches 8332; ghostd also refuses anyone not in rpcallowip.
for ip in $RPC_ALLOW; do
  ufw allow proto tcp from "$ip" to any port 8332 >/dev/null 2>&1 || true
done
# The node pool's share-chain relay is gone: its port (8566, or as an older config named it) is
# closed on a re-run.
for p in $(np_uniq "8566 ${OLD_RELAY_PORT:-}"); do
  ufw delete allow "${p}/tcp" >/dev/null 2>&1 || true
done
# The old mesh (8555-8562 ZMQ, 8563 Noise) and verification HTTPS (8443) stay CLOSED. ghost-mining
# no longer runs the old mesh and binds 8443 to loopback, and a Ghost Pool node must never be
# reachable by the old fleet's mesh, which keeps running `main`. The template server (TDP, 8442)
# is for the node's own pool_sv2 only and listens on 127.0.0.1 (`--tdp-bind`), so it is not opened
# either. A rule left by an older install is removed. The dashboard (3000) is loopback-only too.
ufw delete allow 8555:8562/tcp >/dev/null 2>&1 || true
ufw delete allow 8563/tcp      >/dev/null 2>&1 || true
ufw delete allow 8443/tcp      >/dev/null 2>&1 || true
ufw delete allow 8442/tcp      >/dev/null 2>&1 || true
# Tor-only: clearnet P2P is disabled (onlynet=onion), so close 8333 — inbound
# peering happens over the onion. Hybrid leaves the rule above in place (still
# reachable on clearnet). Idempotent: `ufw delete` is a no-op if absent.
if [[ "$TOR" == "true" && "$TOR_MODE" == "tor-only" ]]; then
  ufw delete allow "${NP_P2P_PORT}/tcp" >/dev/null 2>&1 || true   # tor-only: no clearnet P2P
fi
ufw --force enable      >/dev/null 2>&1

# Stratum V1 (3333) + V2 (34255) and the farm tier (4444) are always open: every
# node is a public Ghost Pool node. The reconcile service still runs at boot and
# whenever pool.toml changes (a .path unit), so a rule removed by hand or left
# closed by an older private/solo install is put back with no manual ufw step.
log "Installing mining-firewall reconcile (stratum ports follow pool.toml)"
cat > /opt/ghost/bin/reconcile-mining-firewall.sh <<'RECONCILE_MINING_FW_EOF'
#!/usr/bin/env bash
# Reconcile the Stratum firewall ports to the node's config.
#
# Run by `ghost-mining-firewall.service`, triggered at boot and by
# `ghost-mining-firewall.path` whenever pool.toml changes. Idempotent.
#
# This file is inlined VERBATIM in scripts/install-node.sh, which is fetched
# standalone over curl and has no repo to read from. check-inlined-copies.sh
# compares the two byte-for-byte — edit both, or neither.
set -euo pipefail
PORTS=(3333 34255)
# Every node is a public Ghost Pool node, so external miners are always accepted.
# There is no mining mode left to key off: an older pool.toml that still carries a
# `mining_mode` line is ignored by ghost-mining, and is ignored here too.
for p in "${PORTS[@]}"; do ufw allow "${p}/tcp" >/dev/null 2>&1 || true; done
logger -t ghost-mining-firewall "external miners ON -> Stratum 3333+34255 OPEN"

# Farm/rental tier (#410) listens on 4444 on every node.
#
# It must track `install-node.sh`, which always emits the [farm_tier] block. If these two ever
# disagree the node either advertises a port nothing listens on, or listens on a port nothing
# can reach — the second is what the config comment warns about.
ufw allow 4444/tcp >/dev/null 2>&1 || true
logger -t ghost-mining-firewall "farm tier ON -> Stratum 4444 OPEN"

# 9100 was the Wraith coordinator port. Nothing listens on it any more, so a rule
# left open by an older install is closed.
ufw delete allow 9100/tcp >/dev/null 2>&1 || true
RECONCILE_MINING_FW_EOF
chmod 755 /opt/ghost/bin/reconcile-mining-firewall.sh

cat > /etc/systemd/system/ghost-mining-firewall.service <<'EOF'
[Unit]
Description=Ghost mining firewall reconcile (Stratum ports follow pool.toml)
After=ufw.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/opt/ghost/bin/reconcile-mining-firewall.sh
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/ghost-mining-firewall.path <<'EOF'
[Unit]
Description=Watch pool.toml and reconcile the Stratum firewall on change
[Path]
PathModified=/etc/ghost/pool.toml
Unit=ghost-mining-firewall.service
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload >/dev/null 2>&1
systemctl enable --now ghost-mining-firewall.path >/dev/null 2>&1
/opt/ghost/bin/reconcile-mining-firewall.sh >/dev/null 2>&1 || true   # apply initial state

# ────────────────────── 10b. auto-update (opt-in) ────────────────────────────
# Always install the updater, its toggle, the sudoers scope, and the systemd
# units — but the timer is enabled (and the conf says true) ONLY when the
# operator opted in. With AUTO_UPDATE=false the node NEVER self-upgrades; the
# pieces just sit dormant so the dashboard toggle can flip it on later.
log "Installing auto-update (opt-in: ${AUTO_UPDATE})"

# The verifying updater (canonical source: scripts/ghost-auto-update.sh). It is
# a strict no-op unless /etc/ghost/auto-update.conf opts in, and it GPG-verifies
# every release before swapping a binary.
cat > /opt/ghost/bin/ghost-auto-update.sh <<'GHOST_AUTOUPDATE_SH_EOF'
#!/usr/bin/env bash
#
# Bitcoin Ghost — opt-in node auto-update.
#
# Runs as root from `ghost-auto-update.timer` (every 6h, randomised). It is a
# strict no-op unless the operator has opted in via /etc/ghost/auto-update.conf
# (AUTO_UPDATE=true). When opted in, it resolves the latest published release,
# and — ONLY if it is newer than what is installed — downloads the signed
# release tarball (which now bundles ghostd alongside ghost-mining),
# verifies the detached GPG signature against the pinned release key and the
# tarball's SHA256, backs up the current binaries, swaps them with a
# stop→verify-inactive→swap→start sequence, health-checks, and rolls back on any
# failure.
#
# On a node pool node the node dashboard (/opt/ghost/dashboard) moves with the release too: the
# release's `bitcoin-ghost-<tag>-dashboard.tar.gz`, checked against the same signed SHA256SUMS.txt,
# replaces the tree once the node's own health checks have passed, and ghost-dashboard restarts on
# it. A dashboard that then does not answer is put back by itself; it never rolls back the node.
# A release without a dashboard leaves the installed one as it is.
#
# ⛔ Two release channels share one GitHub repository. Which one a node follows is decided by
# /etc/ghost/release-channel, written by the node pool installer:
#   * `node-pool`  — the newest published `np-vX.Y.Z` release, picked from the release LIST.
#                    Node pool releases are pre-releases and never `latest`.
#   * no marker    — the old network: `releases/latest`, exactly as before the channel existed.
#                    An install running an `np-` build without the marker is refused.
#   * anything else — refused.
#
# ⛔ The SV2 stratum stack (`pool_sv2` under sri-pool, `translator_sv2` under
# sri-translator) is swapped in the SAME set as ghost-mining (#1044). Share-batch
# signing lives in the pool_sv2 binary (#742), so a new ghost-mining against an old
# pool_sv2 is the split the fleet's roll order exists to prevent. All of it moves,
# or none of it does: a release that is missing an installed SV2 binary is refused,
# and a rollback restores the whole set.
#
# SUPPLY-CHAIN-CRITICAL: a binary is NEVER written unless the GPG signature over
# the tarball verifies. ghostd rides that SAME signature (it lives inside the
# tarball now), so there is no longer a separate ghostd checksum side-channel.
# The verification logic mirrors the first-run installer (scripts/install-node.sh).
#
# This file is the canonical source. scripts/install-node.sh installs a verbatim
# copy at /opt/ghost/bin/ghost-auto-update.sh.
#
set -euo pipefail

# ─────────────────────────── pinned trust anchors ────────────────────────────
# Defaults are the production values. Every one is overridable via the
# environment SOLELY so the abort/accept paths can be exercised hermetically in
# tests (file:// URLs, a throwaway signing key, temp dirs). Production runs use
# the pinned defaults untouched.
GPG_KEY_FP="${GHOST_GPG_KEY_FP:-777FE81F8CC077FD3D08055E852C2B3190F5B928}"
RELEASE_KEY_URL="${GHOST_RELEASE_KEY_URL:-https://get.bitcoinghost.org/ghost-release-key.asc}"
INSTALL_SH_URL="${GHOST_INSTALL_SH_URL:-https://get.bitcoinghost.org/install.sh}"
# Latest-release source of truth. install.sh auto-tracks this same API, so we
# resolve the newest version straight from it rather than scraping install.sh
# (whose GHOST_VERSION is now a dynamic ${...} expansion with no literal version).
RELEASES_API_URL="${GHOST_RELEASES_API_URL:-https://api.github.com/repos/bitcoin-ghost/ghost/releases/latest}"
# NOTE: ghostd is no longer fetched from a standalone URL — it ships inside the
# signed release tarball (below), so the old GHOSTD_URL side-channel is gone.
# Release tarball base. When GHOST_RELEASE_BASE is set it is used verbatim;
# otherwise it is constructed per-version as <download URL>/<tag>, GitHub's layout.
RELEASE_BASE_OVERRIDE="${GHOST_RELEASE_BASE:-}"
# The download URL that tags hang off. Overridable, like the anchors above, only for a local test
# mirror laid out the same way (the install rehearsal; install-node.sh writes these into a
# `test-release-mirror.conf` drop-in of ghost-auto-update.service when installed against one).
RELEASE_DOWNLOAD_URL="${GHOST_RELEASE_DOWNLOAD_URL:-https://github.com/bitcoin-ghost/ghost/releases/download}"
PRODUCTION_GPG_KEY_FP="777FE81F8CC077FD3D08055E852C2B3190F5B928"

# ───────────────────────────── managed paths ─────────────────────────────────
CONF_FILE="${GHOST_AUTOUPDATE_CONF:-/etc/ghost/auto-update.conf}"
VERSION_FILE="${GHOST_VERSION_FILE:-/etc/ghost/version}"
STATUS_FILE="${GHOST_AUTOUPDATE_STATUS:-/var/lib/ghost/auto-update.status}"
BIN_DIR="${GHOST_BIN_DIR:-/opt/ghost/bin}"
BITCOIN_CONF="${GHOST_BITCOIN_CONF:-/etc/bitcoin/bitcoin.conf}"
SYSTEMCTL="${GHOST_SYSTEMCTL:-systemctl}"
DASHBOARD_DIR="${GHOST_DASHBOARD_DIR:-/opt/ghost/dashboard}"
DASHBOARD_URL="${GHOST_DASHBOARD_URL:-http://127.0.0.1:3000/login}"

# ──────────────────────────────── options ────────────────────────────────────
DRY_RUN="${GHOST_AUTOUPDATE_DRYRUN:-false}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN="true"; shift;;
    -h|--help)
      echo "Usage: ghost-auto-update.sh [--dry-run]"; exit 0;;
    *) echo "Unknown option: $1" >&2; exit 2;;
  esac
done

TAG="ghost-auto-update"
# Log to stderr (captured by the systemd journal for the .service) AND to syslog.
log()  { echo "[$TAG] $*" >&2; logger -t "$TAG" -- "$*" 2>/dev/null || true; }
warn() { echo "[$TAG] WARNING: $*" >&2; logger -t "$TAG" -p user.warning -- "$*" 2>/dev/null || true; }
err()  { echo "[$TAG] ERROR: $*" >&2; logger -t "$TAG" -p user.err -- "$*" 2>/dev/null || true; }

# is_core_rpc_client PATH — true only if PATH is the Ghost Core RPC client (#1028).
# Two programs have been called `ghost-cli`: the Core RPC client, which is what the name means
# on every node and in every runbook, and the Rust administration tool, which release tarballs
# up to v1.11.45 shipped under that name (it is `ghost-admin` from then on). A file name in a
# tarball therefore proves nothing, so ask the binary. The admin tool answers `-version` with
# a usage error on stderr; a binary that hangs is cut off and refused.
is_core_rpc_client() {
  [[ -f "$1" && -x "$1" ]] || return 1
  local out
  out="$(timeout "${CLI_IDENTITY_TIMEOUT:-10}" "$1" -version 2>/dev/null)" || return 1
  [[ "${out%%$'\n'*}" == *"RPC client"* ]]
}

# write_status RESULT MESSAGE [LATEST]
# Records the outcome of this run as JSON for the dashboard to surface. Always
# best-effort — a missing directory or read-only fs never affects the update.
write_status() {
  local result="$1" message="$2" latest="${3:-}"
  local installed; installed="$(read_installed_version || true)"
  local dir; dir="$(dirname "$STATUS_FILE")"
  mkdir -p "$dir" 2>/dev/null || true
  cat > "$STATUS_FILE" 2>/dev/null <<EOF || true
{
  "last_run": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "result": "${result}",
  "message": "${message//\"/\'}",
  "installed_version": "${installed}",
  "latest_version": "${latest}",
  "channel": "${CHANNEL:-}"
}
EOF
  chmod 644 "$STATUS_FILE" 2>/dev/null || true
}

# ─────────────────────────────── helpers ─────────────────────────────────────

# >>> NP_RELEASE_CHANNEL
# The node pool release channel. Node pool releases are tagged `np-vMAJOR.MINOR.PATCH` and are
# published as GitHub PRE-releases, so GitHub can never make one the repository's `latest`: the
# old network's nodes resolve `releases/latest` and must never be handed a node pool build. A node
# pool node therefore never asks for `latest`; it lists the releases and picks the newest
# `np-v` tag itself. The same block is in scripts/install-node.sh, which resolves
# GHOST_VERSION=np-latest with it; scripts/test-release-channel.sh keeps the copies identical.
NP_RELEASES_API_URL="${GHOST_NP_RELEASES_API_URL:-https://api.github.com/repos/bitcoin-ghost/ghost/releases?per_page=100}"
# The marker the node pool installer writes. Present and saying `node-pool`: this node follows the
# np- channel. Absent: an install from before the channel existed, which keeps the old channel.
# Anything else is refused, never guessed.
NP_CHANNEL_FILE="${GHOST_RELEASE_CHANNEL_FILE:-/etc/ghost/release-channel}"

# np_tag_ok TAG — an exact node pool release tag, final or with a suffix (np-v1.2.3-rc1).
np_tag_ok() { [[ "$1" =~ ^np-v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; }
# np_tag_final TAG — a final node pool release: the only kind np-latest ever picks.
np_tag_final() { [[ "$1" =~ ^np-v[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

# np_latest_tag — reads a GitHub "list releases" JSON array on stdin and prints the highest final
# np- tag of a PUBLISHED release. Drafts, tags of any other shape (the old network's v1.11.x,
# np-v…-rc1) and anything else are skipped. Exit 1 when there is none, 2 when the JSON does not
# have the shape this expects (each release carries one tag_name and one draft), so a changed API
# fails closed instead of picking something. The prerelease flag is not used: every node pool
# release carries it, which is what keeps them out of `latest`.
np_latest_tag() {
  local tok key val tag="" draft="" cands=""
  while IFS= read -r tok; do
    key="${tok#\"}"; key="${key%%\"*}"
    val="${tok#*:}"; val="${val#"${val%%[![:space:]]*}"}"; val="${val//\"/}"
    case "$key" in
      tag_name) [[ -z "$tag" ]] || return 2; tag="$val" ;;
      draft)    [[ -z "$draft" ]] || return 2; draft="$val" ;;
    esac
    if [[ -n "$tag" && -n "$draft" ]]; then
      if [[ "$draft" == false ]] && np_tag_final "$tag"; then cands+="${tag#np-v}"$'\n'; fi
      tag=""; draft=""
    fi
  done < <(grep -oE '"(tag_name|draft)"[[:space:]]*:[[:space:]]*("[^"]*"|true|false)' || true)
  [[ -z "$tag" && -z "$draft" ]] || return 2
  [[ -n "$cands" ]] || return 1
  echo "np-v$(printf '%s' "$cands" | sort -V | tail -1)"
}

# np_channel — prints this node's release channel: `node-pool` or `old-network`. Fails, printing
# why on stderr, when the marker exists but says anything else.
np_channel() {
  [[ -e "$NP_CHANNEL_FILE" ]] || { echo old-network; return 0; }
  local v
  v="$(grep -vE '^[[:space:]]*(#|$)' "$NP_CHANNEL_FILE" 2>/dev/null | head -1 | tr -d '[:space:]')"
  [[ "$v" == node-pool ]] || { echo "release channel marker $NP_CHANNEL_FILE says '${v}', expected 'node-pool'" >&2; return 1; }
  echo node-pool
}
# <<< NP_RELEASE_CHANNEL

# Normalise a version string for comparison: strip a leading 'np-' (the node pool channel's tag
# prefix) and then a leading 'v'.
normver() { local v="${1#np-}"; echo "${v#v}"; }

# Installed version: prefer the file we write on update, fall back to parsing
# `ghost-mining --version` (clap prints "ghost-mining <semver>").
read_installed_version() {
  if [[ -r "$VERSION_FILE" ]]; then
    local v; v="$(tr -d '[:space:]' < "$VERSION_FILE")"
    [[ -n "$v" ]] && { echo "$v"; return 0; }
  fi
  if [[ -x "$BIN_DIR/ghost-mining" ]]; then
    local out; out="$("$BIN_DIR/ghost-mining" --version 2>/dev/null || true)"
    local v; v="$(echo "$out" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    [[ -n "$v" ]] && { echo "v$v"; return 0; }
  fi
  return 1
}

# Is $2 strictly newer than $1? (sort -V semantics, leading 'v' ignored)
is_newer() {
  local cur new; cur="$(normver "$1")"; new="$(normver "$2")"
  [[ "$cur" == "$new" ]] && return 1
  local top; top="$(printf '%s\n%s\n' "$cur" "$new" | sort -V | tail -1)"
  [[ "$top" == "$new" ]]
}

# Run a systemctl verb unless we are in dry-run.
svc() {
  if [[ "$DRY_RUN" == "true" ]]; then
    log "DRY-RUN: would run: $SYSTEMCTL $*"
    return 0
  fi
  $SYSTEMCTL "$@"
}

# Stop a unit and block until it is no longer "active" (avoids the swap racing a
# still-running process to "Job canceled"). Best-effort up to ~60s.
stop_and_wait() {
  local unit="$1"
  $SYSTEMCTL list-unit-files "$unit" >/dev/null 2>&1 || \
    [[ -f "/etc/systemd/system/$unit" ]] || { return 0; }
  svc stop "$unit" || true
  [[ "$DRY_RUN" == "true" ]] && return 0
  for _ in $(seq 1 60); do
    if [[ "$($SYSTEMCTL is-active "$unit" 2>/dev/null || true)" != "active" ]]; then
      return 0
    fi
    sleep 1
  done
  warn "$unit did not go inactive within 60s"
  return 1
}

unit_present() {
  local unit="$1"
  [[ -f "/etc/systemd/system/$unit" ]] && return 0
  $SYSTEMCTL list-unit-files "$unit" >/dev/null 2>&1
}

# unit_in_use — present and not masked. A masked unit is one the operator switched off; starting
# or health-checking it would fail by design and roll back every update.
unit_in_use() {
  unit_present "$1" || return 1
  [[ "$($SYSTEMCTL is-enabled "$1" 2>/dev/null || true)" != masked ]]
}

# ─────────────────────────── health checks ───────────────────────────────────

health_ghostd() {
  local user pass port resp
  user="$(grep -m1 '^rpcuser=' "$BITCOIN_CONF" 2>/dev/null | cut -d= -f2- || true)"
  pass="$(grep -m1 '^rpcpassword=' "$BITCOIN_CONF" 2>/dev/null | cut -d= -f2- || true)"
  port="$(grep -m1 '^rpcport=' "$BITCOIN_CONF" 2>/dev/null | cut -d= -f2- || true)"
  port="${port:-8332}"
  [[ -n "$user" && -n "$pass" ]] || { warn "ghostd RPC creds not found in $BITCOIN_CONF"; return 1; }
  for _ in $(seq 1 30); do
    resp="$(curl -s --max-time 8 --user "$user:$pass" \
      --data '{"jsonrpc":"1.0","method":"getblockchaininfo","params":[]}' \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if echo "$resp" | grep -q '"blocks"'; then
      log "health: ghostd RPC up"
      return 0
    fi
    sleep 2
  done
  err "health: ghostd RPC did not respond"
  return 1
}

# ghost-mining's /health block_height: present whenever ghost-mining answers. Empty when it does not.
read_node_height() {
  curl -fsS --max-time 8 "http://127.0.0.1:8080/health?unsigned=true" 2>/dev/null \
    | grep -oE '"block_height"[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1 || true
}

# ghost-mining answers /health. ⛔ Not its peer_count any more: that was the node pool's share-chain
# relay peers, which no Ghost Pool node has, so it stays null and would roll back every update.
# pool_sv2 and the translator are checked by health_stratum (their listening ports).
health_ghost_pool() {
  local h=""
  for _ in $(seq 1 30); do
    h="$(read_node_height)"
    if [[ -n "$h" ]]; then
      log "health: ghost-mining /health answers (block_height=$h)"
      return 0
    fi
    sleep 2
  done
  err "health: ghost-mining /health does not answer: ghost-mining is not up"
  return 1
}

# health_stratum — the SV2 stack is listening: sri-pool on :34255 (SV2) and
# sri-translator on :3333 (SV1, what miners connect to). Only units the node has.
# A listening socket is what the miners need; neither binary has a cheaper probe.
health_stratum() {
  local unit port ok
  for unit in sri-pool sri-translator; do
    unit_in_use "$unit.service" || { log "health: $unit not installed — skipped"; continue; }
    case "$unit" in sri-pool) port=34255 ;; sri-translator) port=3333 ;; esac
    ok=""
    for _ in $(seq 1 30); do
      if ss -Hltn "sport = :$port" 2>/dev/null | grep -q .; then ok=1; break; fi
      sleep 2
    done
    [[ -n "$ok" ]] || { err "health: $unit is not listening on :$port"; return 1; }
    log "health: $unit listening on :$port"
  done
  return 0
}

run_health_checks() {
  # GHOST_HEALTHCHECK_OVERRIDE lets an operator substitute a custom post-update
  # probe (and is the seam the test harness uses to drive the swap/rollback
  # paths offline). Unset in production → the real ghostd/pool/stratum probes run.
  if [[ -n "${GHOST_HEALTHCHECK_OVERRIDE:-}" ]]; then
    log "health: running override probe"
    bash -c "$GHOST_HEALTHCHECK_OVERRIDE"
    return $?
  fi
  health_ghostd && health_ghost_pool && health_stratum
}

# The node's units, in START order. Stops run this list backwards. Same order as the boot
# gate (wait-for-ghostd-sync.sh): the stratum stack has nothing to serve until the node is up.
# Ghost Pay is retired and not in the list: a host that still has its unit keeps it as it is —
# not stopped, swapped, started or health-checked by an update.
START_ORDER=(ghostd.service ghost-mining.service sri-pool.service sri-translator.service)

# stop_all — reverse start order, each verified inactive. Returns non-zero naming the first
# unit that would not stop; units the node does not have are skipped by stop_and_wait.
stop_all() {
  local i
  for (( i=${#START_ORDER[@]}-1; i>=0; i-- )); do
    stop_and_wait "${START_ORDER[$i]}" || { STOP_FAILED="${START_ORDER[$i]}"; return 1; }
  done
}

# start_all — start order. ghostd and ghost-mining always exist; the rest only where present.
# Returns non-zero naming the first unit that failed to start.
start_all() {
  local u
  for u in "${START_ORDER[@]}"; do
    case "$u" in
      ghostd.service|ghost-mining.service) ;;
      *) unit_in_use "$u" || continue ;;
    esac
    if ! $SYSTEMCTL start "$u"; then
      START_FAILED="$u"; return 1
    fi
    [[ "$u" == ghostd.service ]] && sleep 3
  done
  return 0
}

# ─────────────────────────────── dashboard ───────────────────────────────────

# health_dashboard — the dashboard answers its login page. GHOST_DASHBOARD_HEALTH_OVERRIDE stands in
# for it in tests, as GHOST_HEALTHCHECK_OVERRIDE does for the node.
health_dashboard() {
  if [[ -n "${GHOST_DASHBOARD_HEALTH_OVERRIDE:-}" ]]; then
    bash -c "$GHOST_DASHBOARD_HEALTH_OVERRIDE"
    return $?
  fi
  local code
  for _ in $(seq 1 30); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$DASHBOARD_URL" 2>/dev/null || true)"
    [[ "$code" == 200 ]] && { log "health: dashboard answers ($DASHBOARD_URL)"; return 0; }
    sleep 2
  done
  err "health: dashboard does not answer $DASHBOARD_URL (last='${code:-none}')"
  return 1
}

# swap_dashboard NEW_TREE STAMP — replace the dashboard tree, restart it, and put the previous tree
# back if it does not answer. Prints the outcome for the status line. Never fails the update.
swap_dashboard() {
  local new="$1" ts="$2" bak="${DASHBOARD_DIR}.bak.$2"
  $SYSTEMCTL stop ghost-dashboard.service >/dev/null 2>&1 || true
  rm -rf "${DASHBOARD_DIR}.new"
  if ! cp -a "$new" "${DASHBOARD_DIR}.new" || ! mv "$DASHBOARD_DIR" "$bak" || ! mv "${DASHBOARD_DIR}.new" "$DASHBOARD_DIR"; then
    err "dashboard: could not put the new tree in place — keeping the installed one"
    [[ -d "$DASHBOARD_DIR" ]] || mv "$bak" "$DASHBOARD_DIR" 2>/dev/null || true
    rm -rf "${DASHBOARD_DIR}.new"
    $SYSTEMCTL start ghost-dashboard.service >/dev/null 2>&1 || true
    echo "dashboard kept (swap failed)"; return 0
  fi
  if [[ "$(id -u)" -eq 0 ]]; then
    chown -R root:root "$DASHBOARD_DIR" 2>/dev/null || true
    install -d -o ghost -g ghost -m 0755 "$DASHBOARD_DIR/.next/cache" 2>/dev/null || true
  fi
  log "swapped $DASHBOARD_DIR (previous tree: $bak)"
  $SYSTEMCTL start ghost-dashboard.service >/dev/null 2>&1 || true
  if health_dashboard; then
    # One previous tree is kept for a manual rollback; older ones go (each is a whole build).
    local old
    for old in "${DASHBOARD_DIR}".bak.*; do
      [[ -d "$old" && "$old" != "$bak" ]] && rm -rf "$old"
    done
    echo "dashboard updated"; return 0
  fi
  err "dashboard: the new one does not answer — putting the previous one back"
  $SYSTEMCTL stop ghost-dashboard.service >/dev/null 2>&1 || true
  rm -rf "$DASHBOARD_DIR" && mv "$bak" "$DASHBOARD_DIR"
  $SYSTEMCTL start ghost-dashboard.service >/dev/null 2>&1 || true
  echo "dashboard rolled back"
  return 0
}

# ──────────────────────────────── main ───────────────────────────────────────

main() {
  # 1. Opt-in gate. Anything other than exactly AUTO_UPDATE=true is a no-op.
  local optin=""
  if [[ -r "$CONF_FILE" ]]; then
    optin="$(grep -m1 -oE '^[[:space:]]*AUTO_UPDATE[[:space:]]*=[[:space:]]*[A-Za-z]+' "$CONF_FILE" 2>/dev/null \
      | grep -oE '[A-Za-z]+$' || true)"
  fi
  if [[ "$optin" != "true" ]]; then
    log "auto-update disabled (AUTO_UPDATE='${optin:-unset}') — no-op"
    write_status "disabled" "auto-update opt-in is off"
    exit 0
  fi
  log "auto-update enabled${DRY_RUN:+ }$([[ "$DRY_RUN" == "true" ]] && echo '(dry-run)')"
  if [[ "$GPG_KEY_FP" != "$PRODUCTION_GPG_KEY_FP" ]]; then
    warn "TEST RELEASE MIRROR: releases are verified against ${GPG_KEY_FP}, not the release key — this node is not following real releases"
  fi

  # 2. Resolve installed + latest versions.
  local installed latest install_sh
  installed="$(read_installed_version || true)"
  [[ -n "$installed" ]] || { err "could not determine installed version"; write_status "error" "installed version unknown"; exit 1; }

  # 2a. Which release channel this node follows. The node pool installer writes the marker; an
  #     install without it is an old-network node and keeps tracking `releases/latest` exactly as
  #     before. A node running a node pool build with no marker is refused rather than "updated"
  #     to the old network's latest, which has no node pool in it.
  CHANNEL="$(np_channel)" || { err "unreadable release channel marker — refusing to pick a channel"; CHANNEL=""; write_status "error" "release channel marker invalid"; exit 1; }
  if [[ "$CHANNEL" == old-network && "$installed" == np-* ]]; then
    err "installed $installed is a node pool release but $NP_CHANNEL_FILE is missing — refusing to track the old network's releases"
    write_status "error" "node pool install without its channel marker"
    exit 1
  fi
  log "release channel: $CHANNEL"

  if [[ "$CHANNEL" == node-pool ]]; then
    # The newest np- release, picked from the list. Never `releases/latest`: that is the old
    # network's, and node pool releases are pre-releases precisely so it never points at one.
    local releases rc=0
    releases="$(curl -fsSL --max-time 30 "$NP_RELEASES_API_URL" 2>/dev/null)" \
      || { err "could not fetch the release list from $NP_RELEASES_API_URL"; write_status "error" "latest node pool version unresolved"; exit 1; }
    latest="$(np_latest_tag <<<"$releases")" || rc=$?
    if [[ $rc -ne 0 || -z "$latest" ]]; then
      case "$rc" in
        1) err "no published node pool release (np-v*) at $NP_RELEASES_API_URL" ;;
        *) err "the release list at $NP_RELEASES_API_URL is not in the expected shape (rc=$rc) — refusing to pick" ;;
      esac
      write_status "error" "latest node pool version unresolved"; exit 1
    fi
  else
    # Resolve the latest published release directly from the GitHub releases API
    # (the same source install.sh auto-tracks). Robust to install.sh's format.
    latest="$(curl -fsSL --max-time 30 "$RELEASES_API_URL" 2>/dev/null | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1 || true)"
    [[ -n "$latest" ]] || { err "could not resolve latest release from $RELEASES_API_URL"; write_status "error" "latest version unresolved"; exit 1; }
    # A node pool release can never be `latest` (it is a pre-release). If one ever is, it is not
    # for this node: refuse rather than move an old-network node onto the node pool.
    if [[ "$latest" == np-* ]]; then
      err "releases/latest is a node pool release ($latest) — not for an old-network node, refusing"
      write_status "error" "latest release is on the node pool channel" "$latest"; exit 1
    fi
    [[ "$latest" == v* ]] || latest="v${latest}"
  fi

  log "installed=$installed latest=$latest"
  if ! is_newer "$installed" "$latest"; then
    log "already up to date ($installed) — no-op"
    write_status "up-to-date" "installed $installed is current" "$latest"
    exit 0
  fi
  log "newer version available: $installed -> $latest"

  # This updater stops and starts `ghost-mining.service`. A node still running the unit under
  # its old name (#1018) has no such unit: the stop would be a no-op, the binary would be
  # swapped under a live process, and the start would fail. Refuse before downloading anything.
  if [[ ! -e /etc/systemd/system/ghost-mining.service && -e /etc/systemd/system/ghost-pool.service ]]; then
    err "this node's unit is still ghost-pool.service — rename it first (scripts/ops/rename-node-unit.sh)"
    write_status "error" "node unit not renamed to ghost-mining" "$latest"
    exit 1
  fi

  # 3. Download artefacts to an isolated temp dir.
  local tarball release_base tmp gnupg
  tarball="bitcoin-ghost-${latest}-x86_64-unknown-linux-gnu.tar.gz"
  if [[ -n "$RELEASE_BASE_OVERRIDE" ]]; then
    release_base="$RELEASE_BASE_OVERRIDE"
  else
    release_base="${RELEASE_DOWNLOAD_URL}/${latest}"
  fi
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  gnupg="$tmp/gnupg"; mkdir -m700 "$gnupg"
  export GNUPGHOME="$gnupg"

  log "downloading $tarball + signature (ghostd is inside the tarball)"
  curl -fsSL --max-time 600 "${release_base}/${tarball}"            -o "$tmp/$tarball"          || { err "download tarball failed"; write_status "error" "tarball download failed" "$latest"; exit 1; }
  curl -fsSL --max-time 60  "${release_base}/SHA256SUMS.txt"        -o "$tmp/SHA256SUMS.txt"    || { err "download SHA256SUMS.txt failed"; write_status "error" "checksums download failed" "$latest"; exit 1; }
  curl -fsSL --max-time 60  "${release_base}/SHA256SUMS.txt.asc"    -o "$tmp/SHA256SUMS.txt.asc" || { err "download signature failed"; write_status "error" "signature download failed" "$latest"; exit 1; }

  # ══════════════════════════════════════════════════════════════════════════
  # 4. MANDATORY VERIFICATION GATE — no binary is touched unless this passes.
  #    (a) detached GPG signature over SHA256SUMS.txt is VALID *and* the signer
  #        is EXACTLY the pinned release-key fingerprint;
  #    (b) the release tarball's SHA256 matches SHA256SUMS.txt (this transitively
  #        covers ghostd, which now lives inside the tarball).
  #    ANY failure → loud abort, binaries untouched, non-zero exit.
  # ══════════════════════════════════════════════════════════════════════════
  curl -fsSL --max-time 60 "$RELEASE_KEY_URL" 2>/dev/null | gpg --quiet --import 2>/dev/null || true
  # Trust the pinned key so gpg suppresses the cosmetic WoT warning.
  echo "${GPG_KEY_FP}:6:" | gpg --quiet --import-ownertrust 2>/dev/null || true

  # Require VALIDSIG to be EXACTLY our pinned key. This is stronger than "Good
  # signature from <name>" (which ANY imported key satisfies).
  if gpg --status-fd=1 --verify "$tmp/SHA256SUMS.txt.asc" "$tmp/SHA256SUMS.txt" 2>/dev/null \
       | grep -q "VALIDSIG ${GPG_KEY_FP}"; then
    log "VERIFY ok: release signature valid (key ${GPG_KEY_FP})"
  else
    err "VERIFY FAILED: release signature is NOT a valid signature from ${GPG_KEY_FP} — ABORTING, no binary touched."
    write_status "verify-failed" "GPG signature verification failed for $latest" "$latest"
    exit 1
  fi

  if ( cd "$tmp" && grep " ${tarball}\$" SHA256SUMS.txt | sha256sum -c - >/dev/null 2>&1 ); then
    log "VERIFY ok: tarball checksum matches SHA256SUMS.txt"
  else
    err "VERIFY FAILED: tarball SHA256 mismatch — ABORTING, no binary touched."
    write_status "verify-failed" "tarball checksum mismatch for $latest" "$latest"
    exit 1
  fi

  # 5. Unpack the verified tarball and locate the binaries it carries (ghostd is
  #    now bundled in the tarball, so it is covered by the checks above).
  tar -xzf "$tmp/$tarball" -C "$tmp"
  local new_pool new_cli new_admin new_ghostd new_pool_sv2 new_translator new_audit
  new_pool="$(find "$tmp" -name ghost-mining -type f | head -1 || true)"
  new_cli="$(find "$tmp" -name ghost-cli -type f | head -1 || true)"
  new_admin="$(find "$tmp" -name ghost-admin -type f | head -1 || true)"
  new_ghostd="$(find "$tmp" -name ghostd -type f | head -1 || true)"
  new_pool_sv2="$(find "$tmp" -name pool_sv2 -type f | head -1 || true)"
  new_translator="$(find "$tmp" -name translator_sv2 -type f | head -1 || true)"
  new_audit="$(find "$tmp" -name ghost-audit -type f | head -1 || true)"
  [[ -n "$new_pool" ]] || { err "verified tarball did not contain ghost-mining"; write_status "error" "tarball missing ghost-mining" "$latest"; exit 1; }
  [[ -n "$new_ghostd" ]] || { err "verified tarball did not contain ghostd (release predates the unified build?)"; write_status "error" "tarball missing ghostd" "$latest"; exit 1; }

  # 5a. The node dashboard (node pool channel, and only where one is installed). Verified against
  #     the same signed manifest before anything is stopped; a mismatch stops the whole update.
  local new_dash="" dash_tar="bitcoin-ghost-${latest}-dashboard.tar.gz"
  if [[ "$CHANNEL" == node-pool && -d "$DASHBOARD_DIR" ]]; then
    if grep -q " ${dash_tar}\$" "$tmp/SHA256SUMS.txt"; then
      curl -fsSL --max-time 600 "${release_base}/${dash_tar}" -o "$tmp/$dash_tar" \
        || { err "download $dash_tar failed"; write_status "error" "dashboard download failed" "$latest"; exit 1; }
      if ! ( cd "$tmp" && grep " ${dash_tar}\$" SHA256SUMS.txt | sha256sum -c - >/dev/null 2>&1 ); then
        err "VERIFY FAILED: dashboard SHA256 mismatch — ABORTING, nothing touched."
        write_status "verify-failed" "dashboard checksum mismatch for $latest" "$latest"
        exit 1
      fi
      log "VERIFY ok: dashboard checksum matches SHA256SUMS.txt"
      mkdir -p "$tmp/dash" && tar -xzf "$tmp/$dash_tar" -C "$tmp/dash"
      [[ -f "$tmp/dash/ghost-dashboard/server.js" ]] \
        || { err "$dash_tar does not carry ghost-dashboard/server.js"; write_status "error" "dashboard archive malformed" "$latest"; exit 1; }
      new_dash="$tmp/dash/ghost-dashboard"
    else
      warn "release $latest ships no dashboard — the installed one is left as it is"
    fi
  fi

  # Build the swap plan: (dest <- src), only for binaries currently installed.
  local -a SWAP_DEST=() SWAP_SRC=()
  SWAP_DEST+=("$BIN_DIR/ghostd");     SWAP_SRC+=("$new_ghostd")
  SWAP_DEST+=("$BIN_DIR/ghost-mining"); SWAP_SRC+=("$new_pool")
  # ghost-cli is the Core RPC client. A release up to v1.11.45 carries the admin tool under
  # that name; swapping it in would replace a working RPC client with a different program, so
  # the installed one is kept and the tarball's is treated as the admin tool it is.
  if [[ -n "$new_cli" ]] && ! is_core_rpc_client "$new_cli"; then
    [[ -n "$new_admin" ]] || new_admin="$new_cli"
    new_cli=""
    log "release $latest carries the admin tool as ghost-cli — the installed RPC client is left as it is"
  fi
  if [[ -x "$BIN_DIR/ghost-cli" && -n "$new_cli" ]] \
     && is_core_rpc_client "$new_cli"; then
    SWAP_DEST+=("$BIN_DIR/ghost-cli"); SWAP_SRC+=("$new_cli")
  fi
  if [[ -x "$BIN_DIR/ghost-admin" && -n "$new_admin" ]]; then
    SWAP_DEST+=("$BIN_DIR/ghost-admin"); SWAP_SRC+=("$new_admin")
  fi
  # ghost-audit (a miner's job check; nothing runs it) is swapped with the rest.
  if [[ -x "$BIN_DIR/ghost-audit" && -n "$new_audit" ]]; then
    SWAP_DEST+=("$BIN_DIR/ghost-audit"); SWAP_SRC+=("$new_audit")
  fi
  # The SV2 stack moves with ghost-mining or the update does not happen (#1044). An installed
  # binary the release does not carry would be left at the old version under a new ghost-mining
  # — refuse before anything is touched rather than split the stack.
  local sv2 sv2_src
  for sv2 in pool_sv2 translator_sv2; do
    [[ -x "$BIN_DIR/$sv2" ]] || continue
    if [[ "$sv2" == pool_sv2 ]]; then sv2_src="$new_pool_sv2"; else sv2_src="$new_translator"; fi
    if [[ -z "$sv2_src" ]]; then
      err "verified tarball does not contain $sv2, which this node runs — refusing to split the stack, no binary touched"
      write_status "error" "tarball missing $sv2" "$latest"
      exit 1
    fi
    SWAP_DEST+=("$BIN_DIR/$sv2"); SWAP_SRC+=("$sv2_src")
  done

  if [[ "$DRY_RUN" == "true" ]]; then
    log "DRY-RUN: verification PASSED for $latest. Would back up + swap:"
    local k
    for k in "${!SWAP_DEST[@]}"; do log "DRY-RUN:   ${SWAP_DEST[$k]} <- ${SWAP_SRC[$k]}"; done
    [[ -z "$new_dash" ]] || log "DRY-RUN:   $DASHBOARD_DIR <- $dash_tar"
    log "DRY-RUN: would then restart services + health-check, rolling back on failure."
    write_status "dry-run" "verification passed; swap skipped (dry-run) for $latest" "$latest"
    exit 0
  fi

  # 6. Back up the current binaries (for rollback).
  local ts; ts="$(date +%Y%m%d-%H%M%S)"
  local -a BACKUP_DEST=() BACKUP_OF=()
  local k
  for k in "${!SWAP_DEST[@]}"; do
    local dest="${SWAP_DEST[$k]}"
    if [[ -e "$dest" ]]; then
      cp -p "$dest" "${dest}.bak.${ts}"
      BACKUP_DEST+=("${dest}.bak.${ts}"); BACKUP_OF+=("$dest")
      log "backed up $dest -> ${dest}.bak.${ts}"
    fi
  done

  # rollback: restore every backup taken this run, restart, log.
  rollback() {
    err "rolling back to pre-update binaries"
    stop_all || true
    local j
    for j in "${!BACKUP_DEST[@]}"; do
      cp -p "${BACKUP_DEST[$j]}" "${BACKUP_OF[$j]}" && log "restored ${BACKUP_OF[$j]}"
    done
    start_all || err "rollback: ${START_FAILED:-a unit} did not start"
    return 0  # never let the rollback's last status trip `set -e` in the caller
  }

  # 7. Stop services (reverse start order: translator, pool, ghost-mining, ghostd), each
  #    verified inactive. Nothing has been swapped yet, so a refusal rolls back to a no-op.
  local STOP_FAILED="" START_FAILED=""
  stop_all || { err "$STOP_FAILED would not stop — rolling back"; rollback; write_status "rolled-back" "$STOP_FAILED failed to stop" "$latest"; exit 1; }

  # 8. Swap the verified binaries into place atomically (install = temp+rename).
  # Owned root:root in production (the unit runs as root); a non-root manual run
  # installs as the caller. If any swap fails, roll the whole set back.
  local -a OWNER_ARGS=()
  [[ "$(id -u)" -eq 0 ]] && OWNER_ARGS=(-o root -g root)
  for k in "${!SWAP_DEST[@]}"; do
    if install -m755 "${OWNER_ARGS[@]}" "${SWAP_SRC[$k]}" "${SWAP_DEST[$k]}"; then
      log "swapped ${SWAP_DEST[$k]}"
    else
      err "failed to install ${SWAP_DEST[$k]} — rolling back"
      rollback
      write_status "rolled-back" "binary swap failed for ${SWAP_DEST[$k]}" "$latest"
      exit 1
    fi
  done

  # 9. Start services (start order: ghostd, ghost-mining, pool, translator).
  start_all || { err "$START_FAILED failed to start — rolling back"; rollback; write_status "rolled-back" "$START_FAILED failed to start" "$latest"; exit 1; }

  # 10. Health-check; roll back on any failure.
  if run_health_checks; then
    echo "$latest" > "$VERSION_FILE"; chmod 644 "$VERSION_FILE" 2>/dev/null || true
    local dash_note=""
    [[ -z "$new_dash" ]] || dash_note="; $(swap_dashboard "$new_dash" "$ts")"
    log "UPDATE COMPLETE: now running $latest (backups: *.bak.${ts})${dash_note}"
    write_status "updated" "updated $installed -> $latest${dash_note}" "$latest"
    exit 0
  else
    err "health checks FAILED after swap — rolling back"
    rollback
    if run_health_checks; then
      log "rollback healthy — back on $installed"
    else
      err "rollback health checks ALSO failing — manual intervention required"
    fi
    write_status "rolled-back" "health check failed after update to $latest" "$latest"
    exit 1
  fi
}

main "$@"
GHOST_AUTOUPDATE_SH_EOF
chmod 755 /opt/ghost/bin/ghost-auto-update.sh
chown root:root /opt/ghost/bin/ghost-auto-update.sh

# ── restart-loop watchdog ────────────────────────────────────────────────────
# systemd restarts a crashing service forever and reports it `active` between
# crashes, so `is-active` and every dashboard say the node is healthy while it is
# dying on a loop. sri-pool reached 84-88 restarts on three nodes and nothing
# surfaced it (#412). This watches the restart RATE and complains.
#
# Canonical source: scripts/ghost-restart-watch.sh — kept in step by hand, same as
# ghost-auto-update.sh above. The installer is fetched standalone over curl and has
# no repo to read from, which is why these are duplicated; see #431.
cat > /opt/ghost/bin/ghost-restart-watch.sh <<'GHOST_RESTART_WATCH_SH_EOF'
#!/usr/bin/env bash
#
# Restart-loop watchdog.
#
# sri-pool reached 84-88 restarts on three nodes and nothing surfaced it — it was found
# by accident, long after the fact. systemd restarts a crashing service forever and
# reports it `active` between crashes, so every dashboard and every `is-active` check
# says the node is fine while it is in fact dying on a loop.
#
# It watches TWO failure modes, which are opposites and read oppositely:
#
#   * a unit restarting too often — a crash loop, below;
#   * a unit that is `active`, has NEVER restarted, and is serving nothing.
#
# The second was found the hard way. ghost-vm2's translator deadlocked on downstream-disconnect
# cleanup and held no listener for ~45 minutes while `systemctl is-active` said `active` and
# NRestarts stayed at 0 — the calmest possible reading of the one number this script used to
# examine (#812). It surfaced only because check-fleet-uniformity.sh happens to assert that
# something must listen on a port ufw allows. A hang is the same lie as a crash loop, told more
# quietly, and this script now asks the other question: is the unit holding the socket it
# exists to serve?
#
# This watches the RATE, not the total. NRestarts is cumulative since the last
# daemon-reload, so a node that crash-looped last week and has been stable since still
# shows a large number; and a `systemctl daemon-reload` silently resets it to zero. What
# matters is "how many restarts in the last N minutes", which is the delta between runs.
#
# Alerting goes through the node's own alert centre — `[alerts]` in pool.toml, configured
# from the dashboard at Settings -> Alerts, delivering to email, push (ntfy-style) and
# Telegram. This script POSTs to `/api/v1/alerts/internal/service-restart` and the node
# dispatches it, honouring the master switch, the `service_restart_loop` event flag, the
# rate limit and every channel the operator has enabled.
#
# It previously POSTed to its own ALERT_WEBHOOK read from /etc/ghost/alerting.conf. That was
# a second, parallel alerting system sitting beside a complete one, and it silently did
# nothing unless an operator found and populated a file that nothing else referenced — so in
# practice a crash loop alerted no one. Two sources of truth for the same job, which is the
# same mistake as #431.
#
# A journal entry at error priority is always written regardless, which is only useful
# because the journal is now persistent (#414) — before that a restart loop erased its own
# evidence roughly every four hours.
#
# Config, all optional, /etc/ghost/restart-watch.conf:
#   NODE_API=127.0.0.1:8080       where to POST the signal
#   INTERNAL_AUTH_KEY=<hex>       shared secret; when the node has internal auth configured
#                                 the signal must be HMAC-signed or it is rejected. Read from
#                                 the node config automatically when not set here.
#   RESTART_THRESHOLD=3           restarts within one window before alerting
#   RESTART_RENOTIFY_SECS=3600    minimum gap between repeat alerts for the same unit
#   LIVENESS_MISSES=3             consecutive runs active-but-not-listening before alerting.
#                                 Never 1: a single miss is a legitimate restart in flight.
#   LIVENESS_RESTART=false        also `systemctl restart` a unit judged hung. OFF by default —
#                                 detection is the gap; restarting a production service from a
#                                 watchdog is a policy the operator opts into. If enabled and the
#                                 port still does not come back, the restart-rate check above
#                                 catches the resulting loop, so the two compose.
#
# Usage:
#   ghost-restart-watch.sh          # normal run, intended for the timer
#   ghost-restart-watch.sh --check  # report current state, never alert, never persist

set -uo pipefail

# Both overridable so scripts/test-restart-watch.sh can drive this hermetically, exactly as
# deploy-node.sh allows for its own self-test. A watchdog whose logic cannot be exercised is
# the same class of problem as the hang it now looks for.
CONF="${CONF:-/etc/ghost/restart-watch.conf}"
STATE_DIR="${STATE_DIR:-/var/lib/ghost/restart-watch}"
# The node unit was `ghost-pool` until #1018. deploy-node.sh converges THIS script before it
# switches the unit, and a node that is never deployed to never switches — so watch whichever
# name the node has. Naming only the new one would skip the unit silently on such a node (the
# loop below `continue`s past a unit that does not exist), which is a watchdog watching three
# things and reporting on four. Never both: after the switch the old name is an alias of the
# same unit, and listing it too would raise every alert twice.
NODE_UNIT=ghost-mining
systemctl cat ghost-mining.service >/dev/null 2>&1 || NODE_UNIT=ghost-pool
UNITS="$NODE_UNIT sri-pool sri-translator ghostd"

NODE_API="127.0.0.1:8080"
INTERNAL_AUTH_KEY=""
RESTART_THRESHOLD=3
RESTART_RENOTIFY_SECS=3600
# `${VAR:-default}` so these are settable from the environment as well as from CONF, which is
# sourced below and still wins. Assigning unconditionally would make the knob unsettable — the
# self-test caught exactly that: LIVENESS_RESTART=true was silently ignored.
LIVENESS_MISSES="${LIVENESS_MISSES:-3}"
LIVENESS_RESTART="${LIVENESS_RESTART:-false}"

# The socket each unit exists to serve. Absence of this listener while the unit is `active`
# is the definition of "running but not working".
#
# These are the SAME ports deploy-node.sh uses as its READY_PORT gate after a swap — that path
# already treats "listening here" as the definition of a working unit, and it would be worse
# than useless for the two to disagree about what healthy means. Measured on the fleet, not
# assumed: ghost-mining also holds 8080/8443/8555-8563, sri-translator also holds 4444/9092; the
# port named here is the one whose absence means the unit is not doing its job.
liveness_port_for() {
    case "$1" in
        ghost-mining|ghost-pool) echo 8442 ;;  # TDP, what pool_sv2 connects to
        sri-pool)        echo 34255 ;;  # SV2, what the translator connects to
        sri-translator)  echo 3333 ;;   # SV1, what miners connect to
        ghostd)          echo 8332 ;;   # RPC, what ghost-mining depends on
        *)               echo "" ;;
    esac
}
# shellcheck source=/dev/null
[ -r "$CONF" ] && . "$CONF"

# Fall back to the node's own configured secret so an operator does not have to copy it
# into a second file — the whole point of this change is to stop duplicating config.
if [ -z "$INTERNAL_AUTH_KEY" ]; then
    # ⚠ The key is `internal_api_secret` under [network] — that is what ghost-mining reads
    # (`config.network.internal_api_secret` -> `InternalAuth::from_hex`). This used to grep for
    # `internal_auth_key`, a name that exists nowhere in the codebase or any config, so the
    # lookup ALWAYS came back empty, the POST always went unsigned, and the endpoint always
    # answered 401 — reported only to syslog. The replacement for a silent alerting path was
    # silent in exactly the same way.
    for f in /etc/ghost/pool.toml /etc/ghost/ghost-pool.toml; do
        [ -r "$f" ] || continue
        INTERNAL_AUTH_KEY=$(grep -aoE '^[[:space:]]*internal_api_secret[[:space:]]*=[[:space:]]*"[^"]+"' "$f" 2>/dev/null \
                            | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
        [ -n "$INTERNAL_AUTH_KEY" ] && break
    done
    if [ -z "$INTERNAL_AUTH_KEY" ]; then
        # Say so. A watchdog that cannot authenticate will 401 on every alert it ever raises,
        # and the whole point of this script is to not fail quietly.
        logger -t ghost-restart-watch -p daemon.warning -- \
            "no internal_api_secret found in /etc/ghost/pool.toml — alerts will be REJECTED (401)" 2>/dev/null || true
    fi
fi

# POST a restart-loop signal to the node's alert centre.
# Auth mirrors the dashboard proxy: HMAC-SHA256(secret, u64_le(timestamp) || body), hex,
# in X-Ghost-Signature, with the unix timestamp in X-Ghost-Timestamp.
send_alert() {
    local unit="$1" restarts="$2" window="$3" reason="${4:-}"
    local body ts sig
    if [ -n "$reason" ]; then
        # A reason means this is not a restart loop. The node renders it instead of the
        # "restarted N times" wording, which for a hang would read "restarted 0 times" — the
        # calmest possible description of the opposite of what happened (#812).
        body=$(printf '{"unit":"%s","restarts":%s,"window_secs":%s,"reason":"%s"}' \
                      "$unit" "$restarts" "$window" "$reason")
    else
        body=$(printf '{"unit":"%s","restarts":%s,"window_secs":%s}' "$unit" "$restarts" "$window")
    fi
    ts=$(date +%s)

    local -a auth_headers=()
    if [ -n "$INTERNAL_AUTH_KEY" ]; then
        # u64 little-endian timestamp, then the raw body, HMAC'd with the hex secret.
        sig=$( { printf '%016x' "$ts" | sed -E 's/(..)(..)(..)(..)(..)(..)(..)(..)/\8\7\6\5\4\3\2\1/' | xxd -r -p
                 printf '%s' "$body"
               } | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$INTERNAL_AUTH_KEY" -binary 2>/dev/null | xxd -p -c 256 )
        [ -n "$sig" ] && auth_headers=(-H "X-Ghost-Signature: $sig" -H "X-Ghost-Timestamp: $ts")
    fi

    curl -fsS -m 10 -X POST -H 'Content-Type: application/json' \
         "${auth_headers[@]}" -d "$body" \
         "http://${NODE_API}/api/v1/alerts/internal/service-restart" >/dev/null 2>&1 \
      || logger -t ghost-restart-watch -p daemon.warning -- \
           "alert POST failed for ${unit}; see journal for the restart itself" 2>/dev/null || true
}

CHECK_ONLY=false
[ "${1:-}" = "--check" ] && CHECK_ONLY=true

$CHECK_ONLY || mkdir -p "$STATE_DIR"
now=$(date +%s)
problems=()

for unit in $UNITS; do
    systemctl list-unit-files "${unit}.service" >/dev/null 2>&1 || continue
    systemctl cat "$unit" >/dev/null 2>&1 || continue

    n=$(systemctl show -p NRestarts --value "$unit" 2>/dev/null)
    [ -n "$n" ] || continue

    f="$STATE_DIR/$unit"
    prev_n=""; prev_t=""; last_alert=0; misses=0; last_live_alert=0
    # Five fields now. A file written by an older version has three, so the two new ones read
    # as empty and fall back below — no migration, no reset of the restart counters.
    [ -r "$f" ] && read -r prev_n prev_t last_alert misses last_live_alert < "$f" 2>/dev/null
    : "${last_alert:=0}"; : "${misses:=0}"; : "${last_live_alert:=0}"

    port=$(liveness_port_for "$unit")
    active=$(systemctl is-active "$unit" 2>/dev/null)
    listening=""
    if [ -n "$port" ]; then
        if ss -ltn 2>/dev/null | grep -q ":${port}\b"; then listening=yes; else listening=no; fi
    fi

    if $CHECK_ONLY; then
        printf "  %-16s NRestarts=%-4s active=%-10s port=%-6s listening=%s\n" \
               "$unit" "$n" "$active" "${port:-none}" "${listening:-n/a}"
        continue
    fi

    # ---- liveness: active, but holding nothing ----------------------------------------
    #
    # Only meaningful while the unit is `active`. A unit that is stopped, activating or failed
    # is a different condition and systemd already represents it honestly; this exists for the
    # case where systemd's own view is reassuring and wrong.
    if [ -n "$port" ] && [ "$active" = "active" ] && [ "$listening" = "no" ]; then
        misses=$(( misses + 1 ))
        if [ "$misses" -ge "$LIVENESS_MISSES" ]; then
            msg="$(hostname -s): ${unit} is active but has not been listening on :${port} for ${misses} consecutive checks — running, not working"
            if [ $(( now - last_live_alert )) -ge "$RESTART_RENOTIFY_SECS" ]; then
                logger -t ghost-restart-watch -p daemon.err -- "$msg" 2>/dev/null || true
                echo "ALERT: $msg" >&2
                send_alert "$unit" 0 "$(( misses * 60 ))" \
                    "active but not listening on :${port} for ${misses} consecutive checks"
                last_live_alert=$now
            fi
            problems+=("$msg")

            if [ "$LIVENESS_RESTART" = "true" ]; then
                logger -t ghost-restart-watch -p daemon.err -- \
                    "$(hostname -s): restarting ${unit} — hung with no listener on :${port}" 2>/dev/null || true
                systemctl restart "$unit" >/dev/null 2>&1 || true
                # Reset so a restart that works is not immediately re-alerted, and so a restart
                # that does NOT work re-arms from zero rather than firing every single run.
                misses=0
            fi
        fi
    else
        misses=0
    fi

    # First run for this unit, or the counter went backwards because something ran
    # daemon-reload. Either way there is no meaningful delta — record and move on
    # rather than inventing one.
    if [ -z "$prev_n" ] || [ "$n" -lt "$prev_n" ]; then
        printf '%s %s %s %s %s\n' "$n" "$now" "$last_alert" "$misses" "$last_live_alert" > "$f"
        continue
    fi

    delta=$(( n - prev_n ))
    elapsed=$(( now - ${prev_t:-$now} ))

    if [ "$delta" -ge "$RESTART_THRESHOLD" ]; then
        mins=$(( elapsed / 60 )); [ "$mins" -lt 1 ] && mins=1
        msg="$(hostname -s): ${unit} restarted ${delta} times in ${mins}m (total ${n})"

        if [ $(( now - last_alert )) -ge "$RESTART_RENOTIFY_SECS" ]; then
            logger -t ghost-restart-watch -p daemon.err -- "$msg" 2>/dev/null || true
            echo "ALERT: $msg" >&2
            send_alert "$unit" "$delta" "$elapsed"
            last_alert=$now
        fi
        problems+=("$msg")
    fi

    printf '%s %s %s %s %s\n' "$n" "$now" "$last_alert" "$misses" "$last_live_alert" > "$f"
done

# Non-zero when something is looping, so this is usable as a check from elsewhere
# (a fleet script, a CI job, a human) and not only as a timer that mails itself.
[ ${#problems[@]} -eq 0 ]
GHOST_RESTART_WATCH_SH_EOF
chmod 755 /opt/ghost/bin/ghost-restart-watch.sh
chown root:root /opt/ghost/bin/ghost-restart-watch.sh
mkdir -p /var/lib/ghost/restart-watch

cat > /etc/systemd/system/ghost-restart-watch.service <<'GHOST_RESTART_WATCH_SERVICE_EOF'
[Unit]
Description=Bitcoin Ghost restart-loop watchdog
Documentation=https://github.com/bitcoin-ghost/ghost/issues/412
# Only meaningful once the node is up; never block boot on it.
After=network-online.target ghostd.service ghost-mining.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/ghost/bin/ghost-restart-watch.sh
# systemctl show and the state directory under /var/lib both need root.
User=root
# The script exits non-zero when a service is looping — that is a finding, not a
# failure of the check. Without this, the thing that reports problems would itself
# show up as a failed unit, which is exactly the noise that gets ignored.
SuccessExitStatus=0 1
GHOST_RESTART_WATCH_SERVICE_EOF

cat > /etc/systemd/system/ghost-restart-watch.timer <<'GHOST_RESTART_WATCH_TIMER_EOF'
[Unit]
Description=Run the Bitcoin Ghost restart-loop watchdog every 5 minutes
Documentation=https://github.com/bitcoin-ghost/ghost/issues/412

[Timer]
# Five minutes: short enough that a loop is caught while it is still happening rather
# than reconstructed afterwards, long enough that the restart delta is meaningful.
OnBootSec=5min
OnUnitActiveSec=5min
# Do not let every node in the fleet fire at the same instant and stampede a webhook.
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
GHOST_RESTART_WATCH_TIMER_EOF

systemctl daemon-reload 2>/dev/null || true
systemctl enable --now ghost-restart-watch.timer >/dev/null 2>&1 \
  && log "Restart-loop watchdog enabled (every 5 min)" \
  || log "WARNING: could not enable ghost-restart-watch.timer"

# The privileged toggle the dashboard may sudo (scoped to on|off only).
cat > /opt/ghost/bin/ghost-autoupdate-toggle <<'GHOST_AUTOUPDATE_TOGGLE_EOF'
#!/usr/bin/env bash
#
# ghost-autoupdate-toggle — flip the node auto-update opt-in.
#
# This is the ONLY privileged operation the node dashboard performs. The
# dashboard service user (ghost) may run it via a tightly-scoped sudoers rule
# (/etc/sudoers.d/ghost-autoupdate) that pins the exact argument to `on` or
# `off` — nothing else. The script takes NO free-form input: it writes a fixed
# AUTO_UPDATE=true|false to /etc/ghost/auto-update.conf and enables/disables the
# timer to match. There is no path by which the dashboard can run an arbitrary
# command or smuggle other state through this helper.
#
# Installed root-owned 0755 at /opt/ghost/bin/ghost-autoupdate-toggle.
#
# The toggle never chooses WHAT the updater follows. The release channel lives in its own file,
# /etc/ghost/release-channel, which only the installer writes and this script never touches, so
# switching updates on from the dashboard follows the same channel as `--auto-update` at install:
# a node pool node follows the np- releases, an old-network node `releases/latest`. A marker that
# says anything but `node-pool` is refused here as it is by the updater (fail closed).
#
set -euo pipefail

CONF="${GHOST_AUTOUPDATE_CONF:-/etc/ghost/auto-update.conf}"
CHANNEL_FILE="${GHOST_RELEASE_CHANNEL_FILE:-/etc/ghost/release-channel}"
SYSTEMCTL="${GHOST_SYSTEMCTL:-systemctl}"

case "${1:-}" in
  on)  val="true" ;;
  off) val="false" ;;
  *) echo "usage: ghost-autoupdate-toggle on|off" >&2; exit 2 ;;
esac

channel="old-network"
if [[ -e "$CHANNEL_FILE" ]]; then
  channel="$(grep -vE '^[[:space:]]*(#|$)' "$CHANNEL_FILE" 2>/dev/null | head -1 | tr -d '[:space:]')"
  if [[ "$channel" != node-pool && "$val" == true ]]; then
    echo "refusing to turn auto-update on: $CHANNEL_FILE says '${channel}', expected 'node-pool'" >&2
    exit 1
  fi
fi

umask 022
mkdir -p "$(dirname "$CONF")"
tmp="$(mktemp "${CONF}.XXXXXX")"
cat > "$tmp" <<EOF
# Bitcoin Ghost node auto-update opt-in.
# Managed by the installer and the node dashboard (ghost-autoupdate-toggle).
# When AUTO_UPDATE is anything other than exactly 'true', the updater is a no-op.
AUTO_UPDATE=${val}
EOF
chmod 644 "$tmp"
mv -f "$tmp" "$CONF"

# Keep the timer state in lockstep with the opt-in. Best-effort: the conf flag
# is the authoritative gate, so a systemd hiccup here can never cause an update.
if [[ "$val" == "true" ]]; then
  "$SYSTEMCTL" enable --now ghost-auto-update.timer >/dev/null 2>&1 || true
else
  "$SYSTEMCTL" disable --now ghost-auto-update.timer >/dev/null 2>&1 || true
fi

echo "auto-update set to ${val} (release channel: ${channel})"
GHOST_AUTOUPDATE_TOGGLE_EOF
chmod 755 /opt/ghost/bin/ghost-autoupdate-toggle
chown root:root /opt/ghost/bin/ghost-autoupdate-toggle

# Sudoers scope: the dashboard user (ghost) may run ONLY the toggle, on|off.
cat > /etc/sudoers.d/ghost-autoupdate <<'GHOST_AUTOUPDATE_SUDOERS_EOF'
# Bitcoin Ghost — node-dashboard auto-update toggle.
#
# Grants the dashboard service user (ghost) permission to flip the auto-update
# opt-in, and NOTHING else. The command is pinned with its exact argument, so
# `ghost` can run only:
#     sudo /opt/ghost/bin/ghost-autoupdate-toggle on
#     sudo /opt/ghost/bin/ghost-autoupdate-toggle off
# Any other argument (or other command) is rejected by sudo. The toggle binary
# is root-owned 0755, so the dashboard user cannot rewrite what runs as root.
#
# Installed 0440 at /etc/sudoers.d/ghost-autoupdate; validated with `visudo -cf`.
Defaults!/opt/ghost/bin/ghost-autoupdate-toggle !requiretty
ghost ALL=(root) NOPASSWD: /opt/ghost/bin/ghost-autoupdate-toggle on, /opt/ghost/bin/ghost-autoupdate-toggle off
GHOST_AUTOUPDATE_SUDOERS_EOF
chmod 440 /etc/sudoers.d/ghost-autoupdate
chown root:root /etc/sudoers.d/ghost-autoupdate
# Refuse to ship a malformed sudoers file (would otherwise break ALL sudo).
# Non-fatal: on failure we remove it (sudo stays safe) and continue — the node
# installs fine; only the dashboard toggle would be unavailable until fixed.
if ! visudo -cf /etc/sudoers.d/ghost-autoupdate >/dev/null 2>&1; then
  rm -f /etc/sudoers.d/ghost-autoupdate
  log "WARNING: generated sudoers file failed validation — removed it (dashboard auto-update toggle disabled)"
fi

# OPTIONAL off-node copy of the nightly database backups (#1016). Installing the helper turns
# nothing on: it acts only once /etc/ghost/backup.conf exists, which only the operator creates
# (from the dashboard). A node that never configures it behaves exactly as before.
# Canonical source: scripts/ghost-backup-offsite.sh.
cat > /opt/ghost/bin/ghost-backup-offsite <<'GHOST_BACKUP_OFFSITE_SH_EOF'
#!/usr/bin/env bash
#
# ghost-backup-offsite — OPTIONAL off-node copy of the nightly database backups (#1016).
#
# The nightly job (backup-databases.sh) writes gzipped copies to /var/backups/ghost/db, on the same
# disk as the database. That covers a bad migration; it does not cover losing the disk or the VM.
# This helper lets a node runner point those copies at a second place they control. The fleet pays
# for no storage: it is OFF by default, never mandatory, and a node with no /etc/ghost/backup.conf
# behaves exactly as it did before this file existed.
#
# Two kinds of destination, and only two:
#
#   local  an absolute directory on a DIFFERENT filesystem — a mounted USB drive or NFS share.
#          ⛔ A destination on the same filesystem as the local backups is refused: it would not be
#          off-disk. That is also what makes an UNMOUNTED drive safe: its empty mountpoint sits on
#          the root filesystem, so the copy is refused instead of quietly filling the root disk.
#   ssh    user@host:/path over SFTP, with a dedicated ed25519 key this node generates. The private
#          key never leaves the state directory and is never printed. The host key is pinned on the
#          first successful `test` (accept-new) and the nightly copy then requires that exact key
#          (StrictHostKeyChecking=yes). Host key checking is never turned off.
#
# Subcommands. Every one prints ONE JSON object on stdout. Exit 0 = done, 1 = refused/failed (the
# JSON says why, verbatim), 2 = usage.
#
#   show      the whole state: enabled, kind, target, port, keep, public key, pinned host key,
#             the last off-node result, and the newest local backup.
#   set       read the new settings from STDIN, one `key=value` per line (kind, target, keep,
#             port), validate every one, and write /etc/ghost/backup.conf.
#   disable   remove /etc/ghost/backup.conf. The key pair stays, so turning it back on does not
#             mean re-adding a key at the destination.
#   keygen    create the key pair if there is none; print the PUBLIC key.
#   test      write and remove a small probe file at the configured destination, as the backup
#             user, and report the error verbatim if that fails.
#   push [--deadline SECONDS] FILE...
#             (backup-databases.sh only, as the backup user — NOT in sudoers) copy the given
#             backups to the destination, prune the destination to `keep`, record the outcome.
#
# Why settings arrive on STDIN and not argv: the sudoers rule can then pin every subcommand to its
# EXACT argv (`… set`, no wildcard), so nothing the dashboard sends can reach sudo's command line.
# The values are data: they are parsed line by line, matched against fixed character sets, and
# never evaluated, sourced or interpolated into a shell. Under sudo the GHOST_* overrides below are
# stripped by env_reset; they exist for the self-test.
#
# Installed root-owned 0755 at /opt/ghost/bin/ghost-backup-offsite. Canonical source:
# scripts/ghost-backup-offsite.sh (install-node.sh embeds a byte-identical copy;
# scripts/check-inlined-copies.sh holds them together).
#
set -euo pipefail
umask 077

CONF="${GHOST_BACKUP_CONF:-/etc/ghost/backup.conf}"
STATE_DIR="${GHOST_BACKUP_STATE_DIR:-/var/lib/ghost-backup}"
LOCAL_DIR="${GHOST_BACKUP_DIR:-/var/backups/ghost/db}"
GHOST_DIR="${GHOST_BACKUP_GHOST_DIR:-/home/ghost/.ghost}"
BACKUP_USER="${GHOST_BACKUP_USER:-ghost}"
SYSTEMCTL="${GHOST_SYSTEMCTL:-systemctl}"
# Room to leave on a local destination beyond the files themselves.
HEADROOM_KB="${GHOST_BACKUP_OFFSITE_HEADROOM_KB:-262144}"

KEY="$STATE_DIR/id_ed25519"
KNOWN_HOSTS="$STATE_DIR/known_hosts"
STATUS="$STATE_DIR/offsite.status"
KEY_COMMENT="ghost-node-backup"
DEFAULT_KEEP=7

# The names this helper creates and the ONLY names it will ever delete at a destination. Anything
# else in the directory — the operator's own files — is invisible to the prune.
BACKUP_NAME_RE='^ghost(-pay)?-[0-9]{12}\.db\.gz$'

# ------------------------------------------------------------------------------------------ output

# A JSON string literal. Errors can carry any byte (they are a remote server's words), so they are
# reduced to printable ASCII by `clean` before they get here.
json_str() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/ }"
    s="$(printf '%s' "$s" | LC_ALL=C tr -cd '\40-\176')"
    printf '"%s"' "$s"
}

# Printable ASCII, newlines folded to " | ", at most 600 characters.
clean() {
    printf '%s' "$1" | LC_ALL=C tr '\n\t' '\036 ' | LC_ALL=C tr -cd '\36\40-\176' \
        | sed 's/\x1e/ | /g; s/^ | //; s/ | $//' | cut -c1-600
}

fail() {
    printf '{"ok":false,"error":%s}\n' "$(json_str "$(clean "$1")")"
    exit 1
}

usage() {
    echo "usage: ghost-backup-offsite show|set|disable|keygen|test|push [--deadline S] FILE..." >&2
    exit 2
}

# ------------------------------------------------------------------------------------- validation
#
# Each check is a whitelist. A value that fails one is refused, never repaired: stripping the bad
# characters out of `a;rm -rf /` leaves a different path that the operator never asked for.

valid_path() {
    local p="$1"
    [[ "$p" =~ ^/[A-Za-z0-9._/-]{1,254}$ ]] || return 1
    [[ "$p" != *//* ]] || return 1
    [[ "$p/" != */./* && "$p/" != */../* ]] || return 1
    [ "$p" != "/" ] || return 1
    return 0
}

valid_user() { [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9._-]{0,31}$ ]]; }

# A DNS name or IPv4 address. Every label starts and ends alphanumeric, so nothing that reaches ssh
# can begin with `-` and be read as an option.
valid_host() {
    local h="$1"
    [ "${#h}" -le 253 ] || return 1
    [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]
}

valid_port() {
    [[ "$1" =~ ^[0-9]{1,5}$ ]] || return 1
    [ "$((10#$1))" -ge 1 ] && [ "$((10#$1))" -le 65535 ]
}

valid_keep() {
    [[ "$1" =~ ^[0-9]{1,3}$ ]] || return 1
    [ "$((10#$1))" -ge 1 ] && [ "$((10#$1))" -le 365 ]
}

# Splits an ssh target into SSH_USER / SSH_HOST / SSH_PATH, or returns 1.
split_ssh_target() {
    local t="$1"
    [[ "$t" =~ ^([^@:/]+)@([^@:/]+):(/.*)$ ]] || return 1
    SSH_USER="${BASH_REMATCH[1]}"
    SSH_HOST="${BASH_REMATCH[2]}"
    SSH_PATH="${BASH_REMATCH[3]}"
    valid_user "$SSH_USER" && valid_host "$SSH_HOST" && valid_path "$SSH_PATH"
}

# Validates a complete setting. Prints the reason and returns 1 on the first problem.
validate_setting() {
    local kind="$1" target="$2" keep="$3" port="$4"
    case "$kind" in
        local)
            valid_path "$target" || { echo "local target must be an absolute path of letters, digits and . _ - / only (no spaces, no '..')"; return 1; }
            [ -z "$port" ] || { echo "a port applies to an ssh destination only"; return 1; }
            ;;
        ssh)
            split_ssh_target "$target" || { echo "ssh target must be user@host:/absolute/path — user and host of letters, digits and . _ -, path of letters, digits and . _ - /"; return 1; }
            valid_port "${port:-22}" || { echo "port must be a number from 1 to 65535"; return 1; }
            ;;
        *) echo "kind must be 'local' or 'ssh'"; return 1 ;;
    esac
    valid_keep "$keep" || { echo "keep must be a number from 1 to 365"; return 1; }
    return 0
}

# ---------------------------------------------------------------------------------------- config
#
# /etc/ghost/backup.conf is NOT sourced. Each line is a comment, blank, or one of four exact keys;
# anything else makes the whole file invalid, and an invalid file copies nothing.

C_KIND="" C_TARGET="" C_KEEP="" C_PORT="" C_ERROR=""
load_conf() {
    C_KIND="" C_TARGET="" C_KEEP="" C_PORT="" C_ERROR=""
    [ -e "$CONF" ] || return 1
    local line n=0 key val
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        case "$line" in ''|'#'*) continue ;; esac
        key="${line%%=*}"
        val="${line#*=}"
        [ "$key" != "$line" ] || { C_ERROR="$CONF line $n is not KEY=VALUE"; return 1; }
        case "$key" in
            OFFSITE_KIND)   C_KIND="$val" ;;
            OFFSITE_TARGET) C_TARGET="$val" ;;
            OFFSITE_KEEP)   C_KEEP="$val" ;;
            OFFSITE_PORT)   C_PORT="$val" ;;
            *) C_ERROR="$CONF line $n: unknown key"; return 1 ;;
        esac
    done < "$CONF" || { C_ERROR="cannot read $CONF"; return 1; }
    [ -n "$C_KEEP" ] || C_KEEP="$DEFAULT_KEEP"
    local why
    if ! why="$(validate_setting "$C_KIND" "$C_TARGET" "$C_KEEP" "$C_PORT")"; then
        C_ERROR="$CONF is invalid: $why"
        return 1
    fi
    if [ "$C_KIND" = ssh ]; then
        split_ssh_target "$C_TARGET"
        C_PORT="$((10#${C_PORT:-22}))"
    fi
    C_KEEP="$((10#$C_KEEP))"
    return 0
}

write_conf() {
    local kind="$1" target="$2" keep="$3" port="$4" tmp
    mkdir -p "$(dirname "$CONF")"
    tmp="$(mktemp "${CONF}.XXXXXX")"
    {
        echo "# Bitcoin Ghost — optional off-node copy of the nightly database backups (#1016)."
        echo "# Managed by ghost-backup-offsite (the node dashboard). Not sourced: every line is"
        echo "# parsed and validated, and an invalid file copies nothing. Delete it to turn it off."
        echo "OFFSITE_KIND=$kind"
        echo "OFFSITE_TARGET=$target"
        [ "$kind" != ssh ] || echo "OFFSITE_PORT=$port"
        echo "OFFSITE_KEEP=$keep"
    } > "$tmp"
    chmod 644 "$tmp"
    mv -f "$tmp" "$CONF"
}

# ------------------------------------------------------------------------------- the backup user

i_am_backup_user() { [ "$(id -un)" = "$BACKUP_USER" ]; }

# Runs a command as the backup user — the user the nightly job runs as — so a test proves what the
# nightly copy will be able to do, and the key and pinned host key stay owned by that user.
as_backup_user() {
    if i_am_backup_user; then
        "$@"
    elif [ "$(id -u)" -eq 0 ]; then
        (cd / && runuser -u "$BACKUP_USER" -- "$@")
    else
        echo "must run as root or as $BACKUP_USER" >&2
        return 1
    fi
}

ensure_state_dir() {
    if [ ! -d "$STATE_DIR" ]; then
        mkdir -p "$STATE_DIR"
    fi
    chmod 700 "$STATE_DIR"
    if [ "$(id -u)" -eq 0 ] && ! i_am_backup_user; then
        chown "$BACKUP_USER:" "$STATE_DIR"
    fi
}

public_key() {
    [ -r "$KEY.pub" ] || return 1
    local pk
    pk="$(head -n1 "$KEY.pub")"
    [[ "$pk" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ .*)?$ ]] || return 1
    printf '%s' "${pk%% *} $(printf '%s' "$pk" | awk '{print $2}') $KEY_COMMENT"
}

# The host as ssh writes it into known_hosts: bare on port 22, bracketed with the port otherwise.
known_hosts_name() {
    if [ "$2" = 22 ]; then printf '%s' "$1"; else printf '[%s]:%s' "$1" "$2"; fi
}

host_key_pinned() {
    [ -s "$KNOWN_HOSTS" ] || return 1
    ssh-keygen -F "$(known_hosts_name "$1" "$2")" -f "$KNOWN_HOSTS" >/dev/null 2>&1
}

# ------------------------------------------------------------------------------- filesystem checks

# The device a path lives on. For a path that does not exist yet, its nearest existing ancestor.
fs_id() {
    local p="$1"
    while [ ! -e "$p" ] && [ "$p" != / ]; do p="$(dirname "$p")"; done
    stat -L -c %d -- "$p"
}

# Is a local directory usable as an off-disk destination? Prints the reason and returns 1 if not.
check_local_dest() {
    local dir="$1" dev
    [ -e "$dir" ] || { echo "local destination $dir does not exist (is the drive mounted?)"; return 1; }
    [ -d "$dir" ] || { echo "local destination $dir is not a directory"; return 1; }
    as_backup_user test -w "$dir" -a -x "$dir" 2>/dev/null \
        || { echo "local destination $dir is not writable by the backup user '$BACKUP_USER'"; return 1; }
    dev="$(fs_id "$dir")" || { echo "cannot stat $dir"; return 1; }
    if [ "$dev" = "$(fs_id "$LOCAL_DIR")" ]; then
        echo "refusing $dir: it is on the same filesystem as the local backups in $LOCAL_DIR, so a copy there is not off-disk (if it should be a mounted drive, it is not mounted)"
        return 1
    fi
    if [ "$dev" = "$(fs_id "$GHOST_DIR")" ]; then
        echo "refusing $dir: it is on the same filesystem as the database in $GHOST_DIR, so a copy there is not off-disk"
        return 1
    fi
    return 0
}

# ------------------------------------------------------------------------------------- transports

# Remaining seconds before the deadline; empty when there is none.
DEADLINE_AT=""
remaining() {
    [ -n "$DEADLINE_AT" ] || { echo 86400; return 0; }
    local left=$((DEADLINE_AT - $(date +%s)))
    [ "$left" -gt 0 ] || return 1
    echo "$left"
}

# Runs one SFTP batch against the configured server. $1 = StrictHostKeyChecking value, $2 = the
# batch file. The private key is passed by path and never read here.
SFTP_OUT=""
run_sftp() {
    local strict="$1" batch="$2" left
    left="$(remaining)" || { SFTP_OUT="deadline reached before the copy could start"; return 1; }
    SFTP_OUT="$(timeout "$left" sftp -q -b "$batch" -F /dev/null -P "$C_PORT" \
        -i "$KEY" \
        -o IdentitiesOnly=yes \
        -o BatchMode=yes \
        -o PasswordAuthentication=no \
        -o StrictHostKeyChecking="$strict" \
        -o UserKnownHostsFile="$KNOWN_HOSTS" \
        -o GlobalKnownHostsFile=/dev/null \
        -o ConnectTimeout=20 \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=4 \
        -- "$SSH_USER@$SSH_HOST" 2>&1)"
    local rc=$?
    [ "$rc" -ne 124 ] || SFTP_OUT="timed out after ${left}s. $SFTP_OUT"
    return "$rc"
}

# What sftp said, minus its echo of the batch commands.
sftp_error() {
    printf '%s\n' "$SFTP_OUT" | /usr/bin/grep -v '^sftp> ' || true
}

# ------------------------------------------------------------------------------------- subcommands

cmd_show() {
    local enabled=false kind="" target="" keep="$DEFAULT_KEEP" port="" conf_error=""
    local pk="" pinned=false
    if load_conf; then
        enabled=true kind="$C_KIND" target="$C_TARGET" keep="$C_KEEP" port="$C_PORT"
        if [ "$kind" = ssh ] && host_key_pinned "$SSH_HOST" "$C_PORT"; then pinned=true; fi
    elif [ -e "$CONF" ]; then
        conf_error="$C_ERROR"
    fi
    pk="$(public_key)" || pk=""

    # The last off-node outcome, as the nightly run recorded it.
    local last="null"
    if [ -r "$STATUS" ]; then
        local r t e f
        r="$(sed -n 's/^last_offsite_result=//p' "$STATUS" | head -n1)"
        t="$(sed -n 's/^last_offsite_time=//p' "$STATUS" | head -n1)"
        e="$(sed -n 's/^last_offsite_error=//p' "$STATUS" | head -n1)"
        f="$(sed -n 's/^last_offsite_files=//p' "$STATUS" | head -n1)"
        last="{\"result\":$(json_str "$r"),\"time\":$(json_str "$t"),\"error\":$(json_str "$e"),\"files\":$(json_str "$f")}"
    fi

    # The newest LOCAL backup of ghost.db, and how many there are.
    local newest="" newest_time="" count=0 name
    if [ -d "$LOCAL_DIR" ]; then
        for f in "$LOCAL_DIR"/ghost-*.db.gz; do
            [ -e "$f" ] || continue
            name="${f##*/}"
            [[ "$name" =~ $BACKUP_NAME_RE ]] || continue
            [[ "$name" == ghost-pay-* ]] && continue
            count=$((count + 1))
            if [ -z "$newest" ] || [[ "$name" > "$newest" ]]; then newest="$name"; fi
        done
        [ -z "$newest" ] || newest_time="$(date -u -d "@$(stat -c %Y -- "$LOCAL_DIR/$newest")" +%Y-%m-%dT%H:%M:%SZ)"
    fi
    local timer
    timer="$("$SYSTEMCTL" is-enabled ghost-backup.timer 2>/dev/null | head -n1 | LC_ALL=C tr -cd 'a-z-')" || true
    [ -n "$timer" ] || timer="not-found"

    printf '{"ok":true,"enabled":%s,"kind":%s,"target":%s,"port":%s,"keep":%s,"conf_error":%s,' \
        "$enabled" "$( [ -n "$kind" ] && json_str "$kind" || echo null)" \
        "$( [ -n "$target" ] && json_str "$target" || echo null)" \
        "${port:-null}" "$keep" \
        "$( [ -n "$conf_error" ] && json_str "$(clean "$conf_error")" || echo null)"
    printf '"public_key":%s,"host_key_pinned":%s,"last_result":%s,' \
        "$( [ -n "$pk" ] && json_str "$pk" || echo null)" "$pinned" "$last"
    printf '"local":{"dir":%s,"count":%s,"newest":%s,"newest_time":%s,"timer":%s}}\n' \
        "$(json_str "$LOCAL_DIR")" "$count" \
        "$( [ -n "$newest" ] && json_str "$newest" || echo null)" \
        "$( [ -n "$newest_time" ] && json_str "$newest_time" || echo null)" \
        "$(json_str "$timer")"
}

do_keygen() {
    ensure_state_dir
    if [ ! -s "$KEY" ] || [ ! -s "$KEY.pub" ]; then
        rm -f -- "$KEY" "$KEY.pub"
        as_backup_user ssh-keygen -q -t ed25519 -N '' -C "$KEY_COMMENT" -f "$KEY" >/dev/null 2>&1 \
            || return 1
    fi
    public_key >/dev/null
}

cmd_keygen() {
    do_keygen || fail "could not create the backup key pair in $STATE_DIR"
    printf '{"ok":true,"public_key":%s}\n' "$(json_str "$(public_key)")"
}

cmd_set() {
    local line n=0 key val kind="" target="" keep="" port="" seen=" "
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        [ "$n" -le 8 ] || fail "too many input lines"
        [ -n "$line" ] || continue
        key="${line%%=*}"
        val="${line#*=}"
        case "$key" in
            kind|target|keep|port) ;;
            *) fail "unrecognised input on line $n (expected kind=, target=, keep= or port=)" ;;
        esac
        [ "$key" != "$line" ] || fail "input line $n is not key=value"
        case "$seen" in *" $key "*) fail "'$key' given twice" ;; esac
        seen="$seen$key "
        case "$key" in
            kind) kind="$val" ;;
            target) target="$val" ;;
            keep) keep="$val" ;;
            port) port="$val" ;;
        esac
    done
    [ -n "$keep" ] || keep="$DEFAULT_KEEP"
    local why
    why="$(validate_setting "$kind" "$target" "$keep" "$port")" || fail "$why"
    keep="$((10#$keep))"
    # The nightly run records its outcome here, as the backup user, whatever the kind.
    ensure_state_dir

    if [ "$kind" = local ]; then
        why="$(check_local_dest "$target")" || fail "$why"
    else
        split_ssh_target "$target"
        port="$((10#${port:-22}))"
        do_keygen || fail "could not create the backup key pair in $STATE_DIR"
        # A different server forgets the old pin; the next `test` pins the new one. The same
        # server keeps its pin, so a changed key there is still caught.
        local old_host="" old_port=""
        if load_conf && [ "$C_KIND" = ssh ]; then old_host="$SSH_HOST" old_port="$C_PORT"; fi
        split_ssh_target "$target"
        if [ "$old_host" != "$SSH_HOST" ] || [ "$old_port" != "$port" ]; then
            rm -f -- "$KNOWN_HOSTS" "$KNOWN_HOSTS.old"
        fi
    fi
    write_conf "$kind" "$target" "$keep" "$port"
    printf '{"ok":true,"message":%s}\n' "$(json_str "off-node backups set to $kind $target (keep $keep)")"
}

cmd_disable() {
    rm -f -- "$CONF"
    printf '{"ok":true,"message":"off-node backups disabled; nightly backups stay on this node only"}\n'
}

cmd_test() {
    load_conf || fail "${C_ERROR:-off-node backups are not configured}"
    if [ "$C_KIND" = local ]; then
        local why probe
        why="$(check_local_dest "$C_TARGET")" || fail "$why"
        probe="$(as_backup_user mktemp "$C_TARGET/.ghost-backup-probe.XXXXXX" 2>&1)" \
            || fail "could not write a probe file in $C_TARGET: $probe"
        as_backup_user rm -f -- "$probe" 2>&1 || fail "wrote $probe but could not remove it"
        printf '{"ok":true,"message":%s}\n' "$(json_str "wrote and removed a probe file in $C_TARGET")"
        return 0
    fi

    [ -s "$KEY" ] || fail "no backup key yet: generate one first"
    ensure_state_dir
    local probe batch name
    probe="$(as_backup_user mktemp "$STATE_DIR/probe.XXXXXX")" || fail "cannot create a probe file in $STATE_DIR"
    name=".ghost-backup-probe-$(date +%s)-$$"
    batch="$(as_backup_user mktemp "$STATE_DIR/batch.XXXXXX")" || { rm -f -- "$probe"; fail "cannot create a batch file"; }
    printf 'put %s %s/%s\nrm %s/%s\n' "$probe" "$SSH_PATH" "$name" "$SSH_PATH" "$name" > "$batch"
    # accept-new: the FIRST successful contact pins the host key; a changed key is still refused.
    if run_sftp_as_backup_user accept-new "$batch"; then
        rm -f -- "$probe" "$batch"
        printf '{"ok":true,"message":%s}\n' \
            "$(json_str "wrote and removed a probe file at $C_TARGET; host key pinned")"
        return 0
    fi
    rm -f -- "$probe" "$batch"
    fail "$(sftp_error)"
}

# run_sftp, as the backup user when the helper is root (the dashboard's `test`).
run_sftp_as_backup_user() {
    if i_am_backup_user || [ "$(id -u)" -ne 0 ]; then
        run_sftp "$@"
        return $?
    fi
    local strict="$1" batch="$2"
    SFTP_OUT="$(cd / && runuser -u "$BACKUP_USER" -- env \
        GHOST_BACKUP_CONF="$CONF" GHOST_BACKUP_STATE_DIR="$STATE_DIR" \
        "$0" _sftp "$strict" "$batch" 2>&1)"
}

# Internal: re-entered as the backup user by run_sftp_as_backup_user.
cmd__sftp() {
    load_conf || { echo "${C_ERROR:-not configured}"; exit 1; }
    run_sftp "$1" "$2" || { sftp_error; exit 1; }
}

record_status() {
    local result="$1" err="$2" files="$3" tmp
    [ -d "$STATE_DIR" ] && [ -w "$STATE_DIR" ] || { echo "WARN: cannot record status in $STATE_DIR" >&2; return 0; }
    tmp="$(mktemp "$STATUS.XXXXXX")" || return 0
    {
        echo "last_offsite_result=$result"
        echo "last_offsite_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "last_offsite_error=$(clean "$err")"
        echo "last_offsite_files=$(clean "$files")"
        echo "last_offsite_kind=$C_KIND"
        echo "last_offsite_target=$C_TARGET"
    } > "$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$STATUS"
}

push_failed() {
    record_status failed "$1" "$PUSH_NAMES"
    fail "$1"
}

# The names to delete so that only the newest `keep` of each database remain. Never the names this
# run just copied.
prune_victims() {
    local keep="$1" listing="$2" prefix_re
    for prefix_re in '^ghost-[0-9]{12}\.db\.gz$' '^ghost-pay-[0-9]{12}\.db\.gz$'; do
        printf '%s\n' "$listing" | /usr/bin/grep -E "$prefix_re" | sort -r | awk -v keep="$keep" 'NR > keep' || true
    done | while IFS= read -r v; do
        case " $PUSH_NAMES " in *" $v "*) continue ;; esac
        if [ -n "$v" ]; then printf '%s\n' "$v"; fi
    done
    return 0
}

PUSH_NAMES=""
cmd_push() {
    [ "$(id -u)" -ne 0 ] || fail "push refuses to run as root; it runs as the backup user from backup-databases.sh"
    if [ "${1:-}" = "--deadline" ]; then
        [[ "${2:-}" =~ ^[0-9]{1,6}$ ]] || usage
        DEADLINE_AT=$(( $(date +%s) + 10#$2 ))
        shift 2
    fi
    [ "$#" -ge 1 ] || usage
    if [ ! -e "$CONF" ]; then
        printf '{"ok":true,"message":"off-node backups are not configured; nothing to do"}\n'
        return 0
    fi
    load_conf || { record_status failed "$C_ERROR" ""; fail "$C_ERROR"; }

    local f name total_kb=0
    for f in "$@"; do
        name="${f##*/}"
        [[ "$name" =~ $BACKUP_NAME_RE ]] || push_failed "refusing to copy '$name': not a backup this job writes"
        [ -f "$f" ] || push_failed "no such backup: $f"
        PUSH_NAMES="${PUSH_NAMES:+$PUSH_NAMES }$name"
        total_kb=$((total_kb + $(du -k -- "$f" | cut -f1)))
    done

    local victims="" v
    if [ "$C_KIND" = local ]; then
        local why avail left dest
        why="$(check_local_dest "$C_TARGET")" || push_failed "$why"
        # ⛔ Refuse rather than fill, as the local backup does.
        avail="$(df -Pk -- "$C_TARGET" | awk 'NR==2{print $4}')"
        [[ "$avail" =~ ^[0-9]+$ ]] || push_failed "cannot read free space on $C_TARGET"
        if [ "$avail" -lt $((total_kb + HEADROOM_KB)) ]; then
            push_failed "refusing to fill $C_TARGET: need $((total_kb + HEADROOM_KB))KB free (the copies plus ${HEADROOM_KB}KB), have ${avail}KB"
        fi
        for f in "$@"; do
            name="${f##*/}"
            dest="$C_TARGET/.$name.partial"
            left="$(remaining)" || push_failed "deadline reached while copying"
            if ! timeout "$left" cp -- "$f" "$dest" 2>/dev/null; then
                rm -f -- "$dest"
                push_failed "copying $name to $C_TARGET failed"
            fi
            if [ "$(stat -c %s -- "$dest")" != "$(stat -c %s -- "$f")" ]; then
                rm -f -- "$dest"
                push_failed "the copy of $name at $C_TARGET is not the same size as the original"
            fi
            mv -f -- "$dest" "$C_TARGET/$name"
        done
        victims="$(prune_victims "$C_KEEP" "$(ls -1A -- "$C_TARGET")")"
        while IFS= read -r v; do
            [ -n "$v" ] || continue
            rm -f -- "$C_TARGET/$v"
        done <<< "$victims"
    else
        [ -s "$KEY" ] || push_failed "no backup key: generate one and add it to the server"
        host_key_pinned "$SSH_HOST" "$C_PORT" \
            || push_failed "the host key for $SSH_HOST is not pinned yet: run Test once to pin it"
        local batch
        batch="$(mktemp "$STATE_DIR/batch.XXXXXX")"
        : > "$batch"
        for f in "$@"; do
            name="${f##*/}"
            {
                echo "put $f $SSH_PATH/.$name.partial"
                echo "-rm $SSH_PATH/$name"
                echo "rename $SSH_PATH/.$name.partial $SSH_PATH/$name"
            } >> "$batch"
        done
        run_sftp yes "$batch" || { rm -f -- "$batch"; push_failed "$(sftp_error)"; }
        echo "ls -1 $SSH_PATH" > "$batch"
        run_sftp yes "$batch" || { rm -f -- "$batch"; push_failed "copied, but listing $SSH_PATH for the prune failed: $(sftp_error)"; }
        local listing
        listing="$(printf '%s\n' "$SFTP_OUT" | /usr/bin/grep -v '^sftp> ' | sed 's|.*/||' || true)"
        victims="$(prune_victims "$C_KEEP" "$listing")"
        if [ -n "$victims" ]; then
            : > "$batch"
            while IFS= read -r v; do
                if [ -n "$v" ]; then echo "rm $SSH_PATH/$v" >> "$batch"; fi
            done <<< "$victims"
            run_sftp yes "$batch" || { rm -f -- "$batch"; push_failed "copied, but pruning $SSH_PATH failed: $(sftp_error)"; }
        fi
        rm -f -- "$batch"
    fi

    local pruned
    pruned="$(printf '%s' "$victims" | /usr/bin/grep -c . || true)"
    record_status ok "" "$PUSH_NAMES"
    printf '{"ok":true,"message":%s}\n' \
        "$(json_str "copied $PUSH_NAMES to $C_KIND $C_TARGET; pruned $pruned old copy(ies), keeping $C_KEEP")"
}

case "${1:-}" in
    show)    [ "$#" -eq 1 ] || usage; cmd_show ;;
    set)     [ "$#" -eq 1 ] || usage; cmd_set ;;
    disable) [ "$#" -eq 1 ] || usage; cmd_disable ;;
    keygen)  [ "$#" -eq 1 ] || usage; cmd_keygen ;;
    test)    [ "$#" -eq 1 ] || usage; cmd_test ;;
    push)    shift; cmd_push "$@" ;;
    _sftp)   [ "$#" -eq 3 ] || usage; cmd__sftp "$2" "$3" ;;
    *) usage ;;
esac
GHOST_BACKUP_OFFSITE_SH_EOF
chmod 755 /opt/ghost/bin/ghost-backup-offsite
chown root:root /opt/ghost/bin/ghost-backup-offsite

# Sudoers scope: five exact argvs, no wildcard; settings travel on stdin as data.
# Canonical source: scripts/ghost-backup-offsite.sudoers.
cat > /etc/sudoers.d/ghost-backup-offsite <<'GHOST_BACKUP_OFFSITE_SUDOERS_EOF'
# Bitcoin Ghost — node-dashboard off-node backup setting (#1016).
#
# Grants the dashboard service user (ghost) the five subcommands of the off-node backup helper,
# each pinned to its EXACT argv, and nothing else:
#     sudo /opt/ghost/bin/ghost-backup-offsite show
#     sudo /opt/ghost/bin/ghost-backup-offsite set        (settings arrive on stdin, as data)
#     sudo /opt/ghost/bin/ghost-backup-offsite disable
#     sudo /opt/ghost/bin/ghost-backup-offsite keygen
#     sudo /opt/ghost/bin/ghost-backup-offsite test
# No wildcard: any extra argument is rejected by sudo. `push` is deliberately absent; the nightly
# job runs it as ghost, without sudo. The helper is root-owned 0755, so the dashboard user cannot
# rewrite what runs as root.
#
# Installed 0440 at /etc/sudoers.d/ghost-backup-offsite; validated with `visudo -cf`.
Defaults!/opt/ghost/bin/ghost-backup-offsite !requiretty
ghost ALL=(root) NOPASSWD: /opt/ghost/bin/ghost-backup-offsite show, /opt/ghost/bin/ghost-backup-offsite set, /opt/ghost/bin/ghost-backup-offsite disable, /opt/ghost/bin/ghost-backup-offsite keygen, /opt/ghost/bin/ghost-backup-offsite test
GHOST_BACKUP_OFFSITE_SUDOERS_EOF
chmod 440 /etc/sudoers.d/ghost-backup-offsite
chown root:root /etc/sudoers.d/ghost-backup-offsite
if ! visudo -cf /etc/sudoers.d/ghost-backup-offsite >/dev/null 2>&1; then
  rm -f /etc/sudoers.d/ghost-backup-offsite
  log "WARNING: generated sudoers file failed validation — removed it (dashboard off-node backup setting disabled)"
fi

# systemd units (service + 6h randomised timer).
cat > /etc/systemd/system/ghost-auto-update.service <<'GHOST_AUTOUPDATE_SERVICE_EOF'
[Unit]
Description=Bitcoin Ghost opt-in node auto-update (verifies GPG signature before applying)
Documentation=https://get.bitcoinghost.org
# Only meaningful once the node is up; never block boot on it.
After=network-online.target ghostd.service ghost-mining.service
Wants=network-online.target

[Service]
Type=oneshot
# The script itself is a no-op unless /etc/ghost/auto-update.conf opts in.
ExecStart=/opt/ghost/bin/ghost-auto-update.sh
# Verification, binary swap, and systemctl control all require root.
User=root
# Never tie the result of a periodic check to a "failed" unit dashboard.
SuccessExitStatus=0
GHOST_AUTOUPDATE_SERVICE_EOF
cat > /etc/systemd/system/ghost-auto-update.timer <<'GHOST_AUTOUPDATE_TIMER_EOF'
[Unit]
Description=Bitcoin Ghost opt-in node auto-update (every 6h, randomised)
Documentation=https://get.bitcoinghost.org

[Timer]
# First check shortly after boot, then every 6 hours.
OnBootSec=15min
OnUnitActiveSec=6h
# Spread fleet load / avoid a thundering herd on the release host.
RandomizedDelaySec=1h
# Catch up a missed window (e.g. the node was off) on next boot.
Persistent=true
Unit=ghost-auto-update.service

[Install]
WantedBy=timers.target
GHOST_AUTOUPDATE_TIMER_EOF

# The release channel marker. ghost-auto-update.sh follows the np- releases ONLY when this says
# `node-pool`; without it a node keeps the old network's `releases/latest`. Written before the
# opt-in and the timer, so the updater can never run on this node without it. Its own file, not a
# line in auto-update.conf: the dashboard's toggle rewrites that file whole.
cat > /etc/ghost/release-channel <<'GHOST_RELEASE_CHANNEL_EOF'
# Bitcoin Ghost release channel. Written by the node pool installer; read by ghost-auto-update.sh.
# node-pool: follow the np-vX.Y.Z releases only, never the old network's releases/latest.
node-pool
GHOST_RELEASE_CHANNEL_EOF
chmod 644 /etc/ghost/release-channel
chown root:root /etc/ghost/release-channel

# Opt-in config (world-readable so the dashboard can show the current state;
# only root, or the scoped toggle via sudo, can write it).
cat > /etc/ghost/auto-update.conf <<EOF
# Bitcoin Ghost node auto-update opt-in.
# Managed by the installer and the node dashboard (ghost-autoupdate-toggle).
# When AUTO_UPDATE is anything other than exactly 'true', the updater is a no-op.
AUTO_UPDATE=${AUTO_UPDATE}
EOF
chmod 644 /etc/ghost/auto-update.conf
chown root:root /etc/ghost/auto-update.conf

# Baseline installed-version marker the updater compares against.
echo "${GHOST_VERSION}" > /etc/ghost/version
chmod 644 /etc/ghost/version
chown root:root /etc/ghost/version

# ⛔ TEST ONLY: a node installed from a test release mirror updates from the same mirror, against the
# same throwaway key. Any other install removes the drop-in, so re-running the installer normally
# puts the node back on real releases and the release key.
TEST_MIRROR_DROPIN=/etc/systemd/system/ghost-auto-update.service.d/test-release-mirror.conf
if [[ -n "$TEST_RELEASE_MIRROR" ]]; then
  install -d -m 0755 /etc/systemd/system/ghost-auto-update.service.d
  cat > "$TEST_MIRROR_DROPIN" <<EOF
# ⛔ TEST RELEASE MIRROR, written by install-node.sh (GHOST_TEST_RELEASE_MIRROR). This node does not
# follow real releases. Re-run the installer without GHOST_TEST_RELEASE_MIRROR to remove it.
[Service]
Environment=GHOST_NP_RELEASES_API_URL=${NP_RELEASES_API_URL}
Environment=GHOST_RELEASE_DOWNLOAD_URL=${RELEASE_DOWNLOAD_URL}
Environment=GHOST_RELEASE_KEY_URL=${RELEASE_KEY_URL}
Environment=GHOST_GPG_KEY_FP=${GPG_KEY_FP}
EOF
  chmod 644 "$TEST_MIRROR_DROPIN"
else
  rm -f "$TEST_MIRROR_DROPIN"
fi

systemctl daemon-reload >/dev/null 2>&1 || true
# Enable + start the timer ONLY when opted in. Default path: timer stays
# installed-but-inactive, so the node can never self-upgrade.
if [[ "$AUTO_UPDATE" == "true" ]]; then
  systemctl enable --now ghost-auto-update.timer >/dev/null 2>&1 || true
  log "auto-update ENABLED — checking for signed Ghost Pool (np-) releases every 6h"
else
  systemctl disable --now ghost-auto-update.timer >/dev/null 2>&1 || true
  log "auto-update disabled (default) — node will not self-upgrade"
fi

# ───────────────────── nightly database backups (#1016) ──────────────────────
# The same nightly job the fleet runs: a gzipped `VACUUM INTO` copy of the node database at
# 03:00 UTC, kept 7 days, refusing rather than filling the disk. Installed on every node so it can
# be switched on later; ENABLED only with BACKUPS=true (the default; --no-backups turns it off).
# Off-node copies stay a separate, optional setting (ghost-backup-offsite, the node dashboard).
install -d -m 0755 -o root -g root /opt/ghost/scripts /opt/ghost/scripts/lib
# Canonical source: scripts/backup-databases.sh.
cat > /opt/ghost/scripts/backup-databases.sh <<'BACKUP_DATABASES_SH_EOF'
#!/usr/bin/env bash
# backup-databases.sh — Automated backup for ghost.db and ghost-pay.db
#
# Gzipped `VACUUM INTO` copies into /var/backups/ghost/db, pruned by BOTH age and count.
# Logs to syslog. Usage: backup-databases.sh [--ghost-dir /home/ghost/.ghost]
#
# ⛔ Run as the database's OWNER, not as root. The databases are WAL mode with `ghost:ghost` 0600
# sidecars, and sqlite3 opens the source read-write. Under the systemd unit this is fine
# because it sets `User=ghost`; a hand-run under sudo that has to recreate `-wal` or `-shm` leaves
# them ROOT-owned, after which the `ghost` user cannot open its own database for writing. The pool
# wedges and it reads as corruption. The guard below refuses rather than relying on anyone
# remembering that.
#
# ⛔ It refuses when there is no room, instead of writing until the filesystem says no. The old
# version did the latter, which on a node near full produced a failed backup AND a full root
# filesystem — the second of which takes the node down and has nothing to do with backups.
#
# ## The sizing this is built around
#
# MEASURED on the fleet 2026-10-04/05: ghost.db is 2.4–2.7 GB, and free space is
#
#     vm1 24,665M   vm2 26,639M   vm3 26,683M   vm4 26,495M
#     vm5 24,172M   vm6 24,004M   vm7 24,313M   vm8 12,217M
#
# Seven daily UNCOMPRESSED copies is 18.2 GB. That fills vm8 in about four days and leaves vm1–vm7
# with 6–9 GB, on nodes whose database grows and whose `optimize` path can still want twice the
# database free. This is why the file is gzipped: the two ceremony snapshots already on every node
# compress 2.6 GB to 788 MB and 901 MB, about 3x, so seven of them is ~6 GB and fits everywhere.

set -euo pipefail

GHOST_DIR="${1:-/home/ghost/.ghost}"
BACKUP_DIR="/var/backups/ghost/db"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
KEEP_COUNT="${BACKUP_KEEP_COUNT:-7}"
# OPTIONAL off-node copy (#1016). Absent file = off, and the run is exactly what it was before.
OFFSITE_CONF="${BACKUP_OFFSITE_CONF:-/etc/ghost/backup.conf}"
# The off-node copy must finish inside the unit's TimeoutStartSec=1800, or systemd stops the whole
# run and reports a local backup that succeeded as failed. Seconds since this script started.
OFFSITE_DEADLINE="${BACKUP_OFFSITE_DEADLINE:-1620}"
TIMESTAMP="$(date +%Y%m%d%H%M)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/backup-retention.sh
. "$SCRIPT_DIR/lib/backup-retention.sh"

log() {
    logger -t ghost-backup "$1"
    echo "[$(date -Iseconds)] $1"
}

die() {
    log "ERROR: $1"
    exit 1
}

# ⛔ An ERR trap, because `set -e` aborts without a word: a failure in a command substitution or a
# pipeline leaves the unit "failed" with the last log line being whatever succeeded before it, which
# reads as a backup that worked and then stopped for no reason.
trap 'rc=$?; [ "$rc" -ne 0 ] && log "ERROR: aborted at line $LINENO with status $rc"; exit $rc' ERR

if [ "$(id -u)" -eq 0 ]; then
    die "refusing to run as root. The databases are WAL mode with ghost-owned 0600 sidecars, and a
root-run sqlite3 that recreates -wal or -shm leaves them root-owned, after which the ghost user
cannot write its own database. Run as the owning user (the systemd unit sets User=ghost)."
fi

# The live database is 0600. Its copies should not be readable by anyone who could not read it.
umask 077

mkdir -p "$BACKUP_DIR"

# The uncompressed copy in flight, if any. Removed on EVERY exit path — `die`, the ERR trap, and a
# `systemctl stop` or start timeout, which arrive as SIGTERM.
PARTIAL=""
discard_copy() {
    rm -f -- "$1" "$1-wal" "$1-shm" "$1-journal"
}
cleanup_partial() {
    [ -n "$PARTIAL" ] || return 0
    discard_copy "$PARTIAL"
    log "removed the incomplete copy at $PARTIAL"
    PARTIAL=""
}
trap cleanup_partial EXIT
trap 'cleanup_partial; exit 143' TERM INT

# Back up one database: check there is room, copy, compress, verify the copy opens.
backup_one() {
    local label="$1" src="$2" prefix="$3"
    if [ ! -f "$src" ]; then
        log "WARN: $label not found at $src, skipping"
        return 0
    fi

    local db_kb avail_kb verdict
    db_kb="$(du -k "$src" | cut -f1)"
    # ⛔ `df -Pk` prints a header, so the available column is taken with NR==2. Guessing a field
    # offset off the whole output picks the header's "Capacity" string.
    avail_kb="$(df -Pk "$BACKUP_DIR" | awk 'NR==2{print $4}')"

    if ! verdict="$(backup_space_verdict "$db_kb" "$avail_kb")"; then
        die "$label: $verdict — need $(echo "$verdict" | awk '{print $2}')KB free under $BACKUP_DIR,
have $(echo "$verdict" | awk '{print $3}')KB. Refusing: filling the root filesystem to take a
backup takes the node down for a reason unrelated to backups."
    fi
    log "$label: ${db_kb}KB database, $(echo "$verdict" | awk '{print $3}')KB free — proceeding"

    local dest="$BACKUP_DIR/${prefix}-${TIMESTAMP}.db"
    log "$label: backing up to ${dest}.gz"
    # From here until the gzip lands, a failure must not leave the uncompressed copy behind: it is
    # the full size of the database, on a filesystem this script was written to stop filling.
    PARTIAL="$dest"
    # `VACUUM INTO` refuses an existing destination, and a stale one can only be debris.
    discard_copy "$dest"

    # ⛔ `VACUUM INTO`, not `.backup`. The online backup API RESTARTS whenever another connection
    # commits to the source, and the pool commits about 45 times a minute. Whether a pass over
    # 2.4 GB fits between two commits depends on the node: vm5-vm7 got through in under four
    # minutes, and on vm8 the same command sat at 84% of a CPU for 23 minutes with the destination
    # fixed at 2,247,475,200 bytes until it was stopped by hand (#1009). `VACUUM INTO` reads inside
    # ONE transaction, so a writer cannot restart it — on vm8 it finished in 11 seconds.
    sqlite3 "$src" "VACUUM INTO '$dest'" || die "$label: sqlite3 VACUUM INTO failed"

    # Verify BEFORE compressing, while it is still a database. A truncated file is still a file, and
    # a gzip of one is still a valid gzip — the kind of backup whose problem surfaces at restore.
    local ver
    ver="$(sqlite3 "file:$dest?mode=ro" 'PRAGMA user_version;' 2>/dev/null)" \
        || die "$label: the copy at $dest does not open as a database"
    # From v65 the version is stored negated (`-65`); either sign is a version.
    case "${ver#-}" in
        ''|*[!0-9]*) die "$label: the copy at $dest reports user_version='$ver'" ;;
    esac
    local integ
    integ="$(sqlite3 "file:$dest?mode=ro" 'PRAGMA quick_check;' 2>/dev/null)"
    [ "$integ" = "ok" ] || die "$label: quick_check on $dest said '$integ'"

    gzip -f "$dest" || die "$label: gzip failed"
    PARTIAL=""
    # Verifying a copy can leave `-wal`/`-shm` beside it. Nothing prunes those — retention matches
    # `*.db.gz` only — so one pair per night would stay for ever.
    rm -f -- "$dest-wal" "$dest-shm" "$dest-journal"
    log "$label: complete — $(du -h "${dest}.gz" | cut -f1) compressed from ${db_kb}KB, user_version=$ver, quick_check=ok"
}

# Each database on its own, so one that cannot be copied does not take the others — or the prune
# below — down with it. vm1-vm4 carry a `ghost-pay.db` that plain sqlite3 cannot open at all
# ("file is not a database": it is encrypted, and its service is retired). When that aborted the
# whole run, `ghost.db` had been copied but nothing was ever pruned, on every night, for ever.
#
# The run still FAILS if any database was not backed up, and says which. Carrying on is not the
# same as calling it a success.
#
# ⛔ The subshell is deliberately not written `( ... ) || rc=$?` or `if ! ( ... )`. Either puts it
# in a condition context, where bash ignores `set -e` for everything inside, and `backup_one`
# relies on it. So the ERR trap is lifted, errexit is suspended out here, and re-armed in there.
FAILED=""
backup_isolated() {
    local rc
    trap - ERR
    set +e
    (
        set -e
        trap cleanup_partial EXIT
        trap 'cleanup_partial; exit 143' TERM INT
        backup_one "$@"
    )
    rc=$?
    set -e
    trap 'rc=$?; [ "$rc" -ne 0 ] && log "ERROR: aborted at line $LINENO with status $rc"; exit $rc' ERR
    # Stopped, not failed: do not carry on to the next database after a SIGTERM.
    [ "$rc" -ne 143 ] || exit 143
    [ "$rc" -eq 0 ] || FAILED="$FAILED $1"
}

backup_isolated "ghost.db"     "$GHOST_DIR/ghost.db"                  "ghost"
backup_isolated "ghost-pay.db" "$GHOST_DIR/ghost-pay/ghost-pay.db"    "ghost-pay"

# Prune. Per prefix, so a missing ghost-pay.db cannot let ghost.db copies count towards its quota.
#
# ⛔ Both rules must condemn a file: older than RETENTION_DAYS *and* not among the newest
# KEEP_COUNT. Age alone was the whole policy and age alone has no bound on COUNT — a node that was
# off and caught up through `Persistent=true` holds any number of same-day copies, none old enough
# to prune, and the disk fills. The count rule alone would delete a copy that is the only recent one
# as soon as an eighth appears the same day. See scripts/test-backup-retention.sh.
for prefix in ghost ghost-pay; do
    listing=""
    for f in "$BACKUP_DIR/${prefix}-"*.db.gz; do
        [ -e "$f" ] || continue
        listing="${listing}$(stat -c '%Y' "$f") $f
"
    done
    [ -n "$listing" ] || continue

    pruned=0
    while IFS= read -r victim; do
        [ -n "$victim" ] || continue
        rm -f -- "$victim" && pruned=$((pruned + 1))
    done < <(backup_prune_list "$KEEP_COUNT" "$RETENTION_DAYS" "$(date +%s)" "$listing")
    [ "$pruned" -gt 0 ] && log "$prefix: pruned $pruned backup(s) (older than ${RETENTION_DAYS}d and beyond the newest ${KEEP_COUNT})"
done

log "Backup complete. Current backups:"
# ⛔ Report a COUNT, positively. `ls | while read` printed nothing when there were no backups, which
# is the same output as a successful run whose files had all just been pruned.
found=0
for f in "$BACKUP_DIR"/ghost*.db.gz; do
    [ -e "$f" ] || continue
    found=$((found + 1))
    log "  $(ls -lh "$f" | awk '{print $5, $9}')"
done
log "  $found backup file(s) in $BACKUP_DIR, $(df -Pk "$BACKUP_DIR" | awk 'NR==2{print $4}')KB free"
[ "$found" -gt 0 ] || die "no backup files present after a run that reported success"

# ---------------------------------------------------------------- optional off-node copy (#1016)
#
# Only when /etc/ghost/backup.conf exists. Nothing in this block can fail or undo the local backup
# above: the helper runs with errexit and the ERR trap lifted, its exit status is LOGGED and never
# returned, and it records its own outcome where the dashboard reads it (`last_offsite_result`). The
# run's exit status below is decided by the local backup alone.
offsite_copy() {
    local helper="${BACKUP_OFFSITE_HELPER:-$SCRIPT_DIR/ghost-backup-offsite.sh}"
    local files=() prefix f budget out rc
    # This run's copies only. An older file was already sent, or failed and will be superseded.
    for prefix in ghost ghost-pay; do
        f="$BACKUP_DIR/${prefix}-${TIMESTAMP}.db.gz"
        if [ -f "$f" ]; then files+=("$f"); fi
    done
    if [ "${#files[@]}" -eq 0 ]; then
        log "off-node: configured, but this run produced no backup to copy"
        return 0
    fi
    if [ ! -x "$helper" ]; then
        log "WARN: off-node: $OFFSITE_CONF is present but the helper $helper is not — nothing copied"
        return 0
    fi
    budget=$((OFFSITE_DEADLINE - SECONDS))
    if [ "$budget" -lt 60 ]; then
        log "WARN: off-node: only ${budget}s left before the unit's timeout — not starting a copy"
        return 0
    fi
    log "off-node: copying ${#files[@]} file(s), ${budget}s allowed"
    out="$(GHOST_BACKUP_CONF="$OFFSITE_CONF" GHOST_BACKUP_DIR="$BACKUP_DIR" \
           GHOST_BACKUP_GHOST_DIR="$GHOST_DIR" \
           timeout --kill-after=10 $((budget + 30)) "$helper" push --deadline "$budget" "${files[@]}" 2>&1)"
    rc=$?
    log "off-node: $out"
    if [ "$rc" -eq 0 ]; then
        log "off-node: copy complete"
    else
        log "WARN: off-node copy FAILED (exit $rc) — the local backup above is complete and unaffected"
    fi
    return 0
}

if [ -e "$OFFSITE_CONF" ]; then
    trap - ERR
    set +e
    offsite_copy
    set -e
    trap 'rc=$?; [ "$rc" -ne 0 ] && log "ERROR: aborted at line $LINENO with status $rc"; exit $rc' ERR
fi

# The verdict, last, so it is the final line anyone reads in the journal.
[ -z "$FAILED" ] || die "NOT backed up:$FAILED — every other database above was copied and pruned normally"

exit 0
BACKUP_DATABASES_SH_EOF
# Canonical source: scripts/lib/backup-retention.sh.
cat > /opt/ghost/scripts/lib/backup-retention.sh <<'BACKUP_RETENTION_SH_EOF'
#!/usr/bin/env bash
#
# The sizing and retention decisions for scripts/backup-databases.sh (#996).
#
# ## Why this is a separate file
#
# Both decisions are arithmetic over a handful of numbers, and both are the kind of arithmetic that
# is wrong in a way nothing notices until a disk is full. They are driven directly by
# scripts/test-backup-retention.sh rather than by running a backup, which would need a 2.6 GB
# database to be interesting.
#
# ## The numbers these exist to respect
#
# MEASURED on the fleet 2026-10-04/05. Database 2.4–2.7 GB; free space:
#
#     vm1 24,665M   vm2 26,639M   vm3 26,683M   vm4 26,495M
#     vm5 24,172M   vm6 24,004M   vm7 24,313M   vm8 12,217M
#
# Seven daily UNCOMPRESSED copies is 18.2 GB, which fills vm8 in about four days and leaves vm1–vm7
# with 6–9 GB on a node whose `optimize` path can still want twice the database free. Gzip is the
# established shape here — the two ceremony snapshots on every node are already gzipped, at 788 MB
# and 901 MB against 2.6 GB raw, so about 3x. Seven of those is ~6 GB and fits everywhere.

# Decide whether there is room to take a backup.
#
# Usage: backup_space_verdict <db_kb> <avail_kb>
#
# A backup needs the FULL uncompressed size transiently — `.backup` writes a plain copy and gzip
# then reads it — plus headroom, so this asks for the database size plus a margin rather than the
# compressed size it will settle at. Prints one verdict and returns 0 to proceed, 1 to refuse:
#
#   OK <need_kb> <avail_kb>
#   REFUSE_SPACE <need_kb> <avail_kb>
#   REFUSE_PARSE <field> <value>
#
# ⛔ Refusing is the behaviour that was missing. `sqlite3 .backup` writes until it cannot and then
# fails, so on a node near full the old script produced a failed backup AND a full root filesystem —
# the second of which takes the node down and has nothing to do with backups.
BACKUP_HEADROOM_KB=${BACKUP_HEADROOM_KB:-1048576}   # 1 GiB

backup_space_verdict() {
    local db_kb="${1:-}" avail_kb="${2:-}"
    local field
    # Each field separately. Concatenating them and testing `*[!0-9]*` makes an EMPTY field
    # invisible whenever the others are numeric, which is how a probe that answered nothing reads
    # as a probe that answered fine.
    for field in "db_kb:${db_kb}" "avail_kb:${avail_kb}"; do
        case "${field#*:}" in
            ''|*[!0-9]*) echo "REFUSE_PARSE ${field%%:*} ${field#*:}"; return 1 ;;
        esac
    done

    local need_kb=$((db_kb + BACKUP_HEADROOM_KB))
    if [ "$avail_kb" -lt "$need_kb" ]; then
        echo "REFUSE_SPACE $need_kb $avail_kb"
        return 1
    fi
    echo "OK $need_kb $avail_kb"
    return 0
}

# Choose which backups to delete.
#
# Usage: backup_prune_list <keep_count> <retention_days> <now_epoch> <listing>
#
# `listing` is one `<epoch> <path>` line per existing backup, any order. Prints the paths to delete,
# newest-surviving-first order not guaranteed. Returns 0 always: "nothing to prune" is an answer.
#
# Two rules, and a file is deleted only when BOTH agree it may go:
#
#   * older than `retention_days`, AND
#   * not among the newest `keep_count`.
#
# ⛔ The age rule alone was the whole policy, and age alone has no bound on COUNT. A node that was
# off and caught up through `Persistent=true` can hold an unlimited number of same-day copies, none
# of which is old enough to prune. The count rule alone is not enough either: it would delete a
# backup that is the only one there is as soon as an eighth appears on the same day.
#
# ⛔ And the newest is never deleted, whatever the numbers say. A prune that can remove every copy
# is not a retention policy — see the `CONTROL: offset 1` case in test-deploy-gate.sh for the same
# mistake made with binaries.
backup_prune_list() {
    local keep="${1:-}" days="${2:-}" now="${3:-}" listing="${4:-}"
    case "${keep}${days}${now}" in
        ''|*[!0-9]*) echo "REFUSE_PARSE args ${keep}/${days}/${now}" >&2; return 1 ;;
    esac
    [ "$keep" -ge 1 ] || { echo "REFUSE_PARSE keep_count $keep" >&2; return 1; }

    local cutoff=$((now - days * 86400))
    # Newest first, so the line number IS the rank.
    printf '%s\n' "$listing" \
        | /usr/bin/grep -E '^[0-9]+ ' \
        | sort -k1,1nr \
        | awk -v cutoff="$cutoff" -v keep="$keep" '
            NR > keep && $1 < cutoff { $1 = ""; sub(/^ /, ""); print }
          '
}
BACKUP_RETENTION_SH_EOF
chmod 755 /opt/ghost/scripts/backup-databases.sh
chmod 644 /opt/ghost/scripts/lib/backup-retention.sh
# The nightly job looks for the off-node helper next to itself.
install -m 0755 -o root -g root /opt/ghost/bin/ghost-backup-offsite /opt/ghost/scripts/ghost-backup-offsite.sh
# Canonical source: scripts/systemd/ghost-backup.service (read from the fleet, byte for byte).
cat > /etc/systemd/system/ghost-backup.service <<'GHOST_BACKUP_SERVICE_EOF'
[Unit]
Description=Ghost Pool Database Backup
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/ghost/scripts/backup-databases.sh /home/ghost/.ghost
User=ghost
Group=ghost

# ⛔ User=ghost is load-bearing, not tidiness. The databases are WAL mode with ghost-owned 0600
# sidecars and sqlite3 opens the source read-write; a root-run that has to recreate
# -wal or -shm leaves them root-owned, after which the ghost user cannot write its own database.
# backup-databases.sh also refuses to run as root, so these two agree.

# A 2.6 GB read plus gzip competes with the pool for the same disk. Deprioritised so a backup can
# never be the reason a share took too long to credit.
# A healthy run is under four minutes. Type=oneshot has NO start timeout by default, so a copy
# that cannot finish holds a CPU until someone notices — 23 minutes on vm8 before it was stopped
# by hand (#1009). The script removes its partial copy when this fires.
TimeoutStartSec=1800

Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7

[Install]
WantedBy=multi-user.target
GHOST_BACKUP_SERVICE_EOF
# Canonical source: scripts/systemd/ghost-backup.timer.
cat > /etc/systemd/system/ghost-backup.timer <<'GHOST_BACKUP_TIMER_EOF'
[Unit]
Description=Daily Ghost Pool Database Backup

[Timer]
OnCalendar=*-*-* 03:00:00 UTC
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
GHOST_BACKUP_TIMER_EOF
mkdir -p /var/backups/ghost/db
chown ghost:ghost /var/backups/ghost/db
systemctl daemon-reload >/dev/null 2>&1 || true
if [[ "$BACKUPS" == "true" ]]; then
  systemctl enable --now ghost-backup.timer >/dev/null 2>&1 || true
  log "nightly backups ENABLED — 03:00 UTC, kept 7 days in /var/backups/ghost/db"
else
  systemctl disable --now ghost-backup.timer >/dev/null 2>&1 || true
  log "nightly backups disabled (--no-backups) — enable later: systemctl enable --now ghost-backup.timer"
fi

# ─────────────────────── 10b2. what the node pool left behind ───────────────────
# The open-listing lister and the share-chain relay are gone with the share chain. A re-run over a
# node pool install stops and removes the lister's unit and env file (it holds the RPC password);
# its user, its state (/var/lib/ghost-audit) and the relay's store (/var/lib/ghost/node-pool.db)
# are data, kept like the rest until --uninstall --purge.
# >>> NP_LISTER_GONE
if [[ -e /etc/systemd/system/ghost-lister.service || -e /etc/ghost/lister.env ]]; then
  systemctl disable --now ghost-lister.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/ghost-lister.service /etc/ghost/lister.env
  systemctl daemon-reload >/dev/null 2>&1 || true
  log "Removed an older install's open-listing lister (ghost-lister.service, /etc/ghost/lister.env)"
fi
# <<< NP_LISTER_GONE

# ───────────────────────────── 10c. node dashboard ───────────────────────────
# The operator dashboard (dashboard/, a Next.js standalone build) from this release, run by a
# Node.js runtime of its own under /opt/ghost/node. Ubuntu's apt nodejs is 18 on 24.04 and the
# dashboard needs 22 or later, so the official nodejs.org build is used, pinned to one version and
# checked against the SHA-256 below before anything is unpacked. The hash is the one in that
# release's SHASUMS256.txt, whose signature verified against Node.js release key
# 5BE8A3F6C8A5C01D106C0AD820B1A390B168D356 when it was pinned. Bump the version and the hash
# together.
#
# The dashboard listens on 127.0.0.1:3000 only and no firewall rule is opened for it: reach it
# through an SSH tunnel (ssh -L 3000:127.0.0.1:3000 <you>@<node>). Its password is generated here
# once, into /etc/ghost/dashboard.env (root-only), which the unit reads with EnvironmentFile=. Not
# an Environment= line in a drop-in: systemd shows those to every local user (`systemctl show
# ghost-dashboard -p Environment`), and it never shows a file's contents. Kept on a re-run and on
# --uninstall, so the password survives both.
NODEJS_VERSION="v22.23.4"
NODEJS_TARBALL="node-${NODEJS_VERSION}-linux-x64.tar.gz"
NODEJS_SHA256="b8492284c76a54baf58d61668dd0e41ee0fc98adabf9503d30f05d08f55b4406"
NODEJS_URL="https://nodejs.org/dist/${NODEJS_VERSION}/${NODEJS_TARBALL}"
# A test mirror serves the same tarball (the pinned hash still decides), so a rehearsal fetches
# nothing from outside it.
[[ -n "$TEST_RELEASE_MIRROR" ]] && NODEJS_URL="${TEST_RELEASE_MIRROR}/nodejs/${NODEJS_TARBALL}"
DASHBOARD_ENV=/etc/ghost/dashboard.env
DASHBOARD_PW_NOTE=""
if [[ -n "$DASHBOARD_SRC" ]]; then
  log "Installing the node dashboard (Node.js ${NODEJS_VERSION})"
  if [[ "$(/opt/ghost/node/bin/node --version 2>/dev/null || true)" != "$NODEJS_VERSION" ]]; then
    curl -fsSL "$NODEJS_URL" -o "$TMP/$NODEJS_TARBALL" || err "Could not download Node.js from ${NODEJS_URL}."
    echo "${NODEJS_SHA256}  $TMP/$NODEJS_TARBALL" | sha256sum -c - >/dev/null \
      || err "Checksum verification FAILED for ${NODEJS_TARBALL} (expected ${NODEJS_SHA256})."
    rm -rf "/opt/ghost/node-${NODEJS_VERSION}.new"
    mkdir -p "/opt/ghost/node-${NODEJS_VERSION}.new"
    tar -xzf "$TMP/$NODEJS_TARBALL" -C "/opt/ghost/node-${NODEJS_VERSION}.new" --strip-components=1 --no-same-owner
    rm -rf "/opt/ghost/node-${NODEJS_VERSION}"
    mv "/opt/ghost/node-${NODEJS_VERSION}.new" "/opt/ghost/node-${NODEJS_VERSION}"
    ln -sfn "node-${NODEJS_VERSION}" /opt/ghost/node
  fi
  # Runtimes an earlier install pinned, now unused.
  for old in /opt/ghost/node-v*; do
    [[ -d "$old" && "$old" != "/opt/ghost/node-${NODEJS_VERSION}" ]] && rm -rf "$old"
  done
  [[ "$(/opt/ghost/node/bin/node --version 2>/dev/null || true)" == "$NODEJS_VERSION" ]] \
    || err "Node.js ${NODEJS_VERSION} did not install under /opt/ghost/node."

  # The dashboard tree, replaced whole; root-owned, readable by the ghost user that runs it.
  rm -rf /opt/ghost/dashboard.new
  cp -a "$DASHBOARD_SRC" /opt/ghost/dashboard.new
  chown -R root:root /opt/ghost/dashboard.new
  chmod -R go-w,a+rX /opt/ghost/dashboard.new
  rm -rf /opt/ghost/dashboard
  mv /opt/ghost/dashboard.new /opt/ghost/dashboard
  # Next.js writes its cache beside the build.
  install -d -o ghost -g ghost -m 0755 /opt/ghost/dashboard/.next/cache

  # The password. An operator's own DASHBOARD_PASSWORD in a drop-in (the old manual setup) is kept
  # and wins; otherwise one is generated once and kept across re-runs.
  if grep -qsE '^Environment="?DASHBOARD_PASSWORD=' /etc/systemd/system/ghost-dashboard.service.d/*.conf; then
    DASHBOARD_PW_NOTE="your own, set in /etc/systemd/system/ghost-dashboard.service.d/"
  else
    if ! grep -qsE '^DASHBOARD_PASSWORD=.+' "$DASHBOARD_ENV"; then
      ( umask 077
        printf '# Bitcoin Ghost node dashboard. Written once by install-node.sh; read by ghost-dashboard.service.\n# Change the password here, then: sudo systemctl restart ghost-dashboard\nDASHBOARD_PASSWORD=%s\n' \
          "$(openssl rand -hex 16)" > "$DASHBOARD_ENV" )
    fi
    DASHBOARD_PW_NOTE="sudo grep DASHBOARD_PASSWORD ${DASHBOARD_ENV}"
  fi
  [[ -e "$DASHBOARD_ENV" ]] && { chown root:root "$DASHBOARD_ENV"; chmod 600 "$DASHBOARD_ENV"; }

  cat > /etc/systemd/system/ghost-dashboard.service <<'GHOST_DASHBOARD_SERVICE_EOF'
[Unit]
Description=Bitcoin Ghost node dashboard
# Ordering only: the dashboard shows the node as unavailable until ghost-mining answers, and it
# must never start the node ahead of ghost-mining-gate.
After=network-online.target ghost-mining.service
Wants=network-online.target

[Service]
Type=simple
User=ghost
Group=ghost
WorkingDirectory=/opt/ghost/dashboard
# `node server.js`, never `next start`: server.js is the custom server that authenticates the
# /api/ws relay, and the standalone build has no `next start`.
ExecStart=/opt/ghost/node/bin/node server.js
Environment=NODE_ENV=production
Environment=PORT=3000
# Loopback only, no firewall rule: reach it through an SSH tunnel.
Environment=HOSTNAME=127.0.0.1
Environment=NEXT_PUBLIC_API_URL=http://127.0.0.1:8080
# DASHBOARD_PASSWORD, generated by the installer, root-only. INTERNAL_AUTH_KEY comes from the
# internal-auth.conf drop-in, which the installer keeps equal to pool.toml's internal_api_secret.
EnvironmentFile=-/etc/ghost/dashboard.env
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
GHOST_DASHBOARD_SERVICE_EOF
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable ghost-dashboard >/dev/null 2>&1 || true
fi

# ─────────────────────────────── 11. start ───────────────────────────────────
log "Starting services"
systemctl daemon-reload
# A re-run replaced the binaries and rewrote the configs under a running node, which kept running
# the deleted binaries with the old configs until something restarted it. Restart it as a boot
# does: the stratum stack and the node stop, ghostd restarts, and the gate (below) starts the rest
# once ghostd answers.
if [[ "$NODE_WAS_RUNNING" == true ]]; then
  log "Re-run: restarting the node on the new binaries and configs"
  systemctl stop sri-translator sri-pool ghost-mining >/dev/null 2>&1 || true
  systemctl restart ghostd
  systemctl stop ghost-mining-gate >/dev/null 2>&1 || true
fi
systemctl enable --now ghostd >/dev/null 2>&1
# Nothing else is started or enabled here. The gate is the ONLY thing that starts
# ghost-mining and the SV2 stratum stack, once ghostd has left initial block
# download; all three units are installed and left disabled. Starting sri-pool from
# here used to start ghost-mining with it, which put a node at chain height 0 on the
# live mesh seconds into the install (#1020). scripts/test-boot-gate.sh holds this.
systemctl enable --now ghost-mining-gate >/dev/null 2>&1
# The dashboard does not wait for the gate: it shows the node as unavailable until it answers.
# Restarted on a re-run so it runs the tree just installed.
if [[ -n "$DASHBOARD_SRC" ]]; then
  systemctl restart ghost-dashboard >/dev/null 2>&1 || log "WARNING: ghost-dashboard did not start: sudo journalctl -u ghost-dashboard -n 50"
fi
sleep 5

# The Bitcoin node, checked again now that it runs: the preflight could only see one a re-run had
# left behind. ghostd takes a few seconds to open RPC, so this waits up to a minute.
post_chain=""
for _ in $(seq 1 12); do
  post_chain="$(pf_bitcoin_chain)"
  [[ -n "$post_chain" ]] && break
  sleep 5
done
if [[ "$post_chain" == "$(np_core_chain "$NETWORK")" ]]; then
  BITCOIN_CHECK="[PASS] Bitcoin node answers on 127.0.0.1:8332 (chain ${post_chain})"
elif [[ -n "$post_chain" ]]; then
  BITCOIN_CHECK="[FAIL] Bitcoin node on 127.0.0.1:8332 runs chain '${post_chain}', not ${NETWORK}"
else
  BITCOIN_CHECK="[FAIL] Bitcoin node does not answer on 127.0.0.1:8332 yet: sudo journalctl -u ghostd -n 50"
fi
NODE_ID="$(sudo -u ghost /opt/ghost/bin/ghost-mining --config /etc/ghost/pool.toml --show-identity 2>/dev/null | grep -i 'Node ID' | head -1 || true)"
if [[ -n "$DASHBOARD_SRC" ]]; then
  DASHBOARD_STATUS="$(systemctl is-active ghost-dashboard)  http://127.0.0.1:3000 on this machine (ssh -L 3000:127.0.0.1:3000 <you>@${PUBIP}, then open http://localhost:3000)
     Dashboard password: ${DASHBOARD_PW_NOTE}"
else
  DASHBOARD_STATUS="not installed (${GHOST_VERSION} ships no dashboard)"
fi
if [[ -n "$SUBMIT_NODES" ]]; then
  OTHER_NODE="found blocks also go to ${SUBMIT_NODES}$([[ "$SUBMIT_AUTH_READY" == true ]] || echo "  (NO credentials yet: --submit-auth)")"
else
  OTHER_NODE="none (--peer-node <the other node>): found blocks go to this node's ghostd only"
fi
cat <<EOF

  ✅ Ghost Pool installed (${NETWORK}).
     ${NODE_ID}
     ${BITCOIN_CHECK}
     Other node:      ${OTHER_NODE}
     Bitcoin peers:   ${BITCOIN_PEERS:-none given (ghostd finds its own)}
     Alerts:          ${ALERT_WEBHOOK:-DISABLED (no --alert-webhook)}
     ghostd:          $(systemctl is-active ghostd)   (initial sync — full IBD takes hours; watch: sudo journalctl -u ghostd -f)
     ghost-mining-gate: $(systemctl is-active ghost-mining-gate)  (waiting for sync, then auto-starts ghost-mining)
     ghost-mining:    $(systemctl is-active ghost-mining)  (started by the gate)
     sri-pool:        $(systemctl is-active sri-pool)  (SV2 pool — started by the gate, after ghost-mining)
     sri-translator:  $(systemctl is-active sri-translator)  (SV1->SV2 — started by the gate)
     dashboard:       ${DASHBOARD_STATUS}

  Miners connect to (username: their own Bitcoin address, optionally .<worker>; any password):
     stratum+tcp://${PUBIP}:3333    SV1, small miners (Bitaxe, NerdAxe)
     stratum+tcp://${PUBIP}:4444    SV1, the farm tier (S19/S21-class, rented hashrate)
     ${PUBIP}:34255                 SV2, authority key ${SV2_AUTH_PUB}
  A block a miner finds pays it the subsidy and every fee, less 0.5% of the subsidy (treasury).

  "inactive" is expected for the last three services until ghostd finishes syncing. The gate
  then starts ghost-mining AUTOMATICALLY, followed by the SV2 stratum stack (sri-pool +
  sri-translator).
  Watch the gate:    sudo journalctl -u ghost-mining-gate -f
  Watch the stratum: sudo journalctl -u sri-pool -u sri-translator -f

  Pairing with the other node: run the installer there with --peer-node ${PUBIP}
  --submit-auth <this node's rpcuser:rpcpassword>, which are in /etc/bitcoin/bitcoin.conf:
     sudo grep -E '^rpc(user|password)=' /etc/bitcoin/bitcoin.conf
EOF

