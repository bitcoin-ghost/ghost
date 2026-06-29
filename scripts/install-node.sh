#!/usr/bin/env bash
#
# Bitcoin Ghost — one-command node installer.
#
#   curl -sSL https://get.bitcoinghost.org | sudo bash -s -- --payout-address bc1q...
#
# Stands up a full Ghost node (ghostd + ghost-pool) on Ubuntu, joins the mesh,
# and — while there are still Elder slots free (first 101 nodes) — registers as
# an Elder. Mirrors the proven production setup; every per-node secret is
# generated fresh on this machine and never leaves it.
#
# Derived from the verified provisioning of mainnet-5 (elder #5).
set -euo pipefail

# ─────────────────────────── network constants ───────────────────────────────
GHOST_VERSION="v1.10.6"
# Signed release artefacts (GPG: defenwycke release key).
GPG_KEY_FP="777FE81F8CC077FD3D08055E852C2B3190F5B928"
RELEASE_BASE="https://github.com/bitcoin-ghost/ghost/releases/download/${GHOST_VERSION}"
POOL_TARBALL="bitcoin-ghost-${GHOST_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
GHOSTD_URL="${GHOSTD_URL:-https://get.bitcoinghost.org/bin/ghostd}"
GHOSTD_SHA256="bb3a864248cea6ece930eb76fef525a0f5b1fde65976a886935df34e9e95859d"
RELEASE_KEY_URL="https://get.bitcoinghost.org/ghost-release-key.asc"
# ZK params are auto-fetched from peers on first run; this is the pinned hash.
ZK_PARAMS_HASH="BLOCK:fa9db2b79ee55bd181c33943a466aad24e58618c7cf1e2f23daf91462115ce77"
# Bootstrap peers (the current Elders). The node discovers the rest via gossip.
SEED_NODES='"83.136.251.162:8555", "85.9.198.212:8555", "213.163.207.46:8555", "95.111.221.169:8555"'
# assumevalid checkpoint (speeds signature validation; does NOT skip download).
ASSUMEVALID="000000000000000000010538edbfd2d5b809a33dd83f284aeea41c6d0d96968a"

# ─────────────────────────────── defaults ────────────────────────────────────
PAYOUT_ADDRESS=""
NICKNAME="ghost-node"
SYNC_MODE="ibd"            # ibd (trustless, default) | fast (assumeutxo) | haze (IRREVERSIBLE)
PUBLIC_MINING="true"
REAPER="true"
ARCHIVE="false"
GHOST_PAY="false"
# Wraith mixing coordinator. Empty = "auto": ON when Ghost Pay is on, OFF
# otherwise (mixing rides on Ghost Pay's bond ledger). --wraith / --no-wraith
# pin it explicitly.
WRAITH=""
# Tor. OFF by default — a plain clearnet install is completely unchanged.
#   hybrid   (--tor)      reach outbound peers via Tor AND stay reachable on
#                         clearnet 8333, plus publish an ephemeral v3 onion.
#   tor-only (--tor-only) route everything over Tor, disable clearnet
#                         (onlynet=onion) and close 8333.
# --no-tor pins it off. TOR_MODE only matters when TOR is "true".
TOR="false"
TOR_MODE="hybrid"

usage() {
  cat <<EOF
Bitcoin Ghost node installer

Required:
  --payout-address <bech32>   Where this node's reward share is paid.

Options:
  --nickname <name>           Display name in the mesh        (default: ghost-node)
  --sync <mode>               ibd | fast | haze               (default: ibd)
                                ibd  — full trustless sync + prune (recommended)
                                fast — EXPERIMENTAL: a real assumeutxo snapshot is
                                       not yet distributed, so this currently
                                       behaves exactly like ibd (no snapshot is
                                       loaded). Use ibd.
                                haze — strips block data, ~195GB, FAST but
                                       IRREVERSIBLE. You can never serve raw
                                       blocks or go archive without a full resync.
  --no-public-mining          Don't accept external miners (capability -3)
  --no-reaper                 Don't run the mempool reaper    (capability -2)
  --archive                   Full archive node (~720GB, capability +5)
  --ghost-pay                 Enable the L2 payments service  (capability +4)
  --wraith                    Run a Wraith mixing coordinator (implies --ghost-pay)
  --no-wraith                 Never run a Wraith mixing coordinator
                                (default: follows --ghost-pay — on when Ghost Pay
                                 is on, off otherwise)
  --tor                       Route over Tor (hybrid): outbound peers via Tor +
                                publish an onion, still reachable on clearnet 8333
  --tor-only                  Route over Tor ONLY: no clearnet (onlynet=onion),
                                close 8333 (implies --tor)
  --no-tor                    Never use Tor                   (default)
  --non-interactive           Never prompt; use flags/defaults only (for scripts)
  -h, --help                  This help.

With no config flags on an interactive terminal, a guided setup wizard runs.
EOF
}

# ─────────────────────────────── arg parse ───────────────────────────────────
# CONFIG_FLAGS counts how many config-setting flags were passed. The interactive
# wizard runs ONLY when none were given (and stdin is a TTY and --non-interactive
# was not passed); otherwise the script behaves exactly as the flag interface
# always has.
CONFIG_FLAGS=0
NON_INTERACTIVE="false"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --payout-address) PAYOUT_ADDRESS="$2"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --nickname)       NICKNAME="$2"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --sync)           SYNC_MODE="$2"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --no-public-mining) PUBLIC_MINING="false"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --no-reaper)      REAPER="false"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --archive)        ARCHIVE="true"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --ghost-pay)      GHOST_PAY="true"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --wraith)         WRAITH="true"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --no-wraith)      WRAITH="false"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --tor)            TOR="true"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --tor-only)       TOR="true"; TOR_MODE="tor-only"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --no-tor)         TOR="false"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --non-interactive) NON_INTERACTIVE="true"; shift;;
    -h|--help)        usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

err() { echo "ERROR: $*" >&2; exit 1; }
log() { echo -e "\033[36m==>\033[0m $*"; }

# Set to "true" by the wizard so the post-wizard validation below doesn't ask the
# haze confirmation a second time (the wizard already collected it).
WIZARD_RAN="false"

# Yes/No prompt with a default. Echoes "true" or "false" so the caller can assign
# it straight into PUBLIC_MINING / REAPER / ARCHIVE / GHOST_PAY. The read prompt
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
# sets (PAYOUT_ADDRESS, SYNC_MODE, PUBLIC_MINING, REAPER, ARCHIVE, GHOST_PAY,
# NICKNAME); the rest of the installer is unchanged. Only ever runs with no
# config flags, on a TTY, without --non-interactive.
run_wizard() {
  echo
  log "Bitcoin Ghost — guided node setup"
  echo "This installs a full Ghost node (ghostd + ghost-pool), joins the mesh, and"
  echo "registers as an Elder while slots remain. Press Enter to accept each [default]."
  echo

  # Payout address — REQUIRED, no default, re-prompt until valid.
  local addr
  while :; do
    read -rp "Payout address (mainnet bech32 — where your rewards are paid): " addr || true
    if [[ "$addr" =~ ^bc1[a-z0-9]{20,}$ ]]; then
      PAYOUT_ADDRESS="$addr"; break
    fi
    echo "  ✗ That doesn't look like a mainnet bech32 address (must start 'bc1…'). Try again."
  done

  # Sync mode.
  echo
  echo "Block download / sync method:"
  echo "  1) ibd   full trustless sync — validates every block (hours up to ~a day). RECOMMENDED."
  echo "  2) haze  IRREVERSIBLE — strips block data (~195GB, fast). Can never serve raw blocks or"
  echo "           become an archive node afterwards without a full resync."
  echo "  (A 'fast' assumeutxo snapshot is planned but not yet distributed, so it is not offered"
  echo "   here — it would currently behave just like ibd.)"
  local sync_choice
  read -rp "Choose 1 or 2 [1]: " sync_choice || true
  sync_choice="${sync_choice:-1}"
  case "$sync_choice" in
    1|ibd) SYNC_MODE="ibd";;
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

  # Capabilities.
  echo
  echo "Capabilities (each affects your node's reward share):"
  PUBLIC_MINING="$(prompt_yes_no "  Accept external miners — public mining (+3 shares)?" Y)"
  REAPER="$(prompt_yes_no "  Run the mempool reaper — filters spam/inscriptions (+2 path)?" Y)"
  ARCHIVE="$(prompt_yes_no "  Run as a full archive node — ~720GB disk (+5 shares)?" N)"
  GHOST_PAY="$(prompt_yes_no "  Enable Ghost Pay — L2 instant-payments service (+4 shares)?" N)"

  # Wraith mixing coordinator — only offered when Ghost Pay is on (it relies on
  # ghost-pay's bond ledger). Defaults Y so a Ghost Pay node mixes by default.
  if [[ "$GHOST_PAY" == "true" ]]; then
    WRAITH="$(prompt_yes_no "  Enable Wraith mixing coordinator (requires Ghost Pay)?" Y)"
  else
    WRAITH="false"
  fi

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

  # Nickname.
  echo
  local nn
  read -rp "Node nickname shown in the mesh [ghost-node]: " nn || true
  NICKNAME="${nn:-ghost-node}"

  # Summary + final confirmation before anything destructive happens.
  echo
  log "Summary of your choices"
  echo "  Payout address : $PAYOUT_ADDRESS"
  echo "  Sync mode      : $SYNC_MODE"
  echo "  Public mining  : $PUBLIC_MINING"
  echo "  Reaper         : $REAPER"
  echo "  Archive node   : $ARCHIVE"
  echo "  Ghost Pay      : $GHOST_PAY"
  echo "  Wraith mixing  : $WRAITH"
  echo "  Tor            : $([[ "$TOR" == "true" ]] && echo "$TOR_MODE" || echo "off")"
  echo "  Nickname       : $NICKNAME"
  echo
  local proceed
  proceed="$(prompt_yes_no "Proceed with installation?" Y)"
  [[ "$proceed" == "true" ]] || err "Aborted by user."
  WIZARD_RAN="true"
  echo
}

[[ $EUID -eq 0 ]] || err "Run as root (sudo)."

# Enter the wizard ONLY with no config flags, an interactive terminal, and no
# --non-interactive. Otherwise fall straight through to the flag/validation path
# exactly as before.
if [[ "$CONFIG_FLAGS" -eq 0 && "$NON_INTERACTIVE" != "true" && -t 0 ]]; then
  run_wizard
fi

[[ -n "$PAYOUT_ADDRESS" ]] || { usage; err "--payout-address is required."; }
[[ "$PAYOUT_ADDRESS" =~ ^bc1[a-z0-9]{20,}$ ]] || err "Payout address doesn't look like a mainnet bech32 address."
[[ "$(uname -m)" == "x86_64" ]] || err "Only x86_64 is supported by this installer right now."
case "$SYNC_MODE" in ibd|fast) ;;
  haze) if [[ "$WIZARD_RAN" != "true" ]]; then
          echo -e "\033[33mWARNING\033[0m: --sync haze strips block data IRREVERSIBLY. This node can never";
          echo "         serve raw blocks or become an archive node without a full resync.";
          read -rp "         Type 'yes' to continue: " c; [[ "$c" == "yes" ]] || err "Aborted.";
        fi;;
  *) err "--sync must be ibd, fast, or haze.";;
esac

# Wraith mixing rides on Ghost Pay's bond ledger (the coordinator verifies and
# resolves participant bonds against ghost-pay on 127.0.0.1:8800). Resolve the
# "auto" default — track Ghost Pay — and pull Ghost Pay in when Wraith was asked
# for explicitly without it. We auto-enable Ghost Pay (rather than erroring) so a
# non-interactive `--wraith` install can't half-provision a coordinator that has
# no bond ledger to talk to.
if [[ -z "$WRAITH" ]]; then
  WRAITH="$GHOST_PAY"
fi
if [[ "$WRAITH" == "true" && "$GHOST_PAY" != "true" ]]; then
  log "Wraith mixing requires Ghost Pay — enabling Ghost Pay (capability +4) as well."
  GHOST_PAY="true"
fi

# ────────────────────────────── 1. packages ──────────────────────────────────
log "Installing dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  libevent-2.1-7 libevent-extra-2.1-7 libevent-pthreads-2.1-7 libevent-openssl-2.1-7 \
  libzmq5 ca-certificates ufw openssl curl gnupg tar >/dev/null
# Tor — only when routing over Tor. DEBIAN_FRONTEND is already exported above.
if [[ "$TOR" == "true" ]]; then
  log "Installing Tor"
  apt-get install -y -qq tor >/dev/null
fi

# ─────────────────────────── 2. user + layout ────────────────────────────────
log "Creating ghost user and directories"
id ghost >/dev/null 2>&1 || useradd -r -m -d /home/ghost -s /bin/bash ghost
mkdir -p /opt/ghost/bin /etc/ghost /etc/bitcoin /var/lib/bitcoin /var/lib/ghost /home/ghost/.ghost/data /home/ghost/.ghost/ghost-pay

# ─────────────────────── 3. download + verify binaries ───────────────────────
log "Downloading and verifying binaries (${GHOST_VERSION})"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
curl -fsSLO "${RELEASE_BASE}/${POOL_TARBALL}"
curl -fsSLO "${RELEASE_BASE}/SHA256SUMS.txt"
curl -fsSLO "${RELEASE_BASE}/SHA256SUMS.txt.asc"
# Verify the GPG signature over the checksums, then the checksum of our tarball.
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
tar -xzf "$POOL_TARBALL"
install -m755 -o root -g root "$(find . -name ghost-pool -type f | head -1)" /opt/ghost/bin/ghost-pool
# ghost-pay (L2 + Wraith bond ledger) ships in the same signed tarball; install
# it only when Ghost Pay is enabled.
if [[ "$GHOST_PAY" == "true" ]]; then
  install -m755 -o root -g root "$(find . -name ghost-pay -type f | head -1)" /opt/ghost/bin/ghost-pay
fi
# ghostd (pinned checksum)
curl -fsSL "$GHOSTD_URL" -o ghostd || err "Could not download ghostd from ${GHOSTD_URL}."
echo "${GHOSTD_SHA256}  ghostd" | sha256sum -c - || err "ghostd checksum verification FAILED."
install -m755 -o root -g root ghostd /opt/ghost/bin/ghostd
cd /

# ─────────────────────────── 4. fresh secrets ────────────────────────────────
log "Generating fresh node secrets"
RPCPW="$(openssl rand -hex 32)"
APISECRET="$(openssl rand -hex 32)"
SIGNKEY="$(openssl rand -hex 32)"
PUBIP="$(curl -fsSL https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
# Ghost Pay secrets. On mainnet ghost-pay refuses to start without all three of
# these (key-encryption password, API HMAC secret, coordinator bond-ledger
# token). BOND_LEDGER_TOKEN is generated ONCE here and shared verbatim between
# ghost-pay (GHOST_PAY_BOND_LEDGER_TOKEN) and the ghost-pool coordinator
# ([coordinator] bond_ledger_token) so the two always match.
if [[ "$GHOST_PAY" == "true" ]]; then
  PAY_KEY_PASSWORD="$(openssl rand -hex 32)"
  PAY_API_SECRET="$(openssl rand -hex 32)"
  BOND_LEDGER_TOKEN="$(openssl rand -hex 32)"
fi

# ───────────────────────── 5. ghostd config (sync) ───────────────────────────
log "Writing /etc/bitcoin/bitcoin.conf (sync mode: ${SYNC_MODE})"
{
  echo "server=1"
  echo "listen=1"
  if [[ "$ARCHIVE" == "true" ]]; then echo "hazemode=FullArchive"
  elif [[ "$SYNC_MODE" == "haze" ]]; then echo "hazemode=Hazed"
  else echo "prune=550"; fi
  cat <<EOF
rpcuser=ghostrpc_mainnet
rpcpassword=${RPCPW}
rpcallowip=127.0.0.1
rpcbind=127.0.0.1
rpcport=8332
port=8333
zmqpubhashblock=tcp://127.0.0.1:28332
zmqpubhashtx=tcp://127.0.0.1:28333
zmqpubsequence=tcp://127.0.0.1:28334
dbcache=1024
maxconnections=50
fallbackfee=0.00001
assumevalid=${ASSUMEVALID}
EOF
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
MINING_MODE="public_pool"; [[ "$PUBLIC_MINING" == "true" ]] || MINING_MODE="private_solo"
cat > /etc/ghost/pool.toml <<EOF
[identity]
key_path = "/home/ghost/.ghost/node.key"
display_name = "${NICKNAME}"

[bitcoin]
rpc_host = "127.0.0.1"
rpc_port = 8332
rpc_user = "ghostrpc_mainnet"
rpc_password = "${RPCPW}"
network = "mainnet"
zmq_hashblock = "tcp://127.0.0.1:28332"
zmq_hashtx = "tcp://127.0.0.1:28333"

[network]
internal_api_secret = "${APISECRET}"
signing_key = "${SIGNKEY}"
public_address = "${PUBIP}"
noise_enabled = true
sv2_port = 34255
sv1_port = 3333
http_port = 8080
max_miners = 1000
mining_mode = "${MINING_MODE}"
seed_nodes = [${SEED_NODES}]

[network.p2p]
share_propagation = 8555
block_announcement = 8556
consensus_voting = 8557
health_monitoring = 8558
discovery = 8559
elder_management = 8560
payout_proposal = 8561
payout_transaction = 8562

[policy]
profile = "full_open"

[storage]
db_path = "/home/ghost/.ghost/data"
wal_mode = true
archive_mode = ${ARCHIVE}
prune_height = 0

[pool]
node_payout_address = "${PAYOUT_ADDRESS}"
treasury_address = "bc1qgxg5ywk835c9fp6arz6d6x50xpk6y0ualt900k"
treasury_fee_percent = 1.0
min_payout_sats = 10000
payout_interval_blocks = 100

[ghost_pay]
enabled = ${GHOST_PAY}
virtual_block_secs = 10
epoch_blocks = 100
transfer_fee_bps = 10
min_transfer_fee_sats = 100
wraith_enabled = ${GHOST_PAY}
wraith_fee_percent = 0.5
http_port = 8081

[tdp]
enabled = true
port = 8442
max_connections = 10

[reaper]
enabled = ${REAPER}
mode = "strict"
EOF

# Wraith mixing coordinator. Keys are the `[coordinator]` (CoordinatorConfig)
# fields read by ghost-pool: `coordinator_role_enabled` actually RUNS the
# in-process coordinator when this node wins a seat; `coordinator_port` is the
# listen port (0.0.0.0:<port>); `bond_ledger_url`/`bond_ledger_token` point at
# the local ghost-pay bond ledger (the token MUST equal ghost-pay's
# GHOST_PAY_BOND_LEDGER_TOKEN). The URL is `https://` — ghost-pay serves its
# bond endpoints with an identity-derived TLS cert and the coordinator pins it
# against this node's own node_id (cert pubkey == node_id), so plain HTTP would
# be rejected. `wraith_election_enabled` + `coordinator_enabled`
# + `advertised_endpoint` make this node electable and let it compute the
# per-epoch draw, so a single enabled node is enough and many are safe.
if [[ "$WRAITH" == "true" ]]; then
cat >> /etc/ghost/pool.toml <<EOF

[coordinator]
wraith_election_enabled = true
coordinator_enabled = true
advertised_endpoint = "${PUBIP}:9100"
coordinator_port = 9100
coordinator_role_enabled = true
bond_ledger_url = "https://127.0.0.1:8800"
bond_ledger_token = "${BOND_LEDGER_TOKEN}"
EOF
fi

# H-11: configs with secrets must be 0600.
chown ghost:ghost /etc/bitcoin/bitcoin.conf /etc/ghost/pool.toml
chmod 600 /etc/bitcoin/bitcoin.conf /etc/ghost/pool.toml
chown -R ghost:ghost /home/ghost /var/lib/ghost /var/lib/bitcoin

# ─────────────────────────── 7. node identity ────────────────────────────────
log "Generating node identity"
sudo -u ghost ZK_PARAMS_PATH=/home/ghost/.ghost/mpc_params ZK_PARAMS_HASH="$ZK_PARAMS_HASH" \
  /opt/ghost/bin/ghost-pool --config /etc/ghost/pool.toml --generate-identity 2>&1 | grep -iE "Node ID" || true

# ───────────────────────── 8. sync gate (auto) ───────────────────────────────
# Start ghost-pool only AFTER ghostd finishes its initial sync. An unsynced node
# participating in checkpoint consensus just spams "wrong proposer" and can't
# vote — so we gate it. On a normal reboot ghostd is already synced, so the gate
# returns almost immediately.
log "Installing sync gate"
cat > /opt/ghost/bin/wait-for-ghostd-sync.sh <<'EOF'
#!/usr/bin/env bash
set -u
CONF=/etc/bitcoin/bitcoin.conf
RPCUSER=$(grep -m1 '^rpcuser=' "$CONF" | cut -d= -f2-)
RPCPW=$(grep -m1 '^rpcpassword=' "$CONF" | cut -d= -f2-)
echo "[ghost-pool-gate] waiting for ghostd to finish initial sync..."
while true; do
  RESP=$(curl -s --max-time 8 --user "$RPCUSER:$RPCPW" \
    --data '{"jsonrpc":"1.0","method":"getblockchaininfo","params":[]}' \
    http://127.0.0.1:8332/ 2>/dev/null)
  IBD=$(echo "$RESP" | grep -oE '"initialblockdownload":[[:space:]]*(true|false)' | grep -oE 'true|false')
  if [ "$IBD" = "false" ]; then
    echo "[ghost-pool-gate] ghostd synced — starting ghost-pool"
    systemctl start ghost-pool
    # ghost-pay (when installed) also needs a live ghostd + ghost-pool, so the
    # gate owns its first start too — mirrors ghost-pool, which is not enabled
    # at boot.
    if [ -f /etc/systemd/system/ghost-pay.service ]; then
      echo "[ghost-pool-gate] starting ghost-pay"
      systemctl start ghost-pay
    fi
    exit 0
  fi
  sleep 30
done
EOF
chmod 755 /opt/ghost/bin/wait-for-ghostd-sync.sh
cat > /etc/systemd/system/ghost-pool-gate.service <<'EOF'
[Unit]
Description=Ghost Pool sync gate (starts ghost-pool once ghostd is synced)
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

# ─────────────────────────── 9. systemd units ────────────────────────────────
log "Installing systemd units"
REAPER_FLAGS=""
[[ "$REAPER" == "true" ]] && REAPER_FLAGS="-ghostreaper=enabled -ghostreaper-rejectinscription=1 -ghostreaper-rejectdropstuffing=1 -ghostreaper-rejectfakepubkey=1 -ghostreaper-rejectannex=1 -ghostreaper-rejectopreturn=1 -ghostreaper-rejectrunestone=1 -ghostreaper-maxopreturn=82 -ghostreaper-mindropsize=76"
# Order ghostd after tor when Tor is enabled, so the control port is up before
# ghostd tries to publish its onion. Empty otherwise → unit byte-identical.
GHOSTD_AFTER=""
[[ "$TOR" == "true" ]] && GHOSTD_AFTER=" tor.service"
cat > /etc/systemd/system/ghostd.service <<EOF
[Unit]
Description=Ghost Bitcoin Core (mainnet)
After=network-online.target${GHOSTD_AFTER}
Wants=network-online.target
[Service]
Type=simple
User=ghost
Group=ghost
ExecStart=/opt/ghost/bin/ghostd -conf=/etc/bitcoin/bitcoin.conf -datadir=/var/lib/bitcoin ${REAPER_FLAGS}
Restart=on-failure
RestartSec=30
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/ghost-pool.service <<EOF
[Unit]
Description=Ghost Pool node
After=network-online.target ghostd.service
Wants=network-online.target
[Service]
Type=simple
User=ghost
Group=ghost
WorkingDirectory=/var/lib/ghost
ExecStart=/opt/ghost/bin/ghost-pool --config /etc/ghost/pool.toml --tdp-enabled --tdp-port 8442 --stratum-port 3333
Environment=RUST_LOG=info
Environment=ZK_PARAMS_PATH=/home/ghost/.ghost/mpc_params
Environment=ZK_PARAMS_HASH=${ZK_PARAMS_HASH}
Restart=on-failure
RestartSec=15
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF

# ghost-pay L2 service (also serves the Wraith bond ledger on 8800). Only
# installed when Ghost Pay is enabled. GHOST_PAY_BOND_LEDGER_TOKEN is the SAME
# secret written into pool.toml's [coordinator] bond_ledger_token above, so the
# coordinator authenticates to this bond ledger. MPC verification keys default
# to the sibling of --data-dir (/home/ghost/.ghost/mpc_params), where ghost-pool
# fetches them. The unit carries secrets, so it is locked to 0600.
if [[ "$GHOST_PAY" == "true" ]]; then
cat > /etc/systemd/system/ghost-pay.service <<EOF
[Unit]
Description=Ghost Pay L2 service (Wraith bond ledger)
After=network-online.target ghostd.service ghost-pool.service
Wants=network-online.target
[Service]
Type=simple
User=ghost
Group=ghost
WorkingDirectory=/var/lib/ghost
ExecStart=/opt/ghost/bin/ghost-pay --api-listen 0.0.0.0:8800 --data-dir /home/ghost/.ghost/ghost-pay --bitcoin-rpc http://127.0.0.1:8332 --network mainnet --treasury-address bc1qgxg5ywk835c9fp6arz6d6x50xpk6y0ualt900k --node-payout-address ${PAYOUT_ADDRESS} --identity-key /home/ghost/.ghost/node.key
Environment=RUST_LOG=info
Environment=BITCOIN_RPC_USER=ghostrpc_mainnet
Environment=BITCOIN_RPC_PASSWORD=${RPCPW}
Environment=GHOST_PAY_PASSWORD=${PAY_KEY_PASSWORD}
Environment=GHOST_PAY_API_SECRET=${PAY_API_SECRET}
Environment=GHOST_PAY_BOND_LEDGER_TOKEN=${BOND_LEDGER_TOKEN}
Restart=on-failure
RestartSec=15
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
chmod 600 /etc/systemd/system/ghost-pay.service
fi

# ─────────────────────────────── 9. firewall ─────────────────────────────────
log "Configuring firewall"
ufw allow 22/tcp        >/dev/null 2>&1   # ssh FIRST so we don't lock out
ufw allow 8333/tcp      >/dev/null 2>&1   # bitcoin P2P
ufw allow 8080/tcp      >/dev/null 2>&1   # ghost API
ufw allow 8442/tcp      >/dev/null 2>&1   # TDP
ufw allow 8555:8562/tcp >/dev/null 2>&1   # mesh consensus
# Ghost Pay L2 / Wraith bond ledger (peers issue Ghost Pay verification
# challenges here, and wallets escrow Wraith bonds here) — only when enabled.
[[ "$GHOST_PAY" == "true" ]] && ufw allow 8800/tcp >/dev/null 2>&1   # ghost-pay / bond ledger
# Tor-only: clearnet P2P is disabled (onlynet=onion), so close 8333 — inbound
# peering happens over the onion. Hybrid leaves the rule above in place (still
# reachable on clearnet). Idempotent: `ufw delete` is a no-op if absent.
if [[ "$TOR" == "true" && "$TOR_MODE" == "tor-only" ]]; then
  ufw delete allow 8333/tcp >/dev/null 2>&1 || true   # tor-only: no clearnet P2P
fi
ufw --force enable      >/dev/null 2>&1

# Stratum V1 (3333) + V2 (34255) are exposed ONLY when this node accepts public
# miners. Instead of a static rule baked at install time, a tiny reconcile
# service follows `mining_mode` in pool.toml, and a .path unit re-runs it
# whenever the config changes — so toggling public mining later (dashboard /
# ghost-setup / hand edit) updates the firewall live, with no manual ufw step.
log "Installing mining-firewall reconcile (stratum + coordinator ports follow pool.toml)"
cat > /opt/ghost/bin/reconcile-mining-firewall.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
CONF="${GHOST_POOL_CONF:-/etc/ghost/pool.toml}"
PORTS=(3333 34255)
public="no"
if [[ -r "$CONF" ]]; then
  if grep -qE '^[[:space:]]*public_mining[[:space:]]*=[[:space:]]*true([[:space:]]|$)' "$CONF" 2>/dev/null \
   || grep -qE '^[[:space:]]*mining_mode[[:space:]]*=[[:space:]]*"?public_pool"?' "$CONF" 2>/dev/null; then
    public="yes"
  fi
fi
if [[ "$public" == "yes" ]]; then
  for p in "${PORTS[@]}"; do ufw allow "${p}/tcp" >/dev/null 2>&1 || true; done
  logger -t ghost-mining-firewall "public mining ON -> Stratum 3333+34255 OPEN"
else
  for p in "${PORTS[@]}"; do ufw delete allow "${p}/tcp" >/dev/null 2>&1 || true; done
  logger -t ghost-mining-firewall "public mining OFF -> Stratum 3333+34255 CLOSED"
fi

# Wraith coordinator listen port (9100) follows [coordinator]
# coordinator_role_enabled, exactly as the Stratum ports follow public mining.
coord="no"
if [[ -r "$CONF" ]] \
 && grep -qE '^[[:space:]]*coordinator_role_enabled[[:space:]]*=[[:space:]]*true([[:space:]]|$)' "$CONF" 2>/dev/null; then
  coord="yes"
fi
if [[ "$coord" == "yes" ]]; then
  ufw allow 9100/tcp >/dev/null 2>&1 || true
  logger -t ghost-mining-firewall "coordinator role ON -> Wraith 9100 OPEN"
else
  ufw delete allow 9100/tcp >/dev/null 2>&1 || true
  logger -t ghost-mining-firewall "coordinator role OFF -> Wraith 9100 CLOSED"
fi
EOF
chmod 755 /opt/ghost/bin/reconcile-mining-firewall.sh

cat > /etc/systemd/system/ghost-mining-firewall.service <<'EOF'
[Unit]
Description=Ghost mining firewall reconcile (Stratum + Wraith coordinator ports follow pool.toml)
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
Description=Watch pool.toml and reconcile the Stratum + Wraith coordinator firewall on change
[Path]
PathModified=/etc/ghost/pool.toml
Unit=ghost-mining-firewall.service
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload >/dev/null 2>&1
systemctl enable --now ghost-mining-firewall.path >/dev/null 2>&1
/opt/ghost/bin/reconcile-mining-firewall.sh >/dev/null 2>&1 || true   # apply initial state

# ─────────────────────────────── 11. start ───────────────────────────────────
log "Starting services"
systemctl daemon-reload
systemctl enable --now ghostd >/dev/null 2>&1
# ghost-pool is NOT started here — the gate starts it once ghostd is synced.
# ghost-pool.service is installed but left disabled; the (enabled) gate owns it.
systemctl enable --now ghost-pool-gate >/dev/null 2>&1
sleep 5

NODE_ID="$(sudo -u ghost ZK_PARAMS_PATH=/home/ghost/.ghost/mpc_params ZK_PARAMS_HASH="$ZK_PARAMS_HASH" /opt/ghost/bin/ghost-pool --config /etc/ghost/pool.toml --show-identity 2>/dev/null | grep -i 'Node ID' | head -1 || true)"
cat <<EOF

  ✅ Bitcoin Ghost node installed.
     ${NODE_ID}
     ghostd:          $(systemctl is-active ghostd)   (initial sync — full IBD takes hours; watch: journalctl -u ghostd -f)
     ghost-pool-gate: $(systemctl is-active ghost-pool-gate)  (waiting for sync, then auto-starts ghost-pool)

  ghost-pool starts AUTOMATICALLY once ghostd finishes syncing — then your node
  joins the mesh and registers as an Elder if slots remain (first 101).
  Watch the gate:  journalctl -u ghost-pool-gate -f
EOF
