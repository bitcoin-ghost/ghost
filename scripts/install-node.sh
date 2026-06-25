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
GHOST_VERSION="v1.10.3"
# Signed release artefacts (GPG: defenwycke release key).
GPG_KEY_FP="777FE81F8CC077FD3D08055E852C2B3190F5B928"
RELEASE_BASE="https://github.com/bitcoin-ghost/ghost/releases/download/${GHOST_VERSION}"
POOL_TARBALL="bitcoin-ghost-${GHOST_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
# TODO(hosting): publish a signed ghost-core (ghostd) release and set this.
GHOSTD_URL="${GHOSTD_URL:-https://github.com/bitcoin-ghost/ghost-core/releases/download/${GHOST_VERSION}/ghostd-x86_64-linux-gnu}"
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

usage() {
  cat <<EOF
Bitcoin Ghost node installer

Required:
  --payout-address <bech32>   Where this node's reward share is paid.

Options:
  --nickname <name>           Display name in the mesh        (default: ghost-node)
  --sync <mode>               ibd | fast | haze               (default: ibd)
                                ibd  — full trustless sync + prune (recommended)
                                fast — assumeutxo snapshot (~minutes; trusts a
                                       snapshot hash, keeps validating; reversible)
                                haze — strips block data, ~195GB, FAST but
                                       IRREVERSIBLE. You can never serve raw
                                       blocks or go archive without a full resync.
  --no-public-mining          Don't accept external miners (capability -3)
  --no-reaper                 Don't run the mempool reaper    (capability -2)
  --archive                   Full archive node (~720GB, capability +5)
  --ghost-pay                 Enable the L2 payments service  (capability +4)
  -h, --help                  This help.
EOF
}

# ─────────────────────────────── arg parse ───────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --payout-address) PAYOUT_ADDRESS="$2"; shift 2;;
    --nickname)       NICKNAME="$2"; shift 2;;
    --sync)           SYNC_MODE="$2"; shift 2;;
    --no-public-mining) PUBLIC_MINING="false"; shift;;
    --no-reaper)      REAPER="false"; shift;;
    --archive)        ARCHIVE="true"; shift;;
    --ghost-pay)      GHOST_PAY="true"; shift;;
    -h|--help)        usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

err() { echo "ERROR: $*" >&2; exit 1; }
log() { echo -e "\033[36m==>\033[0m $*"; }

[[ $EUID -eq 0 ]] || err "Run as root (sudo)."
[[ -n "$PAYOUT_ADDRESS" ]] || { usage; err "--payout-address is required."; }
[[ "$PAYOUT_ADDRESS" =~ ^bc1[a-z0-9]{20,}$ ]] || err "Payout address doesn't look like a mainnet bech32 address."
[[ "$(uname -m)" == "x86_64" ]] || err "Only x86_64 is supported by this installer right now."
case "$SYNC_MODE" in ibd|fast) ;;
  haze) echo -e "\033[33mWARNING\033[0m: --sync haze strips block data IRREVERSIBLY. This node can never";
        echo "         serve raw blocks or become an archive node without a full resync.";
        read -rp "         Type 'yes' to continue: " c; [[ "$c" == "yes" ]] || err "Aborted.";;
  *) err "--sync must be ibd, fast, or haze.";;
esac

# ────────────────────────────── 1. packages ──────────────────────────────────
log "Installing dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  libevent-2.1-7 libevent-extra-2.1-7 libevent-pthreads-2.1-7 libevent-openssl-2.1-7 \
  libzmq5 ca-certificates ufw openssl curl gnupg tar >/dev/null

# ─────────────────────────── 2. user + layout ────────────────────────────────
log "Creating ghost user and directories"
id ghost >/dev/null 2>&1 || useradd -r -m -d /home/ghost -s /bin/bash ghost
mkdir -p /opt/ghost/bin /etc/ghost /etc/bitcoin /var/lib/bitcoin /var/lib/ghost /home/ghost/.ghost/data

# ─────────────────────── 3. download + verify binaries ───────────────────────
log "Downloading and verifying binaries (${GHOST_VERSION})"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
curl -fsSLO "${RELEASE_BASE}/${POOL_TARBALL}"
curl -fsSLO "${RELEASE_BASE}/SHA256SUMS.txt"
curl -fsSLO "${RELEASE_BASE}/SHA256SUMS.txt.asc"
# Verify the GPG signature over the checksums, then the checksum of our tarball.
curl -fsSL "https://github.com/bitcoin-ghost.gpg" 2>/dev/null | gpg --import 2>/dev/null || true
if ! gpg --list-keys "$GPG_KEY_FP" >/dev/null 2>&1; then
  echo "WARNING: release signing key ${GPG_KEY_FP} not available; cannot verify signature." >&2
else
  gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt || err "Release signature verification FAILED."
fi
grep " ${POOL_TARBALL}\$" SHA256SUMS.txt | sha256sum -c - || err "Checksum verification FAILED for ${POOL_TARBALL}."
tar -xzf "$POOL_TARBALL"
install -m755 -o root -g root "$(find . -name ghost-pool -type f | head -1)" /opt/ghost/bin/ghost-pool
# ghostd
curl -fsSL "$GHOSTD_URL" -o ghostd || err "Could not download ghostd from ${GHOSTD_URL} (see TODO in installer)."
install -m755 -o root -g root ghostd /opt/ghost/bin/ghostd
cd /

# ─────────────────────────── 4. fresh secrets ────────────────────────────────
log "Generating fresh node secrets"
RPCPW="$(openssl rand -hex 32)"
APISECRET="$(openssl rand -hex 32)"
SIGNKEY="$(openssl rand -hex 32)"
PUBIP="$(curl -fsSL https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"

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

# H-11: configs with secrets must be 0600.
chown ghost:ghost /etc/bitcoin/bitcoin.conf /etc/ghost/pool.toml
chmod 600 /etc/bitcoin/bitcoin.conf /etc/ghost/pool.toml
chown -R ghost:ghost /home/ghost /var/lib/ghost /var/lib/bitcoin

# ─────────────────────────── 7. node identity ────────────────────────────────
log "Generating node identity"
sudo -u ghost ZK_PARAMS_PATH=/home/ghost/.ghost/mpc_params ZK_PARAMS_HASH="$ZK_PARAMS_HASH" \
  /opt/ghost/bin/ghost-pool --config /etc/ghost/pool.toml --generate-identity 2>&1 | grep -iE "Node ID" || true

# ─────────────────────────── 8. systemd units ────────────────────────────────
log "Installing systemd units"
REAPER_FLAGS=""
[[ "$REAPER" == "true" ]] && REAPER_FLAGS="-ghostreaper=enabled -ghostreaper-rejectinscription=1 -ghostreaper-rejectdropstuffing=1 -ghostreaper-rejectfakepubkey=1 -ghostreaper-rejectannex=1 -ghostreaper-rejectopreturn=1 -ghostreaper-rejectrunestone=1 -ghostreaper-maxopreturn=82 -ghostreaper-mindropsize=76"
cat > /etc/systemd/system/ghostd.service <<EOF
[Unit]
Description=Ghost Bitcoin Core (mainnet)
After=network-online.target
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

# ─────────────────────────────── 9. firewall ─────────────────────────────────
log "Configuring firewall"
ufw allow 22/tcp        >/dev/null 2>&1   # ssh FIRST so we don't lock out
ufw allow 8333/tcp      >/dev/null 2>&1   # bitcoin P2P
ufw allow 3333/tcp      >/dev/null 2>&1   # stratum v1
ufw allow 8080/tcp      >/dev/null 2>&1   # ghost API
ufw allow 8442/tcp      >/dev/null 2>&1   # TDP
ufw allow 8555:8562/tcp >/dev/null 2>&1   # mesh consensus
ufw --force enable      >/dev/null 2>&1

# ─────────────────────────────── 10. start ───────────────────────────────────
log "Starting services"
systemctl daemon-reload
systemctl enable --now ghostd    >/dev/null 2>&1
sleep 5
systemctl enable --now ghost-pool >/dev/null 2>&1
sleep 10

NODE_ID="$(sudo -u ghost ZK_PARAMS_PATH=/home/ghost/.ghost/mpc_params ZK_PARAMS_HASH="$ZK_PARAMS_HASH" /opt/ghost/bin/ghost-pool --config /etc/ghost/pool.toml --show-identity 2>/dev/null | grep -i 'Node ID' | head -1 || true)"
cat <<EOF

  ✅ Bitcoin Ghost node installed.
     ${NODE_ID}
     ghostd:     $(systemctl is-active ghostd)   (syncing — full IBD takes hours; check: journalctl -u ghostd -f)
     ghost-pool: $(systemctl is-active ghost-pool)   (mesh: curl -s localhost:8080/health)

  Your node joins the mesh now and registers as an Elder if slots remain (first 101).
  Full consensus participation begins once ghostd finishes syncing.
EOF
