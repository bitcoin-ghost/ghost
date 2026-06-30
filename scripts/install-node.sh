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

# ─────────────────── assumeUTXO snapshot (--sync fast) ────────────────────────
# A verified UTXO snapshot at block height 910000. With `--sync fast` the
# installer downloads this and hands it to ghostd's `loadtxoutset` RPC, giving an
# immediately-usable chainstate at the snapshot height while the node syncs
# 910000→tip in the foreground and validates genesis→910000 in the background.
#
# TRUSTLESS: `loadtxoutset` recomputes the snapshot's UTXO-set hash and rejects
# the file unless it matches the value pinned in ghostd's own chainparams
# (m_assumeutxo_data height 910000 ==
# 4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568). That pinned
# hash — NOT the host, NOT the SHA-256 below — is the trust root. SNAPSHOT_SHA256
# is only an integrity / anti-truncation guard on the ~9GB download so we never
# feed a corrupt file to loadtxoutset.
#
# TODO(hosting): SNAPSHOT_URL is a raw IP for now. Replace it with a
# `snapshot.bitcoinghost.org` DNS record or an object-storage URL once
# provisioned (the file + its `.sha256` should move with it). Both values are
# overridable from the environment for staging/testing.
SNAPSHOT_URL="${SNAPSHOT_URL:-http://94.237.48.104/ghost-utxo-910000.dat}"
SNAPSHOT_SHA256="${SNAPSHOT_SHA256:-6ac0208110d6d6c0783c50ea825aae32f5229cf1dcb63ac986543e95aa0306bf}"
SNAPSHOT_PATH="${SNAPSHOT_PATH:-/home/ghost/.ghost/snapshot.dat}"
SNAPSHOT_HEIGHT="910000"

# ─────────────────────────────── defaults ────────────────────────────────────
PAYOUT_ADDRESS=""
NICKNAME="ghost-node"
SYNC_MODE="ibd"            # ibd (trustless, default) | fast (assumeutxo) | haze (IRREVERSIBLE)
# Mining mode — the single source of truth for who can mine and how rewards are
# shared. One of: public_pool | private_pool | private_solo (mirrors
# ghost-common MiningMode and the dashboard PoolSetupWizard). Default is
# public_pool, unchanged from the historical default.
#   public_pool  — DNS-registered, ANYONE can mine, pool-aggregated rewards (+3).
#   private_pool — password-required, NOT in DNS, your miners + invited external
#                  miners, pool-aggregated (shared) rewards. No +3 DNS capability.
#   private_solo — password-required, NOT in DNS, Stratum closed to external
#                  miners; 99% subsidy + ALL fees to the operator's own address.
MINING_MODE="public_pool"
# Optional custom pool name. Empty = fall back to the mining-mode default coinbase
# tag (nothing written to pool.toml). When set it becomes the block coinbase
# scriptsig tag "- G H O S T - <name>", visible on explorers. ASCII, <=30 chars.
POOL_NAME=""
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
# Automatic updates. OFF by default — a node NEVER self-upgrades unless the
# operator explicitly opts in (here, or later via the dashboard toggle). The
# updater verifies the GPG release signature before applying anything.
AUTO_UPDATE="false"

usage() {
  cat <<EOF
Bitcoin Ghost node installer

Required:
  --payout-address <bech32>   Where this node's reward share is paid.

Options:
  --nickname <name>           Display name in the mesh        (default: ghost-node)
  --pool-name <name>          Custom pool name shown in the block coinbase as
                                '- G H O S T - <name>' on explorers. ASCII only,
                                max 30 chars. Distinct from --nickname (the mesh
                                display name). Default: derived from --mining-mode.
  --sync <mode>               ibd | fast | haze               (default: ibd)
                                ibd  — full trustless sync + prune (recommended)
                                fast — assumeutxo: downloads a verified UTXO
                                       snapshot at height 910000 (~9GB) and loads
                                       it, so the node is usable in minutes; it
                                       then syncs 910000→tip in the foreground and
                                       validates genesis→910000 in the background.
                                       STILL TRUSTLESS — ghostd verifies the
                                       snapshot's UTXO-set hash against its pinned
                                       chainparams and rejects any mismatch.
                                haze — strips block data, ~195GB, FAST but
                                       IRREVERSIBLE. You can never serve raw
                                       blocks or go archive without a full resync.
  --mining-mode <mode>        solo | pool | public            (default: public)
                                public — Public Pool: DNS-registered, ANYONE can
                                         mine, pool-aggregated rewards (+3 shares).
                                pool   — Private Pool: password-required, NOT in
                                         DNS, your miners + invited external
                                         miners, shared rewards (no +3 capability).
                                solo   — Private Solo: password-required, NOT in
                                         DNS, Stratum closed to external miners,
                                         99% subsidy + ALL fees to your address.
                                A miner password is generated automatically for
                                the private modes and printed at the end.
  --no-public-mining          Backward-compatible alias for --mining-mode solo.
                                Prefer --mining-mode. If both are given, the last
                                one on the command line wins.
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
  --auto-update               Automatically apply newer SIGNED releases (off by
                                default). Verifies the GPG signature + ghostd
                                checksum before swapping any binary; health-checks
                                and rolls back on failure. Checked every 6h.
  --no-auto-update            Never auto-update                (default)
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
    --pool-name)      POOL_NAME="${2:-}"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --sync)           SYNC_MODE="$2"; shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --mining-mode)
      case "${2:-}" in
        solo|private_solo)   MINING_MODE="private_solo";;
        pool|private_pool)   MINING_MODE="private_pool";;
        public|public_pool)  MINING_MODE="public_pool";;
        *) echo "Unknown --mining-mode '${2:-}' (expected: solo | pool | public)" >&2; usage; exit 1;;
      esac
      shift 2; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    # Backward-compatible alias for --mining-mode solo. Both write the same
    # MINING_MODE variable, so when --mining-mode and --no-public-mining are both
    # passed the last one on the command line wins (predictable left-to-right).
    --no-public-mining) MINING_MODE="private_solo"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --no-reaper)      REAPER="false"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --archive)        ARCHIVE="true"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --ghost-pay)      GHOST_PAY="true"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --wraith)         WRAITH="true"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --no-wraith)      WRAITH="false"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --tor)            TOR="true"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --tor-only)       TOR="true"; TOR_MODE="tor-only"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --no-tor)         TOR="false"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --auto-update)    AUTO_UPDATE="true"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --no-auto-update) AUTO_UPDATE="false"; shift; CONFIG_FLAGS=$((CONFIG_FLAGS+1));;
    --non-interactive) NON_INTERACTIVE="true"; shift;;
    -h|--help)        usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

err() { echo "ERROR: $*" >&2; exit 1; }
log() { echo -e "\033[36m==>\033[0m $*"; }

# One-line human label for a mining_mode value (summary + final output).
mining_mode_label() {
  case "$1" in
    public_pool)  echo "Public Pool (DNS-registered, anyone can mine, +3 shares)";;
    private_pool) echo "Private Pool (password-required, invited miners, not in DNS)";;
    private_solo) echo "Private Solo (password-required, no external miners, solo rewards)";;
    *)            echo "$1";;
  esac
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
# it straight into REAPER / ARCHIVE / GHOST_PAY. The read prompt
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
# sets (PAYOUT_ADDRESS, SYNC_MODE, MINING_MODE, REAPER, ARCHIVE, GHOST_PAY,
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
  echo "  2) fast  assumeutxo — load a verified UTXO snapshot at height 910000 (~9GB download),"
  echo "           usable in minutes, then sync 910000→tip + validate genesis→910000 in the"
  echo "           background. Still trustless (the snapshot hash is checked against chainparams)."
  echo "  3) haze  IRREVERSIBLE — strips block data (~195GB, fast). Can never serve raw blocks or"
  echo "           become an archive node afterwards without a full resync."
  local sync_choice
  read -rp "Choose 1, 2 or 3 [1]: " sync_choice || true
  sync_choice="${sync_choice:-1}"
  case "$sync_choice" in
    1|ibd)  SYNC_MODE="ibd";;
    2|fast) SYNC_MODE="fast";;
    3|haze)
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

  # Mining mode — who can mine and how rewards are shared. Default = Public Pool
  # (option 1), preserving the historical default behaviour.
  echo
  echo "Mining mode (who can mine and how rewards are shared):"
  echo "  1) Public Pool   DNS-registered, ANYONE can mine, pool-aggregated (shared) rewards (+3 shares). RECOMMENDED."
  echo "  2) Private Pool  Password-required, NOT in DNS; your miners + invited external miners, shared rewards."
  echo "  3) Private Solo  Password-required, NOT in DNS, closed to external miners; 99% of subsidy + ALL fees to you."
  local mode_choice
  read -rp "Choose 1, 2 or 3 [1]: " mode_choice || true
  mode_choice="${mode_choice:-1}"
  case "$mode_choice" in
    1|public|public_pool) MINING_MODE="public_pool";;
    2|pool|private_pool)  MINING_MODE="private_pool";;
    3|solo|private_solo)  MINING_MODE="private_solo";;
    *) echo "  Unrecognised choice — using Public Pool."; MINING_MODE="public_pool";;
  esac

  # Optional custom pool name — offered for the pool modes (the coinbase tag
  # identifies a shared pool). Skipped for Private Solo, which has no shared pool
  # identity; it keeps the mode-default tag (set --pool-name explicitly to change
  # it). Blank = mode default. Validated/re-prompted to match the dashboard.
  POOL_NAME=""
  if [[ "$MINING_MODE" == "public_pool" || "$MINING_MODE" == "private_pool" ]]; then
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
  fi

  # Capabilities.
  echo
  echo "Capabilities (each affects your node's reward share):"
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

  # Automatic updates. Off by default — explicit opt-in only. Every applied
  # update verifies the GPG release signature before swapping any binary.
  echo
  echo "Maintenance:"
  AUTO_UPDATE="$(prompt_yes_no "  Enable automatic updates? (verifies GPG signature before applying)" N)"

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
  echo "  Mining mode    : $(mining_mode_label "$MINING_MODE")"
  [[ -n "$POOL_NAME" ]] && echo "  Pool name      : $POOL_NAME  (coinbase: - G H O S T - $POOL_NAME)"
  [[ "$MINING_MODE" == "private_pool" || "$MINING_MODE" == "private_solo" ]] && \
    echo "  Miner password : (generated automatically — shown when install completes)"
  echo "  Reaper         : $REAPER"
  echo "  Archive node   : $ARCHIVE"
  echo "  Ghost Pay      : $GHOST_PAY"
  echo "  Wraith mixing  : $WRAITH"
  echo "  Tor            : $([[ "$TOR" == "true" ]] && echo "$TOR_MODE" || echo "off")"
  echo "  Auto-update    : $AUTO_UPDATE"
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
# Private-mining password. The private modes (private_pool, private_solo) require
# a miner password — ghost-pool refuses to start without one — so we generate a
# strong one here (secure by default; well over the 8-char minimum) and surface
# it to the operator at the end so they can configure their miners. public_pool
# needs none, so it is left empty and never written to pool.toml.
PRIVATE_MINING_PASSWORD=""
if [[ "$MINING_MODE" == "private_pool" || "$MINING_MODE" == "private_solo" ]]; then
  PRIVATE_MINING_PASSWORD="$(openssl rand -hex 16)"
fi
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
# Build the [network] mining block. public_pool emits exactly the historical
# single line (byte-for-byte unchanged). The private modes append the fields
# ghost-pool REQUIRES: a miner password for both, plus the operator's solo
# payout address for private_solo (99% subsidy + all fees route there).
MINING_BLOCK="mining_mode = \"${MINING_MODE}\""
case "$MINING_MODE" in
  private_pool)
    MINING_BLOCK="${MINING_BLOCK}
private_mining_password = \"${PRIVATE_MINING_PASSWORD}\""
    ;;
  private_solo)
    MINING_BLOCK="${MINING_BLOCK}
private_mining_password = \"${PRIVATE_MINING_PASSWORD}\"
solo_payout_address = \"${PAYOUT_ADDRESS}\""
    ;;
esac
# Build the [pool] node-identity block. The optional custom pool_name is appended
# only when set, so the default (no pool_name) output is byte-for-byte unchanged.
# POOL_NAME is already trimmed + validated (printable ASCII, <=30); we still
# TOML-escape backslash and double-quote so the written basic string round-trips
# to exactly the name the dashboard would store (and thus the same coinbase tag).
POOL_IDENTITY_BLOCK="node_payout_address = \"${PAYOUT_ADDRESS}\""
if [[ -n "$POOL_NAME" ]]; then
  POOL_NAME_ESCAPED="${POOL_NAME//\\/\\\\}"
  POOL_NAME_ESCAPED="${POOL_NAME_ESCAPED//\"/\\\"}"
  POOL_IDENTITY_BLOCK="${POOL_IDENTITY_BLOCK}
pool_name = \"${POOL_NAME_ESCAPED}\""
fi
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
${MINING_BLOCK}
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
${POOL_IDENTITY_BLOCK}
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
# External miners are accepted in public_pool AND private_pool — both open the
# Stratum ports (public_pool to anyone, private_pool to password-holders). Only
# private_solo keeps them closed. mining_mode is the single source of truth: the
# legacy public_mining bool was removed and is ignored by ghost-pool, so we key
# purely off mining_mode here to stay consistent with the running node.
accept_miners="no"
if [[ -r "$CONF" ]] \
 && grep -qE '^[[:space:]]*mining_mode[[:space:]]*=[[:space:]]*"?(public_pool|private_pool)"?' "$CONF" 2>/dev/null; then
  accept_miners="yes"
fi
if [[ "$accept_miners" == "yes" ]]; then
  for p in "${PORTS[@]}"; do ufw allow "${p}/tcp" >/dev/null 2>&1 || true; done
  logger -t ghost-mining-firewall "external miners ON (public_pool/private_pool) -> Stratum 3333+34255 OPEN"
else
  for p in "${PORTS[@]}"; do ufw delete allow "${p}/tcp" >/dev/null 2>&1 || true; done
  logger -t ghost-mining-firewall "external miners OFF (private_solo) -> Stratum 3333+34255 CLOSED"
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
# and — ONLY if it is newer than what is installed — downloads the release
# tarball + ghostd, verifies the detached GPG signature against the pinned
# release key AND the ghostd SHA256 against the freshly-fetched install.sh,
# backs up the current binaries, swaps them with a stop→verify-inactive→swap→
# start sequence, health-checks, and rolls back on any failure.
#
# SUPPLY-CHAIN-CRITICAL: a binary is NEVER written unless BOTH the GPG signature
# and the ghostd checksum verify. The verification logic mirrors the first-run
# installer (scripts/install-node.sh) exactly.
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
GHOSTD_URL="${GHOSTD_URL:-https://get.bitcoinghost.org/bin/ghostd}"
# Release tarball base. When GHOST_RELEASE_BASE is set it is used verbatim;
# otherwise it is constructed per-version from the GitHub releases download URL.
RELEASE_BASE_OVERRIDE="${GHOST_RELEASE_BASE:-}"

# ───────────────────────────── managed paths ─────────────────────────────────
CONF_FILE="${GHOST_AUTOUPDATE_CONF:-/etc/ghost/auto-update.conf}"
VERSION_FILE="${GHOST_VERSION_FILE:-/etc/ghost/version}"
STATUS_FILE="${GHOST_AUTOUPDATE_STATUS:-/var/lib/ghost/auto-update.status}"
BIN_DIR="${GHOST_BIN_DIR:-/opt/ghost/bin}"
BITCOIN_CONF="${GHOST_BITCOIN_CONF:-/etc/bitcoin/bitcoin.conf}"
SYSTEMCTL="${GHOST_SYSTEMCTL:-systemctl}"

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
  "latest_version": "${latest}"
}
EOF
  chmod 644 "$STATUS_FILE" 2>/dev/null || true
}

# ─────────────────────────────── helpers ─────────────────────────────────────

# Normalise a version string for comparison: strip a leading 'v'.
normver() { local v="$1"; echo "${v#v}"; }

# Installed version: prefer the file we write on update, fall back to parsing
# `ghost-pool --version` (clap prints "ghost-pool <semver>").
read_installed_version() {
  if [[ -r "$VERSION_FILE" ]]; then
    local v; v="$(tr -d '[:space:]' < "$VERSION_FILE")"
    [[ -n "$v" ]] && { echo "$v"; return 0; }
  fi
  if [[ -x "$BIN_DIR/ghost-pool" ]]; then
    local out; out="$("$BIN_DIR/ghost-pool" --version 2>/dev/null || true)"
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

health_ghost_pool() {
  local resp pc
  for _ in $(seq 1 30); do
    resp="$(curl -fsS --max-time 8 "http://127.0.0.1:8080/health?unsigned=true" 2>/dev/null || true)"
    pc="$(echo "$resp" | grep -oE '"peer_count"[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1 || true)"
    if [[ -n "$pc" && "$pc" -gt 0 ]]; then
      log "health: ghost-pool /health peer_count=$pc"
      return 0
    fi
    sleep 2
  done
  err "health: ghost-pool /health peer_count not > 0 (last='${pc:-none}')"
  return 1
}

health_ghost_pay() {
  # Only meaningful when ghost-pay is installed. Bond ledger serves TLS with an
  # identity-derived cert, so -k (we are localhost, integrity is the binary swap
  # we just verified, not the transport).
  unit_present ghost-pay.service || { log "health: ghost-pay not installed — skipped"; return 0; }
  local code
  for _ in $(seq 1 30); do
    code="$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 8 "https://127.0.0.1:8800/health" 2>/dev/null || true)"
    if [[ "$code" == "200" ]]; then
      log "health: ghost-pay /health=200"
      return 0
    fi
    sleep 2
  done
  err "health: ghost-pay /health != 200 (last='${code:-none}')"
  return 1
}

run_health_checks() {
  # GHOST_HEALTHCHECK_OVERRIDE lets an operator substitute a custom post-update
  # probe (and is the seam the test harness uses to drive the swap/rollback
  # paths offline). Unset in production → the real ghostd/pool/pay probes run.
  if [[ -n "${GHOST_HEALTHCHECK_OVERRIDE:-}" ]]; then
    log "health: running override probe"
    bash -c "$GHOST_HEALTHCHECK_OVERRIDE"
    return $?
  fi
  health_ghostd && health_ghost_pool && health_ghost_pay
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

  # 2. Resolve installed + latest versions.
  local installed latest install_sh ghostd_sha
  installed="$(read_installed_version || true)"
  [[ -n "$installed" ]] || { err "could not determine installed version"; write_status "error" "installed version unknown"; exit 1; }

  install_sh="$(curl -fsSL --max-time 30 "$INSTALL_SH_URL" 2>/dev/null || true)"
  [[ -n "$install_sh" ]] || { err "could not fetch install.sh from $INSTALL_SH_URL"; write_status "error" "install.sh unreachable"; exit 1; }
  latest="$(echo "$install_sh" | grep -m1 -oE 'GHOST_VERSION="?v?[0-9]+\.[0-9]+\.[0-9]+"?' | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  [[ "$latest" == v* ]] || latest="v${latest}"
  ghostd_sha="$(echo "$install_sh" | grep -m1 -oE 'GHOSTD_SHA256="?[0-9a-fA-F]{64}"?' | grep -oE '[0-9a-fA-F]{64}' | head -1 || true)"
  [[ -n "$latest" && "$latest" != "v" ]] || { err "could not parse latest version from install.sh"; write_status "error" "version parse failed"; exit 1; }
  [[ -n "$ghostd_sha" ]] || { err "could not parse GHOSTD_SHA256 from install.sh"; write_status "error" "ghostd sha parse failed"; exit 1; }

  log "installed=$installed latest=$latest"
  if ! is_newer "$installed" "$latest"; then
    log "already up to date ($installed) — no-op"
    write_status "up-to-date" "installed $installed is current" "$latest"
    exit 0
  fi
  log "newer version available: $installed -> $latest"

  # 3. Download artefacts to an isolated temp dir.
  local tarball release_base tmp gnupg
  tarball="bitcoin-ghost-${latest}-x86_64-unknown-linux-gnu.tar.gz"
  if [[ -n "$RELEASE_BASE_OVERRIDE" ]]; then
    release_base="$RELEASE_BASE_OVERRIDE"
  else
    release_base="https://github.com/bitcoin-ghost/ghost/releases/download/${latest}"
  fi
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  gnupg="$tmp/gnupg"; mkdir -m700 "$gnupg"
  export GNUPGHOME="$gnupg"

  log "downloading $tarball + signature + ghostd"
  curl -fsSL --max-time 600 "${release_base}/${tarball}"            -o "$tmp/$tarball"          || { err "download tarball failed"; write_status "error" "tarball download failed" "$latest"; exit 1; }
  curl -fsSL --max-time 60  "${release_base}/SHA256SUMS.txt"        -o "$tmp/SHA256SUMS.txt"    || { err "download SHA256SUMS.txt failed"; write_status "error" "checksums download failed" "$latest"; exit 1; }
  curl -fsSL --max-time 60  "${release_base}/SHA256SUMS.txt.asc"    -o "$tmp/SHA256SUMS.txt.asc" || { err "download signature failed"; write_status "error" "signature download failed" "$latest"; exit 1; }
  curl -fsSL --max-time 600 "$GHOSTD_URL"                           -o "$tmp/ghostd"           || { err "download ghostd failed"; write_status "error" "ghostd download failed" "$latest"; exit 1; }

  # ══════════════════════════════════════════════════════════════════════════
  # 4. MANDATORY VERIFICATION GATE — no binary is touched unless this passes.
  #    (a) detached GPG signature over SHA256SUMS.txt is VALID *and* the signer
  #        is EXACTLY the pinned release-key fingerprint;
  #    (b) the release tarball's SHA256 matches SHA256SUMS.txt;
  #    (c) ghostd's SHA256 matches the value in the freshly-fetched install.sh.
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

  if ( cd "$tmp" && echo "${ghostd_sha}  ghostd" | sha256sum -c - >/dev/null 2>&1 ); then
    log "VERIFY ok: ghostd checksum matches install.sh (${ghostd_sha})"
  else
    err "VERIFY FAILED: ghostd SHA256 mismatch against install.sh — ABORTING, no binary touched."
    write_status "verify-failed" "ghostd checksum mismatch for $latest" "$latest"
    exit 1
  fi

  # 5. Unpack the verified tarball and locate the binaries it carries.
  tar -xzf "$tmp/$tarball" -C "$tmp"
  local new_pool new_pay new_cli
  new_pool="$(find "$tmp" -name ghost-pool -type f | head -1 || true)"
  new_pay="$(find "$tmp" -name ghost-pay -type f | head -1 || true)"
  new_cli="$(find "$tmp" -name ghost-cli -type f | head -1 || true)"
  [[ -n "$new_pool" ]] || { err "verified tarball did not contain ghost-pool"; write_status "error" "tarball missing ghost-pool" "$latest"; exit 1; }

  # Build the swap plan: (dest <- src), only for binaries currently installed
  # (so we never introduce ghost-pay onto a node that opted out of it).
  local -a SWAP_DEST=() SWAP_SRC=()
  SWAP_DEST+=("$BIN_DIR/ghostd");     SWAP_SRC+=("$tmp/ghostd")
  SWAP_DEST+=("$BIN_DIR/ghost-pool"); SWAP_SRC+=("$new_pool")
  if [[ -x "$BIN_DIR/ghost-pay" && -n "$new_pay" ]]; then
    SWAP_DEST+=("$BIN_DIR/ghost-pay"); SWAP_SRC+=("$new_pay")
  fi
  if [[ -x "$BIN_DIR/ghost-cli" && -n "$new_cli" ]]; then
    SWAP_DEST+=("$BIN_DIR/ghost-cli"); SWAP_SRC+=("$new_cli")
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    log "DRY-RUN: verification PASSED for $latest. Would back up + swap:"
    local k
    for k in "${!SWAP_DEST[@]}"; do log "DRY-RUN:   ${SWAP_DEST[$k]} <- ${SWAP_SRC[$k]}"; done
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
    stop_and_wait ghost-pay.service || true
    stop_and_wait ghost-pool.service || true
    stop_and_wait ghostd.service || true
    local j
    for j in "${!BACKUP_DEST[@]}"; do
      cp -p "${BACKUP_DEST[$j]}" "${BACKUP_OF[$j]}" && log "restored ${BACKUP_OF[$j]}"
    done
    $SYSTEMCTL start ghostd.service || true
    sleep 3
    $SYSTEMCTL start ghost-pool.service || true
    unit_present ghost-pay.service && { $SYSTEMCTL start ghost-pay.service || true; }
    return 0  # never let the rollback's last status trip `set -e` in the caller
  }

  # 7. Stop services (reverse dependency order), verify inactive.
  stop_and_wait ghost-pay.service || true
  stop_and_wait ghost-pool.service || { err "ghost-pool would not stop — rolling back"; rollback; write_status "rolled-back" "ghost-pool failed to stop" "$latest"; exit 1; }
  stop_and_wait ghostd.service    || { err "ghostd would not stop — rolling back"; rollback; write_status "rolled-back" "ghostd failed to stop" "$latest"; exit 1; }

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

  # 9. Start services (dependency order).
  $SYSTEMCTL start ghostd.service || { err "ghostd failed to start — rolling back"; rollback; write_status "rolled-back" "ghostd failed to start" "$latest"; exit 1; }
  sleep 3
  $SYSTEMCTL start ghost-pool.service || { err "ghost-pool failed to start — rolling back"; rollback; write_status "rolled-back" "ghost-pool failed to start" "$latest"; exit 1; }
  if unit_present ghost-pay.service; then
    $SYSTEMCTL start ghost-pay.service || { err "ghost-pay failed to start — rolling back"; rollback; write_status "rolled-back" "ghost-pay failed to start" "$latest"; exit 1; }
  fi

  # 10. Health-check; roll back on any failure.
  if run_health_checks; then
    echo "$latest" > "$VERSION_FILE"; chmod 644 "$VERSION_FILE" 2>/dev/null || true
    log "UPDATE COMPLETE: now running $latest (backups: *.bak.${ts})"
    write_status "updated" "updated $installed -> $latest" "$latest"
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
set -euo pipefail

CONF="${GHOST_AUTOUPDATE_CONF:-/etc/ghost/auto-update.conf}"
SYSTEMCTL="${GHOST_SYSTEMCTL:-systemctl}"

case "${1:-}" in
  on)  val="true" ;;
  off) val="false" ;;
  *) echo "usage: ghost-autoupdate-toggle on|off" >&2; exit 2 ;;
esac

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

echo "auto-update set to ${val}"
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

# systemd units (service + 6h randomised timer).
cat > /etc/systemd/system/ghost-auto-update.service <<'GHOST_AUTOUPDATE_SERVICE_EOF'
[Unit]
Description=Bitcoin Ghost opt-in node auto-update (verifies GPG signature before applying)
Documentation=https://get.bitcoinghost.org
# Only meaningful once the node is up; never block boot on it.
After=network-online.target ghostd.service ghost-pool.service
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

systemctl daemon-reload >/dev/null 2>&1 || true
# Enable + start the timer ONLY when opted in. Default path: timer stays
# installed-but-inactive, so the node can never self-upgrade.
if [[ "$AUTO_UPDATE" == "true" ]]; then
  systemctl enable --now ghost-auto-update.timer >/dev/null 2>&1 || true
  log "auto-update ENABLED — checking for signed releases every 6h"
else
  systemctl disable --now ghost-auto-update.timer >/dev/null 2>&1 || true
  log "auto-update disabled (default) — node will not self-upgrade"
fi

# ─────────────────── assumeUTXO snapshot load (--sync fast) ──────────────────
# Runs ONLY for SYNC_MODE=fast, AFTER ghostd is started (loadtxoutset needs a
# live RPC) and BEFORE the sync gate is enabled. Flow: resumable download →
# SHA-256 integrity check → wait for ghostd RPC → loadtxoutset → cleanup. Any
# failure aborts the install loudly; we never start the pool against a node we
# silently failed to seed. See the SNAPSHOT_* constants at the top of this file
# for the trust model (loadtxoutset verifies against pinned chainparams; the
# SHA-256 is only an anti-truncation guard).
load_assumeutxo_snapshot() {
  local conf="/etc/bitcoin/bitcoin.conf"
  local user pass port
  # Reuse the exact RPC credentials the installer just wrote to bitcoin.conf
  # (rpcuser=ghostrpc_mainnet, rpcpassword=$RPCPW) by reading them back, so this
  # stays correct even if those lines ever change shape.
  user="$(grep -m1 '^rpcuser=' "$conf" | cut -d= -f2-)"
  pass="$(grep -m1 '^rpcpassword=' "$conf" | cut -d= -f2-)"
  port="$(grep -m1 '^rpcport=' "$conf" | cut -d= -f2-)"; port="${port:-8332}"
  [[ -n "$user" && -n "$pass" ]] || err "fast sync: could not read ghostd RPC credentials from ${conf}."

  # 1. Resumable download. The host advertises `Accept-Ranges: bytes`, so `-C -`
  #    continues a partial file after an interruption instead of restarting the
  #    ~9GB transfer. The default progress meter (no -s) shows progress/ETA.
  log "fast sync: downloading UTXO snapshot (height ${SNAPSHOT_HEIGHT}, ~9GB) from ${SNAPSHOT_URL}"
  mkdir -p "$(dirname "$SNAPSHOT_PATH")"
  if ! curl -fL -C - --retry 5 --retry-delay 10 --retry-connrefused \
        -o "$SNAPSHOT_PATH" "$SNAPSHOT_URL"; then
    err "fast sync: snapshot download failed from ${SNAPSHOT_URL}."
  fi

  # 2. Integrity gate — verify the file SHA-256 BEFORE handing it to ghostd. On
  #    mismatch, delete the bad file and abort (never loadtxoutset a corrupt or
  #    truncated snapshot). This is integrity only; trust comes from chainparams.
  log "fast sync: verifying snapshot SHA-256 (integrity guard)"
  if ! echo "${SNAPSHOT_SHA256}  ${SNAPSHOT_PATH}" | sha256sum -c - >/dev/null 2>&1; then
    rm -f "$SNAPSHOT_PATH"
    err "fast sync: snapshot SHA-256 mismatch (expected ${SNAPSHOT_SHA256}) — corrupt download deleted, aborting."
  fi
  log "fast sync: snapshot SHA-256 OK"
  # ghostd runs as the `ghost` user and must be able to read the file it loads.
  chown ghost:ghost "$SNAPSHOT_PATH"

  # 3. Wait for ghostd RPC to be ready (it was just started). Poll
  #    getblockchaininfo until it answers — up to ~5min.
  log "fast sync: waiting for ghostd RPC to come up..."
  local up="false" resp _i
  for _i in $(seq 1 60); do
    resp="$(curl -s --max-time 8 --user "${user}:${pass}" \
      --data '{"jsonrpc":"1.0","method":"getblockchaininfo","params":[]}' \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if echo "$resp" | grep -q '"blocks"'; then up="true"; break; fi
    sleep 5
  done
  [[ "$up" == "true" ]] || err "fast sync: ghostd RPC did not come up — aborting (snapshot left at ${SNAPSHOT_PATH})."

  # 4. loadtxoutset — long-running (loads the UTXO set + verifies it against
  #    pinned chainparams). Give curl a long timeout. ghostd returns an object
  #    with `coins_loaded`/`base_height` on success, or a JSON-RPC error (e.g.
  #    txoutset hash mismatch vs chainparams) on failure. Abort loudly on any
  #    error — never proceed as if the load succeeded.
  log "fast sync: loading snapshot via loadtxoutset (verifies against chainparams; takes several minutes)..."
  local payload load_resp
  payload="$(printf '{"jsonrpc":"1.0","method":"loadtxoutset","params":["%s"]}' "$SNAPSHOT_PATH")"
  load_resp="$(curl -s --max-time 3600 --user "${user}:${pass}" \
    --data "$payload" "http://127.0.0.1:${port}/" 2>/dev/null || true)"
  if echo "$load_resp" | grep -q '"coins_loaded"'; then
    log "fast sync: loadtxoutset OK — node live at height ${SNAPSHOT_HEIGHT}, now background-syncing to tip"
  else
    err "fast sync: loadtxoutset FAILED — ghostd response: ${load_resp:-<none>}. Snapshot left at ${SNAPSHOT_PATH} for inspection."
  fi

  # 5. Clean up the 9GB download — loadtxoutset has copied the UTXO set into the
  #    chainstate, so the .dat is no longer needed. ONLY after confirmed success.
  rm -f "$SNAPSHOT_PATH"
  log "fast sync: removed snapshot file ${SNAPSHOT_PATH} (UTXO set now in chainstate)"
}

# ─────────────────────────────── 11. start ───────────────────────────────────
log "Starting services"
systemctl daemon-reload
systemctl enable --now ghostd >/dev/null 2>&1
# --sync fast: seed the chainstate from the assumeUTXO snapshot now that ghostd's
# RPC is (coming) up, before the gate is enabled. The sync gate below is UNCHANGED
# and already correct for assumeUTXO: getblockchaininfo's initialblockdownload
# reflects the ACTIVE (snapshot) chainstate, whose tip is ~10 months old right
# after the load, so it stays `true` until the 910000→tip sync nears completion —
# i.e. the gate starts ghost-pool when the node is genuinely near-tip and usable,
# not at the instant of load. (ibd/haze paths skip this entirely.)
if [[ "$SYNC_MODE" == "fast" ]]; then
  load_assumeutxo_snapshot
fi
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

# Private modes need a miner password — show it now (and where it lives) so the
# operator can point their mining software at this node.
if [[ "$MINING_MODE" == "private_pool" || "$MINING_MODE" == "private_solo" ]]; then
  if [[ "$MINING_MODE" == "private_pool" ]]; then
    REACH_NOTE="External miners may connect to Stratum on this host's ports 3333 (SV1) / 34255 (SV2)."
  else
    REACH_NOTE="Stratum ports 3333 (SV1) / 34255 (SV2) are CLOSED to external miners — only miners you run locally can connect."
  fi
cat <<EOF

  🔒 Mining mode: $(mining_mode_label "$MINING_MODE")
     Miners must authenticate with this password (stored in
     /etc/ghost/pool.toml as [network] private_mining_password):

         ${PRIVATE_MINING_PASSWORD}

     Keep it safe — anyone with it can mine on this node.
     ${REACH_NOTE}
EOF
fi
