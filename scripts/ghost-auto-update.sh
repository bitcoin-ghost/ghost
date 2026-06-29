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
