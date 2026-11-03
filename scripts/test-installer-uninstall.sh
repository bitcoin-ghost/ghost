#!/usr/bin/env bash
#
# Self-test for `install-node.sh --uninstall` (and `--purge`).
#
# What must hold: the units, timers, drop-ins, /opt/ghost, the firewall rules the installer opened,
# its sudoers files and the release channel marker go; the node's data stays (the chain,
# node-pool.db, node.key, the configs, the backups) unless --purge is given; 22/tcp is never
# closed; and nothing happens without a confirmation, which a script gives with --yes.
#
# Hermetic: the installer's NP_UNINSTALL block is run against a throwaway root (UNINSTALL_ROOT),
# with systemctl, ufw, userdel and id stood in for. Nothing here touches systemd or a firewall.
# shellcheck disable=SC2034,SC2329,SC2016
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

block="$(sed -n '/^# >>> NP_UNINSTALL$/,/^# <<< NP_UNINSTALL$/p' "$INSTALLER")"
is "the uninstall block is present" yes "$([ "$(printf '%s\n' "$block" | wc -l)" -gt 50 ] && echo yes)"

# A node as the installer leaves it, under $TMP/root-NAME.
make_node() {
    local r="$TMP/root-$1" u
    mkdir -p "$r/etc/systemd/system" "$r/opt/ghost/bin" "$r/opt/ghost/dashboard/.next" "$r/opt/ghost/node-v22.23.4/bin" \
             "$r/opt/ghost/scripts" "$r/etc/ghost" "$r/etc/bitcoin" "$r/etc/sudoers.d" "$r/var/lib/bitcoin/signet" \
             "$r/var/lib/ghost" "$r/home/ghost/.ghost/data" "$r/var/backups/ghost/db" "$r/var/lib/ghost-backup" \
             "$r/etc/systemd/journald.conf.d"
    for u in ghostd.service ghost-mining.service ghost-mining-gate.service sri-pool.service sri-translator.service \
             ghost-dashboard.service ghost-auto-update.service ghost-auto-update.timer ghost-restart-watch.service \
             ghost-restart-watch.timer ghost-backup.service ghost-backup.timer ghost-mining-firewall.service \
             ghost-mining-firewall.path; do echo "[Unit]" > "$r/etc/systemd/system/$u"; done
    mkdir -p "$r/etc/systemd/system/ghost-dashboard.service.d" "$r/etc/systemd/system/ghost-mining.service.d" \
             "$r/etc/systemd/system/ghost-auto-update.service.d"
    echo x > "$r/etc/systemd/system/ghost-dashboard.service.d/internal-auth.conf"
    # Something the installer did not write, which must survive.
    echo "[Unit]" > "$r/etc/systemd/system/someone-else.service"
    for b in ghostd ghost-mining pool_sv2 translator_sv2 ghost-cli ghost-admin; do echo bin > "$r/opt/ghost/bin/$b"; done
    echo js > "$r/opt/ghost/dashboard/server.js"
    ln -s node-v22.23.4 "$r/opt/ghost/node"
    printf 'chain=signet\n[signet]\nport=38333\nrpcpassword=pw\n' > "$r/etc/bitcoin/bitcoin.conf"
    printf '[node_pool.relay]\nlisten = "0.0.0.0:9566"\n' > "$r/etc/ghost/pool-config.toml"
    echo 'internal_api_secret = "s"' > "$r/etc/ghost/pool.toml"
    echo 'DASHBOARD_PASSWORD=p' > "$r/etc/ghost/dashboard.env"
    echo node-pool > "$r/etc/ghost/release-channel"
    echo np-v2.0.0 > "$r/etc/ghost/version"
    echo AUTO_UPDATE=true > "$r/etc/ghost/auto-update.conf"
    echo x > "$r/etc/sudoers.d/ghost-autoupdate"; echo x > "$r/etc/sudoers.d/ghost-backup-offsite"
    echo x > "$r/etc/sudoers.d/someone-else"
    echo x > "$r/etc/systemd/journald.conf.d/10-ghost.conf"
    echo key > "$r/home/ghost/.ghost/node.key"
    echo db > "$r/var/lib/ghost/node-pool.db"
    echo chain > "$r/var/lib/bitcoin/signet/blocks"
    echo gz > "$r/var/backups/ghost/db/ghost-202611030300.db.gz"
    echo "$r"
}

# uninstall NAME PURGE YES [tty] — runs the block, records systemctl/ufw/userdel calls in $R/calls.
uninstall() {
    R="$(make_node "$1")"
    ( set -euo pipefail
      calls="$R/calls"; : > "$calls"
      systemctl() { echo "systemctl $*" >> "$calls"; }
      ufw() { echo "ufw $*" >> "$calls"; }
      userdel() { echo "userdel $*" >> "$calls"; }
      id() { [ "$1" = ghost ]; }
      log() { echo "==> $*"; }
      err() { echo "ERROR: $*" >&2; exit 1; }
      UNINSTALL=true PURGE="$2" ASSUME_YES="$3"
      export UNINSTALL_ROOT="$R"
      eval "$block"
      np_uninstall ) > "$R/out" 2>&1 < /dev/null
    echo $? > "$R/rc"
}
gone()  { [ -e "$R$1" ] || [ -L "$R$1" ] && echo present || echo gone; }
calls() { cat "$R/calls" 2>/dev/null; }

echo "1. --uninstall --yes keeps the data"
uninstall keep false true
is "exits 0" 0 "$(cat "$R/rc")"
for u in ghostd.service ghost-mining.service ghost-mining-gate.service sri-pool.service sri-translator.service \
         ghost-dashboard.service ghost-auto-update.timer ghost-restart-watch.timer ghost-backup.timer ghost-mining-firewall.path; do
    is "unit $u removed" gone "$(gone "/etc/systemd/system/$u")"
    has "... after it was disabled and stopped" "systemctl disable --now $u" "$(calls)"
done
is "the dashboard's drop-ins removed" gone "$(gone /etc/systemd/system/ghost-dashboard.service.d)"
is "a unit the installer did not write is left alone" present "$(gone /etc/systemd/system/someone-else.service)"
has "systemd reloaded" "systemctl daemon-reload" "$(calls)"
is "/opt/ghost removed (binaries, dashboard, Node.js)" gone "$(gone /opt/ghost)"
for p in 38333 9566 8080 3333 34255 4444 8442; do
    has "firewall rule $p/tcp removed" "ufw delete allow $p/tcp" "$(calls)"
done
is "22/tcp is never touched" 0 "$(calls | $G -c ' 22/tcp' || true)"
is "ufw is not disabled" 0 "$(calls | $G -cE 'ufw (disable|reset)' || true)"
is "the other networks' P2P ports are not touched when the config names one" 0 "$(calls | $G -cE ' (8333|18444)/tcp' || true)"
for f in /etc/sudoers.d/ghost-autoupdate /etc/sudoers.d/ghost-backup-offsite /etc/ghost/release-channel \
         /etc/ghost/version /etc/ghost/auto-update.conf /etc/systemd/journald.conf.d/10-ghost.conf; do
    is "$f removed" gone "$(gone "$f")"
done
is "another sudoers file is left alone" present "$(gone /etc/sudoers.d/someone-else)"
for f in /var/lib/bitcoin/signet/blocks /var/lib/ghost/node-pool.db /home/ghost/.ghost/node.key /etc/ghost/pool.toml \
         /etc/ghost/pool-config.toml /etc/ghost/dashboard.env /etc/bitcoin/bitcoin.conf /var/backups/ghost/db/ghost-202611030300.db.gz; do
    is "kept: $f" present "$(gone "$f")"
done
is "the ghost user is kept" 0 "$(calls | $G -c userdel || true)"
out="$(cat "$R/out")"
has "it says what it kept" "Kept (installing again reuses all of it):" "$out"
has "... naming node-pool.db" "node-pool.db (share chain and ledger)" "$out"
has "... and node.key" ".ghost/node.key (node identity)" "$out"
has "... and how to delete it too" "--uninstall --purge" "$out"

echo "2. --uninstall --purge --yes deletes the data too"
uninstall purge true true
is "exits 0" 0 "$(cat "$R/rc")"
for d in /var/lib/bitcoin /var/lib/ghost /home/ghost /etc/ghost /etc/bitcoin /var/backups/ghost /var/lib/ghost-backup /opt/ghost; do
    is "$d deleted" gone "$(gone "$d")"
done
has "the ghost user is deleted" "userdel ghost" "$(calls)"
is "22/tcp is still never touched" 0 "$(calls | $G -c ' 22/tcp' || true)"
is "a unit the installer did not write survives a purge" present "$(gone /etc/systemd/system/someone-else.service)"

echo "3. nothing happens without confirmation"
if command -v setsid >/dev/null; then
    # Run detached from any terminal, as under `curl | sudo bash` with no tty.
    R2="$(make_node notty2)"
    setsid -w bash -c '
        R="$1"; block="$2"; calls="$R/calls"
        systemctl() { echo "systemctl $*" >> "$calls"; }; ufw() { echo "ufw $*" >> "$calls"; }
        userdel() { :; }; id() { :; }; log() { :; }; err() { echo "ERROR: $*" >&2; exit 1; }
        UNINSTALL=true PURGE=false ASSUME_YES=false; export UNINSTALL_ROOT="$R"
        eval "$block"; np_uninstall' _ "$R2" "$block" > "$R2/out" 2>&1 < /dev/null
    echo $? > "$R2/rc"; R="$R2"
    is "with no terminal and no --yes it refuses" 1 "$(cat "$R/rc")"
    has "... saying how to confirm" "Re-run with --yes" "$(cat "$R/out")"
    is "... having changed nothing" present "$(gone /opt/ghost/bin/ghostd)"
    is "... and stopped nothing" 0 "$(calls | $G -c . || true)"
else
    echo "  (setsid not available: skipped)"
fi

echo "4. wiring"
is "--uninstall runs before the wizard, the preflight and any download" yes \
   "$(awk '/^  np_uninstall$/{u=NR} /^  run_wizard$/{w=NR} /^np_preflight \|\|/{p=NR} /^curl -fsSLO/{if(!c)c=NR} END{print (u && w && p && c && u<w && u<p && u<c)?"yes":"no"}' "$INSTALLER")"
is "... after the root check" yes \
   "$(awk '/^\[\[ \$EUID -eq 0 \]\]/{r=NR} /^  np_uninstall$/{u=NR} END{print (r && u && r<u)?"yes":"no"}' "$INSTALLER")"
is "--purge alone is refused" 1 "$($G -c '^\[\[ "\$PURGE" != true \]\] || err "--purge goes with --uninstall."' "$INSTALLER" || true)"
is "every unit the installer writes is one it removes" "" \
   "$(comm -23 <($G -oE '^cat > /etc/systemd/system/[a-z-]+\.(service|timer|path)' "$INSTALLER" | sed 's#.*/##' | sort -u) \
              <(printf '%s\n' "$block" | $G -oE '[a-z-]+\.(service|timer|path)' | sort -u) | paste -sd' ')"

echo
echo "test-installer-uninstall: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
