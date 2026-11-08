#!/usr/bin/env bash
#
# Self-test for the end of the open-listing lister (W2.10). Ghost Pool has no share chain and no
# listing, so the installer has no lister: no flag, no unit, no env file, no enable step. What an
# older (node pool) install left is cleaned up. Asserted against the installer's OWN text:
#   1. no --lister flag, no LISTER variable, no unit or env file is written;
#   2. a re-run over an older install stops and removes the lister's unit and its env file (which
#      held the RPC password), reloads systemd, and leaves its data (user, state) for --purge;
#      a machine without one is left untouched;
#   3. --uninstall still knows the lister's unit, its user and its state directory;
#   4. the auto-updater no longer restarts it.
#
# Hermetic: the installer is never run; its pieces are extracted and run against stubs.
# shellcheck disable=SC2034,SC2329
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${INSTALLER:-$REPO_ROOT/scripts/install-node.sh}"
UPDATER="$REPO_ROOT/scripts/ghost-auto-update.sh"
G=/usr/bin/grep
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
is() { if [ "$2" = "$3" ]; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
       else printf "  [BAD] %s\n        wanted: %s\n        got:    %s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }
has() { if printf '%s\n' "$3" | $G -qF -- "$2"; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
        else printf "  [BAD] %s\n        wanted a line with: %s\n        in:\n%s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }

echo "1. nothing installs a lister"
is "no LISTER variable" 0 "$($G -cE '^\s*LISTER(_[A-Z_]+)?=' "$INSTALLER" || true)"
is "no --lister flag arm" 0 "$($G -cE '^\s+--(no-)?lister[a-z-]*(\|[a-z-]+)*\)' "$INSTALLER" || true)"
is "--lister is not in the help" 0 "$($G -cE '^  --(no-)?lister' "$INSTALLER" || true)"
is "no lister unit is written" 0 "$($G -cE 'cat > /etc/systemd/system/ghost-lister.service' "$INSTALLER" || true)"
is "no lister env file is written" 0 "$($G -cE '(cat|printf).*> /etc/ghost/lister.env' "$INSTALLER" || true)"
is "nothing enables it" 0 "$($G -cE 'enable (--now )?ghost-lister' "$INSTALLER" || true)"
is "no ghost-audit user is created" 0 "$($G -cE 'useradd .*ghost-audit' "$INSTALLER" || true)"
is "the unit file is gone from the repository" absent "$([ -e "$REPO_ROOT/scripts/systemd/ghost-lister.service" ] && echo present || echo absent)"

echo "2. an older install's lister is removed on a re-run"
block="$(sed -n '/^# >>> NP_LISTER_GONE$/,/^# <<< NP_LISTER_GONE$/p' "$INSTALLER")"
is "the clean-up block is present" yes "$([ -n "$block" ] && echo yes)"
cleanup() {   # NAME HAS_UNIT HAS_ENV: runs the block against $TMP/root-NAME, prints the calls
    local r="$TMP/root-$1"
    mkdir -p "$r/etc/systemd/system" "$r/etc/ghost" "$r/var/lib/ghost-audit"
    [ "$2" = yes ] && echo "[Unit]" > "$r/etc/systemd/system/ghost-lister.service"
    [ "$3" = yes ] && echo "GHOST_RPC_PASSWORD=pw" > "$r/etc/ghost/lister.env"
    echo state > "$r/var/lib/ghost-audit/state.json"
    ( calls=""; systemctl() { calls+="systemctl $*;"; }; log() { calls+="log $*;"; }
      b="${block//\/etc\//$r\/etc\/}"
      eval "$b"; printf '%s' "$calls" )
}
present() { [ -e "$1" ] && echo present || echo gone; }
c="$(cleanup old yes yes)"
has "the lister is stopped and disabled" "systemctl disable --now ghost-lister.service" "$c"
is "its unit is removed" gone "$(present "$TMP/root-old/etc/systemd/system/ghost-lister.service")"
is "its env file (the RPC password) is removed" gone "$(present "$TMP/root-old/etc/ghost/lister.env")"
has "systemd is reloaded" "systemctl daemon-reload" "$c"
has "the install says so" "Removed an older install's open-listing lister" "$c"
is "its state is data, kept until --purge" present "$(present "$TMP/root-old/var/lib/ghost-audit/state.json")"
c="$(cleanup envonly no yes)"
is "an env file alone is removed too" gone "$(present "$TMP/root-envonly/etc/ghost/lister.env")"
c="$(cleanup fresh no no)"
is "a machine that never had one: nothing is called" "" "$c"
is "the clean-up runs before the services start" yes \
   "$(awk '/^# >>> NP_LISTER_GONE$/{b=NR} /^log "Starting services"$/{s=NR} END{print (b && s && b<s)?"yes":"no"}' "$INSTALLER")"

echo "3. --uninstall still removes what an older install left"
un="$(sed -n '/^# >>> NP_UNINSTALL$/,/^# <<< NP_UNINSTALL$/p' "$INSTALLER")"
has "the lister's unit is in the unit list" "ghost-lister.service" "$(printf '%s\n' "$un" | $G -A4 '^NP_UNITS=(')"
has "its state is in the data list (deleted by --purge)" "/var/lib/ghost-audit" "$(printf '%s\n' "$un" | $G -A2 '^NP_DATA=(')"
has "its user is removed by --purge" "userdel ghost-audit" "$un"

echo "4. the auto-updater"
is "it no longer restarts the lister" 0 "$($G -c 'ghost-lister' "$UPDATER" || true)"
is "nor does the installer's copy of it" 0 "$(sed -n '/^cat > \/opt\/ghost\/bin\/ghost-auto-update.sh/,/^GHOST_AUTOUPDATE_SH_EOF$/p' "$INSTALLER" | $G -c 'ghost-lister' || true)"

echo
echo "test-installer-lister: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
