#!/usr/bin/env bash
#
# Converge the ghost-pool unit's installer-parity drop-in onto the fleet (#1007).
#
# `deploy-node.sh` swaps binaries and never touches a unit file, so a node keeps the unit it was
# provisioned with. vm1-vm4 predate the installer's current ghost-pool unit and were missing four
# of its directives; `check-fleet-is-current.sh` reported them after every roll with no tool that
# owned the fix. `config/ghost-pool.service` is NOT that fix -- it differs from the live unit in
# ExecStart and hardening, and installing it over a running node's unit would change far more than
# the four lines in question.
#
# This does NOT restart anything, and unlike the sri-pool log level there is no restart pending
# afterwards either: none of these directives is read by the running process. Ordering applies at
# the next start and RestartSec at the next automatic restart, both from the unit systemd has
# loaded, so `daemon-reload` is the whole change.
#
# Usage:
#   scripts/ops/converge-ghost-pool-unit.sh [--dry-run] [<node> ...]   # defaults to all eight
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$REPO_ROOT/config/ghost-pool.service.d/installer-parity.conf"
DEST=/etc/systemd/system/ghost-pool.service.d/installer-parity.conf
INSTALLER="$REPO_ROOT/scripts/install-node.sh"

DRY=false
if [ "${1:-}" = "--dry-run" ]; then DRY=true; shift; fi

[ -f "$SRC" ] || { echo "REFUSING: canonical drop-in missing: $SRC"; exit 2; }

# The directives this file asserts, read from the file rather than listed a second time here.
WANT="$(/usr/bin/grep -E '^[A-Za-z][A-Za-z0-9]*=' "$SRC")"
WANT_N="$(printf '%s\n' "$WANT" | /usr/bin/grep -c . || true)"
[ "$WANT_N" -gt 0 ] || { echo "REFUSING: $SRC carries no directives"; exit 1; }

# The drop-in exists to match the installer. If the two have drifted, converging the fleet onto
# this file would move it AWAY from what a fresh node gets, and the currency check would go on
# reporting the difference -- so refuse, and say which line.
UNIT_BODY="$(awk '
    index($0, "Description=") && index($0, "Ghost Pool node") { on = 1 }
    on { print }
    on && /WantedBy=multi-user.target/ { exit }
' "$INSTALLER")"
[ -n "$UNIT_BODY" ] || { echo "REFUSING: no ghost-pool unit found in $INSTALLER"; exit 2; }
while IFS= read -r d; do
    printf '%s\n' "$UNIT_BODY" | /usr/bin/grep -qxF "$d" \
        || { echo "REFUSING: '$d' is in the drop-in but not in the installer's ghost-pool unit"; exit 1; }
done <<< "$WANT"

NODES=("$@")
if [ ${#NODES[@]} -eq 0 ]; then
    NODES=(ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4 ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8)
fi

WANT_SHA="$(sha256sum "$SRC" | cut -c1-16)"
echo "Canonical installer-parity.conf = $WANT_SHA ($WANT_N directives)"
$DRY && echo "(dry run -- nothing will be written)"
echo

rc=0
changed=0
for n in "${NODES[@]}"; do
    printf '%-10s ' "$n"

    live="$(ssh -o ConnectTimeout=15 -o BatchMode=yes "$n" 'systemctl cat ghost-pool 2>/dev/null' 2>/dev/null)"
    if [ -z "$live" ]; then
        echo "UNREADABLE: \`systemctl cat ghost-pool\` returned nothing"; rc=1; continue
    fi
    missing=0
    while IFS= read -r d; do
        printf '%s\n' "$live" | /usr/bin/grep -qxF "$d" || missing=$((missing + 1))
    done <<< "$WANT"

    if [ "$missing" -eq 0 ]; then
        # Already has every directive, from its base unit or from this drop-in. Writing the file
        # anyway would add a drop-in that changes nothing to nodes that do not need one.
        echo "already has all $WANT_N directives"
        continue
    fi

    changed=$((changed + 1))
    if $DRY; then
        echo "WOULD UPDATE ($missing of $WANT_N directives missing)"
        continue
    fi

    if ! scp -q -o ConnectTimeout=15 -o BatchMode=yes "$SRC" "$n:/tmp/ghost-pool-installer-parity.conf" 2>/dev/null; then
        echo "SCP FAILED"; rc=1; continue
    fi
    out="$(ssh -o ConnectTimeout=20 -o BatchMode=yes "$n" \
        'S=$(command -v sudo >/dev/null && echo "sudo -n" || echo)
         $S mkdir -p /etc/systemd/system/ghost-pool.service.d &&
         $S cp /tmp/ghost-pool-installer-parity.conf '"$DEST"' &&
         $S chmod 0644 '"$DEST"' &&
         rm -f /tmp/ghost-pool-installer-parity.conf &&
         $S systemctl daemon-reload && echo RELOAD_OK' 2>&1)"
    if ! printf '%s\n' "$out" | /usr/bin/grep -q RELOAD_OK; then
        echo "FAILED: $(printf '%s\n' "$out" | tail -1)"; rc=1; continue
    fi

    # Positive check, from what systemd has LOADED rather than from the file just written: every
    # directive present, the restart delay in effect, and the service untouched by the reload.
    after="$(ssh -o ConnectTimeout=15 -o BatchMode=yes "$n" \
        'systemctl cat ghost-pool 2>/dev/null; echo "@@RESTART_USEC=$(systemctl show ghost-pool -p RestartUSec --value)"; echo "@@ACTIVE=$(systemctl is-active ghost-pool)"' 2>/dev/null)"
    still=0
    while IFS= read -r d; do
        printf '%s\n' "$after" | /usr/bin/grep -qxF "$d" || still=$((still + 1))
    done <<< "$WANT"
    usec="$(printf '%s\n' "$after" | sed -n 's/^@@RESTART_USEC=//p')"
    active="$(printf '%s\n' "$after" | sed -n 's/^@@ACTIVE=//p')"
    if [ "$still" -eq 0 ] && [ "$usec" = "15s" ] && [ "$active" = "active" ]; then
        echo "updated+reloaded | all $WANT_N directives loaded, RestartSec=$usec, ghost-pool $active (not restarted)"
    else
        echo "updated BUT NOT VERIFIED: $still directive(s) still missing, RestartSec='${usec:-?}', ghost-pool '${active:-?}'"
        rc=1
    fi
done

echo
echo "changed=$changed  exit=$rc"
exit "$rc"
