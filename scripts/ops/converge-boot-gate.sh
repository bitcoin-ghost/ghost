#!/usr/bin/env bash
#
# Make ghost-mining-gate the only thing that starts the node and the stratum stack (#1020).
#
# `sri-pool.service` carried `Wants=ghost-mining.service`, and sri-pool is enabled at boot, so
# the node was started by systemd ahead of the gate on every reboot — the gate's "ghostd synced
# — starting ghost-mining" has been a no-op on every node. `deploy-node.sh` swaps binaries and
# never touches a unit file or its enablement, so nothing else brings a node to the new shape.
#
# Per node, in this order, because each step is only safe after the one before it:
#
#   1. the gate script   — the canonical copy starts sri-pool and sri-translator after the node.
#                          The copy on a node today starts the node only.
#   2. sri-pool.service  — the canonical unit, without `Wants=`. `daemon-reload` only.
#   3. disable sri-pool and sri-translator at boot. NEVER before step 1 is verified: with these
#      disabled and the old gate script, a reboot would leave the node with no stratum.
#
# This does NOT restart, stop or start anything. None of it is read by a running process: the
# gate script runs at boot, and ordering and enablement apply at the next start. Every unit's
# main PID is compared before and after to prove it.
#
# Usage:
#   scripts/ops/converge-boot-gate.sh [--dry-run] [<node> ...]   # defaults to all eight
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE_SRC="$REPO_ROOT/scripts/ops/fleet-files/wait-for-ghostd-sync.sh"
UNIT_SRC="$REPO_ROOT/config/sri/sri-pool.service"
G=/usr/bin/grep

DRY=false
if [ "${1:-}" = "--dry-run" ]; then DRY=true; shift; fi

[ -f "$GATE_SRC" ] && [ -f "$UNIT_SRC" ] || { echo "REFUSING: canonical gate script or sri-pool unit missing"; exit 2; }
bash -n "$GATE_SRC" || { echo "REFUSING: the gate script is not valid bash"; exit 1; }

# Refuse to converge the fleet onto sources that would not do the job: a gate script that does
# not start the stack, or a unit that still pulls the node in.
for svc in sri-pool sri-translator; do
    $G -q "$svc" "$GATE_SRC" || { echo "REFUSING: the canonical gate script does not start $svc"; exit 1; }
done
if $G -qE '^(Wants|Requires|Requisite|BindsTo|Upholds)=.*ghost-(mining|pool)\.service' "$UNIT_SRC"; then
    echo "REFUSING: config/sri/sri-pool.service still pulls the node unit in"; exit 1
fi

NODES=("$@")
if [ ${#NODES[@]} -eq 0 ]; then
    NODES=(ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4 ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8)
fi

GATE_SHA="$(sha256sum "$GATE_SRC" | cut -d' ' -f1)"
UNIT_SHA="$(sha256sum "$UNIT_SRC" | cut -d' ' -f1)"
echo "Canonical wait-for-ghostd-sync.sh = ${GATE_SHA:0:16}"
echo "Canonical sri-pool.service        = ${UNIT_SHA:0:16}"
$DRY && echo "(dry run -- nothing will be written)"
echo

# One line of state per node, read from what systemd has LOADED rather than from files:
#   gate=<sha16> unit=<sha16> pulled=<units that start the node> pool=<is-enabled>
#   trans=<is-enabled> gateunit=<is-enabled> active=<4 states> pids=<4 main pids>
STATE='
S=$(command -v sudo >/dev/null && echo "sudo -n" || echo)
GU=ghost-mining; systemctl cat ghost-mining.service >/dev/null 2>&1 || GU=ghost-pool
printf "gate=%s unit=%s pulled=%s pool=%s trans=%s gateunit=%s active=%s pids=%s\n" \
  "$($S sha256sum /opt/ghost/bin/wait-for-ghostd-sync.sh 2>/dev/null | cut -d" " -f1)" \
  "$($S sha256sum /etc/systemd/system/sri-pool.service 2>/dev/null | cut -d" " -f1)" \
  "$(systemctl show "$GU" -p WantedBy -p RequiredBy -p BoundBy -p UpheldBy --value 2>/dev/null | tr -s " \n" "," | sed -e "s/^,//" -e "s/,\$//")" \
  "$(systemctl is-enabled sri-pool 2>/dev/null | head -1)" \
  "$(systemctl is-enabled sri-translator 2>/dev/null | head -1)" \
  "$(systemctl is-enabled "$GU-gate" 2>/dev/null | head -1)" \
  "$(systemctl is-active ghostd "$GU" sri-pool sri-translator 2>/dev/null | tr "\n" ",")" \
  "$(for u in ghostd "$GU" sri-pool sri-translator; do systemctl show "$u" -p MainPID --value; done | tr "\n" ",")"
'
field() { printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p"; }
state_of() { ssh -o ConnectTimeout=15 -o BatchMode=yes "$1" "$STATE" 2>/dev/null; }
converged() { # converged <state line>
    [ "$(field "$1" gate)" = "$GATE_SHA" ] && [ "$(field "$1" unit)" = "$UNIT_SHA" ] \
        && [ -z "$(field "$1" pulled)" ] && [ "$(field "$1" pool)" = disabled ] \
        && [ "$(field "$1" trans)" = disabled ]
}

rc=0
changed=0
for n in "${NODES[@]}"; do
    printf '%-10s ' "$n"

    before="$(state_of "$n")"
    if [ -z "$before" ] || [ -z "$(field "$before" pids)" ]; then
        echo "UNREADABLE"; rc=1; continue
    fi
    # The gate must own the boot start before anything is taken away from systemd.
    case "$(field "$before" gateunit)" in
        enabled|enabled-runtime|static) ;;
        *) echo "REFUSING: ghost-mining-gate is '$(field "$before" gateunit)' — with the stratum units disabled nothing would start this node at boot"
           rc=1; continue ;;
    esac
    if converged "$before"; then
        echo "already converged"; continue
    fi

    changed=$((changed + 1))
    if $DRY; then
        todo=""
        [ "$(field "$before" gate)" = "$GATE_SHA" ] || todo="$todo gate-script"
        [ "$(field "$before" unit)" = "$UNIT_SHA" ] || todo="$todo sri-pool.service"
        [ "$(field "$before" pool)" = disabled ]    || todo="$todo disable-sri-pool"
        [ "$(field "$before" trans)" = disabled ]   || todo="$todo disable-sri-translator"
        echo "WOULD UPDATE:$todo (node started by: $(field "$before" pulled))"
        continue
    fi

    if ! scp -q -o ConnectTimeout=15 -o BatchMode=yes "$GATE_SRC" "$n:/tmp/wait-for-ghostd-sync.sh.new" 2>/dev/null \
       || ! scp -q -o ConnectTimeout=15 -o BatchMode=yes "$UNIT_SRC" "$n:/tmp/sri-pool.service.new" 2>/dev/null; then
        echo "SCP FAILED"; rc=1; continue
    fi
    TS="$(date -u +%Y%m%d-%H%M%S)"
    # `set -e` on the node: a failed step must stop the ones after it, above all the disable.
    out="$(ssh -o ConnectTimeout=30 -o BatchMode=yes "$n" "
        set -e
        S=\$(command -v sudo >/dev/null && echo 'sudo -n' || echo)
        [ \"\$(sha256sum /tmp/wait-for-ghostd-sync.sh.new | cut -d' ' -f1)\" = '$GATE_SHA' ]
        [ \"\$(sha256sum /tmp/sri-pool.service.new | cut -d' ' -f1)\" = '$UNIT_SHA' ]
        bash -n /tmp/wait-for-ghostd-sync.sh.new
        \$S cp -p /opt/ghost/bin/wait-for-ghostd-sync.sh /opt/ghost/bin/wait-for-ghostd-sync.sh.bak.$TS
        \$S install -m 755 -o root -g root /tmp/wait-for-ghostd-sync.sh.new /opt/ghost/bin/wait-for-ghostd-sync.sh
        [ \"\$(\$S sha256sum /opt/ghost/bin/wait-for-ghostd-sync.sh | cut -d' ' -f1)\" = '$GATE_SHA' ]
        echo GATE_OK
        \$S cp -p /etc/systemd/system/sri-pool.service /etc/systemd/system/sri-pool.service.bak.$TS
        \$S install -m 644 -o root -g root /tmp/sri-pool.service.new /etc/systemd/system/sri-pool.service
        \$S systemctl daemon-reload
        echo UNIT_OK
        \$S systemctl disable sri-pool.service sri-translator.service >/dev/null 2>&1
        echo DISABLE_OK
        rm -f /tmp/wait-for-ghostd-sync.sh.new /tmp/sri-pool.service.new
    " 2>&1)"
    if ! printf '%s\n' "$out" | $G -q DISABLE_OK; then
        last="$(printf '%s\n' "$out" | $G -E '_OK$' | tail -1)"
        echo "FAILED after '${last:-nothing}': $(printf '%s\n' "$out" | $G -vE '_OK$' | tail -1)"
        rc=1; continue
    fi

    after="$(state_of "$n")"
    if converged "$after" \
       && [ "$(field "$after" active)" = "active,active,active,active," ] \
       && [ "$(field "$after" pids)" = "$(field "$before" pids)" ]; then
        echo "converged | gate script canonical, nothing starts the node but the gate, stratum units disabled at boot, all 4 services active on unchanged PIDs"
    else
        echo "updated BUT NOT VERIFIED:"
        echo "             before: $before"
        echo "             after:  $after"
        rc=1
    fi
done

echo
echo "changed=$changed  exit=$rc"
exit "$rc"
