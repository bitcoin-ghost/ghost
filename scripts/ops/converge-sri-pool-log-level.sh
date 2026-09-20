#!/usr/bin/env bash
#
# Converge the sri-pool RUST_LOG drop-in onto the fleet (#903).
#
# The installer used to write `Environment=RUST_LOG=debug` into sri-pool.service, so seven
# of eight nodes run the mining endpoint at debug. That is ~30x the log volume vm8 produces
# and it evicts journald's 2G cap: vm5 retained 4.1 days where every other node retained the
# full two weeks. install-node.sh is fixed, but an ALREADY PROVISIONED node keeps its old
# base unit, and systemd offers no way to unset that except a drop-in or a unit rewrite.
# A drop-in is reversible and is exactly what vm8 has run since 2026-07-25.
#
# Like deploy-fleet-file.sh, this converges CONFIG and deliberately does NOT restart
# anything: `systemd-reload` makes the new value the one the unit will use, and the next
# restart picks it up. That is the point -- it lets the log-level change ride along with a
# binary roll instead of spending a restart of its own, and every node is in the mining DNS
# so every restart sheds that node's miners.
#
# Usage:
#   scripts/ops/converge-sri-pool-log-level.sh [--dry-run] [<node> ...]   # defaults to all eight
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$REPO_ROOT/config/sri/sri-pool.service.d/debug.conf"
DEST=/etc/systemd/system/sri-pool.service.d/debug.conf
WANT_ENV='RUST_LOG=info,pool_sv2::channel_manager::mining_message_handler=debug'

DRY=false
if [ "${1:-}" = "--dry-run" ]; then DRY=true; shift; fi

[ -f "$SRC" ] || { echo "REFUSING: canonical drop-in missing: $SRC"; exit 2; }
grep -qF "Environment=$WANT_ENV" "$SRC" || {
    echo "REFUSING: $SRC does not carry the expected Environment= line"; exit 1; }

NODES=("$@")
if [ ${#NODES[@]} -eq 0 ]; then
    NODES=(ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4 ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8)
fi

WANT="$(sha256sum "$SRC" | cut -c1-16)"
echo "Canonical debug.conf = $WANT"
echo "Target effective value = $WANT_ENV"
$DRY && echo "(dry run -- nothing will be written)"
echo

rc=0
changed=0
pending_restart=0
for n in "${NODES[@]}"; do
    printf '%-10s ' "$n"

    got="$(ssh -o ConnectTimeout=15 -o BatchMode=yes "$n" \
        'S=$(command -v sudo >/dev/null && echo "sudo -n" || echo); $S sha256sum '"$DEST"' 2>/dev/null | cut -c1-16' 2>/dev/null)"
    got="${got:-<missing>}"

    if [ "$got" != "$WANT" ]; then
        changed=$((changed + 1))
        if $DRY; then
            echo -n "WOULD UPDATE (has $got) "
        else
            if ! scp -q -o ConnectTimeout=15 -o BatchMode=yes "$SRC" "$n:/tmp/sri-pool-debug.conf" 2>/dev/null; then
                echo "SCP FAILED"; rc=1; continue
            fi
            out="$(ssh -o ConnectTimeout=20 -o BatchMode=yes "$n" \
                'S=$(command -v sudo >/dev/null && echo "sudo -n" || echo)
                 $S mkdir -p /etc/systemd/system/sri-pool.service.d &&
                 $S cp /tmp/sri-pool-debug.conf '"$DEST"' &&
                 $S chmod 0644 '"$DEST"' &&
                 rm -f /tmp/sri-pool-debug.conf &&
                 $S systemctl daemon-reload && echo RELOAD_OK' 2>&1)"
            if ! echo "$out" | grep -q RELOAD_OK; then
                echo "FAILED: $(echo "$out" | tail -1)"; rc=1; continue
            fi
            echo -n "updated+reloaded "
        fi
    else
        echo -n "already canonical "
    fi

    # Positive check: what will the unit use, and is the RUNNING process still on the old
    # value? A green "converged" that cannot distinguish those two is how a config change
    # gets called done while every node is still logging at debug.
    eff="$(ssh -o ConnectTimeout=15 -o BatchMode=yes "$n" \
        'systemctl show sri-pool -p Environment --value 2>/dev/null' 2>/dev/null)"
    if echo "$eff" | grep -qF "$WANT_ENV"; then
        # Ask the RUNNING PROCESS what it was started with, via /proc/<MainPID>/environ.
        #
        # This used to compare `StateChangeTimestampMonotonic` against
        # `ActiveEnterTimestampMonotonic` on the theory that a daemon-reload bumps the former.
        # It does not do so reliably. On the 2026-09-20 run that comparison reported 5 of 8
        # nodes "live" moments after the drop-in was first written to them -- when every one of
        # the 8 was necessarily still running the old value. Ground truth was
        # restart-pending=7, and the check said 3.
        #
        # That is the precise failure this script exists to prevent, so it now reads the
        # process rather than inferring from a timestamp whose semantics it guessed.
        #
        # ⚠ `sudo cat FILE | tr` -- NOT `sudo tr < FILE`. The redirect is opened by the CALLING
        # shell before sudo runs, so the privileged form silently yields "Permission denied" on
        # the nodes where sri-pool runs as root. That cost a wrong reading once already.
        running="$(ssh -o ConnectTimeout=15 -o BatchMode=yes "$n" \
            'S=$(command -v sudo >/dev/null && echo "sudo -n" || echo)
             P=$(systemctl show sri-pool -p MainPID --value 2>/dev/null)
             [ -n "$P" ] && [ "$P" != 0 ] || exit 0
             $S cat /proc/$P/environ 2>/dev/null | tr "\0" "\n" | grep "^RUST_LOG="' 2>/dev/null)"

        if [ -z "$running" ]; then
            # Unreadable is NOT "live". Silence here previously read as success.
            echo "| unit=OK, running value UNREADABLE — cannot confirm; treat as pending"
            pending_restart=$((pending_restart + 1))
            rc=1
        elif [ "$running" = "$WANT_ENV" ]; then
            echo "| unit=OK, live (process confirms)"
        else
            pending_restart=$((pending_restart + 1))
            echo "| unit=OK, RESTART PENDING (process has ${running#RUST_LOG=})"
        fi
    else
        echo "| EFFECTIVE VALUE STILL WRONG: ${eff:-<unreadable>}"
        rc=1
    fi
done

echo
echo "changed=$changed  restart-pending=$pending_restart  exit=$rc"
if [ "$pending_restart" -gt 0 ]; then
    echo
    echo "Those nodes will not log at the new level until sri-pool restarts."
    echo "Let the next 'deploy-node.sh <node> pool_sv2' do it -- do not spend a restart here."
fi
exit $rc
