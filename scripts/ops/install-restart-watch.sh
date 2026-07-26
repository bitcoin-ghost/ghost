#!/usr/bin/env bash
#
# Install the restart-loop watchdog on nodes that already exist.
#
# Re-running install-node.sh is not an option for an existing node: it rewrites
# /etc/ghost/*.toml and would revert that node's stratum config (#431). This installs
# only the watchdog.
#
# Usage:
#   scripts/ops/install-restart-watch.sh <node> [<node> ...]
#   scripts/ops/install-restart-watch.sh --check <node> [<node> ...]
#
#   --check   report whether it is installed and what it currently sees; change nothing

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CHECK_ONLY=false
if [ "${1:-}" = "--check" ]; then CHECK_ONLY=true; shift; fi
[ $# -gt 0 ] || { echo "usage: $0 [--check] <node> [<node> ...]" >&2; exit 1; }

SCRIPT="$REPO_ROOT/ghost-restart-watch.sh"
SERVICE="$REPO_ROOT/systemd/ghost-restart-watch.service"
TIMER="$REPO_ROOT/systemd/ghost-restart-watch.timer"
for f in "$SCRIPT" "$SERVICE" "$TIMER"; do
    [ -r "$f" ] || { echo "missing: $f" >&2; exit 1; }
done

rc=0
for NODE in "$@"; do
    echo "=== $NODE ==="

    if $CHECK_ONLY; then
        ssh -o ConnectTimeout=10 -o BatchMode=yes "$NODE" '
            if [ -x /opt/ghost/bin/ghost-restart-watch.sh ]; then
                printf "  installed=yes timer=%s\n" "$(systemctl is-active ghost-restart-watch.timer 2>/dev/null)"
                /opt/ghost/bin/ghost-restart-watch.sh --check
            else
                echo "  installed=no"
                exit 1
            fi
        ' 2>&1 || rc=1
        continue
    fi

    if ! { tar -C "$(dirname "$SCRIPT")" -cf - "$(basename "$SCRIPT")" \
             -C "$(dirname "$SERVICE")" "$(basename "$SERVICE")" "$(basename "$TIMER")" \
           | ssh -o ConnectTimeout=10 "$NODE" '
        set -e
        S=$(command -v sudo >/dev/null && echo sudo || echo)
        t=$(mktemp -d); trap "rm -rf $t" EXIT
        tar -C "$t" -xf -
        $S install -m 755 -o root -g root "$t/ghost-restart-watch.sh" /opt/ghost/bin/ghost-restart-watch.sh
        $S install -m 644 -o root -g root "$t/ghost-restart-watch.service" /etc/systemd/system/
        $S install -m 644 -o root -g root "$t/ghost-restart-watch.timer"   /etc/systemd/system/
        $S mkdir -p /var/lib/ghost/restart-watch
        $S systemctl daemon-reload
        $S systemctl enable --now ghost-restart-watch.timer
    '; }; then
        echo "  FAILED to install"
        rc=1
        continue
    fi

    # Verify rather than assume. `enable --now` reports success for a timer whose
    # service cannot run, so check the timer is active AND the script executes.
    out="$(ssh -o ConnectTimeout=10 "$NODE" '
        printf "  timer=%s\n" "$(systemctl is-active ghost-restart-watch.timer)"
        /opt/ghost/bin/ghost-restart-watch.sh --check
    ' 2>&1)" || rc=1
    echo "$out"
    grep -q "timer=active" <<<"$out" || { echo "  VERIFY FAILED: timer not active"; rc=1; }
done

if [ $rc -ne 0 ]; then
    echo
    echo "One or more nodes did not end up in the expected state."
fi
exit $rc
