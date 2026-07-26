#!/usr/bin/env bash
#
# Switch a node's journal from volatile to persistent.
#
# Without /var/log/journal, `Storage=auto` keeps the journal in /run/log/journal —
# tmpfs. Two consequences:
#
#   * capped at 10% of RAM (~386 MB of 3867 MB on our nodes), and
#   * DESTROYED on every reboot and on any journald restart.
#
# The second one is what actually costs. Diagnosing an hourly OOM kill, each kill
# wiped the run-up to the previous one — the evidence was being deleted by the thing
# under investigation, and the cause took four wrong guesses to find. Measured
# retention across the fleet was ~3-4.5 hours, too short to show a daily pattern.
#
# Idempotent: safe to re-run. It does NOT touch /etc/ghost/*.toml, so unlike
# re-running install-node.sh it cannot revert a node's stratum config (see #431).
#
# Usage:
#   scripts/ops/enable-persistent-journal.sh <node> [<node> ...]
#   scripts/ops/enable-persistent-journal.sh --check <node> [<node> ...]
#
#   <node>    ssh alias, e.g. ghost-vm5
#   --check   report only, change nothing

set -uo pipefail

CHECK_ONLY=false
if [ "${1:-}" = "--check" ]; then CHECK_ONLY=true; shift; fi

[ $# -gt 0 ] || { echo "usage: $0 [--check] <node> [<node> ...]" >&2; exit 1; }

# Sized to hold well over a week at the observed ~35 MB per 4h (~210 MB/day), while
# leaving the node room: SystemMaxUse is an explicit cap because the default is 10%
# of the filesystem, which on a large disk would let the journal grow into space the
# node needs. SystemKeepFree is the floor journald will not eat into.
read -r -d '' DROPIN <<'EOF' || true
# Bitcoin Ghost — journal retention. Managed by scripts/ops/enable-persistent-journal.sh.
#
# Persistent so the journal survives the restart of whatever is being diagnosed,
# and long enough to see a daily pattern rather than only the last few hours.
[Journal]
Storage=persistent
SystemMaxUse=2G
SystemKeepFree=1G
MaxRetentionSec=2week
EOF

rc=0
for NODE in "$@"; do
    echo "=== $NODE ==="

    before="$(ssh -o ConnectTimeout=10 -o BatchMode=yes "$NODE" '
        printf "%s|%s|%s|%s" \
          "$([ -d /var/log/journal ] && echo persistent || echo volatile)" \
          "$(journalctl --disk-usage 2>/dev/null | grep -oE "[0-9.]+[KMG]" | head -1)" \
          "$(journalctl -o short-iso --no-pager 2>/dev/null | head -1 | cut -d" " -f1)" \
          "$(df -BG --output=avail /var 2>/dev/null | tail -1 | tr -d " G")"
    ' 2>/dev/null)" || { echo "  UNREACHABLE"; rc=1; continue; }

    IFS='|' read -r mode usage earliest avail <<<"$before"
    echo "  storage=${mode} usage=${usage:-?} earliest=${earliest:-?} /var free=${avail:-?}G"

    if [ "$mode" = "persistent" ]; then
        echo "  already persistent — nothing to do"
        continue
    fi

    if $CHECK_ONLY; then
        echo "  WOULD switch to persistent (--check given, no change made)"
        rc=1
        continue
    fi

    # 3G is SystemMaxUse + SystemKeepFree. Refuse rather than configure a node into a
    # disk-full condition; a full /var takes the node down, which is worse than short logs.
    if [ -n "$avail" ] && [ "$avail" -lt 4 ]; then
        echo "  REFUSED: only ${avail}G free on /var, need >4G for a 2G cap plus 1G floor"
        rc=1
        continue
    fi

    if ! printf '%s\n' "$DROPIN" | ssh -o ConnectTimeout=10 "$NODE" '
        set -e
        S=$(command -v sudo >/dev/null && echo sudo || echo)
        $S mkdir -p /etc/systemd/journald.conf.d /var/log/journal
        $S tee /etc/systemd/journald.conf.d/10-ghost.conf >/dev/null
        $S systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
        $S systemctl restart systemd-journald
    ' 2>&1 | sed 's/^/    /'; then
        echo "  FAILED to apply"
        rc=1
        continue
    fi

    after="$(ssh -o ConnectTimeout=10 "$NODE" '
        printf "%s|%s" \
          "$([ -d /var/log/journal ] && echo persistent || echo volatile)" \
          "$(journalctl --no-pager -n1 >/dev/null 2>&1 && echo readable || echo UNREADABLE)"
    ' 2>/dev/null)"
    IFS='|' read -r mode2 readable <<<"$after"
    echo "  now: storage=${mode2} journal=${readable}"

    # Verify rather than assume: a drop-in that does not parse leaves journald running
    # on the old settings and reports active either way.
    if [ "$mode2" != "persistent" ] || [ "$readable" != "readable" ]; then
        echo "  VERIFY FAILED"
        rc=1
    fi
done

exit $rc
