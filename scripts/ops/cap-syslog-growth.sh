#!/usr/bin/env bash
#
# Cap rsyslog's growth so /var/log cannot fill a node's root disk.
#
# The journal is already bounded — scripts/ops/enable-persistent-journal.sh sets
# SystemMaxUse=2G with a 1G floor. rsyslog is NOT, and it is the larger consumer:
# it writes essentially the same records to /var/log/syslog with no size ceiling
# at all.
#
# Debian's stock /etc/logrotate.d/rsyslog rotates syslog WEEKLY, keeps 4, and uses
# `delaycompress` — so the previous week's file sits uncompressed. Measured on the
# fleet 2026-08-08, before any cleanup:
#
#   vm1   syslog.1 861M (uncompressed)  syslog 600M (active)   .2-.4.gz 362M
#   vm4   syslog  1198M (active)        rotated 1.2G
#   vm2   syslog   818M (active)        rotated 1.2G
#
# ~1.8-2.4 GB per node of syslog alone, and vm1 reached 90% of a 79 GB disk. A full
# root disk is not a logging problem: on 2026-08-01 it truncated
# /var/lib/bitcoin/settings.json to 0 bytes and ghostd crash-looped 125 times for an
# hour while ghost-pool kept answering /health on its existing RPC connection, so
# nothing looked wrong. See the incident notes on #582/#584.
#
# ## Why this edits the stock file rather than adding its own
#
# The obvious approach — drop a new stanza in /etc/logrotate.d/ghost-syslog that
# sorts after "rsyslog" and relies on the last match winning — DOES NOT WORK, and
# fails destructively. logrotate rejects a path listed in two files:
#
#   error: rsyslog:1 duplicate log entry for /var/log/syslog
#   error: found error in file rsyslog, skipping
#
# It skips the whole offending file and the run exits non-zero. Verified on
# ghost-vm8 2026-08-08. So the stock stanza is edited in place instead.
#
# The cost is that /etc/logrotate.d/rsyslog is a dpkg conffile: an rsyslog package
# update will prompt, or under noninteractive apt keep the local version and write
# the new one to .dpkg-dist. That is why this script is idempotent and re-runnable —
# re-run it after any rsyslog upgrade. The original is saved alongside on first run.
#
# `delaycompress` is KEPT. rsyslog holds an open fd on syslog and is signalled by the
# postrotate hook; compressing the file it may still be writing to is how you get a
# truncated .gz. The cost is one uncompressed generation, which `maxsize` now bounds.
#
# Usage:
#   scripts/ops/cap-syslog-growth.sh <node> [<node> ...]
#   scripts/ops/cap-syslog-growth.sh --check <node> [<node> ...]
#   scripts/ops/cap-syslog-growth.sh --revert <node> [<node> ...]
#
#   <node>    ssh alias, e.g. ghost-vm5
#   --check   report only, change nothing
#   --revert  restore the saved original

set -uo pipefail

MODE=apply
case "${1:-}" in
    --check)  MODE=check;  shift ;;
    --revert) MODE=revert; shift ;;
esac

[ $# -gt 0 ] || { echo "usage: $0 [--check|--revert] <node> [<node> ...]" >&2; exit 1; }

CONF=/etc/logrotate.d/rsyslog
# NOT under /etc/logrotate.d: logrotate reads every file in that directory,
# including dotfiles, so a backup kept there becomes a duplicate log entry and
# breaks the very config it exists to protect. Verified on ghost-vm8 2026-08-08.
BACKUP=/var/backups/rsyslog.logrotate.ghost-orig
MARKER='# ghost: size-capped'

# 200M before rotation, 7 generations. At the observed ~120 MB/day on the busiest
# node that is roughly a week of history, and bounds the worst case at one
# uncompressed 200M file plus six compressed generations — well under 1 GB, against
# the 1.8-2.4 GB measured today.
#
# `maxsize` is the trigger the stock config lacks: it rotates when the file exceeds
# the limit OR when the period elapses, whichever comes first, so a burst can no
# longer run for six days before the weekly rotation catches it.
read -r -d '' PATCH <<'AWKEOF' || true
BEGIN { done_size = 0 }
# Idempotency: if the marker is already present the file is patched; emit unchanged.
/^# ghost: size-capped/ { patched = 1 }
{ lines[NR] = $0 }
END {
    if (patched) { for (i = 1; i <= NR; i++) print lines[i]; exit 0 }
    print "# ghost: size-capped — see scripts/ops/cap-syslog-growth.sh (#585)"
    for (i = 1; i <= NR; i++) {
        line = lines[i]
        if (line ~ /^[[:space:]]*rotate[[:space:]]+[0-9]+[[:space:]]*$/) {
            sub(/rotate[[:space:]]+[0-9]+/, "rotate 7", line)
            print line
        } else if (line ~ /^[[:space:]]*(weekly|monthly|daily)[[:space:]]*$/) {
            indent = line; sub(/[^[:space:]].*/, "", indent)
            print indent "daily"
            print indent "maxsize 200M"
            done_size = 1
        } else {
            print line
        }
    }
    if (!done_size) { print "ERROR: no rotation period found" > "/dev/stderr"; exit 3 }
}
AWKEOF

rc=0
for NODE in "$@"; do
    echo "=== $NODE ==="

    state="$(ssh -o ConnectTimeout=10 -o BatchMode=yes "$NODE" "
        printf '%s|%s|%s|%s|%s' \
          \"\$(du -sh /var/log 2>/dev/null | cut -f1)\" \
          \"\$(ls -l /var/log/syslog 2>/dev/null | awk '{printf \"%.0fM\", \$5/1048576}')\" \
          \"\$(grep -q '$MARKER' $CONF 2>/dev/null && echo patched || echo stock)\" \
          \"\$([ -f $BACKUP ] && echo have-backup || echo no-backup)\" \
          \"\$(df -BG --output=avail / 2>/dev/null | tail -1 | tr -d ' G')\"
    " 2>/dev/null)" || { echo "  UNREACHABLE"; rc=1; continue; }

    IFS='|' read -r logsz active patched backup avail <<<"$state"
    echo "  /var/log=${logsz:-?} active=${active:-?} config=${patched} ${backup} / free=${avail:-?}G"

    if [ "$MODE" = check ]; then
        if [ "$patched" = patched ]; then echo "  already capped"; else echo "  WOULD cap"; rc=1; fi
        continue
    fi

    if [ "$MODE" = revert ]; then
        if [ "$backup" != have-backup ]; then
            echo "  REFUSED: no saved original to restore"
            rc=1
            continue
        fi
        ssh -o ConnectTimeout=15 "$NODE" "
            S=\$(command -v sudo >/dev/null && echo sudo || echo)
            \$S cp -a $BACKUP $CONF && \$S rm -f $BACKUP && echo '    restored'" 2>&1 | tail -1
        continue
    fi

    if [ "$patched" = patched ]; then
        echo "  already capped — nothing to do"
        continue
    fi

    if ! printf '%s\n' "$PATCH" | ssh -o ConnectTimeout=20 "$NODE" "
        set -e
        S=\$(command -v sudo >/dev/null && echo sudo || echo)
        [ -f $CONF ] || { echo 'no $CONF on this node' >&2; exit 2; }
        # Save the pristine original once, so --revert is always possible.
        \$S mkdir -p /var/backups; [ -f $BACKUP ] || \$S cp -a $CONF $BACKUP
        \$S awk -f /dev/stdin $CONF > /tmp/.ghost-rsyslog.\$\$
        # Non-empty and still contains the stanza brace: a truncated rewrite here
        # would silently disable rotation for every file in the list.
        [ -s /tmp/.ghost-rsyslog.\$\$ ] && grep -q '{' /tmp/.ghost-rsyslog.\$\$
        \$S cp -a $CONF /var/backups/rsyslog.logrotate.prev
        \$S cp /tmp/.ghost-rsyslog.\$\$ $CONF
        \$S chmod 644 $CONF; \$S chown root:root $CONF
        rm -f /tmp/.ghost-rsyslog.\$\$
    " 2>&1 | sed 's/^/    /'; then
        echo "  FAILED to patch"
        rc=1
        continue
    fi

    # Verify rather than assume. A logrotate config with an error fails the WHOLE
    # daily run, so a bad file here stops every other log on the node rotating too.
    # --debug parses everything and writes nothing.
    verify="$(ssh -o ConnectTimeout=20 "$NODE" "
        S=\$(command -v sudo >/dev/null && echo sudo || echo)
        if out=\$(\$S logrotate --debug /etc/logrotate.conf 2>&1); then
            if grep -qE 'considering log /var/log/syslog' <<<\"\$out\"; then echo PARSE_OK
            else echo PARSE_OK_NOT_MATCHED; fi
        else
            grep -iE 'error' <<<\"\$out\" | head -3
            echo PARSE_FAILED
        fi
    " 2>/dev/null)"

    case "$verify" in
        *PARSE_OK)
            got="$(ssh -o ConnectTimeout=10 "$NODE" "grep -E 'maxsize|rotate [0-9]+|daily' $CONF | tr -d '\t' | tr '\n' ' '" 2>/dev/null)"
            echo "  capped, logrotate parses: ${got}"
            ssh -o ConnectTimeout=10 "$NODE" "S=\$(command -v sudo >/dev/null && echo sudo || echo); \$S rm -f /var/backups/rsyslog.logrotate.prev" >/dev/null 2>&1
            ;;
        *PARSE_OK_NOT_MATCHED)
            echo "  WARNING: parses but /var/log/syslog not matched — rolling back"
            ssh -o ConnectTimeout=10 "$NODE" "S=\$(command -v sudo >/dev/null && echo sudo || echo); \$S cp -a /var/backups/rsyslog.logrotate.prev $CONF" >/dev/null 2>&1
            rc=1 ;;
        *)
            echo "  VERIFY FAILED — rolling back"
            printf '%s\n' "$verify" | sed 's/^/      /'
            ssh -o ConnectTimeout=10 "$NODE" "S=\$(command -v sudo >/dev/null && echo sudo || echo); \$S cp -a /var/backups/rsyslog.logrotate.prev $CONF" >/dev/null 2>&1
            rc=1 ;;
    esac
done

exit $rc
