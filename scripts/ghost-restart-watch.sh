#!/usr/bin/env bash
#
# Restart-loop watchdog.
#
# sri-pool reached 84-88 restarts on three nodes and nothing surfaced it — it was found
# by accident, long after the fact. systemd restarts a crashing service forever and
# reports it `active` between crashes, so every dashboard and every `is-active` check
# says the node is fine while it is in fact dying on a loop.
#
# This watches the RATE, not the total. NRestarts is cumulative since the last
# daemon-reload, so a node that crash-looped last week and has been stable since still
# shows a large number; and a `systemctl daemon-reload` silently resets it to zero. What
# matters is "how many restarts in the last N minutes", which is the delta between runs.
#
# Alerting: a webhook if one is configured, and always a journal entry at error priority.
# The journal is only useful because it is now persistent (#414) — before that, a restart
# loop erased its own evidence roughly every four hours.
#
# Config, all optional, /etc/ghost/alerting.conf:
#   ALERT_WEBHOOK=https://...     POST {"text": "..."} on alert. No default: without it
#                                 this logs and nothing else. See the note in #412.
#   RESTART_THRESHOLD=3           restarts within one window before alerting
#   RESTART_RENOTIFY_SECS=3600    minimum gap between repeat alerts for the same unit
#
# Usage:
#   ghost-restart-watch.sh          # normal run, intended for the timer
#   ghost-restart-watch.sh --check  # report current state, never alert, never persist

set -uo pipefail

CONF=/etc/ghost/alerting.conf
STATE_DIR=/var/lib/ghost/restart-watch
UNITS="ghost-pool sri-pool sri-translator ghostd"

ALERT_WEBHOOK=""
RESTART_THRESHOLD=3
RESTART_RENOTIFY_SECS=3600
# shellcheck source=/dev/null
[ -r "$CONF" ] && . "$CONF"

CHECK_ONLY=false
[ "${1:-}" = "--check" ] && CHECK_ONLY=true

$CHECK_ONLY || mkdir -p "$STATE_DIR"
now=$(date +%s)
problems=()

for unit in $UNITS; do
    systemctl list-unit-files "${unit}.service" >/dev/null 2>&1 || continue
    systemctl cat "$unit" >/dev/null 2>&1 || continue

    n=$(systemctl show -p NRestarts --value "$unit" 2>/dev/null)
    [ -n "$n" ] || continue

    f="$STATE_DIR/$unit"
    prev_n=""; prev_t=""; last_alert=0
    [ -r "$f" ] && read -r prev_n prev_t last_alert < "$f" 2>/dev/null
    : "${last_alert:=0}"

    if $CHECK_ONLY; then
        printf "  %-16s NRestarts=%s active=%s\n" "$unit" "$n" "$(systemctl is-active "$unit")"
        continue
    fi

    # First run for this unit, or the counter went backwards because something ran
    # daemon-reload. Either way there is no meaningful delta — record and move on
    # rather than inventing one.
    if [ -z "$prev_n" ] || [ "$n" -lt "$prev_n" ]; then
        printf '%s %s %s\n' "$n" "$now" "$last_alert" > "$f"
        continue
    fi

    delta=$(( n - prev_n ))
    elapsed=$(( now - ${prev_t:-$now} ))

    if [ "$delta" -ge "$RESTART_THRESHOLD" ]; then
        mins=$(( elapsed / 60 )); [ "$mins" -lt 1 ] && mins=1
        msg="$(hostname -s): ${unit} restarted ${delta} times in ${mins}m (total ${n})"

        if [ $(( now - last_alert )) -ge "$RESTART_RENOTIFY_SECS" ]; then
            logger -t ghost-restart-watch -p daemon.err -- "$msg" 2>/dev/null || true
            echo "ALERT: $msg" >&2
            if [ -n "$ALERT_WEBHOOK" ]; then
                payload=$(printf '{"text":"Ghost alert: %s"}' "$msg")
                curl -fsS -m 10 -X POST -H 'Content-Type: application/json' \
                     -d "$payload" "$ALERT_WEBHOOK" >/dev/null 2>&1 \
                  || logger -t ghost-restart-watch -p daemon.warning -- \
                       "webhook POST failed for: $msg" 2>/dev/null || true
            fi
            last_alert=$now
        fi
        problems+=("$msg")
    fi

    printf '%s %s %s\n' "$n" "$now" "$last_alert" > "$f"
done

# Non-zero when something is looping, so this is usable as a check from elsewhere
# (a fleet script, a CI job, a human) and not only as a timer that mails itself.
[ ${#problems[@]} -eq 0 ]
