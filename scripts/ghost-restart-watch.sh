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
# Alerting goes through the node's own alert centre — `[alerts]` in pool.toml, configured
# from the dashboard at Settings -> Alerts, delivering to email, push (ntfy-style) and
# Telegram. This script POSTs to `/api/v1/alerts/internal/service-restart` and the node
# dispatches it, honouring the master switch, the `service_restart_loop` event flag, the
# rate limit and every channel the operator has enabled.
#
# It previously POSTed to its own ALERT_WEBHOOK read from /etc/ghost/alerting.conf. That was
# a second, parallel alerting system sitting beside a complete one, and it silently did
# nothing unless an operator found and populated a file that nothing else referenced — so in
# practice a crash loop alerted no one. Two sources of truth for the same job, which is the
# same mistake as #431.
#
# A journal entry at error priority is always written regardless, which is only useful
# because the journal is now persistent (#414) — before that a restart loop erased its own
# evidence roughly every four hours.
#
# Config, all optional, /etc/ghost/restart-watch.conf:
#   NODE_API=127.0.0.1:8080       where to POST the signal
#   INTERNAL_AUTH_KEY=<hex>       shared secret; when the node has internal auth configured
#                                 the signal must be HMAC-signed or it is rejected. Read from
#                                 the node config automatically when not set here.
#   RESTART_THRESHOLD=3           restarts within one window before alerting
#   RESTART_RENOTIFY_SECS=3600    minimum gap between repeat alerts for the same unit
#
# Usage:
#   ghost-restart-watch.sh          # normal run, intended for the timer
#   ghost-restart-watch.sh --check  # report current state, never alert, never persist

set -uo pipefail

CONF=/etc/ghost/restart-watch.conf
STATE_DIR=/var/lib/ghost/restart-watch
UNITS="ghost-pool sri-pool sri-translator ghostd"

NODE_API="127.0.0.1:8080"
INTERNAL_AUTH_KEY=""
RESTART_THRESHOLD=3
RESTART_RENOTIFY_SECS=3600
# shellcheck source=/dev/null
[ -r "$CONF" ] && . "$CONF"

# Fall back to the node's own configured secret so an operator does not have to copy it
# into a second file — the whole point of this change is to stop duplicating config.
if [ -z "$INTERNAL_AUTH_KEY" ]; then
    for f in /etc/ghost/pool.toml /etc/ghost/ghost-pool.toml; do
        [ -r "$f" ] || continue
        INTERNAL_AUTH_KEY=$(grep -aoE '^[[:space:]]*internal_auth_key[[:space:]]*=[[:space:]]*"[^"]+"' "$f" 2>/dev/null \
                            | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
        [ -n "$INTERNAL_AUTH_KEY" ] && break
    done
fi

# POST a restart-loop signal to the node's alert centre.
# Auth mirrors the dashboard proxy: HMAC-SHA256(secret, u64_le(timestamp) || body), hex,
# in X-Ghost-Signature, with the unix timestamp in X-Ghost-Timestamp.
send_alert() {
    local unit="$1" restarts="$2" window="$3"
    local body ts sig
    body=$(printf '{"unit":"%s","restarts":%s,"window_secs":%s}' "$unit" "$restarts" "$window")
    ts=$(date +%s)

    local -a auth_headers=()
    if [ -n "$INTERNAL_AUTH_KEY" ]; then
        # u64 little-endian timestamp, then the raw body, HMAC'd with the hex secret.
        sig=$( { printf '%016x' "$ts" | sed -E 's/(..)(..)(..)(..)(..)(..)(..)(..)/\8\7\6\5\4\3\2\1/' | xxd -r -p
                 printf '%s' "$body"
               } | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$INTERNAL_AUTH_KEY" -binary 2>/dev/null | xxd -p -c 256 )
        [ -n "$sig" ] && auth_headers=(-H "X-Ghost-Signature: $sig" -H "X-Ghost-Timestamp: $ts")
    fi

    curl -fsS -m 10 -X POST -H 'Content-Type: application/json' \
         "${auth_headers[@]}" -d "$body" \
         "http://${NODE_API}/api/v1/alerts/internal/service-restart" >/dev/null 2>&1 \
      || logger -t ghost-restart-watch -p daemon.warning -- \
           "alert POST failed for ${unit}; see journal for the restart itself" 2>/dev/null || true
}

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
            send_alert "$unit" "$delta" "$elapsed"
            last_alert=$now
        fi
        problems+=("$msg")
    fi

    printf '%s %s %s\n' "$n" "$now" "$last_alert" > "$f"
done

# Non-zero when something is looping, so this is usable as a check from elsewhere
# (a fleet script, a CI job, a human) and not only as a timer that mails itself.
[ ${#problems[@]} -eq 0 ]
