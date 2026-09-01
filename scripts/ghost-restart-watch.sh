#!/usr/bin/env bash
#
# Restart-loop watchdog.
#
# sri-pool reached 84-88 restarts on three nodes and nothing surfaced it — it was found
# by accident, long after the fact. systemd restarts a crashing service forever and
# reports it `active` between crashes, so every dashboard and every `is-active` check
# says the node is fine while it is in fact dying on a loop.
#
# It watches TWO failure modes, which are opposites and read oppositely:
#
#   * a unit restarting too often — a crash loop, below;
#   * a unit that is `active`, has NEVER restarted, and is serving nothing.
#
# The second was found the hard way. ghost-vm2's translator deadlocked on downstream-disconnect
# cleanup and held no listener for ~45 minutes while `systemctl is-active` said `active` and
# NRestarts stayed at 0 — the calmest possible reading of the one number this script used to
# examine (#812). It surfaced only because check-fleet-uniformity.sh happens to assert that
# something must listen on a port ufw allows. A hang is the same lie as a crash loop, told more
# quietly, and this script now asks the other question: is the unit holding the socket it
# exists to serve?
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
#   LIVENESS_MISSES=3             consecutive runs active-but-not-listening before alerting.
#                                 Never 1: a single miss is a legitimate restart in flight.
#   LIVENESS_RESTART=false        also `systemctl restart` a unit judged hung. OFF by default —
#                                 detection is the gap; restarting a production service from a
#                                 watchdog is a policy the operator opts into. If enabled and the
#                                 port still does not come back, the restart-rate check above
#                                 catches the resulting loop, so the two compose.
#
# Usage:
#   ghost-restart-watch.sh          # normal run, intended for the timer
#   ghost-restart-watch.sh --check  # report current state, never alert, never persist

set -uo pipefail

# Both overridable so scripts/test-restart-watch.sh can drive this hermetically, exactly as
# deploy-node.sh allows for its own self-test. A watchdog whose logic cannot be exercised is
# the same class of problem as the hang it now looks for.
CONF="${CONF:-/etc/ghost/restart-watch.conf}"
STATE_DIR="${STATE_DIR:-/var/lib/ghost/restart-watch}"
UNITS="ghost-pool sri-pool sri-translator ghostd"

NODE_API="127.0.0.1:8080"
INTERNAL_AUTH_KEY=""
RESTART_THRESHOLD=3
RESTART_RENOTIFY_SECS=3600
# `${VAR:-default}` so these are settable from the environment as well as from CONF, which is
# sourced below and still wins. Assigning unconditionally would make the knob unsettable — the
# self-test caught exactly that: LIVENESS_RESTART=true was silently ignored.
LIVENESS_MISSES="${LIVENESS_MISSES:-3}"
LIVENESS_RESTART="${LIVENESS_RESTART:-false}"

# The socket each unit exists to serve. Absence of this listener while the unit is `active`
# is the definition of "running but not working".
#
# These are the SAME ports deploy-node.sh uses as its READY_PORT gate after a swap — that path
# already treats "listening here" as the definition of a working unit, and it would be worse
# than useless for the two to disagree about what healthy means. Measured on the fleet, not
# assumed: ghost-pool also holds 8080/8443/8555-8563, sri-translator also holds 4444/9092; the
# port named here is the one whose absence means the unit is not doing its job.
liveness_port_for() {
    case "$1" in
        ghost-pool)      echo 8442 ;;   # TDP, what pool_sv2 connects to
        sri-pool)        echo 34255 ;;  # SV2, what the translator connects to
        sri-translator)  echo 3333 ;;   # SV1, what miners connect to
        ghostd)          echo 8332 ;;   # RPC, what ghost-pool depends on
        *)               echo "" ;;
    esac
}
# shellcheck source=/dev/null
[ -r "$CONF" ] && . "$CONF"

# Fall back to the node's own configured secret so an operator does not have to copy it
# into a second file — the whole point of this change is to stop duplicating config.
if [ -z "$INTERNAL_AUTH_KEY" ]; then
    # ⚠ The key is `internal_api_secret` under [network] — that is what ghost-pool reads
    # (`config.network.internal_api_secret` -> `InternalAuth::from_hex`). This used to grep for
    # `internal_auth_key`, a name that exists nowhere in the codebase or any config, so the
    # lookup ALWAYS came back empty, the POST always went unsigned, and the endpoint always
    # answered 401 — reported only to syslog. The replacement for a silent alerting path was
    # silent in exactly the same way.
    for f in /etc/ghost/pool.toml /etc/ghost/ghost-pool.toml; do
        [ -r "$f" ] || continue
        INTERNAL_AUTH_KEY=$(grep -aoE '^[[:space:]]*internal_api_secret[[:space:]]*=[[:space:]]*"[^"]+"' "$f" 2>/dev/null \
                            | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
        [ -n "$INTERNAL_AUTH_KEY" ] && break
    done
    if [ -z "$INTERNAL_AUTH_KEY" ]; then
        # Say so. A watchdog that cannot authenticate will 401 on every alert it ever raises,
        # and the whole point of this script is to not fail quietly.
        logger -t ghost-restart-watch -p daemon.warning -- \
            "no internal_api_secret found in /etc/ghost/pool.toml — alerts will be REJECTED (401)" 2>/dev/null || true
    fi
fi

# POST a restart-loop signal to the node's alert centre.
# Auth mirrors the dashboard proxy: HMAC-SHA256(secret, u64_le(timestamp) || body), hex,
# in X-Ghost-Signature, with the unix timestamp in X-Ghost-Timestamp.
send_alert() {
    local unit="$1" restarts="$2" window="$3" reason="${4:-}"
    local body ts sig
    if [ -n "$reason" ]; then
        # A reason means this is not a restart loop. The node renders it instead of the
        # "restarted N times" wording, which for a hang would read "restarted 0 times" — the
        # calmest possible description of the opposite of what happened (#812).
        body=$(printf '{"unit":"%s","restarts":%s,"window_secs":%s,"reason":"%s"}' \
                      "$unit" "$restarts" "$window" "$reason")
    else
        body=$(printf '{"unit":"%s","restarts":%s,"window_secs":%s}' "$unit" "$restarts" "$window")
    fi
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
    prev_n=""; prev_t=""; last_alert=0; misses=0; last_live_alert=0
    # Five fields now. A file written by an older version has three, so the two new ones read
    # as empty and fall back below — no migration, no reset of the restart counters.
    [ -r "$f" ] && read -r prev_n prev_t last_alert misses last_live_alert < "$f" 2>/dev/null
    : "${last_alert:=0}"; : "${misses:=0}"; : "${last_live_alert:=0}"

    port=$(liveness_port_for "$unit")
    active=$(systemctl is-active "$unit" 2>/dev/null)
    listening=""
    if [ -n "$port" ]; then
        if ss -ltn 2>/dev/null | grep -q ":${port}\b"; then listening=yes; else listening=no; fi
    fi

    if $CHECK_ONLY; then
        printf "  %-16s NRestarts=%-4s active=%-10s port=%-6s listening=%s\n" \
               "$unit" "$n" "$active" "${port:-none}" "${listening:-n/a}"
        continue
    fi

    # ---- liveness: active, but holding nothing ----------------------------------------
    #
    # Only meaningful while the unit is `active`. A unit that is stopped, activating or failed
    # is a different condition and systemd already represents it honestly; this exists for the
    # case where systemd's own view is reassuring and wrong.
    if [ -n "$port" ] && [ "$active" = "active" ] && [ "$listening" = "no" ]; then
        misses=$(( misses + 1 ))
        if [ "$misses" -ge "$LIVENESS_MISSES" ]; then
            msg="$(hostname -s): ${unit} is active but has not been listening on :${port} for ${misses} consecutive checks — running, not working"
            if [ $(( now - last_live_alert )) -ge "$RESTART_RENOTIFY_SECS" ]; then
                logger -t ghost-restart-watch -p daemon.err -- "$msg" 2>/dev/null || true
                echo "ALERT: $msg" >&2
                send_alert "$unit" 0 "$(( misses * 60 ))" \
                    "active but not listening on :${port} for ${misses} consecutive checks"
                last_live_alert=$now
            fi
            problems+=("$msg")

            if [ "$LIVENESS_RESTART" = "true" ]; then
                logger -t ghost-restart-watch -p daemon.err -- \
                    "$(hostname -s): restarting ${unit} — hung with no listener on :${port}" 2>/dev/null || true
                systemctl restart "$unit" >/dev/null 2>&1 || true
                # Reset so a restart that works is not immediately re-alerted, and so a restart
                # that does NOT work re-arms from zero rather than firing every single run.
                misses=0
            fi
        fi
    else
        misses=0
    fi

    # First run for this unit, or the counter went backwards because something ran
    # daemon-reload. Either way there is no meaningful delta — record and move on
    # rather than inventing one.
    if [ -z "$prev_n" ] || [ "$n" -lt "$prev_n" ]; then
        printf '%s %s %s %s %s\n' "$n" "$now" "$last_alert" "$misses" "$last_live_alert" > "$f"
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

    printf '%s %s %s %s %s\n' "$n" "$now" "$last_alert" "$misses" "$last_live_alert" > "$f"
done

# Non-zero when something is looping, so this is usable as a check from elsewhere
# (a fleet script, a CI job, a human) and not only as a timer that mails itself.
[ ${#problems[@]} -eq 0 ]
