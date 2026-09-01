#!/usr/bin/env bash
#
# Self-test for ghost-restart-watch.sh's LIVENESS check (#812, #813).
#
# The watchdog's original half — the restart-rate check — exists because a unit reported
# `active` while crash-looping. The half tested here exists because a unit reported `active`
# while hung, holding no listener, with NRestarts=0: the calmest possible reading of the one
# number the watchdog used to examine.
#
# A check that cannot fire is worth nothing, and a check that fires on a normal restart is
# worse than nothing because it trains an operator to ignore it. Both directions are asserted.
#
# Hermetic: systemctl, ss, logger and curl are stubbed on PATH. Nothing here touches a node.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/bin"; mkdir -p "$BIN" "$TMP/state"

# --- stubs -----------------------------------------------------------------------------------
# STUB_ACTIVE   what `systemctl is-active` answers
# STUB_PORTS    what `ss -ltn` lists (space-separated port numbers)
# STUB_RESTARTS what `systemctl show -p NRestarts` answers
cat > "$BIN/systemctl" <<'SC'
#!/usr/bin/env bash
case "$1" in
  list-unit-files|cat) exit 0 ;;
  show) for a in "$@"; do case "$a" in NRestarts|-p) ;; esac; done
        echo "${STUB_RESTARTS:-0}" ;;
  is-active) echo "${STUB_ACTIVE:-active}" ;;
  restart) echo "$2" >> "${STUB_RESTART_LOG:-/dev/null}" ;;
  *) exit 0 ;;
esac
SC
cat > "$BIN/ss" <<'SS'
#!/usr/bin/env bash
for p in ${STUB_PORTS:-}; do echo "LISTEN 0 128 0.0.0.0:$p 0.0.0.0:*"; done
SS
printf '#!/usr/bin/env bash\nexit 0\n' > "$BIN/logger"
printf '#!/usr/bin/env bash\nexit 0\n' > "$BIN/curl"
printf '#!/usr/bin/env bash\necho testhost\n' > "$BIN/hostname"
chmod +x "$BIN"/*

WATCH="$REPO_ROOT/scripts/ghost-restart-watch.sh"
pass=0; fail=0

run() { # run <n-times>; echoes combined output
  local n="$1"; shift
  local out=""
  for _ in $(seq 1 "$n"); do
    out="$out$(PATH="$BIN:$PATH" CONF=/dev/null STATE_DIR="$TMP/state" \
      LIVENESS_MISSES=3 RESTART_RENOTIFY_SECS=0 "$@" bash "$WATCH" 2>&1)"$'\n'
  done
  printf '%s' "$out"
}
check() { if grep -qE "$2" <<<"$3"; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
          else printf "  [BAD] %s\n        wanted: %s\n        got: %s\n" "$1" "$2" "$(tr '\n' ' ' <<<"$3" | cut -c1-160)"; fail=$((fail+1)); fi; }
check_absent() { if grep -qE "$2" <<<"$3"; then printf "  [BAD] %s\n        must NOT match: %s\n" "$1" "$2"; fail=$((fail+1));
                 else printf "  [ok ] %s\n" "$1"; pass=$((pass+1)); fi; }

echo "== liveness: active but not listening =="

# 1. Listening on every expected port -> never alerts. The accept-side control: a watchdog that
#    alerts on a healthy fleet is the one people mute.
rm -f "$TMP/state"/*
out=$(run 5 env STUB_ACTIVE=active STUB_PORTS="8442 34255 3333 8332" STUB_RESTARTS=0)
check_absent "a fully listening node never alerts, however many runs" "not listening|running, not working" "$out"

# 2. Below the threshold -> silent. One miss is a restart in flight, not a hang.
rm -f "$TMP/state"/*
out=$(run 2 env STUB_ACTIVE=active STUB_PORTS="" STUB_RESTARTS=0)
check_absent "2 consecutive misses stay silent (threshold is 3)" "running, not working" "$out"

# 3. At the threshold -> alerts, and says which port and that it is active.
rm -f "$TMP/state"/*
out=$(run 3 env STUB_ACTIVE=active STUB_PORTS="" STUB_RESTARTS=0)
check "3 consecutive misses alert" "running, not working" "$out"
check "and the alert names the port it should be holding" ":(8442|34255|3333|8332)" "$out"
check "and says NRestarts stayed quiet by describing it as active" "is active but has not been listening" "$out"

# 4. THE #812 SHAPE: active, zero restarts, no listener. The restart-rate half must stay silent
#    while the liveness half fires — that combination is the entire point.
rm -f "$TMP/state"/*
out=$(run 3 env STUB_ACTIVE=active STUB_PORTS="" STUB_RESTARTS=0)
check "#812 shape (active, NRestarts=0, no listener) is caught" "running, not working" "$out"
check_absent "and it is NOT reported as a restart loop" "restarted [0-9]+ times" "$out"

# 5. A unit that is not active is a different condition; systemd already reports it honestly.
rm -f "$TMP/state"/*
out=$(run 4 env STUB_ACTIVE=inactive STUB_PORTS="" STUB_RESTARTS=0)
check_absent "an inactive unit does not raise a liveness alert" "running, not working" "$out"

# 6. Recovery resets the counter, so a blip followed by health does not accumulate into an alert.
rm -f "$TMP/state"/*
out=$(run 2 env STUB_ACTIVE=active STUB_PORTS="" STUB_RESTARTS=0)
out="$out$(run 1 env STUB_ACTIVE=active STUB_PORTS="8442 34255 3333 8332" STUB_RESTARTS=0)"
out="$out$(run 2 env STUB_ACTIVE=active STUB_PORTS="" STUB_RESTARTS=0)"
check_absent "misses reset on recovery, so 2+2 around a good run does not reach 3" "running, not working" "$out"

echo "== opt-in restart =="

# 7. Default is OFF — detection without acting.
rm -f "$TMP/state"/* ; : > "$TMP/restarts.log"
run 3 env STUB_ACTIVE=active STUB_PORTS="" STUB_RESTARTS=0 STUB_RESTART_LOG="$TMP/restarts.log" >/dev/null
check "LIVENESS_RESTART defaults off — nothing is restarted" "^0$" "$(wc -l < "$TMP/restarts.log")"

# 8. When enabled, it acts.
rm -f "$TMP/state"/* ; : > "$TMP/restarts.log"
for _ in 1 2 3; do
  PATH="$BIN:$PATH" CONF=/dev/null STATE_DIR="$TMP/state" LIVENESS_MISSES=3 RESTART_RENOTIFY_SECS=0 \
    STUB_ACTIVE=active STUB_PORTS="" STUB_RESTARTS=0 LIVENESS_RESTART=true \
    STUB_RESTART_LOG="$TMP/restarts.log" bash "$WATCH" >/dev/null 2>&1
done
check "LIVENESS_RESTART=true restarts the hung unit" "[1-9]" "$(wc -l < "$TMP/restarts.log")"

echo "== state file compatibility =="

# 9. A state file written by the PREVIOUS version has three fields. Reading five from it must
#    not crash or reset the restart counters — an upgrade that silently zeroes its own history
#    would blind the crash-loop half for a full window.
rm -f "$TMP/state"/*
printf '7 %s 0\n' "$(date +%s)" > "$TMP/state/ghost-pool"
out=$(run 1 env STUB_ACTIVE=active STUB_PORTS="8442 34255 3333 8332" STUB_RESTARTS=7)
check_absent "an old 3-field state file does not error" "unbound variable|integer expression|syntax error" "$out"
check "and it is rewritten with five fields" "^7 [0-9]+ 0 0 0$" "$(cat "$TMP/state/ghost-pool")"

echo
if [ "$fail" -eq 0 ]; then
  echo "All $pass restart-watch checks passed: the watchdog now catches a unit that is active, has never restarted, and is serving nothing — and stays silent on a healthy node, a single blip, and an inactive unit."
else
  echo "*** $fail of $((pass+fail)) restart-watch checks FAILED ***"; exit 1
fi
