#!/usr/bin/env bash
#
# Self-test for the boot gate (#1020).
#
# `ghost-mining-gate` exists so the node starts only once ghostd has left initial block
# download. It was not what held the node back: `sri-pool.service` carried
# `Wants=ghost-mining.service`, so anything that started sri-pool started the node too. On a
# reboot that cost one failed start. On a fresh install it put a node at chain height 0 on the
# live mesh 8 seconds into the install, where it broadcast an MPC contribution while the gate
# sat logging "waiting for ghostd to finish initial sync".
#
# Three things are asserted, because the gate only holds if all three do:
#
#   1. the gate script starts nothing while ghostd is syncing, and then starts the node and
#      the stratum stack in that order;
#   2. no unit pulls the node in — in the repo's unit files or in the installer's copies;
#   3. the installer starts and enables nothing behind the gate itself.
#
# Hermetic: curl, systemctl and sleep are stubbed on PATH. Nothing here touches a node.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$REPO_ROOT/scripts/ops/fleet-files/wait-for-ghostd-sync.sh"
INSTALLER="$REPO_ROOT/scripts/install-node.sh"
G=/usr/bin/grep
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/bin"; mkdir -p "$BIN"

# --- stubs -----------------------------------------------------------------------------------
# STUB_IBD_TRUE_FOR  how many getblockchaininfo answers say `true` before one says `false`;
#                    `forever` never leaves sync, `down` answers nothing at all (RPC not up)
# STUB_FAIL_START    unit names whose `systemctl start` fails
# Every call is appended to $CALLS, so order across the two tools can be read back.
cat > "$BIN/curl" <<'CURL'
#!/usr/bin/env bash
n=$(( $(cat "$STUB_DIR/polls" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$STUB_DIR/polls"
echo "poll $n" >> "$CALLS"
case "${STUB_IBD_TRUE_FOR:-0}" in
  down)    exit 7 ;;
  forever) ibd=true ;;
  *)       if [ "$n" -le "${STUB_IBD_TRUE_FOR:-0}" ]; then ibd=true; else ibd=false; fi ;;
esac
printf '{"result":{"chain":"main","blocks":1,"initialblockdownload":%s},"error":null}\n' "$ibd"
CURL
cat > "$BIN/systemctl" <<'SC'
#!/usr/bin/env bash
echo "$*" >> "$CALLS"
if [ "$1" = start ]; then
  case " ${STUB_FAIL_START:-} " in *" $2 "*) exit 1 ;; esac
fi
exit 0
SC
# The gate sleeps between polls. A `forever` run is ended here, after enough polls to show it
# would have gone on, rather than by a timeout whose length says nothing. SIGKILL, because it is
# the one signal a CI runner cannot have set to "ignore" for every child: this used SIGPIPE to
# keep bash quiet about the death, the runner ignores SIGPIPE, and the test spun for ever.
cat > "$BIN/sleep" <<'SL'
#!/usr/bin/env bash
[ "$(cat "$STUB_DIR/polls" 2>/dev/null || echo 0)" -ge "${STUB_MAX_POLLS:-50}" ] && kill -KILL "$PPID"
exit 0
SL
chmod +x "$BIN"/*

pass=0; fail=0
is() { if [ "$2" = "$3" ]; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
       else printf "  [BAD] %s\n        wanted: %s\n        got:    %s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }

# run_gate <unit files to create, space separated> [VAR=value ...] -> sets RC, CALLS, STARTS
run_gate() {
  local units="$1"; shift
  local d; d="$(mktemp -d -p "$TMP")"
  mkdir -p "$d/units"; printf 'rpcuser=u\nrpcpassword=p\n' > "$d/bitcoin.conf"
  for u in $units; do : > "$d/units/$u.service"; done
  CALLS="$d/calls"; : > "$CALLS"
  # The group's stderr is discarded so bash's own "Killed" notice for a `forever` run is too.
  { env PATH="$BIN:$PATH" STUB_DIR="$d" CALLS="$CALLS" GHOST_BITCOIN_CONF="$d/bitcoin.conf" \
        GHOST_UNIT_DIR="$d/units" "$@" bash "$GATE" >"$d/out" 2>&1; RC=$?; } 2>/dev/null
  STARTS="$($G -E '^start ' "$CALLS" | tr '\n' ',' || true)"
}

echo "1. the gate script"

run_gate "ghost-mining sri-pool sri-translator" STUB_IBD_TRUE_FOR=3
is "synced after 3 polls: node, then pool, then translator" \
   "start ghost-mining,start sri-pool,start sri-translator," "$STARTS"
is "nothing was started before ghostd left sync" "poll 4" "$($G -B1 -m1 -E '^start ' "$CALLS" | head -1)"
is "exit 0 when everything started" 0 "$RC"

run_gate "ghost-mining sri-pool sri-translator" STUB_IBD_TRUE_FOR=forever STUB_MAX_POLLS=6
is "still syncing after 6 polls: nothing started" "" "$STARTS"
is "and it was still polling when it was stopped" 6 "$($G -c '^poll ' "$CALLS" || true)"

run_gate "ghost-mining sri-pool sri-translator" STUB_IBD_TRUE_FOR=down STUB_MAX_POLLS=6
is "ghostd RPC not answering: nothing started" "" "$STARTS"

run_gate "ghost-mining" STUB_IBD_TRUE_FOR=0
is "a node with no stratum units: only the node is started" "start ghost-mining," "$STARTS"
is "and that is not a failure" 0 "$RC"

run_gate "ghost-pool sri-pool sri-translator" STUB_IBD_TRUE_FOR=0
is "a node not yet renamed: the old unit name is started" \
   "start ghost-pool,start sri-pool,start sri-translator," "$STARTS"

run_gate "ghost-mining ghost-pay sri-pool sri-translator" STUB_IBD_TRUE_FOR=0
is "ghost-pay, where installed, is started after the node" \
   "start ghost-mining,start ghost-pay,start sri-pool,start sri-translator," "$STARTS"

run_gate "ghost-mining sri-pool sri-translator" STUB_IBD_TRUE_FOR=0 STUB_FAIL_START=ghost-mining
is "the node fails to start: the stratum stack is not started against nothing" "start ghost-mining," "$STARTS"
is "and the gate reports failure" 1 "$RC"

run_gate "ghost-mining sri-pool sri-translator" STUB_IBD_TRUE_FOR=0 STUB_FAIL_START=sri-pool
is "the pool fails to start: the translator is still attempted" \
   "start ghost-mining,start sri-pool,start sri-translator," "$STARTS"
is "and the gate reports failure" 1 "$RC"

run_gate "ghost-mining ghost-pay sri-pool sri-translator" STUB_IBD_TRUE_FOR=0 STUB_FAIL_START=ghost-pay
is "ghost-pay failing (it is masked on vm1) does not stop the stratum stack" \
   "start ghost-mining,start ghost-pay,start sri-pool,start sri-translator," "$STARTS"
is "nor fail the gate" 0 "$RC"

echo "2. nothing pulls the node in"

# Every directive that makes systemd start (or keep started) another unit. `After=` and
# `Before=` are ordering only and are what the stratum units should carry instead.
PULL='^(Wants|Requires|Requisite|BindsTo|Upholds|OnSuccess|OnFailure)=.*ghost-(mining|pool)\.service'

unit_files="$(find "$REPO_ROOT/config" "$REPO_ROOT/scripts/systemd" -name '*.service' -o -name '*.conf' -path '*.service.d/*' 2>/dev/null | sort)"
is "unit files were found to check" yes "$([ "$(printf '%s\n' "$unit_files" | $G -c .)" -ge 3 ] && echo yes)"
# shellcheck disable=SC2086
is "no unit file in the repo pulls the node in" "" "$($G -HnE "$PULL" $unit_files 2>/dev/null | sed "s|$REPO_ROOT/||" | tr '\n' ' ')"
is "no unit the installer writes pulls the node in" "" "$($G -nE "$PULL" "$INSTALLER" | tr '\n' ' ')"
is "sri-pool still orders itself after the node" 1 "$($G -cE '^After=.*ghost-mining\.service' "$REPO_ROOT/config/sri/sri-pool.service" || true)"

echo "3. the installer starts nothing behind the gate"

# Installer lines that act on a gated unit by name. The gate and the firewall path unit carry
# the node's name as a prefix and are not the node.
gated='(ghost-mining|ghost-pool|sri-pool|sri-translator|ghost-pay)'
acts="$($G -nE "systemctl +(enable|start|restart|reenable)( +--[a-z-]+)* +${gated}(\.service)?( |$)" "$INSTALLER" || true)"
is "the installer does not start or enable the node or the stratum stack" "" "$(printf '%s' "$acts" | tr '\n' ' ')"
is "the installer does enable and start the gate" 1 \
   "$($G -cE '^systemctl enable --now ghost-mining-gate( |$)' "$INSTALLER" || true)"
# Positive control: the pattern above must be able to see such a line, or its silence means nothing.
is "control: the pattern matches a line that starts sri-pool" 1 \
   "$(printf 'systemctl enable --now sri-pool >/dev/null 2>&1\n' | $G -cE "systemctl +(enable|start|restart|reenable)( +--[a-z-]+)* +${gated}(\.service)?( |$)" || true)"
is "control: and does not match the gate" 0 \
   "$(printf 'systemctl enable --now ghost-mining-gate >/dev/null 2>&1\n' | $G -cE "systemctl +(enable|start|restart|reenable)( +--[a-z-]+)* +${gated}(\.service)?( |$)" || true)"

echo
echo "test-boot-gate: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
