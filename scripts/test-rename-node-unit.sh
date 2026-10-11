#!/usr/bin/env bash
#
# Self-test for scripts/ops/rename-node-unit.sh (#1018).
#
# That script stops the unit a node mines through, moves its unit file, and starts it under a new
# name. The two outcomes that matter are the ones a happy-path run never shows:
#
#   * the renamed unit does not come up — the node must be put back EXACTLY as it was, running;
#   * the script is run twice — the second run must change nothing and restart nothing.
#
# Hermetic: every path is under a throwaway root and systemctl/visudo are stubs. The stub keeps
# just enough state (which unit is active, which is enabled) for the script's own verification
# steps to be answered truthfully, and can be told to fail a start or to "crash" after one.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/ops/rename-node-unit.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
G=/usr/bin/grep

pass=0; fail=0
ok()  { printf "  [ok ] %s\n" "$1"; pass=$((pass+1)); }
bad() { printf "  [BAD] %s\n        %s\n" "$1" "${2:-}"; fail=$((fail+1)); }
is()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "wanted '$2', got '$3'"; fi; }
has() { if printf '%s\n' "$3" | $G -qE -- "$2"; then ok "$1"; else bad "$1" "wanted /$2/ in: $(printf '%s' "$3" | tr '\n' '|' | cut -c1-300)"; fi; }

# --- stubs -----------------------------------------------------------------------------------
# State lives in $STUB: `active` holds the name the running unit was started under (or is
# absent), `calls` logs every invocation. Unit existence is read from the real files under $U,
# so a start of a unit whose file was moved away fails, as it would.
#   STUB_FAIL_START=<unit>   `start <unit>` exits 1
#   STUB_DIES=<unit>         `start <unit>` exits 0 but the unit is `failed` afterwards
cat > "$TMP/systemctl" <<'SC'
#!/usr/bin/env bash
echo "$*" >> "$STUB/calls"
resolve() { local f="$U/$1"; [ -e "$f" ] || return 1; basename "$(readlink -f "$f")"; }
case "$1" in
  daemon-reload) exit 0 ;;
  is-active)
      r="$(resolve "$2")" || { echo inactive; exit 3; }
      if [ -f "$STUB/active" ] && [ "$(cat "$STUB/active")" = "$r" ]; then echo active; exit 0; fi
      if [ -f "$STUB/failed" ] && [ "$(cat "$STUB/failed")" = "$r" ]; then echo failed; exit 3; fi
      echo inactive; exit 3 ;;
  start)
      r="$(resolve "$2")" || exit 5
      [ "${STUB_FAIL_START:-}" = "$r" ] && exit 1
      if [ "${STUB_DIES:-}" = "$r" ]; then echo "$r" > "$STUB/failed"; rm -f "$STUB/active"; exit 0; fi
      echo "$r" > "$STUB/active"; exit 0 ;;
  stop)
      r="$(resolve "$2")" || exit 0
      [ -f "$STUB/active" ] && [ "$(cat "$STUB/active")" = "$r" ] && rm -f "$STUB/active"
      exit 0 ;;
  show)
      r="$(resolve "$2")" || exit 1
      out="$r"
      for l in "$U"/*.service; do
          [ -L "$l" ] && [ "$(basename "$(readlink -f "$l")")" = "$r" ] && out="$out $(basename "$l")"
      done
      echo "$out" ;;
  is-enabled) if [ -L "$U/multi-user.target.wants/$2" ]; then echo enabled; else echo disabled; exit 1; fi ;;
  enable)  [ "${STUB_ENABLE_BROKEN:-}" = 1 ] && exit 0
           mkdir -p "$U/multi-user.target.wants"; ln -sf "$U/$2" "$U/multi-user.target.wants/$2" ;;
  disable) rm -f "$U/multi-user.target.wants/$2" ;;
  *) exit 0 ;;
esac
SC
# visudo: accepts anything unless told otherwise.
cat > "$TMP/visudo" <<'VS'
#!/usr/bin/env bash
[ "${STUB_VISUDO_REJECTS:-}" = 1 ] && exit 1
exit 0
VS
chmod +x "$TMP/systemctl" "$TMP/visudo"

# --- a node as the fleet has them --------------------------------------------------------------
# $1 = root, $2 = "staged" (deploy-node placed the incoming binary) or "plain".
make_node() {
    local r="$1" mode="${2:-staged}"
    rm -rf "$r"; mkdir -p "$r/etc/systemd/system/ghost-pool.service.d" "$r/opt/ghost/bin" "$r/etc/sudoers.d" "$r/stub"
    U="$r/etc/systemd/system"
    # `--root` stands in for /, so the unit's ExecStart carries it too.
    cat > "$U/ghost-pool.service" <<EOF
[Unit]
Description=Ghost Pool node
After=network-online.target ghostd.service
[Service]
User=ghost
ExecStart=$r/opt/ghost/bin/ghost-pool --config /etc/ghost/pool.toml --tdp-enabled --tdp-port 8442 --stratum-port 3333
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    printf '[Service]\nEnvironment=ZK_GENESIS_PARAMS_HASH=c9c9\n' > "$U/ghost-pool.service.d/genesis-anchor.conf"
    printf '[Unit]\nDescription=Ghost Pool node\n[Service]\nRestartSec=15\n' > "$U/ghost-pool.service.d/installer-parity.conf"
    cat > "$U/ghost-pool-gate.service" <<'EOF'
[Unit]
Description=Ghost Pool sync gate (starts ghost-pool once ghostd is synced)
After=ghostd.service network-online.target
[Service]
Type=oneshot
ExecStart=/opt/ghost/bin/wait-for-ghostd-sync.sh
[Install]
WantedBy=multi-user.target
EOF
    mkdir -p "$U/multi-user.target.wants"
    ln -s "$U/ghost-pool-gate.service" "$U/multi-user.target.wants/ghost-pool-gate.service"
    printf '[Unit]\nDescription=SRI Pool\nAfter=network.target ghost-pool.service\nWants=ghost-pool.service\n# ghostd, ghost-pool and\n[Service]\nExecStart=/opt/ghost/bin/pool_sv2\n' > "$U/sri-pool.service"
    printf '[Unit]\nAfter=network-online.target ghostd.service ghost-pool.service\n[Service]\nExecStart=/bin/true\n' > "$U/ghost-restart-watch.service"
    printf '[Unit]\nAfter=ghost-pool-gate.service\n[Service]\nExecStart=/bin/true\n' > "$U/unrelated.service"
    echo OLD-BUILD > "$r/opt/ghost/bin/ghost-pool"
    [ "$mode" = staged ] && echo NEW-BUILD > "$r/opt/ghost/bin/ghost-mining"
    cat > "$r/etc/sudoers.d/ghost-services" <<'EOF'
# Allow ghost user to control Ghost services without password
ghost ALL=(ALL) NOPASSWD: /bin/systemctl restart ghost-pay
ghost ALL=(ALL) NOPASSWD: /bin/systemctl start ghost-pool
ghost ALL=(ALL) NOPASSWD: /bin/systemctl stop ghost-pool
ghost ALL=(ALL) NOPASSWD: /bin/systemctl restart ghost-pool
EOF
    echo ghost-pool.service > "$r/stub/active"
    : > "$r/stub/calls"
}
run() { # run <root> [VAR=val ...] [-- script args]
    local r="$1"; shift
    local envs=() args=()
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do envs+=("$1"); shift; done
    [ "${1:-}" = "--" ] && shift
    args=("$@")
    env STUB="$r/stub" U="$r/etc/systemd/system" GHOST_RENAME_SYSTEMCTL="$TMP/systemctl" \
        GHOST_RENAME_VISUDO="$TMP/visudo" GHOST_RENAME_SETTLE_SECS=0 "${envs[@]}" \
        bash "$SCRIPT" --root "$r" "${args[@]}" 2>&1
}
snapshot() { (cd "$1" && find etc opt -mindepth 1 \( -type f -o -type l \) | sort | while IFS= read -r p; do
                  if [ -L "$p" ]; then echo "L $p -> $(readlink "$p")"; else echo "F $p $(sha256sum < "$p" | cut -c1-12)"; fi; done); }

# =========================================================================================
echo "1. a legacy node, as deploy-node.sh leaves it (incoming binary staged beside the old one)"
R="$TMP/n1"; make_node "$R" staged; U="$R/etc/systemd/system"
out="$(run "$R")"; rc=$?
is  "exits 0" 0 "$rc"
has "reports the restart it performed" '^RENAME_OK flipped=yes active=active$' "$(printf '%s\n' "$out" | tail -1)"
is  "the new unit is a real file" yes "$([ -f "$U/ghost-mining.service" ] && [ ! -L "$U/ghost-mining.service" ] && echo yes)"
is  "the old unit name is a symlink to it" ghost-mining.service "$(readlink "$U/ghost-pool.service")"
is  "ExecStart runs the renamed binary" 1 "$($G -c "^ExecStart=$R/opt/ghost/bin/ghost-mining --config /etc/ghost/pool.toml --tdp-enabled" "$U/ghost-mining.service")"
is  "nothing else on the ExecStart line moved (pool.toml is on the keep list)" 1 "$($G -c 'pool\.toml --tdp-enabled --tdp-port 8442 --stratum-port 3333$' "$U/ghost-mining.service")"
is  "Description matches the installer's" 1 "$($G -c '^Description=Ghost Mining node$' "$U/ghost-mining.service")"
is  "both drop-ins moved" 2 "$(find "$U/ghost-mining.service.d" -type f | $G -c .)"
is  "the genesis anchor is byte-identical" "$(printf '[Service]\nEnvironment=ZK_GENESIS_PARAMS_HASH=c9c9\n' | sha256sum)" "$(sha256sum < "$U/ghost-mining.service.d/genesis-anchor.conf")"
is  "the parity drop-in's Description follows" 1 "$($G -c '^Description=Ghost Mining node$' "$U/ghost-mining.service.d/installer-parity.conf")"
is  "the old drop-in directory is gone (it would apply twice through the alias)" no "$([ -e "$U/ghost-pool.service.d" ] && echo yes || echo no)"
is  "the running binary is the INCOMING build" NEW-BUILD "$(cat "$R/opt/ghost/bin/ghost-mining")"
is  "the old binary name is a symlink" ghost-mining "$(readlink "$R/opt/ghost/bin/ghost-pool")"
is  "no set-aside copies are left" 0 "$(find "$R" -name '*pre-rename*' | $G -c . || true)"
is  "the unit that is running is the new one" ghost-mining.service "$(cat "$R/stub/active")"
is  "stopped exactly once, started exactly once" "1 1" "$($G -c '^stop ghost-pool.service$' "$R/stub/calls") $($G -c '^start ghost-mining.service$' "$R/stub/calls")"
is  "the gate is renamed" yes "$([ -f "$U/ghost-mining-gate.service" ] && [ ! -e "$U/ghost-pool-gate.service" ] && echo yes)"
is  "the renamed gate is enabled" yes "$([ -L "$U/multi-user.target.wants/ghost-mining-gate.service" ] && echo yes)"
is  "the old gate's enablement link is gone" no "$([ -e "$U/multi-user.target.wants/ghost-pool-gate.service" ] || [ -L "$U/multi-user.target.wants/ghost-pool-gate.service" ] && echo yes || echo no)"
is  "the gate was NOT started (it would start ghost-pay)" 0 "$($G -c '^start ghost-mining-gate' "$R/stub/calls" || true)"
is  "sri-pool orders on and wants the new name" "After=network.target ghost-mining.service|Wants=ghost-mining.service" "$($G -E '^(After|Wants)=' "$U/sri-pool.service" | paste -sd'|')"
is  "sri-pool's comment is left alone" 1 "$($G -c '^# ghostd, ghost-pool and$' "$U/sri-pool.service")"
is  "the watchdog unit orders on the new name" "After=network-online.target ghostd.service ghost-mining.service" "$($G '^After=' "$U/ghost-restart-watch.service")"
is  "a unit naming only the GATE is not rewritten into nonsense" "After=ghost-pool-gate.service" "$($G '^After=' "$U/unrelated.service")"
is  "sudoers gained three twins" 3 "$($G -c 'systemctl (start|stop|restart) ghost-mining$' -E "$R/etc/sudoers.d/ghost-services")"
is  "sudoers kept the three old rules (a rolled-back binary asks by the old name)" 3 "$($G -cE 'systemctl (start|stop|restart) ghost-pool$' "$R/etc/sudoers.d/ghost-services")"
is  "sudoers mode is 0440" 440 "$(stat -c %a "$R/etc/sudoers.d/ghost-services")"
out="$(run "$R" -- --check)"; is "--check then reports nothing left" 0 "$?"

echo "2. run again: nothing changes and nothing restarts"
before="$(snapshot "$R")"; : > "$R/stub/calls"
out="$(run "$R")"; rc=$?
is  "exits 0" 0 "$rc"
has "says it did not restart" '^RENAME_OK flipped=no active=active$' "$(printf '%s\n' "$out" | tail -1)"
is  "the tree is byte-identical" "$before" "$(snapshot "$R")"
is  "no stop, start, enable or disable was issued" 0 "$($G -cE '^(stop|start|restart|enable|disable) ' "$R/stub/calls" || true)"

echo "3. the renamed unit fails to start: the node is put back exactly, and running"
R="$TMP/n3"; make_node "$R" staged; U="$R/etc/systemd/system"
before="$(snapshot "$R" | $G -v ' opt/ghost/bin/ghost-mining ')"
out="$(run "$R" STUB_FAIL_START=ghost-mining.service)"; rc=$?
is  "exits 1" 1 "$rc"
has "says it was undone, with the old unit active" '^RENAME_UNDONE active=active$' "$(printf '%s\n' "$out" | tail -1)"
is  "units, drop-ins, gate, dependents and sudoers are byte-identical to before" "$before" "$(snapshot "$R" | $G -v ' opt/ghost/bin/ghost-mining ')"
is  "the OLD build is back under the old name, as a real file" OLD-BUILD "$([ ! -L "$R/opt/ghost/bin/ghost-pool" ] && cat "$R/opt/ghost/bin/ghost-pool")"
is  "the old unit is the one running" ghost-pool.service "$(cat "$R/stub/active")"
is  "the gate was not touched" yes "$([ -f "$U/ghost-pool-gate.service" ] && [ -L "$U/multi-user.target.wants/ghost-pool-gate.service" ] && echo yes)"

echo "4. the renamed unit starts and then dies: same undo"
R="$TMP/n4"; make_node "$R" staged; U="$R/etc/systemd/system"
before="$(snapshot "$R" | $G -v ' opt/ghost/bin/ghost-mining ')"
out="$(run "$R" STUB_DIES=ghost-mining.service)"; rc=$?
is  "exits 1" 1 "$rc"
has "names the state it saw" "is 'failed' 0s after starting" "$out"
is  "tree restored" "$before" "$(snapshot "$R" | $G -v ' opt/ghost/bin/ghost-mining ')"
is  "the old unit is running" ghost-pool.service "$(cat "$R/stub/active")"

echo "5. a unit whose ExecStart is not the expected shape is refused, not half-renamed"
R="$TMP/n5"; make_node "$R" staged; U="$R/etc/systemd/system"
sed -i "s|^ExecStart=$R/opt/ghost/bin/ghost-pool |ExecStart=/usr/local/bin/ghost-pool |" "$U/ghost-pool.service"
before="$(snapshot "$R" | $G -v ' opt/ghost/bin/ghost-mining ')"
out="$(run "$R")"; rc=$?
is  "exits 1" 1 "$rc"
has "says why" 'expected exactly one ExecStart=.*/opt/ghost/bin/ghost-mining in the new unit, found 0' "$out"
is  "tree restored" "$before" "$(snapshot "$R" | $G -v ' opt/ghost/bin/ghost-mining ')"
is  "the old unit is running again" ghost-pool.service "$(cat "$R/stub/active")"

echo "6. run by hand, with no incoming binary staged: the binary is moved"
R="$TMP/n6"; make_node "$R" plain; U="$R/etc/systemd/system"
out="$(run "$R")"; rc=$?
is  "exits 0" 0 "$rc"
is  "the one build is now under the new name" OLD-BUILD "$([ ! -L "$R/opt/ghost/bin/ghost-mining" ] && cat "$R/opt/ghost/bin/ghost-mining")"
is  "and the old name aliases it" ghost-mining "$(readlink "$R/opt/ghost/bin/ghost-pool")"

echo "7. a stopped node is renamed without being started"
R="$TMP/n7"; make_node "$R" staged; U="$R/etc/systemd/system"; rm -f "$R/stub/active"
out="$(run "$R")"; rc=$?
is  "exits 0" 0 "$rc"
has "reports it inactive" '^RENAME_OK flipped=yes active=inactive$' "$(printf '%s\n' "$out" | tail -1)"
is  "no start was issued" 0 "$($G -c '^start ' "$R/stub/calls" || true)"

echo "8. a sudoers file that would not validate is left untouched, and the run says so"
R="$TMP/n8"; make_node "$R" staged; U="$R/etc/systemd/system"
want="$(sha256sum < "$R/etc/sudoers.d/ghost-services")"
out="$(run "$R" STUB_VISUDO_REJECTS=1)"; rc=$?
is  "exits 1" 1 "$rc"
has "the unit switch stands — it is not undone for a tidy-up failure" '^RENAME_PARTIAL flipped=yes active=active$' "$(printf '%s\n' "$out" | tail -1)"
is  "sudoers is byte-identical" "$want" "$(sha256sum < "$R/etc/sudoers.d/ghost-services")"
is  "no temp file left in sudoers.d (sudo reads every file there)" 1 "$(find "$R/etc/sudoers.d" -type f | $G -c .)"
is  "the node is serving under the new name" ghost-mining.service "$(cat "$R/stub/active")"

echo "9. a gate that does not come back enabled is a failure, loudly"
R="$TMP/n9"; make_node "$R" staged; U="$R/etc/systemd/system"
out="$(run "$R" STUB_ENABLE_BROKEN=1)"; rc=$?
is  "exits 1" 1 "$rc"
has "says what it will cost" 'WILL NOT START ghost-mining AT BOOT' "$out"

echo "10. states it must not guess about"
R="$TMP/n10"; make_node "$R" staged; U="$R/etc/systemd/system"; cp "$U/ghost-pool.service" "$U/ghost-mining.service"
before="$(snapshot "$R")"
out="$(run "$R")"; is "two real unit files: exit 2" 2 "$?"
is  "and nothing was changed" "$before" "$(snapshot "$R")"
R="$TMP/n11"; make_node "$R" staged; U="$R/etc/systemd/system"; rm "$U/ghost-pool.service"
out="$(run "$R")"; is "no unit under either name: exit 2" 2 "$?"
out="$(run "$R" -- --check)"; is "--check agrees it is inconclusive, not clean" 2 "$?"
R="$TMP/n12"; make_node "$R" staged
out="$(run "$R" -- --check)"; rc=$?
is  "--check on a legacy node: exit 1" 1 "$rc"
has "and it lists the gate, a dependent and sudoers" 'gate: .*dependent: sri-pool.service.*sudoers: 3 rule' "$(printf '%s' "$out" | tr '\n' ' ')"
is  "--check changed nothing" ghost-pool.service "$(cat "$R/stub/active")"

echo
echo "rename-node-unit self-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
