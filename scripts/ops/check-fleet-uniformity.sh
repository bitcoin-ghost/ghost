#!/usr/bin/env bash
#
# Report configuration and binary drift across the fleet.
#
# Drift is invisible until it costs something. Rolling v1.11.18, the binaries went out
# to all eight nodes but the stratum config did not — `deploy-node.sh` swaps binaries
# only. All four production nodes were left handing miners a starting difficulty of
# 1,164 while the canaries handed out 23,283. A 20x difference in what a miner is given,
# decided purely by which node DNS returned, and nothing reported it. It was found by
# reading config files by hand.
#
# Two things this deliberately does NOT do:
#
#   * It does not compare against `config/sri/translator-config.toml`. That file is not
#     read by anything and is currently wrong in two places (#431), so treating it as
#     the reference would assert the wrong values with a straight face.
#   * It does not assume agreement means correctness. All four production nodes agreed
#     with each other on a stale value. Cross-node agreement is necessary, not
#     sufficient — hence the explicit invariants below and the black-box probe.
#
# Usage:
#   scripts/ops/check-fleet-uniformity.sh [<node> ...]     # defaults to all eight
#   scripts/ops/check-fleet-uniformity.sh --probe <node> ...  # also probe live difficulty
#
# Exit 0 iff every node agrees and every invariant holds.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

PROBE=false
if [ "${1:-}" = "--probe" ]; then PROBE=true; shift; fi

NODES=("$@")
if [ ${#NODES[@]} -eq 0 ]; then
    NODES=(ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4 ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8)
fi

# Invariants that must hold on EVERY node regardless of what the others say.
# extranonce2_size: rented-hashrate marketplaces reject a pool below 7 (Braiins).
MIN_EXTRANONCE2_SIZE=7

# Fields collected per node. Keep the remote side to one ssh round trip per node.
COLLECT='
  printf "gp_sha=%s\n"        "$(sha256sum /opt/ghost/bin/ghost-pool 2>/dev/null | cut -c1-12)"
  printf "poolsv2_sha=%s\n"   "$(sha256sum /opt/ghost/bin/pool_sv2 2>/dev/null | cut -c1-12)"
  printf "trans_sha=%s\n"     "$(sha256sum /opt/ghost/bin/translator_sv2 2>/dev/null | cut -c1-12)"
  printf "vardiff=%s\n"       "$(grep -hE "^min_individual_miner_hashrate" /etc/ghost/translator-config.toml 2>/dev/null | cut -d= -f2 | xargs)"
  printf "en2_size=%s\n"      "$(grep -hE "^downstream_extranonce2_size" /etc/ghost/translator-config.toml 2>/dev/null | cut -d= -f2 | xargs)"
  printf "aggregate=%s\n"     "$(grep -hE "^aggregate_channels" /etc/ghost/translator-config.toml 2>/dev/null | cut -d= -f2 | xargs)"
  printf "spm=%s\n"           "$(grep -hE "^shares_per_minute" /etc/ghost/translator-config.toml 2>/dev/null | cut -d= -f2 | xargs)"
  printf "vardiff_on=%s\n"    "$(grep -hE "^enable_vardiff" /etc/ghost/translator-config.toml 2>/dev/null | cut -d= -f2 | xargs)"
  printf "port=%s\n"          "$(grep -hE "^downstream_port" /etc/ghost/translator-config.toml 2>/dev/null | cut -d= -f2 | xargs)"
  printf "journal=%s\n"       "$([ -d /var/log/journal ] && echo persistent || echo volatile)"
  printf "watchdog=%s\n"      "$(systemctl is-active ghost-restart-watch.timer 2>/dev/null)"
  printf "pool_svc=%s\n"      "$(systemctl is-active ghost-pool 2>/dev/null)"
  printf "sripool_svc=%s\n"   "$(systemctl is-active sri-pool 2>/dev/null)"
  printf "trans_svc=%s\n"     "$(systemctl is-active sri-translator 2>/dev/null)"
'

declare -A VALUES   # VALUES[node|field] = value
FIELDS=""
UNREACHABLE=()

for n in "${NODES[@]}"; do
    out="$(ssh -o ConnectTimeout=10 -o BatchMode=yes "$n" "$COLLECT" 2>/dev/null)" || { UNREACHABLE+=("$n"); continue; }
    while IFS='=' read -r k v; do
        [ -n "$k" ] || continue
        VALUES["$n|$k"]="$v"
        case " $FIELDS " in *" $k "*) ;; *) FIELDS="$FIELDS $k" ;; esac
    done <<<"$out"
done

rc=0

if [ ${#UNREACHABLE[@]} -gt 0 ]; then
    echo "UNREACHABLE: ${UNREACHABLE[*]}"
    echo
    rc=1
fi

REACHED=()
for n in "${NODES[@]}"; do
    [[ " ${UNREACHABLE[*]-} " == *" $n "* ]] || REACHED+=("$n")
done
[ ${#REACHED[@]} -gt 0 ] || { echo "No nodes reachable."; exit 1; }

# ---------------------------------------------------------------- cross-node drift
echo "Fleet: ${#REACHED[@]} node(s)"
echo
drifted=0
for f in $FIELDS; do
    # Collect the distinct values for this field.
    declare -A seen=()
    for n in "${REACHED[@]}"; do
        v="${VALUES[$n|$f]:-<missing>}"
        seen["$v"]="${seen[$v]:-} $n"
    done
    if [ ${#seen[@]} -gt 1 ]; then
        drifted=$((drifted + 1))
        echo "DRIFT  $f"
        for v in "${!seen[@]}"; do
            printf "         %-28s %s\n" "$v" "$(echo "${seen[$v]}" | xargs)"
        done
        rc=1
    fi
    unset seen
done
[ "$drifted" -eq 0 ] && echo "No cross-node drift in: $(echo "$FIELDS" | xargs | tr ' ' ',')"
echo

# ---------------------------------------------------------------- invariants
# Agreement is not correctness — all four production nodes agreed on a stale value.
echo "Invariants:"
for n in "${REACHED[@]}"; do
    en2="${VALUES[$n|en2_size]:-}"
    if [ -n "$en2" ] && [ "$en2" -lt "$MIN_EXTRANONCE2_SIZE" ] 2>/dev/null; then
        echo "  FAIL $n extranonce2_size=$en2 (< $MIN_EXTRANONCE2_SIZE — marketplaces reject this)"
        rc=1
    fi
    agg="${VALUES[$n|aggregate]:-}"
    if [ "$agg" = "true" ]; then
        echo "  FAIL $n aggregate_channels=true (collapses per-miner channels; breaks attribution)"
        rc=1
    fi
    for svc in pool_svc sripool_svc trans_svc; do
        s="${VALUES[$n|$svc]:-}"
        [ "$s" = "active" ] || { echo "  FAIL $n $svc=$s"; rc=1; }
    done
    [ "${VALUES[$n|journal]:-}" = "persistent" ] || { echo "  WARN $n journal is volatile — logs die with the service being diagnosed (#414)"; }
    [ "${VALUES[$n|watchdog]:-}" = "active" ] || { echo "  WARN $n restart watchdog timer not active (#412)"; }
done
[ "$rc" -eq 0 ] && echo "  all invariants hold"
echo

# ---------------------------------------------------------------- black-box probe
# The file comparison above can be fooled by a config that is not being READ — wrong
# path, stale WorkingDirectory, service never restarted. The probe asks the pool what
# it actually serves.
if $PROBE; then
    SMOKE="$REPO_ROOT/bins/translator-sv2/tests/sv1_handshake_smoke.py"
    if [ -r "$SMOKE" ]; then
        echo "Live probe (default difficulty served to a miner that requests nothing):"
        for n in "${REACHED[@]}"; do
            ip="$(ssh -o ConnectTimeout=10 "$n" "hostname -I | awk '{print \$1}'" 2>/dev/null)"
            [ -n "$ip" ] || { echo "  $n: no address"; rc=1; continue; }
            line="$(python3 "$SMOKE" "$ip" 3333 2>/dev/null | grep -E "default-diff")" || true
            printf "  %-11s %s\n" "$n" "${line:-probe produced no result}"
            case "$line" in *FAIL*) rc=1 ;; esac
        done
        echo
    else
        echo "Live probe skipped: $SMOKE not found"
        echo
    fi
fi

if [ "$rc" -eq 0 ]; then
    echo "RESULT: fleet uniform"
else
    echo "RESULT: drift or invariant failure — see above"
fi
exit $rc
