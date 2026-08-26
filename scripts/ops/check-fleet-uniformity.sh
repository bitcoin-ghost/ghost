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
  SUDO=$(command -v sudo >/dev/null && echo sudo || echo)
  printf "gp_sha=%s\n"        "$(sha256sum /opt/ghost/bin/ghost-pool 2>/dev/null | cut -c1-12)"
  printf "poolsv2_sha=%s\n"   "$(sha256sum /opt/ghost/bin/pool_sv2 2>/dev/null | cut -c1-12)"
  printf "trans_sha=%s\n"     "$(sha256sum /opt/ghost/bin/translator_sv2 2>/dev/null | cut -c1-12)"
  printf "vardiff=%s\n"       "$(grep -hE "^min_individual_miner_hashrate" /etc/ghost/translator-config.toml 2>/dev/null | cut -d= -f2 | sed "s/#.*//" | xargs | tr "\n" " " | xargs)"
  printf "en2_size=%s\n"      "$(grep -hE "^downstream_extranonce2_size" /etc/ghost/translator-config.toml 2>/dev/null | cut -d= -f2 | sed "s/#.*//" | xargs | tr "\n" " " | xargs)"
  printf "aggregate=%s\n"     "$(grep -hE "^aggregate_channels" /etc/ghost/translator-config.toml 2>/dev/null | cut -d= -f2 | sed "s/#.*//" | xargs | tr "\n" " " | xargs)"
  printf "spm=%s\n"           "$(grep -hE "^shares_per_minute" /etc/ghost/translator-config.toml 2>/dev/null | cut -d= -f2 | sed "s/#.*//" | xargs | tr "\n" " " | xargs)"
  printf "vardiff_on=%s\n"    "$(grep -hE "^enable_vardiff" /etc/ghost/translator-config.toml 2>/dev/null | cut -d= -f2 | sed "s/#.*//" | xargs | tr "\n" " " | xargs)"
  printf "port=%s\n"          "$(grep -hE "^downstream_port" /etc/ghost/translator-config.toml 2>/dev/null | cut -d= -f2 | sed "s/#.*//" | xargs | tr "\n" " " | xargs)"
  printf "journal=%s\n"       "$([ -d /var/log/journal ] && echo persistent || echo volatile)"
  printf "watchdog=%s\n"      "$(systemctl is-active ghost-restart-watch.timer 2>/dev/null)"
  printf "pool_svc=%s\n"      "$(systemctl is-active ghost-pool 2>/dev/null)"
  printf "sripool_svc=%s\n"   "$(systemctl is-active sri-pool 2>/dev/null)"
  printf "trans_svc=%s\n"     "$(systemctl is-active sri-translator 2>/dev/null)"

  # --- duplicates and impostors (#756) -------------------------------------------------
  # ghost-vm1 ran TWO translators: a Feb-dated `ghost-translator` grabbed :3333 at boot and
  # `sri-translator` could then never bind, sitting in `activating` for FIVE DAYS while eight
  # miners fed a superseded binary that could not open a session with pool_sv2. Every check
  # this script had read green throughout, because each one asked "is the right unit enabled"
  # and none asked "is anything ELSE also running, and who actually holds the port".
  # ⚠ `pgrep -c` PRINTS 0 and also EXITS NON-ZERO when nothing matches, so `|| echo 0` emits a
  # SECOND zero on its own line — which this collector then reads as a field named "0". Take the
  # output and default it, rather than falling back on the exit status.
  nproc() { local c; c="$(pgrep -c -x "$1" 2>/dev/null)"; printf "%s" "${c:-0}"; }
  printf "procs_translator=%s,%s\n" "$(nproc translator_sv2)" "$(nproc translator)"
  printf "procs_poolsv2=%s,%s\n"    "$(nproc pool_sv2)" "$(nproc pool)"
  printf "procs_ghostpool=%s\n"     "$(nproc ghost-pool)"
  # Who actually holds each load-bearing port. The binary NAME, not the unit that claims it.
  printf "owner_3333=%s\n"       "$($SUDO ss -ltnp 2>/dev/null | grep -oP ":3333\s.*users:\(\(\"\K[^\"]+" | head -1)"
  printf "owner_34255=%s\n"      "$($SUDO ss -ltnp 2>/dev/null | grep -oP ":34255\s.*users:\(\(\"\K[^\"]+" | head -1)"
  printf "owner_8442=%s\n"       "$($SUDO ss -ltnp 2>/dev/null | grep -oP ":8442\s.*users:\(\(\"\K[^\"]+" | head -1)"
  # Units wedged in activating/failed. `activating` is the one that hid for five days: it is
  # neither active (so no is-active check fires) nor absent (so nothing looks orphaned).
  printf "stuck_units=%s\n"      "$(systemctl list-units --type=service --state=activating,failed,deactivating --no-legend --plain 2>/dev/null | awk "{print \$1}" | paste -sd, - )"
  # Superseded units that should not exist on any node at all.
  printf "stale_units=%s\n"      "$(for u in ghost-translator ghost-pool-sv2 ghost-sri-pool sri-pool-old; do systemctl cat \$u >/dev/null 2>&1 && printf "%s " \$u; done | xargs)"
  # Superseded binaries left in the deploy dir alongside the real ones.
  printf "stale_bins=%s\n"       "$(for b in translator pool jd-client jd-server; do [ -f /opt/ghost/bin/\$b ] && printf "%s " \$b; done | xargs)"
  # BOOT ENABLEMENT. `is-active` says a service is running NOW; `is-enabled` says it comes back.
  # A service that is active-but-disabled survives until the next reboot and no further, and no
  # health check that asks "is it running" will ever notice.
  printf "en_ghostd=%s\n"        "$(systemctl is-enabled ghostd 2>/dev/null | head -1)"
  printf "en_ghostpool=%s\n"     "$(systemctl is-enabled ghost-pool 2>/dev/null | head -1)"
  printf "en_sripool=%s\n"       "$(systemctl is-enabled sri-pool 2>/dev/null | head -1)"
  printf "en_sritrans=%s\n"      "$(systemctl is-enabled sri-translator 2>/dev/null | head -1)"
  printf "en_bitcoind=%s\n"      "$(systemctl is-enabled bitcoind 2>/dev/null | head -1)"
  printf "en_poolgate=%s\n"      "$(systemctl is-enabled ghost-pool-gate 2>/dev/null | head -1)"
  # #758: the farm tier was decided ON for every public mining node (#410, 2026-07-27) and reached
  # exactly ONE of eight. It was visible here only as `vardiff` drift, because vm8 returned two
  # min_individual_miner_hashrate values where others returned one — which reads as a config
  # preference, not as "a shipped feature is missing on seven nodes". Assert the thing itself.
  printf "farm_cfg=%s\n"         "$(grep -cE "^\[farm_tier\]" /etc/ghost/translator-config.toml 2>/dev/null)"
  printf "farm_listen=%s\n"      "$($SUDO ss -ltn 2>/dev/null | grep -c ":4444")"
  printf "farm_ufw=%s\n"         "$($SUDO ufw status 2>/dev/null | grep -c "4444")"
  printf "mining_mode=%s\n"      "$(grep -oP "^\s*mining_mode\s*=\s*\"\K[^\"]+" /etc/ghost/pool.toml 2>/dev/null | head -1)"
  # #759: config is never reconciled against what the repo ships, so dead keys survive for months
  # and required ones are absent while the compiled default silently covers for them. Both are
  # "correct by accident" — a value nobody chose. List the names, not just a count, so the report
  # says WHICH.
  printf "dead_keys=%s\n"        "$(grep -ohE "^[[:space:]]*(public_mining|bond_ledger_url|bond_ledger_token)[[:space:]]*=" /etc/ghost/pool.toml /etc/ghost/translator-config.toml 2>/dev/null | tr -d " =" | sort -u | paste -sd, -)"
  printf "tdp_cfg=%s\n"          "$(grep -cE "^\[tdp\]" /etc/ghost/pool.toml 2>/dev/null)"
  printf "cfg_parses=%s\n"       "$(/opt/ghost/bin/ghost-pool --config /etc/ghost/pool.toml --show-identity >/dev/null 2>&1 && echo ok || echo FAIL)"
  # Ops scripts are deployed by NOTHING — `deploy-node.sh` handles ghost-pool, pool_sv2 and
  # translator_sv2 and nothing else. So these drift silently and stay drifted: the restart
  # watchdog sat on a pre-fix version on all eight for months, posting to an ALERT_WEBHOOK
  # from a config file that does not exist, and nobody could tell.
  printf "ops_restart_watch=%s\n" "$($SUDO sha256sum /opt/ghost/bin/ghost-restart-watch.sh 2>/dev/null | cut -c1-16)"
  printf "ops_auto_update=%s\n"   "$($SUDO sha256sum /opt/ghost/bin/ghost-auto-update.sh 2>/dev/null | cut -c1-16)"
  printf "ops_pool_sig=%s\n"      "$($SUDO sha256sum /opt/ghost/bin/update-pool-signature.sh 2>/dev/null | cut -c1-16)"
  printf "ops_wait_sync=%s\n"     "$($SUDO sha256sum /opt/ghost/bin/wait-for-ghostd-sync.sh 2>/dev/null | cut -c1-16)"
  # #761: the dead_keys grep above can only ever find the three names written into it, so a clean
  # report from it proves nothing about any OTHER unknown key. --check-config is the generic
  # oracle: it round-trips the file through NodeConfig and diffs written-vs-understood, so the
  # struct is its own source of truth. Prints key NAMES only, never values.
  #
  # The flag does not exist in binaries older than the #761 release. Distinguish "no unknown keys"
  # from "this binary cannot answer" — reporting the second as the first is how a check that
  # cannot fail gets built.
  printf "cfg_unknown=%s\n"      "$(if ! /opt/ghost/bin/ghost-pool --help 2>&1 | grep -q -- "--check-config"; then echo unsupported; elif /opt/ghost/bin/ghost-pool --config /etc/ghost/pool.toml --check-config >/dev/null 2>&1; then echo none; else /opt/ghost/bin/ghost-pool --config /etc/ghost/pool.toml --check-config 2>&1 | sed -n "s/^  //p" | paste -sd, -; fi)"
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
    # ⛔ This gate is CORRECT, not leftover caution — do not relax it (scoped under #411,
    # 2026-08-23). Aggregated mode is not broken and not unfinished: the translator already
    # mints real per-downstream extranonces locally, with no upstream round trip. What is
    # missing is that the per-share TLV carries only the WORKER NAME, not the payout address,
    # so payout derivation has nothing per-miner to key on and every miner in the aggregate
    # collapses onto ONE channel address. Turning this on pays the wrong people.
    #
    # Making it safe means moving payout derivation to the per-share TLV for every SV1 miner —
    # a money-path change needing a height gate and a fleet roll. Deferred deliberately: the
    # pool runs ~4 miners against a cap of 1,000, so aggregation optimises a problem it does
    # not have. Revisit with multi-operator, when scale makes per-channel overhead real.
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

    # ---- duplicates and impostors (#756) ----------------------------------------------
    # Exactly one process per role. The second copy is never harmless: on ghost-vm1 a Feb-dated
    # `translator` held :3333 for five days and eight miners' work went nowhere.
    IFS=, read -r n_tsv2 n_told <<<"${VALUES[$n|procs_translator]:-0,0}"
    IFS=, read -r n_psv2 n_pold <<<"${VALUES[$n|procs_poolsv2]:-0,0}"
    n_gp="${VALUES[$n|procs_ghostpool]:-0}"
    [ "${n_tsv2:-0}" -le 1 ] 2>/dev/null || { echo "  FAIL $n ${n_tsv2} translator_sv2 processes (expected 1)"; rc=1; }
    [ "${n_psv2:-0}" -le 1 ] 2>/dev/null || { echo "  FAIL $n ${n_psv2} pool_sv2 processes (expected 1)"; rc=1; }
    [ "${n_gp:-0}"   -le 1 ] 2>/dev/null || { echo "  FAIL $n ${n_gp} ghost-pool processes (expected 1)"; rc=1; }
    [ "${n_told:-0}" -eq 0 ] 2>/dev/null || { echo "  FAIL $n ${n_told} SUPERSEDED 'translator' process(es) running — this is the #756 outage"; rc=1; }
    [ "${n_pold:-0}" -eq 0 ] 2>/dev/null || { echo "  FAIL $n ${n_pold} SUPERSEDED 'pool' process(es) running"; rc=1; }

    # The port must be held by the binary we think serves it. An impostor answers happily.
    for spec in "owner_3333:translator_sv2:SV1 miners" "owner_34255:pool_sv2:SV2 upstream" "owner_8442:ghost-pool:template provider"; do
        IFS=: read -r fld want what <<<"$spec"
        got="${VALUES[$n|$fld]:-}"
        if [ -z "$got" ]; then
            echo "  WARN $n ${fld#owner_} has NO listener ($what) — or ss could not read it"
        elif [ "$got" != "$want" ]; then
            echo "  FAIL $n ${fld#owner_} is held by '$got', expected '$want' ($what)"; rc=1
        fi
    done

    # `activating` is neither active nor absent, so every is-active check reads past it.
    stuck="${VALUES[$n|stuck_units]:-}"
    [ -z "$stuck" ] || { echo "  FAIL $n units wedged in activating/failed: $stuck"; rc=1; }

    stale_u="${VALUES[$n|stale_units]:-}"
    [ -z "$stale_u" ] || { echo "  FAIL $n superseded unit(s) still installed: $stale_u"; rc=1; }
    stale_b="${VALUES[$n|stale_bins]:-}"
    [ -z "$stale_b" ] || { echo "  FAIL $n superseded binary/binaries in /opt/ghost/bin: $stale_b"; rc=1; }

    # Running is not surviving. Measured 2026-08-23: ghost-pool was DISABLED on all eight nodes
    # and ghostd on all four production nodes — every one of them active, so every check that
    # asked `is-active` read green. A reboot would have taken the pool down fleet-wide and the
    # chain daemon with it on vm1-4, and nothing here would have said so first.
    # ghost-pool is DELIBERATELY disabled where `ghost-pool-gate` owns its start: the gate is a
    # oneshot that blocks until ghostd leaves initial block download and only then starts the pool.
    # Enabling ghost-pool directly there would race the gate and start it against an unsynced
    # chain. So the invariant is "something brings it back", not "this unit is enabled".
    gate="${VALUES[$n|en_poolgate]:-}"
    case "$gate" in
        enabled|enabled-runtime|static) gp_units="en_sripool:sri-pool" ;;
        *)                              gp_units="en_ghostpool:ghost-pool en_sripool:sri-pool"
                                        echo "  WARN $n no ghost-pool-gate — ghost-pool must be enabled directly here" ;;
    esac
    for spec in "en_ghostd:ghostd" $gp_units "en_sritrans:sri-translator"; do
        IFS=: read -r fld unit <<<"$spec"
        e="${VALUES[$n|$fld]:-}"
        case "$e" in
            enabled|enabled-runtime|static|indirect) ;;
            "")        echo "  WARN $n could not read is-enabled for $unit — boot survival UNKNOWN" ;;
            not-found) echo "  FAIL $n $unit unit is MISSING"; rc=1 ;;
            *)         echo "  FAIL $n $unit is $e — running now, will NOT come back after a reboot"; rc=1 ;;
        esac
    done
    # The superseded chain unit must not be enabled anywhere; on vm1 it was enabled AND
    # crash-looping while the real ghostd ran disabled beside it.
    # The farm tier: config, listener and firewall must agree. An open ufw rule with no listener
    # is the worst of the three states — anything auditing reachability by firewall says yes and
    # is wrong. Seven nodes sat exactly there.
    fc="${VALUES[$n|farm_cfg]:-0}"; fl="${VALUES[$n|farm_listen]:-0}"; fw="${VALUES[$n|farm_ufw]:-0}"
    mm="${VALUES[$n|mining_mode]:-}"
    if [ "$mm" = "public_pool" ]; then
        [ "${fc:-0}" -gt 0 ] 2>/dev/null || { echo "  FAIL $n public_pool but no [farm_tier] in translator-config.toml (#758)"; rc=1; }
        [ "${fl:-0}" -gt 0 ] 2>/dev/null || { echo "  FAIL $n public_pool but nothing is LISTENING on :4444 (#758)"; rc=1; }
    fi
    if [ "${fw:-0}" -gt 0 ] 2>/dev/null && [ "${fl:-0}" -eq 0 ] 2>/dev/null; then
        echo "  FAIL $n ufw allows 4444 but NOTHING listens there — an audit by firewall reads this as reachable"; rc=1
    fi
    # mining_mode decides whether payouts go through BFT. Relying on MiningMode::default() means a
    # change to that default silently reconfigures the node.
    [ -n "$mm" ] || { echo "  FAIL $n mining_mode is not set in pool.toml — running on MiningMode::default() (#758)"; rc=1; }

    # #759: keys for features that no longer exist, and required keys covered for by a default.
    dk="${VALUES[$n|dead_keys]:-}"
    [ -z "$dk" ] || { echo "  FAIL $n config carries dead key(s) for removed features: $dk (#759)"; rc=1; }
    # ⛔ #759: this used to FAIL on a missing `[tdp]` block. That invariant was UNSATISFIABLE.
    #
    # `[tdp]` is not a section of `NodeConfig` — the accepted set is identity, bitcoin, network,
    # policy, storage, pool, ghost_pay, reaper, coordinator, node_launch, alerts, backup. It is not
    # in `pool-config.toml` either (that carries `[share_tier_binding]` and `[share_webhook]`), and
    # no shipped template contains it. TDP is pool_sv2's concern, configured by `--tdp-port` /
    # `--tdp-pubkey-from-keyfile`, not by a block in pool.toml.
    #
    # So the check demanded something that could never be present, on any node, ever — and since
    # #761 added `deny_unknown_fields`, satisfying it would REFUSE TO START the node:
    #
    #     unknown field `tdp`, expected one of `identity`, `bitcoin`, ...
    #
    # The underlying worry was real — TDP does run on compiled defaults, because the sri-pool unit
    # passes no `--tdp-port`. But that is a statement about the unit file, not a missing config
    # block, and it is the same on all eight, so it is not drift. Reported, not failed.
    [ "${VALUES[$n|tdp_cfg]:-0}" -gt 0 ] 2>/dev/null || tdp_default_nodes="${tdp_default_nodes:-}$n "
    # The strongest single check available: does the shipped binary actually accept this file?
    # #761: generic unknown-key oracle. `unsupported` is a WARN, not a pass — the check arms
    # itself once the #761 release is deployed and must not read as clean before then.
    case "${VALUES[$n|cfg_unknown]:-}" in
        none) ;;
        unsupported) echo "  WARN $n binary predates --check-config; unknown-key check did not run (#761)" ;;
        "") echo "  WARN $n could not run the unknown-key check" ;;
        *) echo "  FAIL $n config carries key(s) this binary does not understand: ${VALUES[$n|cfg_unknown]} (#761)"; rc=1 ;;
    esac
    case "${VALUES[$n|cfg_parses]:-}" in
        ok) ;;
        "") echo "  WARN $n could not run the config parse check" ;;
        *)  echo "  FAIL $n pool.toml does NOT parse with the deployed ghost-pool — this node will not restart"; rc=1 ;;
    esac

    eb="${VALUES[$n|en_bitcoind]:-}"
    case "$eb" in
        not-found|"") ;;
        enabled|enabled-runtime) echo "  FAIL $n superseded 'bitcoind' unit is ENABLED (ghostd is the chain daemon)"; rc=1 ;;
        *) echo "  WARN $n superseded 'bitcoind' unit still installed ($eb) — remove it" ;;
    esac
    # ⛔ Compare ops scripts against the REPO, not just node-to-node.
    #
    # Cross-node drift detection alone would have called the watchdog healthy: all eight were
    # stale IDENTICALLY, so they agreed perfectly with each other and disagreed with the source
    # of truth. Uniform staleness is the failure mode that hid the pre-fix watchdog for months
    # and put a February binary on vm1's :3333 for five days.
    #
    # Only files that HAVE a repo source are compared. `update-pool-signature.sh` and
    # `wait-for-ghostd-sync.sh` are node-local, so they are still gathered above for cross-node
    # drift, which is all that can honestly be said about them.
    for ops in "ops_restart_watch:scripts/ghost-restart-watch.sh" "ops_auto_update:scripts/ghost-auto-update.sh"; do
        field="${ops%%:*}"; src="$REPO_ROOT/${ops#*:}"
        [ -r "$src" ] || { echo "  WARN $n cannot read $src to compare $field"; continue; }
        want="$(sha256sum "$src" 2>/dev/null | cut -c1-16)"
        got="${VALUES[$n|$field]:-}"
        if [ -z "$got" ]; then
            echo "  WARN $n $field not readable on the node"
        elif [ "$got" != "$want" ]; then
            echo "  FAIL $n ${ops#*:} is STALE (node $got, repo $want) — nothing deploys it; copy it by hand"; rc=1
        fi
    done
done
# #759: reported once for the fleet, not failed per node. See the note above — `[tdp]` is not a
# NodeConfig section, so its absence is the only possible state, and it is identical everywhere.
if [ -n "${tdp_default_nodes:-}" ]; then
    echo "  NOTE TDP runs on compiled defaults (no --tdp-port in the sri-pool unit): ${tdp_default_nodes% }"
    echo "       Not drift and not fixable in pool.toml — adding [tdp] there fails deny_unknown_fields (#759, #761)"
fi
[ "$rc" -eq 0 ] && echo "  all invariants hold"
echo

# ---------------------------------------------------------------- black-box probe
# The file comparison above can be fooled by a config that is not being READ — wrong
# path, stale WorkingDirectory, service never restarted. The probe asks the pool what
# it actually serves.
if $PROBE; then
    SMOKE="$REPO_ROOT/bins/translator-sv2/tests/sv1_handshake_smoke.py"
    if [ -r "$SMOKE" ]; then
        # #774: probe BOTH listeners. Checking :3333 only is how #611 stayed invisible for
        # weeks — the farm tier was enabled fleet-wide on 2026-08-23 and served the HOBBY floor
        # to undeclared miners the whole time, while `farm_cfg`, `farm_listen` and `farm_ufw` all
        # read green. Configured, listening and permitted is not the same as serving the right
        # thing.
        echo "Live probe (default difficulty served to a miner that requests nothing):"
        for n in "${REACHED[@]}"; do
            ip="$(ssh -o ConnectTimeout=10 "$n" "hostname -I | awk '{print \$1}'" 2>/dev/null)"
            [ -n "$ip" ] || { echo "  $n: no address"; rc=1; continue; }
            for port in 3333 4444; do
                line="$(python3 "$SMOKE" "$ip" "$port" 2>/dev/null | grep -E "default-diff")" || true
                printf "  %-11s :%s %s\n" "$n" "$port" "${line:-probe produced no result}"
                case "$line" in *FAIL*) rc=1 ;; esac
            done
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
