#!/usr/bin/env bash
# soak-test-mainnet-readiness.sh — Comprehensive Mainnet Readiness Soak Test
#
# 30-minute iterations covering all layers:
#   - L1 Mining: block height, shares, payout rounds
#   - L2 Operations: shield, L2 payment, wraith session, tree root check
#   - Bridge: test-withdrawal, simulate-unshield, lock creation + funding
#   - Health: services, DB integrity, checkpoint pipeline
#   - Fault Injection: SIGKILL random VM (configurable)
#
# Usage:
#   ./scripts/soak-test-mainnet-readiness.sh [--hours N] [--no-inject] [--no-mining] [--dry-run]
#   SOAK_HOURS=168 nohup ./scripts/soak-test-mainnet-readiness.sh > soak-7day.log 2>&1 &

set -uo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

SOAK_HOURS="${SOAK_HOURS:-168}"
NO_INJECT=""
NO_MINING=""
DRY_RUN=""
ITER_INTERVAL=1800  # 30 minutes between iterations

SSH_KEY="$HOME/.ssh/ghost_signet_ed25519"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPath=/tmp/ghost-mainnet-soak-ssh-%h -o ControlPersist=120"

VM_IPS=("83.136.251.162" "85.9.198.212" "213.163.207.46" "95.111.221.169")
VM_NAMES=("signet-1" "signet-2" "signet-3" "signet-4")
VM_SSH=("ghost-vm1" "ghost-vm2" "ghost-vm3" "ghost-vm4")
VM_COUNT=${#VM_IPS[@]}

POOL_PORT=8080
PAY_PORT=8800
GHOST_PORTS="8555,8556,8557,8558,8559,8560,8561,8562"

VM_PAY_SECRETS=(
    "ba0447893e9f2225602cc89696d440fa8853a2f5c2f37e9e19e9cfc2ad985a06"
    "bdfcde9e80efd95fdf8f0db9be22f89252f99adc6b78bdb8f02b2495289e26b4"
    "88502a969e1ad8426acd9d3cf34d5231f5ea36064edd7fa1ba28ccaaf2dfd187"
    "97e54ac957b78564ec5cb48f5024d824d096f6a5d0c4677b5f54ce28d3033c30"
)
POOL_API_SECRET="b8404e28a10925d41a644a62a6078eab18e0522bcc2a2ef5d4596323be9be555"

# ─── Global Counters ─────────────────────────────────────────────────────────

MINING_CHECKS=0
MINING_ADVANCING=0
L2_SHIELD_ATTEMPTS=0
L2_SHIELD_SUCCESSES=0
L2_SIM_ATTEMPTS=0
L2_SIM_SUCCESSES=0
WRAITH_ATTEMPTS=0
WRAITH_SUCCESSES=0
BRIDGE_WITHDRAWAL_ATTEMPTS=0
BRIDGE_WITHDRAWAL_SUCCESSES=0
BRIDGE_UNSHIELD_ATTEMPTS=0
BRIDGE_UNSHIELD_SUCCESSES=0
BRIDGE_LOCK_ATTEMPTS=0
BRIDGE_LOCK_SUCCESSES=0
BRIDGE_WRAITH_ATTEMPTS=0
BRIDGE_WRAITH_SUCCESSES=0
BRIDGE_SETTLEMENT_CHECKS=0
BRIDGE_SETTLEMENT_CONFIRMED=0
HEALTH_CHECKS=0
HEALTH_PASSES=0
FAULT_INJECT_ATTEMPTS=0
FAULT_INJECT_RECOVERIES=0
TOTAL_FAILURES=0

INITIAL_BLOCK_HEIGHT=0
LAST_BLOCK_HEIGHT=0

# ─── CLI Parsing ─────────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hours)     SOAK_HOURS="$2"; shift 2 ;;
        --no-inject) NO_INJECT=true; shift ;;
        --no-mining) NO_MINING=true; shift ;;
        --dry-run)   DRY_RUN=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--hours N] [--no-inject] [--no-mining] [--dry-run]"
            echo "  --hours N      Duration in hours (default: 168 = 7 days)"
            echo "  --no-inject    Disable fault injection"
            echo "  --no-mining    Skip mining layer checks"
            echo "  --dry-run      Validate connections only"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

TOTAL_ITERATIONS=$(( (SOAK_HOURS * 3600) / ITER_INTERVAL ))

# ─── Colors ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Logging ─────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOGDIR="$PROJECT_DIR/soak-logs/mainnet-readiness-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$LOGDIR"

MAIN_LOG="$LOGDIR/soak-mainnet.log"
EVENTS_LOG="$LOGDIR/events.jsonl"
METRICS_LOG="$LOGDIR/metrics.csv"
BALANCE_LOG="$LOGDIR/balance.csv"

# CSV headers
echo "timestamp,iteration,layer,metric,value" > "$METRICS_LOG"
echo "timestamp,iteration,vm1_pay_notes,vm2_pay_notes,vm3_pay_notes,vm4_pay_notes,vm1_pool_notes,vm2_pool_notes,vm3_pool_notes,vm4_pool_notes,vm1_checkpoint_root,vm2_checkpoint_root,vm3_checkpoint_root,vm4_checkpoint_root" > "$BALANCE_LOG"

log() {
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo -e "[$ts] $*" | tee -a "$MAIN_LOG"
}

log_event() {
    local type="$1" detail="$2" result="${3:-ok}"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '{"ts":"%s","type":"%s","detail":"%s","result":"%s"}\n' \
        "$ts" "$type" "$detail" "$result" >> "$EVENTS_LOG"
}

log_metric() {
    local iteration="$1" layer="$2" metric="$3" value="$4"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "$ts,$iteration,$layer,$metric,$value" >> "$METRICS_LOG"
}

vm_label() {
    echo "${VM_NAMES[$1]} (${VM_IPS[$1]})"
}

# ─── SSH / API Helpers ───────────────────────────────────────────────────────

ssh_cmd() {
    local vm_idx="$1"; shift
    timeout 30 ssh $SSH_OPTS "root@${VM_IPS[$vm_idx]}" "$@" 2>/dev/null
}

pool_api() {
    local vm_idx="$1" path="$2"
    curl -sf --connect-timeout 5 --max-time 15 \
        "http://${VM_IPS[$vm_idx]}:${POOL_PORT}${path}" 2>/dev/null
}

pay_hmac_sign() {
    local secret="$1" timestamp="$2" body="$3"
    echo -n "${timestamp}${body}" | openssl dgst -sha256 -hmac "$secret" -binary | xxd -p -c 256
}

pay_api_auth() {
    local vm_idx="$1" path="$2" body="$3"
    local secret="${VM_PAY_SECRETS[$vm_idx]}"
    local timestamp sig result
    timestamp=$(date +%s)
    sig=$(pay_hmac_sign "$secret" "$timestamp" "$body")

    result=$(curl -s --connect-timeout 5 --max-time 15 \
        -X POST -H 'Content-Type: application/json' \
        -H "X-Ghost-Signature: $sig" \
        -H "X-Ghost-Timestamp: $timestamp" \
        -d "$body" \
        "http://${VM_IPS[$vm_idx]}:${PAY_PORT}${path}" 2>/dev/null)

    if [[ -z "$result" ]]; then
        timestamp=$(date +%s)
        sig=$(pay_hmac_sign "$secret" "$timestamp" "$body")
        local remote_tmp="/tmp/ghost-mainnet-soak-body-$$.json"
        echo -n "$body" | ssh $SSH_OPTS "root@${VM_IPS[$vm_idx]}" "cat > $remote_tmp" 2>/dev/null
        result=$(ssh_cmd "$vm_idx" "curl -sf -X POST \
            -H 'Content-Type: application/json' \
            -H 'X-Ghost-Signature: $sig' \
            -H 'X-Ghost-Timestamp: $timestamp' \
            -d @$remote_tmp \
            http://localhost:${PAY_PORT}${path}; rm -f $remote_tmp" 2>/dev/null)
    fi
    echo "$result"
}

pool_hmac_sign() {
    local secret_hex="$1" timestamp="$2" body="$3"
    local ts_le_hex
    ts_le_hex=$(printf '%016x' "$timestamp" | sed 's/\(..\)/\1\n/g' | tac | tr -d '\n')
    local msg_hex="${ts_le_hex}$(echo -n "$body" | xxd -p -c 65536)"
    echo -n "$msg_hex" | xxd -r -p | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${secret_hex}" -binary | xxd -p -c 256
}

bitcoin_cli() {
    local vm_idx="$1"; shift
    ssh_cmd "$vm_idx" "bitcoin-cli -signet -datadir=/var/lib/bitcoin -rpcport=38332 -rpcuser=ghostrpc -rpcpassword=ghost_signet_rpc_2024 $*"
}

# ─── Pre-flight ──────────────────────────────────────────────────────────────

preflight() {
    log "${BOLD}═══ Pre-flight Checks ═══${RESET}"
    local failed=false

    for i in $(seq 0 $((VM_COUNT - 1))); do
        local label
        label="$(vm_label $i)"

        # SSH
        if ! ssh_cmd "$i" "echo ok" >/dev/null 2>&1; then
            log "  ${RED}FAIL: SSH to $label${RESET}"
            failed=true
            continue
        fi

        # ghost-mining health
        local pool_health
        pool_health=$(pool_api "$i" "/health")
        if [[ -z "$pool_health" ]]; then
            pool_health=$(ssh_cmd "$i" "curl -sf http://localhost:${POOL_PORT}/health" 2>/dev/null)
        fi
        if [[ -z "$pool_health" ]]; then
            log "  ${RED}FAIL: ghost-mining on $label${RESET}"
            failed=true
            continue
        fi

        # ghost-pay health
        local pay_health
        pay_health=$(ssh_cmd "$i" "curl -sf http://localhost:${PAY_PORT}/health" 2>/dev/null)
        if [[ -z "$pay_health" ]]; then
            log "  ${RED}FAIL: ghost-pay on $label${RESET}"
            failed=true
            continue
        fi

        # VK files
        local vk_ok=true
        for vk in note_spend_vk.bin payout_vk.bin unshield_vk.bin; do
            if ! ssh_cmd "$i" "test -f /home/ghost/.ghost/mpc_params/$vk" 2>/dev/null; then
                log "  ${RED}FAIL: Missing $vk on $label${RESET}"
                vk_ok=false
                failed=true
            fi
        done

        # DB integrity
        local integrity
        integrity=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'PRAGMA integrity_check;'" 2>/dev/null)
        if [[ "$integrity" != "ok" ]]; then
            log "  ${RED}FAIL: DB integrity on $label: $integrity${RESET}"
            failed=true
        fi

        # Schema version
        local schema
        schema=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'PRAGMA user_version;'" 2>/dev/null)

        log "  $label: ${GREEN}OK${RESET} (schema=$schema, vk=$( $vk_ok && echo ok || echo missing))"
    done

    # Block height baseline
    local height
    height=$(pool_api 0 "/api/v1/node/status" | jq -r '.block_height // 0' 2>/dev/null)
    if [[ -z "$height" ]]; then
        height=$(ssh_cmd 0 "curl -sf http://localhost:${POOL_PORT}/api/v1/node/status" | jq -r '.block_height // 0' 2>/dev/null)
    fi
    INITIAL_BLOCK_HEIGHT="${height:-0}"
    LAST_BLOCK_HEIGHT="$INITIAL_BLOCK_HEIGHT"
    log "  Baseline block height: $INITIAL_BLOCK_HEIGHT"

    # Bitcoin Core sync check
    if [[ -z "$NO_MINING" ]]; then
        local bc_info
        bc_info=$(bitcoin_cli 0 "getblockchaininfo")
        if [[ -n "$bc_info" ]]; then
            local ibd
            ibd=$(echo "$bc_info" | jq -r '.initialblockdownload // true' 2>/dev/null)
            if [[ "$ibd" == "true" ]]; then
                log "  ${YELLOW}WARNING: Bitcoin Core still in IBD${RESET}"
            else
                log "  Bitcoin Core: ${GREEN}synced${RESET}"
            fi
        fi
    fi

    if $failed; then
        log "  ${RED}Pre-flight FAILED — aborting${RESET}"
        exit 1
    fi

    log "  Pre-flight: ${GREEN}ALL CHECKS PASSED${RESET}"
    log_event "preflight" "block_height=$INITIAL_BLOCK_HEIGHT" "ok"
}

# ═══════════════════════════════════════════════════════════════════════════════
# L1 MINING LAYER — every iteration
# ═══════════════════════════════════════════════════════════════════════════════

check_mining() {
    local iteration="$1"
    [[ -n "$NO_MINING" ]] && return 0

    log "  ${BLUE}── L1 Mining ──${RESET}"
    ((MINING_CHECKS++))

    # Block height from VM1
    local height
    height=$(pool_api 0 "/api/v1/node/status" | jq -r '.block_height // 0' 2>/dev/null)
    if [[ -z "$height" || "$height" == "0" ]]; then
        height=$(ssh_cmd 0 "curl -sf http://localhost:${POOL_PORT}/api/v1/node/status" | jq -r '.block_height // 0' 2>/dev/null)
    fi
    height="${height:-0}"

    local advanced=false
    if (( height > LAST_BLOCK_HEIGHT )); then
        advanced=true
        ((MINING_ADVANCING++))
    fi

    log "    Block height: $height (was $LAST_BLOCK_HEIGHT) $( $advanced && echo "${GREEN}+$((height - LAST_BLOCK_HEIGHT))${RESET}" || echo "${YELLOW}stalled${RESET}")"
    log_metric "$iteration" "mining" "block_height" "$height"
    LAST_BLOCK_HEIGHT="$height"

    # Share counts across all VMs
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local share_count
        share_count=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'SELECT COUNT(*) FROM miners;'" 2>/dev/null)
        log "    ${VM_NAMES[$i]} miners: ${share_count:-?}"
        log_metric "$iteration" "mining" "miners_vm$i" "${share_count:-0}"
    done

    # Payout round status from VM1
    local payout_status
    payout_status=$(ssh_cmd 0 "journalctl -u ghost-mining --since '30 min ago' --no-pager 2>/dev/null | grep -c 'payout.*round\|payout.*complete\|payout.*distributed'" 2>/dev/null)
    log "    Payout events (30min): ${payout_status:-0}"
    log_metric "$iteration" "mining" "payout_events" "${payout_status:-0}"

    log_event "mining-check" "height=$height,advancing=$advanced" "$( $advanced && echo ok || echo warn)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# L2 OPERATIONS LAYER — every iteration
# ═══════════════════════════════════════════════════════════════════════════════

shield_on_vm() {
    local vm_idx="$1" iteration="$2"
    ((L2_SHIELD_ATTEMPTS++))
    local amount=$((1000 + RANDOM % 9000))
    local blinding_hex owner_pubkey
    blinding_hex="$(openssl rand -hex 24)0000000000000000"
    owner_pubkey="$(openssl rand -hex 24)0000000000000000"

    local body
    body=$(printf '{"amount_sats":%d,"blinding_hex":"%s","owner_pubkey":"%s"}' \
        "$amount" "$blinding_hex" "$owner_pubkey")

    local result
    result=$(pay_api_auth "$vm_idx" "/api/v1/confidential/shield" "$body")

    if [[ -n "$result" ]] && ! echo "$result" | jq -e '.error' >/dev/null 2>&1; then
        local note_idx
        note_idx=$(echo "$result" | jq -r '.note_index // "?"' 2>/dev/null)
        log "    Shield $amount sats on ${VM_NAMES[$vm_idx]}: ${GREEN}OK${RESET} (index=$note_idx)"
        log_event "l2-shield" "vm=${VM_NAMES[$vm_idx]},amount=$amount" "ok"
        ((L2_SHIELD_SUCCESSES++))
        return 0
    else
        local err
        err=$(echo "$result" | jq -r '.error // .message // empty' 2>/dev/null)
        log "    Shield on ${VM_NAMES[$vm_idx]}: ${YELLOW}${err:-no response}${RESET}"
        log_event "l2-shield" "vm=${VM_NAMES[$vm_idx]}" "fail:${err:-timeout}"
        return 1
    fi
}

simulate_l2_on_vm() {
    local vm_idx="$1" iteration="$2"
    ((L2_SIM_ATTEMPTS++))

    local result
    result=$(ssh_cmd "$vm_idx" \
        "curl -sf --max-time 60 -X POST http://localhost:${PAY_PORT}/api/v1/admin/simulate-l2-activity" 2>/dev/null)

    if [[ -z "$result" ]]; then
        log "    L2 sim on ${VM_NAMES[$vm_idx]}: ${YELLOW}timeout${RESET}"
        log_event "l2-simulate" "vm=${VM_NAMES[$vm_idx]}" "fail:timeout"
        return 1
    fi

    local success
    success=$(echo "$result" | jq -r '.success // false' 2>/dev/null)

    if [[ "$success" == "true" ]]; then
        local proof_ms
        proof_ms=$(echo "$result" | jq -r '.steps.zk_proof.elapsed_ms // "?"' 2>/dev/null)
        log "    L2 sim on ${VM_NAMES[$vm_idx]}: ${GREEN}OK${RESET} (proof=${proof_ms}ms)"
        log_event "l2-simulate" "vm=${VM_NAMES[$vm_idx]},proof_ms=$proof_ms" "ok"
        ((L2_SIM_SUCCESSES++))
        return 0
    else
        local fail_step
        fail_step=$(echo "$result" | jq -r '[.steps | to_entries[] | select(.value.pass == false) | .key] | first // "unknown"' 2>/dev/null)
        log "    L2 sim on ${VM_NAMES[$vm_idx]}: ${RED}FAILED${RESET} at $fail_step"
        log_event "l2-simulate" "vm=${VM_NAMES[$vm_idx]},fail_step=$fail_step" "fail"
        return 1
    fi
}

wraith_session_on_vm() {
    local vm_idx="$1" iteration="$2"
    ((WRAITH_ATTEMPTS++))

    local result
    result=$(ssh_cmd "$vm_idx" \
        "curl -s --max-time 10 -X POST http://localhost:${PAY_PORT}/api/v1/admin/simulate-wraith-session" 2>/dev/null)

    if [[ -z "$result" ]]; then
        log "    Wraith on ${VM_NAMES[$vm_idx]}: ${YELLOW}no response${RESET}"
        log_event "wraith-session" "vm=${VM_NAMES[$vm_idx]}" "fail:timeout"
        return 1
    fi

    local session_id error_msg
    session_id=$(echo "$result" | jq -r '.session_id // empty' 2>/dev/null)
    error_msg=$(echo "$result" | jq -r '.error // empty' 2>/dev/null)

    if [[ -n "$error_msg" ]]; then
        log "    Wraith on ${VM_NAMES[$vm_idx]}: ${YELLOW}$error_msg${RESET}"
        log_event "wraith-session" "vm=${VM_NAMES[$vm_idx]},error=$error_msg" "fail"
        return 1
    fi

    if [[ -z "$session_id" ]]; then
        log "    Wraith on ${VM_NAMES[$vm_idx]}: ${YELLOW}no session_id${RESET}"
        log_event "wraith-session" "vm=${VM_NAMES[$vm_idx]}" "fail:no-session-id"
        return 1
    fi

    log "    Wraith on ${VM_NAMES[$vm_idx]}: ${GREEN}started $session_id${RESET}"

    # Poll for completion (35 min timeout)
    local poll_timeout=2100 poll_interval=15 elapsed=0 final_state="unknown"

    while (( elapsed < poll_timeout )); do
        sleep "$poll_interval"
        elapsed=$((elapsed + poll_interval))

        local status_result
        status_result=$(ssh_cmd "$vm_idx" \
            "curl -s --max-time 5 http://localhost:${PAY_PORT}/api/v1/wraith/sessions" 2>/dev/null)

        [[ -z "$status_result" ]] && continue

        local state
        state=$(echo "$status_result" | jq -r --arg id "$session_id" \
            '.[] | select(.id == $id or .session_id == $id) | .state // "unknown"' 2>/dev/null)

        case "$state" in
            complete|completed)
                final_state="complete"
                break
                ;;
            failed|error)
                final_state="failed"
                break
                ;;
        esac
    done

    if [[ "$final_state" == "complete" ]]; then
        log "    Wraith $session_id: ${GREEN}COMPLETE${RESET} (${elapsed}s)"
        log_event "wraith-session" "vm=${VM_NAMES[$vm_idx]},session=$session_id,elapsed=${elapsed}s" "ok"
        ((WRAITH_SUCCESSES++))
        return 0
    else
        log "    Wraith $session_id: ${RED}$final_state${RESET} (${elapsed}s)"
        log_event "wraith-session" "vm=${VM_NAMES[$vm_idx]},session=$session_id,state=$final_state" "fail"
        return 1
    fi
}

check_l2() {
    local iteration="$1"

    log "  ${BLUE}── L2 Operations ──${RESET}"

    # Shield on a round-robin VM
    local shield_vm=$((iteration % VM_COUNT))
    shield_on_vm "$shield_vm" "$iteration" || true

    # L2 simulation on a round-robin VM (different from shield)
    local sim_vm=$(( (iteration + 1) % VM_COUNT ))
    simulate_l2_on_vm "$sim_vm" "$iteration" || true

    # Wraith session: every iteration (long-running, polls in background)
    local wraith_vm=$(( (iteration + 2) % VM_COUNT ))
    wraith_session_on_vm "$wraith_vm" "$iteration" || true

    # Triple-snapshot tree root check (from f5f1d22)
    check_tree_convergence "$iteration"
}

check_tree_convergence() {
    local iteration="$1"
    local pay_notes=() pool_notes=() checkpoint_roots=()

    for i in $(seq 0 $((VM_COUNT - 1))); do
        local pay_json pool_json
        pay_json=$(ssh_cmd "$i" "curl -sf http://localhost:${PAY_PORT}/api/v1/confidential/tree" 2>/dev/null)
        pool_json=$(pool_api "$i" "/api/v1/l2/tree-state" 2>/dev/null)
        if [[ -z "$pool_json" ]]; then
            pool_json=$(ssh_cmd "$i" "curl -sf http://localhost:${POOL_PORT}/api/v1/l2/tree-state" 2>/dev/null)
        fi

        pay_notes+=("$(echo "$pay_json" | jq -r '.note_count // "?"' 2>/dev/null)")
        pool_notes+=("$(echo "$pool_json" | jq -r '.note_count // "?"' 2>/dev/null)")
        checkpoint_roots+=("$(echo "$pool_json" | jq -r '.checkpoint_root // "?"' 2>/dev/null)")
    done

    # Log balance CSV
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "$ts,$iteration,${pay_notes[0]},${pay_notes[1]},${pay_notes[2]},${pay_notes[3]},${pool_notes[0]},${pool_notes[1]},${pool_notes[2]},${pool_notes[3]},${checkpoint_roots[0]:0:16},${checkpoint_roots[1]:0:16},${checkpoint_roots[2]:0:16},${checkpoint_roots[3]:0:16}" >> "$BALANCE_LOG"

    # Check pool convergence (all must match)
    local ref="${pool_notes[0]}" converged=true
    if [[ "$ref" != "?" ]]; then
        for i in $(seq 1 $((VM_COUNT - 1))); do
            [[ "${pool_notes[$i]}" == "$ref" ]] || converged=false
        done
    else
        converged=false
    fi

    # Check checkpoint root convergence
    local root_ref="${checkpoint_roots[0]}" roots_match=true
    if [[ "$root_ref" != "?" ]]; then
        for i in $(seq 1 $((VM_COUNT - 1))); do
            [[ "${checkpoint_roots[$i]}" == "$root_ref" ]] || roots_match=false
        done
    else
        roots_match=false
    fi

    if $converged && $roots_match; then
        log "    Tree: ${GREEN}CONVERGED${RESET} (pool=${pool_notes[*]}, root=${root_ref:0:16})"
    elif $converged; then
        log "    Tree: ${YELLOW}notes converged, roots diverged${RESET}"
    else
        log "    Tree: ${YELLOW}DIVERGED${RESET} (pool=${pool_notes[*]})"
    fi

    log_metric "$iteration" "l2" "pool_notes_vm0" "${pool_notes[0]}"
    log_metric "$iteration" "l2" "convergence" "$( $converged && echo 1 || echo 0)"
    log_event "tree-convergence" "iter=$iteration,converged=$converged,roots_match=$roots_match" \
        "$( $converged && $roots_match && echo ok || echo warn)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# BRIDGE LAYER — every 3rd iteration (test-withdrawal/unshield), every 6th (lock)
# ═══════════════════════════════════════════════════════════════════════════════

bridge_wraith_to_withdrawal() {
    local iteration="$1"
    local vm_idx=$((iteration % VM_COUNT))
    ((BRIDGE_WRAITH_ATTEMPTS++))

    log "    Path A: wraith→lock→settle on ${VM_NAMES[$vm_idx]}..."

    # Step 1: Trigger wraith session
    local wraith_result
    wraith_result=$(ssh_cmd "$vm_idx" \
        "curl -s --max-time 120 -X POST http://localhost:${PAY_PORT}/api/v1/admin/simulate-wraith-session" 2>/dev/null)

    if [[ -z "$wraith_result" ]]; then
        log "    wraith session: ${YELLOW}timeout${RESET}"
        log_event "bridge-wraith" "vm=${VM_NAMES[$vm_idx]}" "fail:timeout"
        return 1
    fi

    local session_id
    session_id=$(echo "$wraith_result" | jq -r '.session_id // empty' 2>/dev/null)
    if [[ -z "$session_id" ]]; then
        log "    wraith session: ${YELLOW}no session_id${RESET}"
        log_event "bridge-wraith" "vm=${VM_NAMES[$vm_idx]}" "fail:wraith"
        return 1
    fi
    log "    wraith session: ${GREEN}started $session_id${RESET}"

    # Wait for wraith session to complete (poll up to 5 min)
    local poll_timeout=300 poll_interval=15 elapsed=0
    while (( elapsed < poll_timeout )); do
        sleep "$poll_interval"
        elapsed=$((elapsed + poll_interval))
        local state
        state=$(ssh_cmd "$vm_idx" \
            "curl -s --max-time 5 http://localhost:${PAY_PORT}/api/v1/wraith/sessions" 2>/dev/null \
            | jq -r --arg id "$session_id" '.[] | select(.id == $id or .session_id == $id) | .state // "unknown"' 2>/dev/null)
        [[ "$state" == "complete" || "$state" == "completed" ]] && break
        [[ "$state" == "failed" || "$state" == "error" ]] && {
            log "    wraith session: ${YELLOW}$state${RESET}"
            log_event "bridge-wraith" "vm=${VM_NAMES[$vm_idx]}" "fail:wraith-$state"
            return 1
        }
    done

    # Step 2: Create a fresh lock, fund it, then reconcile
    local body='{"amount_sats":10000,"timelock_tier":"short"}'
    local create_result
    create_result=$(pay_api_auth "$vm_idx" "/api/v1/locks/create" "$body")

    local lock_id address
    lock_id=$(echo "$create_result" | jq -r '.lock.id // .lock_id // .id // empty' 2>/dev/null)
    address=$(echo "$create_result" | jq -r '.lock.address // .address // .funding_address // empty' 2>/dev/null)

    if [[ -z "$lock_id" || -z "$address" ]]; then
        local err
        err=$(echo "$create_result" | jq -r '.error // empty' 2>/dev/null)
        log "    Lock create: ${YELLOW}${err:-missing fields}${RESET}"
        log_event "bridge-wraith" "vm=${VM_NAMES[$vm_idx]},error=${err:-missing}" "fail:no_lock"
        return 1
    fi
    log "    Lock created: ${GREEN}$lock_id${RESET} → $address"

    # Step 3: Fund the lock
    local btc_amount="0.0001"
    local txid
    txid=$(ssh_cmd "$vm_idx" "bitcoin-cli -signet -datadir=/var/lib/bitcoin -rpcport=38332 -rpcuser=ghostrpc -rpcpassword=ghost_signet_rpc_2024 sendtoaddress '$address' $btc_amount" 2>/dev/null)
    if [[ -z "$txid" ]]; then
        log "    Funding: ${YELLOW}sendtoaddress failed${RESET}"
        log_event "bridge-wraith" "vm=${VM_NAMES[$vm_idx]},lock=$lock_id" "fail:fund"
        return 1
    fi
    log "    Funded: ${GREEN}$txid${RESET}"

    # Notify ghost-pay to scan
    local scan_body
    scan_body=$(printf '{"txid":"%s","vout":0}' "$txid")
    pay_api_auth "$vm_idx" "/api/v1/payments/scan" "$scan_body" >/dev/null 2>&1
    sleep 2

    # Step 4: Request withdrawal with express settlement class
    local reconcile_body
    reconcile_body=$(printf '{"destination_address":"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx","settlement_class":"express"}')
    local reconcile_result
    reconcile_result=$(pay_api_auth "$vm_idx" "/api/v1/locks/${lock_id}/reconcile" "$reconcile_body")

    local reconcile_ok
    reconcile_ok=$(echo "$reconcile_result" | jq -r '.success // false' 2>/dev/null)

    if [[ "$reconcile_ok" == "true" ]]; then
        local wid
        wid=$(echo "$reconcile_result" | jq -r '.withdrawal_id // "?"' 2>/dev/null)
        log "    Reconcile: ${GREEN}OK${RESET} withdrawal_id=$wid class=express"
        log_event "bridge-wraith" "vm=${VM_NAMES[$vm_idx]},lock=$lock_id,wid=$wid,class=express" "ok"
        ((BRIDGE_WRAITH_SUCCESSES++))
    else
        local err
        err=$(echo "$reconcile_result" | jq -r '.error // empty' 2>/dev/null)
        log "    Reconcile: ${YELLOW}${err:-failed}${RESET}"
        log_event "bridge-wraith" "vm=${VM_NAMES[$vm_idx]},lock=$lock_id,error=${err:-unknown}" "fail"
    fi
}

bridge_create_lock() {
    local iteration="$1"
    local vm_idx=$((iteration % VM_COUNT))
    ((BRIDGE_LOCK_ATTEMPTS++))

    log "    Path B: manual lock→fund→settle on ${VM_NAMES[$vm_idx]}..."
    local body='{"amount_sats":10000,"timelock_tier":"short"}'
    local result
    result=$(pay_api_auth "$vm_idx" "/api/v1/locks/create" "$body")

    if [[ -z "$result" ]]; then
        log "    Lock create: ${YELLOW}no response${RESET}"
        log_event "bridge-lock-create" "vm=${VM_NAMES[$vm_idx]}" "fail:timeout"
        return 1
    fi

    local lock_id address
    lock_id=$(echo "$result" | jq -r '.lock.id // .lock_id // .id // empty' 2>/dev/null)
    address=$(echo "$result" | jq -r '.lock.address // .address // .funding_address // empty' 2>/dev/null)

    if [[ -z "$lock_id" || -z "$address" ]]; then
        local err
        err=$(echo "$result" | jq -r '.error // empty' 2>/dev/null)
        log "    Lock create: ${YELLOW}${err:-missing fields}${RESET}"
        log_event "bridge-lock-create" "vm=${VM_NAMES[$vm_idx]},error=${err:-missing}" "fail"
        return 1
    fi

    log "    Lock created: ${GREEN}$lock_id${RESET} → $address"

    # Fund the lock
    local btc_amount="0.0001"  # 10k sats
    local txid
    txid=$(ssh_cmd "$vm_idx" "bitcoin-cli -signet -datadir=/var/lib/bitcoin -rpcport=38332 -rpcuser=ghostrpc -rpcpassword=ghost_signet_rpc_2024 sendtoaddress '$address' $btc_amount" 2>/dev/null)
    if [[ -n "$txid" ]]; then
        log "    Funded: ${GREEN}$txid${RESET}"
        # Notify ghost-pay to scan the funding TX
        local scan_body
        scan_body=$(printf '{"txid":"%s","vout":0}' "$txid")
        pay_api_auth "$vm_idx" "/api/v1/payments/scan" "$scan_body" >/dev/null 2>&1

        # Request withdrawal with express settlement class
        sleep 2  # Brief pause for scan to process
        local reconcile_body
        reconcile_body=$(printf '{"destination_address":"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx","settlement_class":"express"}')
        local reconcile_result
        reconcile_result=$(pay_api_auth "$vm_idx" "/api/v1/locks/${lock_id}/reconcile" "$reconcile_body")

        local reconcile_ok
        reconcile_ok=$(echo "$reconcile_result" | jq -r '.success // false' 2>/dev/null)
        if [[ "$reconcile_ok" == "true" ]]; then
            local wid
            wid=$(echo "$reconcile_result" | jq -r '.withdrawal_id // "?"' 2>/dev/null)
            log "    Withdrawal requested: ${GREEN}OK${RESET} wid=$wid class=express"
        else
            log "    Withdrawal request: ${YELLOW}$(echo "$reconcile_result" | jq -r '.error // "failed"' 2>/dev/null)${RESET}"
        fi

        ((BRIDGE_LOCK_SUCCESSES++))
    else
        log "    Funding: ${YELLOW}sendtoaddress failed (insufficient funds?)${RESET}"
    fi

    log_event "bridge-lock-create" "vm=${VM_NAMES[$vm_idx]},lock=$lock_id,funded=${txid:+true}" "ok"
}

bridge_check_settlements() {
    local iteration="$1"
    ((BRIDGE_SETTLEMENT_CHECKS++))

    log "    Settlement status check..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local status
        status=$(ssh_cmd "$i" \
            "curl -s --max-time 5 http://localhost:${PAY_PORT}/api/v1/status" 2>/dev/null)
        if [[ -n "$status" ]]; then
            local pending batched submitted confirmed
            pending=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost-pay.db \
                \"SELECT COUNT(*) FROM withdrawal_requests WHERE status='pending'\"" 2>/dev/null)
            batched=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost-pay.db \
                \"SELECT COUNT(*) FROM withdrawal_requests WHERE status='batched'\"" 2>/dev/null)
            submitted=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost-pay.db \
                \"SELECT COUNT(*) FROM withdrawal_requests WHERE status='submitted'\"" 2>/dev/null)
            confirmed=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost-pay.db \
                \"SELECT COUNT(*) FROM withdrawal_requests WHERE status='confirmed'\"" 2>/dev/null)
            log "      ${VM_NAMES[$i]}: pending=${pending:-0} batched=${batched:-0} submitted=${submitted:-0} confirmed=${confirmed:-0}"
            log_metric "$iteration" "bridge" "settlements_vm$i" "p=${pending:-0},b=${batched:-0},s=${submitted:-0},c=${confirmed:-0}"

            if [[ "${confirmed:-0}" -gt 0 ]]; then
                ((BRIDGE_SETTLEMENT_CONFIRMED+=${confirmed:-0}))
            fi
        fi
    done
}

check_bridge() {
    local iteration="$1"

    log "  ${BLUE}── Bridge ──${RESET}"

    # Every 6th iteration (alternating paths): wraith-sourced or manual lock
    if (( iteration % 6 == 0 )); then
        if (( (iteration / 6) % 2 == 0 )); then
            bridge_wraith_to_withdrawal "$iteration" || true
        else
            bridge_create_lock "$iteration" || true
        fi
    fi

    # Every iteration: check settlement status and progression
    bridge_check_settlements "$iteration" || true
}

# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH LAYER — every iteration
# ═══════════════════════════════════════════════════════════════════════════════

check_health() {
    local iteration="$1"

    log "  ${BLUE}── Health ──${RESET}"
    ((HEALTH_CHECKS++))
    local all_ok=true

    for i in $(seq 0 $((VM_COUNT - 1))); do
        local pool_ok=false pay_ok=false

        # ghost-mining
        local pool_h
        pool_h=$(pool_api "$i" "/health" 2>/dev/null)
        [[ -z "$pool_h" ]] && pool_h=$(ssh_cmd "$i" "curl -sf http://localhost:${POOL_PORT}/health" 2>/dev/null)
        [[ -n "$pool_h" ]] && pool_ok=true

        # ghost-pay
        local pay_h
        pay_h=$(ssh_cmd "$i" "curl -sf http://localhost:${PAY_PORT}/health" 2>/dev/null)
        [[ -n "$pay_h" ]] && pay_ok=true

        if $pool_ok && $pay_ok; then
            log "    ${VM_NAMES[$i]}: ${GREEN}pool+pay OK${RESET}"
        else
            log "    ${VM_NAMES[$i]}: ${RED}pool=$( $pool_ok && echo OK || echo DOWN) pay=$( $pay_ok && echo OK || echo DOWN)${RESET}"
            all_ok=false
        fi
    done

    # Checkpoint pipeline — check for recent checkpoint activity
    local ckpt_count
    ckpt_count=$(ssh_cmd 0 "journalctl -u ghost-mining --since '30 min ago' --no-pager 2>/dev/null | grep -c 'checkpoint\|Checkpoint'" 2>/dev/null)
    log "    Checkpoint events (30min): ${ckpt_count:-0}"
    log_metric "$iteration" "health" "checkpoint_events" "${ckpt_count:-0}"

    # Every 3rd iteration: memory + disk
    if (( iteration % 3 == 0 )); then
        log "    Resource check:"
        for i in $(seq 0 $((VM_COUNT - 1))); do
            local mem_pct disk_pct
            mem_pct=$(ssh_cmd "$i" "free | awk '/Mem:/{printf \"%.0f\", \$3/\$2*100}'" 2>/dev/null)
            disk_pct=$(ssh_cmd "$i" "df / | awk 'NR==2{print \$5}'" 2>/dev/null)
            log "      ${VM_NAMES[$i]}: mem=${mem_pct:-?}% disk=${disk_pct:-?}"
            log_metric "$iteration" "health" "mem_pct_vm$i" "${mem_pct:-0}"
        done
    fi

    # Panic check (last 30 min)
    local panics=0
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local p
        p=$(ssh_cmd "$i" "journalctl -u ghost-mining -u ghost-pay --since '30 min ago' --no-pager 2>/dev/null | grep -ci 'panic\|PANIC'" 2>/dev/null)
        panics=$((panics + ${p:-0}))
    done
    if (( panics > 0 )); then
        log "    ${RED}PANICS DETECTED: $panics in last 30min${RESET}"
        all_ok=false
    fi

    if $all_ok; then
        ((HEALTH_PASSES++))
    else
        ((TOTAL_FAILURES++))
    fi
    log_event "health-check" "iter=$iteration,panics=$panics" "$( $all_ok && echo ok || echo fail)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FAULT INJECTION — every 6th iteration
# ═══════════════════════════════════════════════════════════════════════════════

inject_fault() {
    local iteration="$1"

    [[ -n "$NO_INJECT" ]] && return 0
    (( iteration % 6 != 0 )) && return 0

    log "  ${RED}── Fault Injection ──${RESET}"
    ((FAULT_INJECT_ATTEMPTS++))

    # Pick a random VM
    local victim_idx=$((RANDOM % VM_COUNT))
    local label="${VM_NAMES[$victim_idx]}"

    # Alternate between ghost-mining and ghost-pay kills
    local service
    if (( (iteration / 6) % 2 == 0 )); then
        service="ghost-mining"
    else
        service="ghost-pay"
    fi

    log "    ${RED}SIGKILL $service on $label${RESET}"

    # Get pre-state
    local pre_notes
    if [[ "$service" == "ghost-mining" ]]; then
        pre_notes=$(ssh_cmd "$victim_idx" "sqlite3 /home/ghost/.ghost/ghost.db 'SELECT COUNT(*) FROM l2_notes;'" 2>/dev/null)
    else
        pre_notes=$(ssh_cmd "$victim_idx" "sqlite3 /home/ghost/.ghost/ghost-pay/ghost-pay.db 'SELECT COUNT(*) FROM confidential_notes;'" 2>/dev/null)
    fi

    # Kill
    ssh_cmd "$victim_idx" "kill -9 \$(pgrep -f '/opt/ghost/bin/$service') 2>/dev/null; true" || true
    sleep 2

    # Restart
    ssh_cmd "$victim_idx" "systemctl start $service" || true
    log "    Restarted $service on $label — waiting for recovery..."

    # Wait for recovery (check health every 5s for 5 min max)
    local recovery_timeout=300 elapsed=0 recovered=false
    while (( elapsed < recovery_timeout )); do
        sleep 5
        elapsed=$((elapsed + 5))

        local health
        if [[ "$service" == "ghost-mining" ]]; then
            health=$(ssh_cmd "$victim_idx" "curl -sf http://localhost:${POOL_PORT}/health" 2>/dev/null)
        else
            health=$(ssh_cmd "$victim_idx" "curl -sf http://localhost:${PAY_PORT}/health" 2>/dev/null)
        fi

        if [[ -n "$health" ]]; then
            recovered=true
            break
        fi
    done

    if $recovered; then
        log "    ${GREEN}RECOVERED${RESET} in ${elapsed}s"
        ((FAULT_INJECT_RECOVERIES++))
        log_event "fault-injection" "vm=$label,service=$service,recovered=${elapsed}s" "ok"
    else
        log "    ${RED}FAILED TO RECOVER${RESET} after ${recovery_timeout}s"
        ((TOTAL_FAILURES++))
        log_event "fault-injection" "vm=$label,service=$service,timeout" "fail"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# FINAL REPORT
# ═══════════════════════════════════════════════════════════════════════════════

final_report() {
    local end_ts
    end_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local elapsed_hours=$(( ($(date +%s) - START_TIME) / 3600 ))

    log ""
    log "${BOLD}╔═══════════════════════════════════════════════════════════════╗${RESET}"
    log "${BOLD}║         MAINNET READINESS SOAK — FINAL REPORT               ║${RESET}"
    log "${BOLD}╚═══════════════════════════════════════════════════════════════╝${RESET}"
    log ""
    log "  Duration:    ${elapsed_hours}h (target: ${SOAK_HOURS}h)"
    log "  Iterations:  $CURRENT_ITERATION / $TOTAL_ITERATIONS"
    log "  Logs:        $LOGDIR"
    log ""
    log "  ${BOLD}── Mining ──${RESET}"
    log "    Checks:       $MINING_CHECKS"
    log "    Advancing:    $MINING_ADVANCING / $MINING_CHECKS ($( (( MINING_CHECKS > 0 )) && echo "$((MINING_ADVANCING * 100 / MINING_CHECKS))%" || echo "N/A"))"
    log "    Height:       $INITIAL_BLOCK_HEIGHT → $LAST_BLOCK_HEIGHT (+$((LAST_BLOCK_HEIGHT - INITIAL_BLOCK_HEIGHT)))"
    log ""
    log "  ${BOLD}── L2 Operations ──${RESET}"
    log "    Shields:      $L2_SHIELD_SUCCESSES / $L2_SHIELD_ATTEMPTS ($( (( L2_SHIELD_ATTEMPTS > 0 )) && echo "$((L2_SHIELD_SUCCESSES * 100 / L2_SHIELD_ATTEMPTS))%" || echo "N/A"))"
    log "    Simulations:  $L2_SIM_SUCCESSES / $L2_SIM_ATTEMPTS ($( (( L2_SIM_ATTEMPTS > 0 )) && echo "$((L2_SIM_SUCCESSES * 100 / L2_SIM_ATTEMPTS))%" || echo "N/A"))"
    log "    Wraith:       $WRAITH_SUCCESSES / $WRAITH_ATTEMPTS ($( (( WRAITH_ATTEMPTS > 0 )) && echo "$((WRAITH_SUCCESSES * 100 / WRAITH_ATTEMPTS))%" || echo "N/A"))"
    log ""
    log "  ${BOLD}── Bridge ──${RESET}"
    log "    Wraith→Settle: $BRIDGE_WRAITH_SUCCESSES / $BRIDGE_WRAITH_ATTEMPTS"
    log "    Lock→Settle:   $BRIDGE_LOCK_SUCCESSES / $BRIDGE_LOCK_ATTEMPTS"
    log "    Settlements:   $BRIDGE_SETTLEMENT_CONFIRMED confirmed ($BRIDGE_SETTLEMENT_CHECKS checks)"
    log ""
    log "  ${BOLD}── Health ──${RESET}"
    log "    Checks:       $HEALTH_PASSES / $HEALTH_CHECKS"
    log ""
    log "  ${BOLD}── Fault Injection ──${RESET}"
    log "    Recoveries:   $FAULT_INJECT_RECOVERIES / $FAULT_INJECT_ATTEMPTS"
    log ""
    log "  ${BOLD}── Failures ──${RESET}"
    log "    Total:        $TOTAL_FAILURES"
    log ""

    # Mainnet readiness gate
    local gate_pass=true

    # Mining advancing (if mining enabled)
    if [[ -z "$NO_MINING" ]] && (( MINING_CHECKS > 0 )); then
        local mining_pct=$((MINING_ADVANCING * 100 / MINING_CHECKS))
        if (( mining_pct < 50 )); then
            log "  ${RED}GATE FAIL: Mining advancing only ${mining_pct}% (need blocks)${RESET}"
            gate_pass=false
        fi
    fi

    # L2 >95% success
    if (( L2_SHIELD_ATTEMPTS > 0 )); then
        local l2_pct=$((L2_SHIELD_SUCCESSES * 100 / L2_SHIELD_ATTEMPTS))
        if (( l2_pct < 95 )); then
            log "  ${RED}GATE FAIL: L2 shield success ${l2_pct}% (need >95%)${RESET}"
            gate_pass=false
        fi
    fi

    # Bridge >95% success
    local total_bridge_attempts=$((BRIDGE_WRAITH_ATTEMPTS + BRIDGE_LOCK_ATTEMPTS))
    local total_bridge_successes=$((BRIDGE_WRAITH_SUCCESSES + BRIDGE_LOCK_SUCCESSES))
    if (( total_bridge_attempts > 0 )); then
        local bridge_pct=$((total_bridge_successes * 100 / total_bridge_attempts))
        if (( bridge_pct < 95 )); then
            log "  ${RED}GATE FAIL: Bridge success ${bridge_pct}% (need >95%)${RESET}"
            gate_pass=false
        fi
    fi

    # Fault injection 100% recovery
    if (( FAULT_INJECT_ATTEMPTS > 0 )) && (( FAULT_INJECT_RECOVERIES < FAULT_INJECT_ATTEMPTS )); then
        log "  ${RED}GATE FAIL: Fault injection recovery $FAULT_INJECT_RECOVERIES/$FAULT_INJECT_ATTEMPTS (need 100%)${RESET}"
        gate_pass=false
    fi

    # No total failures
    if (( TOTAL_FAILURES > 0 )); then
        log "  ${RED}GATE FAIL: $TOTAL_FAILURES total failures${RESET}"
        gate_pass=false
    fi

    log ""
    if $gate_pass; then
        log "  ${GREEN}${BOLD}═══ MAINNET READINESS: PASS ═══${RESET}"
    else
        log "  ${RED}${BOLD}═══ MAINNET READINESS: FAIL ═══${RESET}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    START_TIME=$(date +%s)
    CURRENT_ITERATION=0

    log "${BOLD}╔═══════════════════════════════════════════════════════════════╗${RESET}"
    log "${BOLD}║  Ghost Mainnet Readiness Soak Test                          ║${RESET}"
    log "${BOLD}║  Duration: ${SOAK_HOURS}h  Iterations: ${TOTAL_ITERATIONS}  Interval: $((ITER_INTERVAL/60))min$(printf '%*s' $((14 - ${#SOAK_HOURS} - ${#TOTAL_ITERATIONS})) '')║${RESET}"
    log "${BOLD}║  Inject: $( [[ -z "$NO_INJECT" ]] && echo "ON " || echo "OFF")  Mining: $( [[ -z "$NO_MINING" ]] && echo "ON " || echo "OFF")$(printf '%*s' 38 '')║${RESET}"
    log "${BOLD}╚═══════════════════════════════════════════════════════════════╝${RESET}"

    # Pre-flight
    preflight

    if [[ -n "$DRY_RUN" ]]; then
        log ""
        log "${GREEN}Dry run complete — all pre-flight checks passed.${RESET}"
        exit 0
    fi

    # Save baseline DB state
    for i in $(seq 0 $((VM_COUNT - 1))); do
        ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db '.tables'" > "$LOGDIR/baseline-db-vm${i}.txt" 2>/dev/null
        ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'SELECT COUNT(*) FROM l2_notes;'" >> "$LOGDIR/baseline-db-vm${i}.txt" 2>/dev/null
    done

    # Trap for clean report on interrupt
    trap 'log ""; log "${YELLOW}Interrupted — generating report...${RESET}"; final_report; exit 1' INT TERM

    # Main iteration loop
    for (( iter=1; iter<=TOTAL_ITERATIONS; iter++ )); do
        CURRENT_ITERATION=$iter
        local iter_start
        iter_start=$(date +%s)
        local now_ts
        now_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        local elapsed_hours=$(( (iter_start - START_TIME) / 3600 ))

        log ""
        log "${BOLD}═══ Iteration $iter / $TOTAL_ITERATIONS  [${elapsed_hours}h elapsed] ═══${RESET}"

        # L1 Mining — every iteration
        check_mining "$iter"

        # L2 Operations — every iteration
        check_l2 "$iter"

        # Bridge — settlement checks every iteration, wraith/lock every 6th
        check_bridge "$iter"

        # Health — every iteration
        check_health "$iter"

        # Fault injection — every 6th
        inject_fault "$iter"

        # Calculate sleep time
        local iter_end
        iter_end=$(date +%s)
        local iter_duration=$((iter_end - iter_start))
        local sleep_time=$((ITER_INTERVAL - iter_duration))

        log "  Iteration $iter complete (${iter_duration}s). $( (( sleep_time > 0 )) && echo "Next in ${sleep_time}s." || echo "Running behind!")"

        if (( sleep_time > 0 )); then
            sleep "$sleep_time"
        fi
    done

    # Final report
    final_report

    # Save final DB state
    for i in $(seq 0 $((VM_COUNT - 1))); do
        ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db '.tables'" > "$LOGDIR/final-db-vm${i}.txt" 2>/dev/null
        ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'SELECT COUNT(*) FROM l2_notes;'" >> "$LOGDIR/final-db-vm${i}.txt" 2>/dev/null
    done
}

main "$@"
