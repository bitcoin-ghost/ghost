#!/bin/bash
set -uo pipefail

# ---------------------------------------------------------------------------
# Ghost Network Health Check
# Quick parallel health dashboard across all 4 Ghost VMs.
# ---------------------------------------------------------------------------

SSH_KEY="$HOME/.ssh/ghost_signet_ed25519"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes"
VM_IPS=("83.136.251.162" "85.9.198.212" "213.163.207.46" "95.111.221.169")
VM_NAMES=("signet-1" "signet-2" "signet-3" "signet-4")

# Defaults
QUIET=false
ALERT_WEBHOOK=""
POOL_PORT=8080
GHOST_PAY_PORT=8800

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

# ---------------------------------------------------------------------------
# Parse CLI flags
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quiet)
            QUIET=true
            shift
            ;;
        --alert-webhook)
            ALERT_WEBHOOK="$2"
            shift 2
            ;;
        --pool-port)
            POOL_PORT="$2"
            shift 2
            ;;
        --ghost-pay-port)
            GHOST_PAY_PORT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $(basename "$0") [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quiet                Only output if something is wrong (for cron)"
            echo "  --alert-webhook <url>  POST alert to webhook if any check fails"
            echo "  --pool-port <port>     Pool HTTP port (default: 8080)"
            echo "  --ghost-pay-port <port> Ghost Pay HTTP port (default: 8800)"
            echo "  -h, --help             Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Temp directory for parallel results
# ---------------------------------------------------------------------------
TMPDIR_HEALTH=$(mktemp -d)
trap 'rm -rf "$TMPDIR_HEALTH"' EXIT

# ---------------------------------------------------------------------------
# Check a single node (runs as background job)
# ---------------------------------------------------------------------------
check_node() {
    local idx="$1"
    local ip="${VM_IPS[$idx]}"
    local name="${VM_NAMES[$idx]}"
    local out="$TMPDIR_HEALTH/$idx"

    # 1. ghost-pool reachable
    if curl -sf --connect-timeout 3 "http://$ip:$POOL_PORT/health" >/dev/null 2>&1; then
        echo "pool_ok=1" >> "$out"
    else
        echo "pool_ok=0" >> "$out"
    fi

    # 2. ghost-pay reachable (ghost-pay serves HTTPS with an identity-derived
    #    self-signed cert, so probe https with -k)
    if curl -skf --connect-timeout 3 "https://$ip:$GHOST_PAY_PORT/health" >/dev/null 2>&1 \
       || curl -skf --connect-timeout 3 "https://$ip:$GHOST_PAY_PORT/api/v1/l2/state" >/dev/null 2>&1; then
        echo "pay_ok=1" >> "$out"
    else
        echo "pay_ok=0" >> "$out"
    fi

    # 3. Bitcoin block height
    local block_height
    block_height=$(curl -sf --connect-timeout 3 "http://$ip:$POOL_PORT/api/v1/node/status" 2>/dev/null \
        | jq -r '.block_height // "?"' 2>/dev/null) || block_height="?"
    [[ -z "$block_height" ]] && block_height="?"
    echo "block_height=$block_height" >> "$out"

    # 4. L2 block height (from ghost-pool's authoritative checkpoint state)
    local l2_height
    l2_height=$(curl -sf --connect-timeout 3 "http://$ip:$POOL_PORT/api/v1/l2/tree-state" 2>/dev/null \
        | jq -r '.checkpoint_height // "?"' 2>/dev/null) || l2_height="?"
    [[ -z "$l2_height" ]] && l2_height="?"
    echo "l2_height=$l2_height" >> "$out"

    # 5. Peer count
    local peers
    peers=$(curl -sf --connect-timeout 3 "http://$ip:$POOL_PORT/peers" 2>/dev/null \
        | jq '.peer_count // (if type == "array" then length else .peers | length end) // 0' 2>/dev/null) || peers="?"
    [[ -z "$peers" ]] && peers="?"
    echo "peers=$peers" >> "$out"

    # 6. Active miners
    local miners
    miners=$(curl -sf --connect-timeout 3 "http://$ip:$POOL_PORT/api/v1/mining/miners" 2>/dev/null \
        | jq 'if type == "array" then length else .count // 0 end' 2>/dev/null) || miners="?"
    [[ -z "$miners" ]] && miners="?"
    echo "miners=$miners" >> "$out"

    # 7. Service status via SSH
    local svc_status
    svc_status=$(ssh $SSH_OPTS "root@$ip" "systemctl is-active ghost-pool" 2>/dev/null) || svc_status="unknown"
    [[ -z "$svc_status" ]] && svc_status="unknown"
    echo "svc_status=$svc_status" >> "$out"
}

# ---------------------------------------------------------------------------
# Run all checks in parallel
# ---------------------------------------------------------------------------
for i in "${!VM_IPS[@]}"; do
    check_node "$i" &
done
wait

# ---------------------------------------------------------------------------
# Collect results
# ---------------------------------------------------------------------------
declare -a R_POOL_OK R_PAY_OK R_BLOCK R_L2 R_PEERS R_MINERS R_SVC

for i in "${!VM_IPS[@]}"; do
    out="$TMPDIR_HEALTH/$i"
    if [[ -f "$out" ]]; then
        # Source the file safely by reading key=value pairs
        R_POOL_OK[$i]=$(grep '^pool_ok=' "$out" | cut -d= -f2)
        R_PAY_OK[$i]=$(grep '^pay_ok=' "$out" | cut -d= -f2)
        R_BLOCK[$i]=$(grep '^block_height=' "$out" | cut -d= -f2)
        R_L2[$i]=$(grep '^l2_height=' "$out" | cut -d= -f2)
        R_PEERS[$i]=$(grep '^peers=' "$out" | cut -d= -f2)
        R_MINERS[$i]=$(grep '^miners=' "$out" | cut -d= -f2)
        R_SVC[$i]=$(grep '^svc_status=' "$out" | cut -d= -f2)
    else
        R_POOL_OK[$i]=0
        R_PAY_OK[$i]=0
        R_BLOCK[$i]="?"
        R_L2[$i]="?"
        R_PEERS[$i]="?"
        R_MINERS[$i]="?"
        R_SVC[$i]="unreachable"
    fi
done

# ---------------------------------------------------------------------------
# Determine max block height (to detect nodes that are behind)
# ---------------------------------------------------------------------------
max_block=0
for i in "${!VM_IPS[@]}"; do
    b="${R_BLOCK[$i]}"
    if [[ "$b" =~ ^[0-9]+$ ]] && (( b > max_block )); then
        max_block=$b
    fi
done

# ---------------------------------------------------------------------------
# Build problem list and alert message
# ---------------------------------------------------------------------------
HAS_PROBLEMS=false
ALERT_PARTS=()

for i in "${!VM_IPS[@]}"; do
    name="${VM_NAMES[$i]}"

    if [[ "${R_POOL_OK[$i]}" != "1" ]]; then
        HAS_PROBLEMS=true
        ALERT_PARTS+=("$name ghost-pool DOWN")
    fi

    if [[ "${R_PAY_OK[$i]}" != "1" ]]; then
        HAS_PROBLEMS=true
        ALERT_PARTS+=("$name ghost-pay DOWN")
    fi

    if [[ "${R_SVC[$i]}" != "active" && "${R_POOL_OK[$i]}" != "1" ]]; then
        # Only flag service status if the pool is also unreachable via HTTP.
        # SSH systemctl checks can timeout transiently without indicating a real problem.
        HAS_PROBLEMS=true
        ALERT_PARTS+=("$name service ${R_SVC[$i]}")
    fi

    b="${R_BLOCK[$i]}"
    if [[ "$b" =~ ^[0-9]+$ ]] && (( max_block > 0 )) && (( max_block - b > 1 )); then
        HAS_PROBLEMS=true
        ALERT_PARTS+=("$name block height behind ($b vs $max_block)")
    elif [[ "$b" == "?" ]]; then
        HAS_PROBLEMS=true
        ALERT_PARTS+=("$name block height unknown")
    fi
done

# ---------------------------------------------------------------------------
# Quiet mode: exit early if no problems
# ---------------------------------------------------------------------------
if $QUIET && ! $HAS_PROBLEMS; then
    exit 0
fi

# ---------------------------------------------------------------------------
# Render table
# ---------------------------------------------------------------------------
NOW=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

# Column widths (fixed)
# Node:10  Pool:9  GhostPay:10  Block:7  L2:5  Peers:7  Miners:14
W_TOTAL=69

fmt_status() {
    local ok="$1"
    if [[ "$ok" == "1" ]]; then
        printf "${GREEN}%-8s${RESET}" "OK"
    else
        printf "${RED}%-8s${RESET}" "DOWN"
    fi
}

fmt_check() {
    local ok="$1"
    if [[ "$ok" == "1" ]]; then
        echo -e "${GREEN}✓${RESET}"
    else
        echo -e "${RED}✗ DOWN${RESET}"
    fi
}

# Print the table
echo -e "┌─────────────────────────────────────────────────────────────────────┐"
printf  "│ ${BOLD}Ghost Network Health${RESET} — %-47s │\n" "$NOW"
echo -e "├──────────┬─────────┬──────────┬───────┬─────┬───────┬──────────────┤"
echo -e "│ ${BOLD}Node${RESET}     │ ${BOLD}Pool${RESET}    │ ${BOLD}GhostPay${RESET} │ ${BOLD}Block${RESET} │ ${BOLD}L2${RESET}  │ ${BOLD}Peers${RESET} │ ${BOLD}Miners${RESET}       │"
echo -e "├──────────┼─────────┼──────────┼───────┼─────┼───────┼──────────────┤"

for i in "${!VM_IPS[@]}"; do
    name="${VM_NAMES[$i]}"
    pool_ok="${R_POOL_OK[$i]}"
    pay_ok="${R_PAY_OK[$i]}"
    block="${R_BLOCK[$i]}"
    l2="${R_L2[$i]}"
    peers="${R_PEERS[$i]}"
    miners="${R_MINERS[$i]}"

    # Determine if the entire row should be red (pool down)
    ROW_COLOR=""
    ROW_RESET=""
    if [[ "$pool_ok" != "1" ]]; then
        ROW_COLOR="$RED"
        ROW_RESET="$RESET"
    fi

    # Format pool status
    if [[ "$pool_ok" == "1" ]]; then
        pool_str="${GREEN}✓${RESET}"
    else
        pool_str="${RED}✗ DOWN${RESET}"
    fi

    # Format ghost-pay status
    if [[ "$pay_ok" == "1" ]]; then
        pay_str="${GREEN}✓${RESET}"
    else
        pay_str="${RED}✗ DOWN${RESET}"
    fi

    # Block height coloring (behind = red)
    block_str="$block"
    if [[ "$block" =~ ^[0-9]+$ ]] && (( max_block > 0 )) && (( max_block - block > 1 )); then
        block_str="${RED}${block}${RESET}"
    elif [[ "$block" == "?" ]]; then
        block_str="${RED}?${RESET}"
    fi

    # Build the row
    # Use printf for alignment. ANSI codes mess up width calculation,
    # so we pad the visible content manually.
    printf "│ ${ROW_COLOR}%-8s${ROW_RESET} │ "  "$name"

    # Pool column (7 visible chars)
    if [[ "$pool_ok" == "1" ]]; then
        printf "${GREEN}✓${RESET}       │ "
    else
        printf "${RED}✗ DOWN${RESET}  │ "
    fi

    # GhostPay column (8 visible chars)
    if [[ "$pay_ok" == "1" ]]; then
        printf "${GREEN}✓${RESET}        │ "
    else
        printf "${RED}✗ DOWN${RESET}   │ "
    fi

    # Block column (5 visible chars)
    if [[ "$block" =~ ^[0-9]+$ ]] && (( max_block > 0 )) && (( max_block - block > 1 )); then
        printf "${RED}%-5s${RESET} │ " "$block"
    elif [[ "$block" == "?" ]]; then
        printf "${RED}%-5s${RESET} │ " "?"
    else
        printf "%-5s │ " "$block"
    fi

    # L2 column (3 visible chars)
    if [[ "$l2" == "?" ]]; then
        printf "${RED}%-3s${RESET} │ " "?"
    else
        printf "%-3s │ " "$l2"
    fi

    # Peers column (5 visible chars)
    if [[ "$peers" == "?" ]] || [[ "$peers" == "0" ]]; then
        printf "${RED}%-5s${RESET} │ " "$peers"
    else
        printf "%-5s │ " "$peers"
    fi

    # Miners column (12 visible chars)
    printf "%-12s │\n" "$miners"
done

echo -e "└──────────┴─────────┴──────────┴───────┴─────┴───────┴──────────────┘"

# Service status summary (below table if any are not active)
for i in "${!VM_IPS[@]}"; do
    svc="${R_SVC[$i]}"
    if [[ "$svc" != "active" ]]; then
        echo -e "  ${RED}⚠${RESET}  ${VM_NAMES[$i]} ghost-pool.service: ${RED}${svc}${RESET}"
    fi
done

# ---------------------------------------------------------------------------
# Send webhook alert if configured and there are problems
# ---------------------------------------------------------------------------
if $HAS_PROBLEMS && [[ -n "$ALERT_WEBHOOK" ]]; then
    alert_text="Ghost alert: $(IFS=', '; echo "${ALERT_PARTS[*]}")"
    alert_json=$(jq -nc --arg text "$alert_text" '{"text": $text}')
    curl -sf -X POST -H "Content-Type: application/json" \
        -d "$alert_json" "$ALERT_WEBHOOK" >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Exit code
# ---------------------------------------------------------------------------
if $HAS_PROBLEMS; then
    exit 1
else
    exit 0
fi
