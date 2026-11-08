#!/bin/bash
set -uo pipefail

# ---------------------------------------------------------------------------
# Ghost Node Comparison
# Compares critical state across all 4 Ghost VMs to detect drift.
# ---------------------------------------------------------------------------

SSH_KEY="$HOME/.ssh/ghost_signet_ed25519"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=5"
VM_IPS=("83.136.251.162" "85.9.198.212" "213.163.207.46" "95.111.221.169")
VM_NAMES=("signet-1" "signet-2" "signet-3" "signet-4")

# Defaults
QUIET=false
POOL_PORT=8080

# Colors
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
BOLD='\033[1m'
DIM='\033[2m'
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
        --pool-port)
            POOL_PORT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $(basename "$0") [OPTIONS]"
            echo ""
            echo "Compares critical state across all 4 Ghost VMs to detect drift."
            echo ""
            echo "Options:"
            echo "  --quiet              Only output if drift detected"
            echo "  --pool-port <port>   Pool HTTP port (default: 8080)"
            echo "  -h, --help           Show this help"
            echo ""
            echo "Exit codes:"
            echo "  0  All nodes in sync"
            echo "  1  Warnings detected (drift within tolerance)"
            echo "  2  Critical issues detected"
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
TMPDIR_CMP=$(mktemp -d)
trap 'rm -rf "$TMPDIR_CMP"' EXIT

# ---------------------------------------------------------------------------
# Collect data from a single node (runs as background job)
# ---------------------------------------------------------------------------
collect_node() {
    local idx="$1"
    local ip="${VM_IPS[$idx]}"
    local out="$TMPDIR_CMP/$idx"
    local base="http://$ip:$POOL_PORT"

    # Block height + network from /api/v1/node/status
    local node_status
    node_status=$(curl -sf --connect-timeout 3 "$base/api/v1/node/status" 2>/dev/null) || node_status=""
    if [[ -n "$node_status" ]]; then
        echo "block_height=$(echo "$node_status" | jq -r '.block_height // "?"' 2>/dev/null)" >> "$out"
        echo "network=$(echo "$node_status" | jq -r '.network // "?"' 2>/dev/null)" >> "$out"
    else
        echo "block_height=?" >> "$out"
        echo "network=?" >> "$out"
    fi

    # Peer count from /peers
    local peers
    peers=$(curl -sf --connect-timeout 3 "$base/peers" 2>/dev/null \
        | jq '.peer_count // (if type == "array" then length else .peers | length end) // 0' 2>/dev/null) || peers="?"
    [[ -z "$peers" ]] && peers="?"
    echo "peers=$peers" >> "$out"

    # Binary version from /api/v1/system/version
    local version
    version=$(curl -sf --connect-timeout 3 "$base/api/v1/system/version" 2>/dev/null \
        | jq -r '.version // "?"' 2>/dev/null) || version="?"
    [[ -z "$version" ]] && version="?"
    echo "version=$version" >> "$out"

    # Ghost mode from /api/v1/config/ghost_mode
    local ghost_mode
    ghost_mode=$(curl -sf --connect-timeout 3 "$base/api/v1/config/ghost_mode" 2>/dev/null \
        | jq -r 'if .ghost_mode != null then .ghost_mode else "?" end' 2>/dev/null) || ghost_mode="?"
    [[ -z "$ghost_mode" ]] && ghost_mode="?"
    echo "ghost_mode=$ghost_mode" >> "$out"

    # Reaper config from /api/v1/config/reaper
    local reaper_json reaper_enabled reaper_mode
    reaper_json=$(curl -sf --connect-timeout 3 "$base/api/v1/config/reaper" 2>/dev/null) || reaper_json=""
    if [[ -n "$reaper_json" ]]; then
        reaper_enabled=$(echo "$reaper_json" | jq -r '.enabled // "?"' 2>/dev/null)
        reaper_mode=$(echo "$reaper_json" | jq -r '.mode // "?"' 2>/dev/null)
    else
        reaper_enabled="?"
        reaper_mode="?"
    fi
    [[ -z "$reaper_enabled" ]] && reaper_enabled="?"
    [[ -z "$reaper_mode" ]] && reaper_mode="?"
    echo "reaper_enabled=$reaper_enabled" >> "$out"
    echo "reaper_mode=$reaper_mode" >> "$out"
}

# ---------------------------------------------------------------------------
# Run all collection in parallel
# ---------------------------------------------------------------------------
for i in "${!VM_IPS[@]}"; do
    collect_node "$i" &
done
wait

# ---------------------------------------------------------------------------
# Read results into arrays
# ---------------------------------------------------------------------------
declare -a R_BLOCK R_PEERS R_VERSION R_MODE R_REAPER_EN R_REAPER_MODE R_NETWORK

read_val() {
    local file="$1" key="$2" default="${3:-?}"
    local val
    val=$(grep "^${key}=" "$file" 2>/dev/null | head -1 | cut -d= -f2-)
    [[ -z "$val" ]] && val="$default"
    echo "$val"
}

for i in "${!VM_IPS[@]}"; do
    out="$TMPDIR_CMP/$i"
    R_BLOCK[$i]=$(read_val "$out" block_height)
    R_PEERS[$i]=$(read_val "$out" peers)
    R_VERSION[$i]=$(read_val "$out" version)
    R_MODE[$i]=$(read_val "$out" ghost_mode)
    R_REAPER_EN[$i]=$(read_val "$out" reaper_enabled)
    R_REAPER_MODE[$i]=$(read_val "$out" reaper_mode)
    R_NETWORK[$i]=$(read_val "$out" network)
done

# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------
WARNINGS=0
CRITICAL=0

# Accumulate section output; each section is stored as a string.
# In quiet mode, only sections with issues are printed.
declare -a SECTIONS
declare -a SECTION_HAS_ISSUE

# Helper: find numeric max across nodes
numeric_max() {
    local max=0
    for val in "$@"; do
        if [[ "$val" =~ ^[0-9]+$ ]] && (( val > max )); then
            max=$val
        fi
    done
    echo "$max"
}

# Helper: check if all values are identical
all_identical() {
    local first="$1"
    shift
    for val in "$@"; do
        [[ "$val" != "$first" ]] && return 1
    done
    return 0
}

# --- Block Height ---
section=""
max_block=$(numeric_max "${R_BLOCK[@]}")
has_issue=false

section+="  ${BOLD}Block Height:${RESET}\n    "
for i in "${!VM_IPS[@]}"; do
    (( i > 0 )) && section+="   "
    val="${R_BLOCK[$i]}"
    if [[ "$val" == "?" ]]; then
        section+="${VM_NAMES[$i]}: ${RED}?${RESET}"
        has_issue=true
    elif (( max_block > 0 )) && (( max_block - val > 1 )); then
        section+="${VM_NAMES[$i]}: ${RED}${val}${RESET} ${YELLOW}⚠ BEHIND${RESET}"
        has_issue=true
    elif (( max_block > 0 )) && (( max_block - val == 1 )); then
        section+="${VM_NAMES[$i]}: ${YELLOW}${val}${RESET} ${YELLOW}⚠ BEHIND${RESET}"
        has_issue=true
    else
        section+="${VM_NAMES[$i]}: ${val}"
    fi
done
section+="\n"

if $has_issue; then
    # Determine which nodes are behind and by how much
    for i in "${!VM_IPS[@]}"; do
        val="${R_BLOCK[$i]}"
        if [[ "$val" == "?" ]]; then
            section+="    ${RED}→ WARNING: ${VM_NAMES[$i]} block height unavailable${RESET}\n"
            (( WARNINGS++ ))
        elif (( max_block > 0 )) && (( max_block - val > 1 )); then
            section+="    ${RED}→ CRITICAL: ${VM_NAMES[$i]} is $((max_block - val)) blocks behind${RESET}\n"
            (( CRITICAL++ ))
        elif (( max_block > 0 )) && (( max_block - val == 1 )); then
            section+="    ${YELLOW}→ WARNING: ${VM_NAMES[$i]} is 1 block behind${RESET}\n"
            (( WARNINGS++ ))
        fi
    done
else
    section+="    ${GREEN}→ OK: All nodes in sync${RESET}\n"
fi
SECTIONS+=("$section")
SECTION_HAS_ISSUE+=("$has_issue")

# --- Peer Count ---
section=""
has_issue=false

section+="  ${BOLD}Peer Count:${RESET}\n    "
for i in "${!VM_IPS[@]}"; do
    (( i > 0 )) && section+="   "
    val="${R_PEERS[$i]}"
    if [[ "$val" == "?" ]]; then
        section+="${VM_NAMES[$i]}: ${RED}?${RESET}"
        has_issue=true
    elif (( val < 2 )); then
        section+="${VM_NAMES[$i]}: ${RED}${val}${RESET} ${YELLOW}⚠ LOW${RESET}"
        has_issue=true
    else
        section+="${VM_NAMES[$i]}: ${val}"
    fi
done
section+="\n"

if $has_issue; then
    for i in "${!VM_IPS[@]}"; do
        val="${R_PEERS[$i]}"
        if [[ "$val" == "?" ]]; then
            section+="    ${RED}→ WARNING: ${VM_NAMES[$i]} peer count unavailable${RESET}\n"
            (( WARNINGS++ ))
        elif (( val < 2 )); then
            section+="    ${RED}→ CRITICAL: ${VM_NAMES[$i]} has only ${val} peer(s)${RESET}\n"
            (( CRITICAL++ ))
        fi
    done
else
    section+="    ${GREEN}→ OK${RESET}\n"
fi
SECTIONS+=("$section")
SECTION_HAS_ISSUE+=("$has_issue")


# --- Binary Version ---
section=""
has_issue=false

section+="  ${BOLD}Binary Version:${RESET}\n    "
for i in "${!VM_IPS[@]}"; do
    (( i > 0 )) && section+="   "
    section+="${VM_NAMES[$i]}: ${R_VERSION[$i]}"
done
section+="\n"

if ! all_identical "${R_VERSION[@]}"; then
    has_issue=true
    section+="    ${RED}→ CRITICAL: Binary versions differ across nodes${RESET}\n"
    (( CRITICAL++ ))
else
    section+="    ${GREEN}→ OK: Identical${RESET}\n"
fi
SECTIONS+=("$section")
SECTION_HAS_ISSUE+=("$has_issue")

# --- Ghost Mode ---
section=""
has_issue=false

section+="  ${BOLD}Ghost Mode:${RESET}\n    "
for i in "${!VM_IPS[@]}"; do
    (( i > 0 )) && section+="   "
    section+="${VM_NAMES[$i]}: ${R_MODE[$i]}"
done
section+="\n"

if ! all_identical "${R_MODE[@]}"; then
    has_issue=true
    section+="    ${RED}→ CRITICAL: Ghost modes differ across nodes${RESET}\n"
    (( CRITICAL++ ))
else
    section+="    ${GREEN}→ OK: Identical${RESET}\n"
fi
SECTIONS+=("$section")
SECTION_HAS_ISSUE+=("$has_issue")

# --- Reaper ---
section=""
has_issue=false

section+="  ${BOLD}Reaper:${RESET}\n    "
for i in "${!VM_IPS[@]}"; do
    (( i > 0 )) && section+="   "
    en="${R_REAPER_EN[$i]}"
    mode="${R_REAPER_MODE[$i]}"
    if [[ "$en" == "true" ]]; then
        section+="${VM_NAMES[$i]}: enabled/${mode}"
    elif [[ "$en" == "false" ]]; then
        section+="${VM_NAMES[$i]}: disabled"
    else
        section+="${VM_NAMES[$i]}: ${RED}?${RESET}"
        has_issue=true
    fi
done
section+="\n"

# Check if enabled status differs (warning, not critical — mixed reaper config is expected)
if ! all_identical "${R_REAPER_EN[@]}"; then
    section+="    ${GREEN}→ OK (mixed config is expected for reaper)${RESET}\n"
else
    section+="    ${GREEN}→ OK: Identical${RESET}\n"
fi

# Only flag as issue if we got "?" values
if $has_issue; then
    section+="    ${YELLOW}→ WARNING: Could not read reaper config from some nodes${RESET}\n"
    (( WARNINGS++ ))
fi
SECTIONS+=("$section")
SECTION_HAS_ISSUE+=("$has_issue")

# --- Network ---
section=""
has_issue=false

section+="  ${BOLD}Network:${RESET}\n    "
for i in "${!VM_IPS[@]}"; do
    (( i > 0 )) && section+="   "
    section+="${VM_NAMES[$i]}: ${R_NETWORK[$i]}"
done
section+="\n"

if ! all_identical "${R_NETWORK[@]}"; then
    has_issue=true
    section+="    ${RED}→ CRITICAL: Nodes are on different networks!${RESET}\n"
    (( CRITICAL++ ))
else
    section+="    ${GREEN}→ OK: Identical${RESET}\n"
fi
SECTIONS+=("$section")
SECTION_HAS_ISSUE+=("$has_issue")

# ---------------------------------------------------------------------------
# Quiet mode: exit early if no issues
# ---------------------------------------------------------------------------
if $QUIET && (( WARNINGS == 0 )) && (( CRITICAL == 0 )); then
    exit 0
fi

# ---------------------------------------------------------------------------
# Render output
# ---------------------------------------------------------------------------
NOW=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
BAR="═══════════════════════════════════════════════════════════════"

echo ""
echo -e "$BAR"
echo -e "  ${BOLD}Ghost Node Comparison${RESET} — $NOW"
echo -e "$BAR"
echo ""

for i in "${!SECTIONS[@]}"; do
    if $QUIET && [[ "${SECTION_HAS_ISSUE[$i]}" == "false" ]]; then
        continue
    fi
    echo -e "${SECTIONS[$i]}"
done

# Summary
if (( CRITICAL > 0 )); then
    summary_color="$RED"
elif (( WARNINGS > 0 )); then
    summary_color="$YELLOW"
else
    summary_color="$GREEN"
fi

echo -e "$BAR"
echo -e "  ${summary_color}Summary: ${WARNINGS} warning(s), ${CRITICAL} critical issue(s)${RESET}"
echo -e "$BAR"
echo ""

# ---------------------------------------------------------------------------
# Exit code
# ---------------------------------------------------------------------------
if (( CRITICAL > 0 )); then
    exit 2
elif (( WARNINGS > 0 )); then
    exit 1
else
    exit 0
fi
