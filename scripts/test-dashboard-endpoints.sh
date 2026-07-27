#!/bin/bash
#
# Ghost Dashboard Endpoint Test Suite
#
# Tests every GET endpoint consumed by the Ghost dashboard.
# Verifies HTTP 200 + valid JSON for each endpoint.
#
# Usage:
#   ./scripts/test-dashboard-endpoints.sh                     # Test VM1 (default)
#   ./scripts/test-dashboard-endpoints.sh --host 10.0.0.5     # Test specific host
#   ./scripts/test-dashboard-endpoints.sh --all-vms           # Test all 4 VMs
#   ./scripts/test-dashboard-endpoints.sh --pool-port 9090    # Custom pool port
#   ./scripts/test-dashboard-endpoints.sh --ghost-pay-port 9900  # Custom Ghost Pay port
#

set -uo pipefail

# ── Configuration ─────────────────────────────────────────────────────

SSH_KEY="$HOME/.ssh/ghost_signet_ed25519"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10"

VM1_IP="83.136.251.162"
VM2_IP="85.9.198.212"
VM3_IP="213.163.207.46"
VM4_IP="95.111.221.169"

ALL_VM_IPS=("$VM1_IP" "$VM2_IP" "$VM3_IP" "$VM4_IP")
VM_NAMES=("signet-1" "signet-2" "signet-3" "signet-4")

# Defaults
HOST="$VM1_IP"
POOL_PORT=8080
GHOST_PAY_PORT=8800
ALL_VMS=false

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
PASS=0
FAIL=0
SKIP=0
TOTAL=0

# ── CLI Argument Parsing ─────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)           HOST="$2"; shift 2 ;;
        --pool-port)      POOL_PORT="$2"; shift 2 ;;
        --ghost-pay-port) GHOST_PAY_PORT="$2"; shift 2 ;;
        --all-vms)        ALL_VMS=true; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --host <ip>             Target host IP (default: $VM1_IP)"
            echo "  --pool-port <port>      Ghost pool API port (default: 8080)"
            echo "  --ghost-pay-port <port> Ghost Pay API port (default: 8800)"
            echo "  --all-vms               Test all 4 production VMs sequentially"
            echo "  -h, --help              Show this help"
            exit 0
            ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ── Test Framework ───────────────────────────────────────────────────

run_test() {
    local id="$1" name="$2"
    TOTAL=$((TOTAL + 1))
    printf "  ${CYAN}[%s]${NC} %-60s " "$id" "$name"
}

pass() {
    PASS=$((PASS + 1))
    echo -e "${GREEN}PASS${NC}"
}

fail() {
    local reason="${1:-}"
    FAIL=$((FAIL + 1))
    echo -e "${RED}FAIL${NC}"
    [[ -n "$reason" ]] && echo -e "        ${RED}-> $reason${NC}"
}

skip() {
    local reason="${1:-}"
    SKIP=$((SKIP + 1))
    echo -e "${YELLOW}SKIP${NC}"
    [[ -n "$reason" ]] && echo -e "        ${YELLOW}-> $reason${NC}"
}

group_header() {
    local num="$1" name="$2" count="$3"
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  Group $num: $name ($count endpoints)${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ── Endpoint Test Helper ─────────────────────────────────────────────

test_endpoint() {
    local id="$1" name="$2" url="$3"
    run_test "$id" "$name"
    local response http_code body attempt
    for attempt in 1 2 3; do
        response=$(curl -s --connect-timeout 5 --max-time 15 -w "\n%{http_code}" "$url" 2>/dev/null)
        http_code=$(echo "$response" | tail -1)
        if [[ "$attempt" -lt 3 ]] && { [[ "$http_code" == "429" ]] || [[ "$http_code" == "000" ]] || [[ -z "$response" ]]; }; then
            sleep 3  # Back off and retry on rate limit or connection failure
            continue
        fi
        break
    done
    if [[ -z "$response" ]] || [[ "$http_code" == "000" ]]; then
        fail "Connection failed"
        return
    fi
    body=$(echo "$response" | sed '$d')
    if [[ "$http_code" != "200" ]]; then
        fail "HTTP $http_code"
        return
    fi
    if ! echo "$body" | jq . >/dev/null 2>&1; then
        fail "Invalid JSON"
        return
    fi
    pass
    sleep 0.5  # Stay under 5 req/s rate limit
}

# Endpoints that carry payout identities are served from the authenticated tier, so an
# unsigned probe must be REFUSED. Asserting 401 checks the property that matters — the gate
# is holding — without this script needing to hold the operator secret. A 200 here means the
# route has fallen back onto the public tier and the payout ledger is world-readable again.
test_endpoint_gated() {
    local id="$1" name="$2" url="$3"
    run_test "$id" "$name (must require auth)"
    local http_code attempt
    for attempt in 1 2 3; do
        http_code=$(curl -s -o /dev/null --connect-timeout 5 --max-time 15 -w "%{http_code}" "$url" 2>/dev/null)
        if [[ "$attempt" -lt 3 ]] && { [[ "$http_code" == "429" ]] || [[ "$http_code" == "000" ]]; }; then
            sleep 3  # Back off and retry on rate limit or connection failure
            continue
        fi
        break
    done
    case "$http_code" in
        000) fail "Connection failed" ;;
        401) pass ;;
        200) fail "HTTP 200 — endpoint is PUBLIC but must require auth" ;;
        *)   fail "HTTP $http_code — expected 401" ;;
    esac
    sleep 0.5  # Stay under 5 req/s rate limit
}

# Test endpoint that may return non-JSON (health, metrics)
test_endpoint_raw() {
    local id="$1" name="$2" url="$3"
    run_test "$id" "$name"
    local http_code attempt
    for attempt in 1 2 3; do
        http_code=$(curl -s --connect-timeout 5 --max-time 15 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
        if [[ "$attempt" -lt 3 ]] && { [[ "$http_code" == "429" ]] || [[ "$http_code" == "000" ]] || [[ -z "$http_code" ]]; }; then
            sleep 3
            continue
        fi
        break
    done
    if [[ "$http_code" == "000" ]] || [[ -z "$http_code" ]]; then
        fail "Connection failed"
        return
    fi
    if [[ "$http_code" != "200" ]]; then
        fail "HTTP $http_code"
        return
    fi
    pass
    sleep 0.5
}

# ── Test Groups ──────────────────────────────────────────────────────

run_all_tests() {
    local host="$1"
    local pool="http://$host:$POOL_PORT"

    # ── Group 1: Overview (6 endpoints) ──────────────────────────────

    group_header 1 "Overview" 6

    test_endpoint "1.1" "/api/v1/node/status"              "$pool/api/v1/node/status"
    test_endpoint "1.2" "/api/v1/mining/status"             "$pool/api/v1/mining/status"
    test_endpoint "1.3" "/api/v1/rewards/current"           "$pool/api/v1/rewards/current"
    test_endpoint "1.4" "/api/v1/mesh/status"               "$pool/api/v1/mesh/status"
    test_endpoint "1.5" "/api/v1/ghostpay/status"           "$pool/api/v1/ghostpay/status"
    test_endpoint_gated "1.6" "/api/v1/ghostpay/payout-history"   "$pool/api/v1/ghostpay/payout-history"

    # ── Group 2: Mining (7 endpoints) ────────────────────────────────

    group_header 2 "Mining" 7

    test_endpoint "2.1" "/api/v1/mining/miners"             "$pool/api/v1/mining/miners"
    test_endpoint "2.2" "/api/v1/mining/best-hash"          "$pool/api/v1/mining/best-hash"
    test_endpoint "2.3" "/api/v1/mining/payout_address"     "$pool/api/v1/mining/payout_address"
    test_endpoint "2.4" "/api/v1/mining/private"            "$pool/api/v1/mining/private"
    test_endpoint "2.5" "/api/v1/mining/public"             "$pool/api/v1/mining/public"
    test_endpoint_gated "2.6" "/shares"                           "$pool/shares"
    test_endpoint "2.7" "/api/v1/node/shares"               "$pool/api/v1/node/shares"

    # ── Group 3: Network/Peers (6 endpoints) ─────────────────────────

    group_header 3 "Network/Peers" 6

    test_endpoint "3.1" "/peers"                            "$pool/peers"
    test_endpoint "3.2" "/api/v1/network/peers"             "$pool/api/v1/network/peers"
    test_endpoint "3.3" "/api/v1/network/pool"              "$pool/api/v1/network/pool"
    test_endpoint "3.4" "/api/v1/network/public-nodes"      "$pool/api/v1/network/public-nodes"
    test_endpoint "3.5" "/api/v1/network/treasury"          "$pool/api/v1/network/treasury"
    test_endpoint_gated "3.6" "/api/v1/network/payout-history"    "$pool/api/v1/network/payout-history"

    # ── Group 4: Settings/Config (13 endpoints) ──────────────────────

    group_header 4 "Settings/Config" 13

    test_endpoint_gated "4.01" "/api/v1/config/full"              "$pool/api/v1/config/full"
    test_endpoint "4.02" "/api/v1/config/archive_mode"      "$pool/api/v1/config/archive_mode"
    test_endpoint "4.03" "/api/v1/config/ghost_mode"        "$pool/api/v1/config/ghost_mode"
    test_endpoint "4.04" "/api/v1/config/mempool_profile"   "$pool/api/v1/config/mempool_profile"
    test_endpoint "4.05" "/api/v1/config/template_profile"  "$pool/api/v1/config/template_profile"
    test_endpoint "4.06" "/api/v1/config/public_mining"     "$pool/api/v1/config/public_mining"
    test_endpoint "4.07" "/api/v1/config/reaper"            "$pool/api/v1/config/reaper"
    test_endpoint "4.08" "/api/v1/config/ghost_pay"         "$pool/api/v1/config/ghost_pay"
    test_endpoint "4.09" "/api/v1/config/elder"             "$pool/api/v1/config/elder"
    test_endpoint "4.10" "/api/v1/config/prune_profile"     "$pool/api/v1/config/prune_profile"
    test_endpoint "4.11" "/api/v1/config/operator_window"   "$pool/api/v1/config/operator_window"
    test_endpoint "4.12" "/api/v1/config/profiles/mempool"  "$pool/api/v1/config/profiles/mempool"
    test_endpoint "4.13" "/api/v1/config/profiles/template" "$pool/api/v1/config/profiles/template"

    # ── Group 5: Elders/MPC (3 endpoints) ────────────────────────────

    group_header 5 "Elders/MPC" 3

    test_endpoint "5.1" "/api/v1/network/elder"             "$pool/api/v1/network/elder"
    test_endpoint "5.2" "/api/v1/mpc/status"                "$pool/api/v1/mpc/status"
    test_endpoint "5.3" "/api/v1/mpc/contributors"          "$pool/api/v1/mpc/contributors"

    # ── Group 6: System (4 endpoints) ────────────────────────────────

    group_header 6 "System" 4

    test_endpoint "6.1" "/api/v1/resources/status"          "$pool/api/v1/resources/status"
    test_endpoint "6.2" "/api/v1/system/version"            "$pool/api/v1/system/version"
    test_endpoint "6.3" "/api/v1/node/info"                 "$pool/api/v1/node/info"
    test_endpoint "6.4" "/node-info"                        "$pool/node-info"

    # ── Group 7: Rewards (3 endpoints) ───────────────────────────────

    group_header 7 "Rewards" 3

    test_endpoint "7.1" "/api/v1/rewards/history"           "$pool/api/v1/rewards/history"
    test_endpoint "7.2" "/api/v1/rewards/full"              "$pool/api/v1/rewards/full"
    test_endpoint "7.3" "/api/v1/rewards/node-history"      "$pool/api/v1/rewards/node-history"

    # ── Group 8: Privacy - Wraith/Shroud/Haze (3 endpoints) ─────────

    group_header 8 "Privacy (Wraith/Shroud/Haze)" 3

    test_endpoint "8.1" "/api/v1/wraith/sessions"           "$pool/api/v1/wraith/sessions"
    test_endpoint "8.2" "/api/v1/shroud/status"             "$pool/api/v1/shroud/status"
    test_endpoint "8.3" "/api/v1/haze/status"               "$pool/api/v1/haze/status"

    # ── Group 9: Reaper/Buds (2 endpoints) ───────────────────────────

    group_header 9 "Reaper/Buds" 2

    test_endpoint "9.1" "/api/v1/buds/capabilities"         "$pool/api/v1/buds/capabilities"
    test_endpoint "9.2" "/api/v1/buds/mempool"              "$pool/api/v1/buds/mempool"

    # ── Group 10: Locks/Payments (2 endpoints) ───────────────────────

    group_header 10 "Locks/Payments" 2

    test_endpoint "10.1" "/api/v1/locks"                    "$pool/api/v1/locks"
    test_endpoint_gated "10.2" "/api/v1/payments"                 "$pool/api/v1/payments"

    # ── Group 11: Swarm (2 endpoints) ────────────────────────────────

    group_header 11 "Swarm" 2

    test_endpoint "11.1" "/api/v1/swarm"                    "$pool/api/v1/swarm"
    test_endpoint "11.2" "/api/v1/swarm/nodes"              "$pool/api/v1/swarm/nodes"

    # ── Group 12: Watchdog (1 endpoint) ──────────────────────────────

    group_header 12 "Watchdog" 1

    test_endpoint "12.1" "/api/v1/watchdog/status"          "$pool/api/v1/watchdog/status"

    # ── Group 13: Backup (1 endpoint) ────────────────────────────────

    group_header 13 "Backup" 1

    test_endpoint "13.1" "/api/v1/backup/history"           "$pool/api/v1/backup/history"

    # ── Group 14: Additional (3 endpoints) ───────────────────────────

    group_header 14 "Additional" 3

    test_endpoint     "14.1" "/api/v1/settlement/status"    "$pool/api/v1/settlement/status"
    test_endpoint_raw "14.2" "/health"                      "$pool/health"
    test_endpoint_raw "14.3" "/metrics"                     "$pool/metrics"
}

# ── Main ─────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Ghost Dashboard Endpoint Test Suite"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  Pool port:      $POOL_PORT"
echo "  Ghost Pay port: $GHOST_PAY_PORT"

START_TIME=$(date +%s)

if [[ "$ALL_VMS" == true ]]; then
    echo "  Mode:           All VMs"
    echo ""
    for i in "${!ALL_VM_IPS[@]}"; do
        ip="${ALL_VM_IPS[$i]}"
        name="${VM_NAMES[$i]}"
        echo ""
        echo -e "${BOLD}################################################################${NC}"
        echo -e "${BOLD}  VM: $name ($ip)${NC}"
        echo -e "${BOLD}################################################################${NC}"
        run_all_tests "$ip"
    done
else
    echo "  Target:         $HOST"
    echo ""
    run_all_tests "$HOST"
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# ── Summary ──────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo -e "  ${BOLD}Dashboard Endpoint Tests Complete${NC}"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo -e "  ${GREEN}PASSED:${NC}  $PASS"
echo -e "  ${RED}FAILED:${NC}  $FAIL"
echo -e "  ${YELLOW}SKIPPED:${NC} $SKIP"
echo -e "  Total:   $TOTAL"
echo -e "  Time:    ${DURATION}s"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}ALL ENDPOINTS HEALTHY${NC}"
else
    echo -e "  ${RED}${BOLD}$FAIL ENDPOINT(S) FAILED${NC}"
fi

echo ""
exit $((FAIL > 0 ? 1 : 0))
