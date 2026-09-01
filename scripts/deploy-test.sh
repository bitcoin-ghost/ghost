#!/bin/bash
#
# ⛔ THIS DEPLOYS TO REAL NODES. It is NOT a test of the deploy gate.
#
# If you want the deploy-gate SELF-TEST — the hermetic one `record-tests.sh` runs — you want
# `scripts/test-deploy-gate.sh`. The names differ only by word order, and that has already cost
# something: this script was run in mistake for it, stopped ghost-pool and sri-pool on
# ghost-vm1 (a PRODUCTION node in the mining DNS), and closed :3333 and :34255 for ~50s while
# pool_sv2 waited for its initial template and the translator crash-looped. The node self-healed,
# but miners could not connect for the duration.
#
#   deploy-test.sh       -> THIS. Deploys to real nodes. Destructive.
#   test-deploy-gate.sh  -> the 76-check self-test. Hermetic. Safe.
#
# Deploy ghost-pool binary with role-specific configs for stress testing
#
# VM1+VM2: Reaper strict (aggressive filtering)
# VM3+VM4: Standard archive + permissive (Reaper disabled)
#
# This creates a split network that guarantees different template fee totals,
# directly exercising the bidirectional fee adjustment code.
#

set -euo pipefail

SSH_KEY="$HOME/.ssh/ghost_signet_ed25519"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10"
BINARY="target/release/ghost-pool"
REMOTE_BIN="/opt/ghost/bin/ghost-pool"
REMOTE_CONFIG="/etc/ghost/pool.toml"
SERVICE="ghost-pool"

# VM definitions: name IP role
VM1_NAME="signet-1"; VM1_IP="83.136.251.162"; VM1_ROLE="reaper"
VM2_NAME="signet-2"; VM2_IP="85.9.198.212";   VM2_ROLE="reaper"
VM3_NAME="signet-3"; VM3_IP="213.163.207.46";  VM3_ROLE="standard"
VM4_NAME="signet-4"; VM4_IP="95.111.221.169";  VM4_ROLE="standard"

ALL_VMS=("$VM1_NAME:$VM1_IP:$VM1_ROLE" "$VM2_NAME:$VM2_IP:$VM2_ROLE" \
         "$VM3_NAME:$VM3_IP:$VM3_ROLE" "$VM4_NAME:$VM4_IP:$VM4_ROLE")

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_ok()   { echo -e "${GREEN}[OK]${NC}   $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
log_info() { echo -e "${YELLOW}[..]${NC}   $1"; }

ssh_cmd() {
    local ip="$1"; shift
    ssh $SSH_OPTS "root@$ip" "$@"
}

scp_file() {
    local src="$1" ip="$2" dst="$3"
    scp $SSH_OPTS "$src" "root@$ip:$dst"
}

# ── Step 1: Build release binary ──────────────────────────────────────
echo "════════════════════════════════════════════════════════════"
echo "  Ghost Pool Deployment Test — Build & Deploy"
echo "════════════════════════════════════════════════════════════"
echo ""

if [[ "${SKIP_BUILD:-}" == "1" ]]; then
    log_info "Skipping build (SKIP_BUILD=1)"
else
    log_info "Building release binary..."
    cargo build --release -p ghost-pool 2>&1 | tail -3
    if [[ ! -f "$BINARY" ]]; then
        log_fail "Binary not found at $BINARY"
        exit 1
    fi
    log_ok "Binary built: $(ls -lh $BINARY | awk '{print $5}')"
fi
echo ""

# ── Step 2: Deploy to each VM ─────────────────────────────────────────
patch_config() {
    local ip="$1"
    local role="$2"

    if [[ "$role" == "reaper" ]]; then
        # VM1+VM2: Reaper strict
        ssh_cmd "$ip" bash -s <<'REAPER_EOF'
            CONFIG="/etc/ghost/pool.toml"
            # Back up original
            cp "$CONFIG" "$CONFIG.bak.$(date +%s)"

            # Patch [reaper] section
            if grep -q '^\[reaper\]' "$CONFIG"; then
                sed -i '/^\[reaper\]/,/^\[/{
                    s/^enabled = .*/enabled = true/
                    s/^mode = .*/mode = "strict"/
                }' "$CONFIG"
            else
                printf '\n[reaper]\nenabled = true\nmode = "strict"\n' >> "$CONFIG"
            fi

            # Patch [policy] section
            if grep -q '^\[policy\]' "$CONFIG"; then
                sed -i '/^\[policy\]/,/^\[/{
                    s/^profile = .*/profile = "bitcoin_pure"/
                }' "$CONFIG"
            else
                printf '\n[policy]\nprofile = "bitcoin_pure"\n' >> "$CONFIG"
            fi

            # Ensure archive_mode in [storage]
            if grep -q '^\[storage\]' "$CONFIG"; then
                if grep -q '^archive_mode' "$CONFIG"; then
                    sed -i 's/^archive_mode = .*/archive_mode = true/' "$CONFIG"
                else
                    sed -i '/^\[storage\]/a archive_mode = true' "$CONFIG"
                fi
            fi

            echo "DONE"
REAPER_EOF
    else
        # VM3+VM4: Reaper disabled + permissive
        ssh_cmd "$ip" bash -s <<'STANDARD_EOF'
            CONFIG="/etc/ghost/pool.toml"
            cp "$CONFIG" "$CONFIG.bak.$(date +%s)"

            # Patch [reaper] section
            if grep -q '^\[reaper\]' "$CONFIG"; then
                sed -i '/^\[reaper\]/,/^\[/{
                    s/^enabled = .*/enabled = false/
                    s/^mode = .*/mode = "monitor"/
                }' "$CONFIG"
            else
                printf '\n[reaper]\nenabled = false\nmode = "monitor"\n' >> "$CONFIG"
            fi

            # Patch [policy] section
            if grep -q '^\[policy\]' "$CONFIG"; then
                sed -i '/^\[policy\]/,/^\[/{
                    s/^profile = .*/profile = "permissive"/
                }' "$CONFIG"
            else
                printf '\n[policy]\nprofile = "permissive"\n' >> "$CONFIG"
            fi

            # Ensure archive_mode in [storage]
            if grep -q '^\[storage\]' "$CONFIG"; then
                if grep -q '^archive_mode' "$CONFIG"; then
                    sed -i 's/^archive_mode = .*/archive_mode = true/' "$CONFIG"
                else
                    sed -i '/^\[storage\]/a archive_mode = true' "$CONFIG"
                fi
            fi

            echo "DONE"
STANDARD_EOF
    fi
}

deploy_vm() {
    local name="$1" ip="$2" role="$3"

    echo "────────────────────────────────────────"
    echo "  $name ($ip) — role: $role"
    echo "────────────────────────────────────────"

    # Stop service and wait for it to fully stop
    log_info "Stopping $SERVICE..."
    ssh_cmd "$ip" "systemctl stop $SERVICE 2>/dev/null || true"

    local retries=0
    while [[ $retries -lt 10 ]]; do
        local state
        state=$(ssh_cmd "$ip" "systemctl is-active $SERVICE 2>/dev/null || echo 'inactive'")
        [[ "$state" == "inactive" || "$state" == "failed" ]] && break
        retries=$((retries + 1))
        sleep 1
    done
    [[ $retries -ge 10 ]] && { log_fail "$SERVICE did not stop on $ip"; return 1; }

    # Copy binary
    log_info "Copying binary..."
    scp_file "$BINARY" "$ip" "/tmp/ghost-pool"
    ssh_cmd "$ip" "cp /tmp/ghost-pool $REMOTE_BIN && chmod +x $REMOTE_BIN && rm /tmp/ghost-pool"
    log_ok "Binary deployed"

    # Patch config
    log_info "Patching config ($role)..."
    result=$(patch_config "$ip" "$role")
    if [[ "$result" == *"DONE"* ]]; then
        log_ok "Config patched"
    else
        log_fail "Config patch failed"
        echo "$result"
        return 1
    fi

    # Start service
    log_info "Starting $SERVICE..."
    ssh_cmd "$ip" "systemctl start $SERVICE"
    sleep 2

    # Verify clean startup (check last 10s of logs for panics)
    log_info "Checking startup health..."
    local logs
    logs=$(ssh_cmd "$ip" "journalctl -u $SERVICE --since '10 seconds ago' --no-pager 2>/dev/null || true")
    if echo "$logs" | grep -qi "panic"; then
        log_fail "PANIC detected in startup logs!"
        echo "$logs" | grep -i "panic" | head -5
        return 1
    fi

    local status
    status=$(ssh_cmd "$ip" "systemctl is-active $SERVICE 2>/dev/null || echo 'dead'")
    if [[ "$status" == "active" ]]; then
        log_ok "$SERVICE is active"
    else
        log_fail "$SERVICE status: $status"
        return 1
    fi

    echo ""
}

# Deploy VM1 (genesis) first, then the rest
log_info "Deploying VM1 (genesis node) first..."
deploy_vm "$VM1_NAME" "$VM1_IP" "$VM1_ROLE"

log_info "Waiting 15s for genesis node to initialize..."
sleep 15

for entry in "${ALL_VMS[@]:1}"; do
    IFS=':' read -r name ip role <<< "$entry"
    deploy_vm "$name" "$ip" "$role"
done

# ── Step 3: Wait for mesh formation ──────────────────────────────────
echo ""
log_info "Waiting 30s for mesh formation..."
sleep 30

# ── Step 4: Verify mesh connectivity ─────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Mesh Verification"
echo "════════════════════════════════════════════════════════════"
echo ""

MESH_OK=true
for entry in "${ALL_VMS[@]}"; do
    IFS=':' read -r name ip role <<< "$entry"

    peer_count=$(curl -sf --connect-timeout 5 "http://$ip:8080/api/v1/network/peers" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('peers', d.get('data', []))))" 2>/dev/null \
        || echo "0")

    if [[ "$peer_count" -ge 3 ]]; then
        log_ok "$name ($ip): $peer_count peers"
    elif [[ "$peer_count" -ge 1 ]]; then
        log_info "$name ($ip): $peer_count peers (partial mesh)"
    else
        log_fail "$name ($ip): $peer_count peers (no mesh)"
        MESH_OK=false
    fi
done

echo ""

# Verify config took effect
echo "════════════════════════════════════════════════════════════"
echo "  Config Verification"
echo "════════════════════════════════════════════════════════════"
echo ""

for entry in "${ALL_VMS[@]}"; do
    IFS=':' read -r name ip role <<< "$entry"

    health=$(curl -sf --connect-timeout 5 "http://$ip:8080/health?unsigned=true" 2>/dev/null || echo "{}")
    reaper_cap=$(echo "$health" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    r = d.get('response', d)
    caps = r.get('capabilities', {})
    print(caps.get('reaper', 'unknown'))
except: print('error')
" 2>/dev/null)

    if [[ "$role" == "reaper" ]]; then
        if [[ "$reaper_cap" == "True" || "$reaper_cap" == "true" ]]; then
            log_ok "$name: reaper=$reaper_cap (expected for reaper strict)"
        else
            log_fail "$name: reaper=$reaper_cap (expected true for reaper strict)"
        fi
    else
        if [[ "$reaper_cap" == "False" || "$reaper_cap" == "false" ]]; then
            log_ok "$name: reaper=$reaper_cap (expected for standard)"
        else
            log_fail "$name: reaper=$reaper_cap (expected false for standard)"
        fi
    fi
done

echo ""

if $MESH_OK; then
    log_ok "Deployment complete — ready for test-deployment.sh"
else
    log_fail "Mesh not fully formed — tests may have partial results"
fi

echo ""
echo "Next: ./scripts/test-deployment.sh"
