#!/bin/bash
#
# Bitcoin Ghost - Full Node Installer
# https://bitcoinghost.org
#
# Usage: curl -sSL https://get.bitcoinghost.org/install.sh | bash
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Version
GHOST_VERSION="1.4.0"
GHOST_REPO="https://github.com/bitcoin-ghost/ghost"

echo -e "${CYAN}"
echo "  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █"
echo " ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █"
echo " ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒"
echo " ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒"
echo " ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░"
echo -e "${NC}"
echo -e "${GREEN}Bitcoin Ghost Node Installer v${GHOST_VERSION}${NC}"
echo "=================================================="
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}Warning: Running as root. Will create ghost user.${NC}"
    SUDO=""
else
    SUDO="sudo"
fi

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        echo -e "${RED}Error: Cannot detect OS. Only Ubuntu 22.04+ and Debian 12+ are supported.${NC}"
        exit 1
    fi

    echo -e "Detected: ${CYAN}${OS} ${VERSION}${NC}"
}

# Check requirements
check_requirements() {
    echo -e "\n${CYAN}Checking requirements...${NC}"

    # Check OS
    if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
        echo -e "${RED}Error: Only Ubuntu and Debian are supported.${NC}"
        exit 1
    fi

    # Check version
    if [[ "$OS" == "ubuntu" && "${VERSION%%.*}" -lt 22 ]]; then
        echo -e "${RED}Error: Ubuntu 22.04 or higher required.${NC}"
        exit 1
    fi

    if [[ "$OS" == "debian" && "${VERSION%%.*}" -lt 12 ]]; then
        echo -e "${RED}Error: Debian 12 or higher required.${NC}"
        exit 1
    fi

    # Check disk space (need at least 50GB for pruned, 1TB for archive)
    AVAILABLE=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [ "$AVAILABLE" -lt 50 ]; then
        echo -e "${RED}Error: At least 50GB free disk space required. You have ${AVAILABLE}GB.${NC}"
        exit 1
    fi
    echo -e "  Disk space: ${GREEN}${AVAILABLE}GB available${NC}"

    # Check RAM (need at least 4GB)
    RAM=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$RAM" -lt 4 ]; then
        echo -e "${YELLOW}Warning: 4GB+ RAM recommended. You have ${RAM}GB.${NC}"
    else
        echo -e "  RAM: ${GREEN}${RAM}GB${NC}"
    fi

    echo -e "${GREEN}Requirements check passed!${NC}"
}

# Install dependencies
install_dependencies() {
    echo -e "\n${CYAN}Installing dependencies...${NC}"

    $SUDO apt-get update -qq
    $SUDO apt-get install -y -qq \
        curl \
        wget \
        git \
        build-essential \
        pkg-config \
        libssl-dev \
        libsqlite3-dev \
        jq \
        ufw \
        fail2ban

    # Install Rust if not present
    if ! command -v cargo &> /dev/null; then
        echo -e "${CYAN}Installing Rust...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi

    echo -e "${GREEN}Dependencies installed!${NC}"
}

# Create ghost user
create_user() {
    if ! id "ghost" &>/dev/null; then
        echo -e "\n${CYAN}Creating ghost user...${NC}"
        $SUDO useradd -r -m -d /var/lib/ghost -s /bin/bash ghost
        $SUDO usermod -aG sudo ghost
    fi
}

# Download and build Ghost
install_ghost() {
    echo -e "\n${CYAN}Downloading Bitcoin Ghost v${GHOST_VERSION}...${NC}"

    # Create directories
    $SUDO mkdir -p /opt/ghost
    $SUDO mkdir -p /etc/ghost
    $SUDO mkdir -p /var/lib/ghost
    $SUDO mkdir -p /var/log/ghost

    # Clone or download release
    cd /tmp
    if [ -d "ghost" ]; then
        rm -rf ghost
    fi

    git clone --depth 1 --branch "v${GHOST_VERSION}" "${GHOST_REPO}" ghost 2>/dev/null || \
    git clone --depth 1 "${GHOST_REPO}" ghost

    cd ghost

    echo -e "${CYAN}Building Ghost (this may take a few minutes)...${NC}"
    cargo build --release -p ghost-mining -p ghost-coordinator -p ghost-translator -p ghost-light-wallet-cli

    # Install binaries
    $SUDO cp target/release/ghost-mining /opt/ghost/
    $SUDO cp target/release/ghost-coordinator /opt/ghost/
    $SUDO cp target/release/ghost-translator /opt/ghost/
    $SUDO cp target/release/ghost-light-wallet-cli /opt/ghost/

    # Create symlinks
    $SUDO ln -sf /opt/ghost/ghost-mining /usr/local/bin/ghost-mining
    $SUDO ln -sf /opt/ghost/ghost-coordinator /usr/local/bin/ghost-coordinator
    $SUDO ln -sf /opt/ghost/ghost-translator /usr/local/bin/ghost-translator
    $SUDO ln -sf /opt/ghost/ghost-light-wallet-cli /usr/local/bin/ghost-wallet

    # Set permissions
    $SUDO chown -R ghost:ghost /opt/ghost
    $SUDO chown -R ghost:ghost /var/lib/ghost
    $SUDO chown -R ghost:ghost /var/log/ghost
    $SUDO chown -R ghost:ghost /etc/ghost

    echo -e "${GREEN}Ghost binaries installed!${NC}"
}

# Configure Ghost
configure_ghost() {
    echo -e "\n${CYAN}Configuring Ghost...${NC}"

    # Generate node identity
    NODE_ID=$(openssl rand -hex 16)

    # Prompt for payout address
    echo -e "\n${YELLOW}Enter your Bitcoin payout address (or press Enter to skip):${NC}"
    read -r PAYOUT_ADDRESS

    if [ -z "$PAYOUT_ADDRESS" ]; then
        PAYOUT_ADDRESS="YOUR_BTC_ADDRESS_HERE"
    fi

    # Prompt for network
    echo -e "\n${YELLOW}Select network:${NC}"
    echo "  1) signet (recommended for testing)"
    echo "  2) mainnet"
    read -r -p "Choice [1]: " NETWORK_CHOICE

    case "$NETWORK_CHOICE" in
        2) NETWORK="mainnet" ;;
        *) NETWORK="signet" ;;
    esac

    # Create config
    cat << EOF | $SUDO tee /etc/ghost/pool.toml > /dev/null
# Bitcoin Ghost Pool Configuration
# Generated by installer on $(date)

[node]
id = "${NODE_ID}"
data_dir = "/var/lib/ghost"
log_dir = "/var/log/ghost"

[bitcoin]
network = "${NETWORK}"
rpc_host = "127.0.0.1"
rpc_port = $([ "$NETWORK" = "signet" ] && echo "38332" || echo "8332")
rpc_user = "ghost"
rpc_password = "CHANGE_ME"

[pool]
payout_address = "${PAYOUT_ADDRESS}"
public_mining = false
min_payout = 100000

[stratum]
v1_port = 3333
v2_port = 34255

[network]
http_port = 8080
p2p_port = 8555
seed_nodes = [
    "pool.bitcoinghost.org:8555"
]

[rewards]
archive_mode = false
ghost_pay = false
policy_node = true
EOF

    $SUDO chown ghost:ghost /etc/ghost/pool.toml
    $SUDO chmod 600 /etc/ghost/pool.toml

    echo -e "${GREEN}Configuration created at /etc/ghost/pool.toml${NC}"
    echo -e "${YELLOW}Remember to update rpc_password to match your Bitcoin Core config!${NC}"
}

# Create systemd services
create_services() {
    echo -e "\n${CYAN}Creating systemd services...${NC}"

    # Ghost Pool service
    cat << 'EOF' | $SUDO tee /etc/systemd/system/ghost-mining.service > /dev/null
[Unit]
Description=Bitcoin Ghost Pool
After=network.target bitcoind.service
Wants=bitcoind.service

[Service]
Type=simple
User=ghost
Group=ghost
ExecStart=/opt/ghost/ghost-mining --config /etc/ghost/pool.toml
Restart=always
RestartSec=10
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    # Ghost Translator service
    cat << 'EOF' | $SUDO tee /etc/systemd/system/ghost-translator.service > /dev/null
[Unit]
Description=Bitcoin Ghost Stratum Translator (SV1 to SV2)
After=network.target ghost-mining.service
Wants=ghost-mining.service

[Service]
Type=simple
User=ghost
Group=ghost
ExecStart=/opt/ghost/ghost-translator --listen 0.0.0.0:3333 --upstream 127.0.0.1:34255
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Ghost Coordinator service
    cat << 'EOF' | $SUDO tee /etc/systemd/system/ghost-coordinator.service > /dev/null
[Unit]
Description=Bitcoin Ghost Coordinator (Fire Ping)
After=network.target ghost-mining.service

[Service]
Type=simple
User=ghost
Group=ghost
ExecStart=/opt/ghost/ghost-coordinator --listen 0.0.0.0:8334
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    $SUDO systemctl daemon-reload

    echo -e "${GREEN}Systemd services created!${NC}"
}

# Configure firewall
configure_firewall() {
    echo -e "\n${CYAN}Configuring firewall...${NC}"

    $SUDO ufw allow 22/tcp comment 'SSH'
    $SUDO ufw allow 8080/tcp comment 'Ghost HTTP API'
    $SUDO ufw allow 8555:8562/tcp comment 'Ghost P2P Mesh'
    $SUDO ufw allow 3333/tcp comment 'Stratum V1'
    $SUDO ufw allow 34255/tcp comment 'Stratum V2'

    # Enable if not already
    if ! $SUDO ufw status | grep -q "Status: active"; then
        echo -e "${YELLOW}Enabling firewall (UFW)...${NC}"
        $SUDO ufw --force enable
    fi

    echo -e "${GREEN}Firewall configured!${NC}"
}

# Print summary
print_summary() {
    echo -e "\n${GREEN}=================================================="
    echo -e "  Bitcoin Ghost Installation Complete!"
    echo -e "==================================================${NC}"
    echo ""
    echo -e "${CYAN}Installed components:${NC}"
    echo "  - ghost-mining      (Mining pool daemon)"
    echo "  - ghost-translator (SV1→SV2 translator)"
    echo "  - ghost-coordinator (Fire Ping load balancer)"
    echo "  - ghost-wallet    (Light wallet CLI)"
    echo ""
    echo -e "${CYAN}Configuration:${NC}"
    echo "  - Config file: /etc/ghost/pool.toml"
    echo "  - Data dir:    /var/lib/ghost"
    echo "  - Log dir:     /var/log/ghost"
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo "  1. Install and sync Bitcoin Core (${NETWORK})"
    echo "  2. Update /etc/ghost/pool.toml with your Bitcoin RPC credentials"
    echo "  3. Update your payout address in the config"
    echo "  4. Start the services:"
    echo ""
    echo -e "     ${YELLOW}sudo systemctl enable --now ghost-mining${NC}"
    echo -e "     ${YELLOW}sudo systemctl enable --now ghost-translator${NC}"
    echo ""
    echo -e "${CYAN}Useful commands:${NC}"
    echo "  - Check status:  sudo systemctl status ghost-mining"
    echo "  - View logs:     sudo journalctl -u ghost-mining -f"
    echo "  - Test health:   curl http://localhost:8080/health"
    echo ""
    echo -e "${CYAN}Documentation:${NC}"
    echo "  https://bitcoinghost.org/docs/"
    echo ""
    echo -e "${GREEN}Happy mining! 🚀${NC}"
}

# Main
main() {
    detect_os
    check_requirements
    install_dependencies
    create_user
    install_ghost
    configure_ghost
    create_services
    configure_firewall
    print_summary
}

main "$@"
