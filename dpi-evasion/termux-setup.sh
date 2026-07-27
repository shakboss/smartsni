#!/bin/bash
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
BOLD='\033[1m'

info()  { echo -e "${CYAN}►${NC} $*"; }
ok()    { echo -e "${GREEN}✔${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC} $*"; }
fail()  { echo -e "${RED}✘${NC} $*"; }

echo -e "\n${BOLD}DPI Evasion Client - Termux Setup${NC}\n"

# Check if running in Termux
if [[ ! -d "/data/data/com.termux" ]] && [[ -z "${TERMUX_VERSION:-}" ]]; then
    warn "Not running in Termux. Some steps may differ."
fi

# Step 1: Install Go
info "Installing Go..."
if command -v go &>/dev/null; then
    ok "Go already installed: $(go version)"
else
    pkg update -y 2>/dev/null || apt update -y
    pkg install golang -y 2>/dev/null || apt install golang -y
    if command -v go &>/dev/null; then
        ok "Go installed: $(go version)"
    else
        fail "Go installation failed. Install manually: pkg install golang"
        exit 1
    fi
fi

# Step 2: Setup project directory
INSTALL_DIR="${HOME}/dpi-evasion"
info "Setting up project in ${INSTALL_DIR}..."

mkdir -p "${INSTALL_DIR}/cmd/client"
mkdir -p "${INSTALL_DIR}/lib"
mkdir -p "${INSTALL_DIR}/certs"

# Copy files if running from source directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/go.mod" ]]; then
    cp -r "${SCRIPT_DIR}/"* "${INSTALL_DIR}/" 2>/dev/null || true
    ok "Files copied from ${SCRIPT_DIR}"
else
    warn "Run this script from the dpi-evasion directory, or copy files manually to ${INSTALL_DIR}"
fi

# Step 3: Build client
info "Building client binary..."
cd "${INSTALL_DIR}"
if [[ -f "go.mod" ]]; then
    go build -o client ./cmd/client/
    if [[ -f "client" ]]; then
        ok "Client binary built: $(ls -lh client | awk '{print $5}')"
    else
        fail "Build failed. Check errors above."
        exit 1
    fi
else
    fail "go.mod not found in ${INSTALL_DIR}"
    exit 1
fi

# Step 4: Create client config if not exists
if [[ ! -f "client-config.json" ]]; then
    info "Creating default client config..."
    cat > client-config.json << 'EOF'
{
  "server": "YOUR_SERVER_IP",
  "port": 443,
  "password": "CHANGE_ME",
  "sni": "www.microsoft.com",
  "mode": "shadowtls",
  "wsPath": "/wstunnel",
  "secret": "",
  "socksPort": 1080
}
EOF
    ok "client-config.json created — edit it with your server details"
else
    ok "client-config.json already exists"
fi

# Step 5: Create run script
cat > run.sh << 'RUNEOF'
#!/bin/bash
cd "$(dirname "$0")"
echo "========================================="
echo "  DPI Evasion Client"
echo "========================================="
echo ""
echo "SOCKS5 proxy: 127.0.0.1:1080"
echo ""
echo "Configure your browser:"
echo "  Firefox: Settings → Network → Manual Proxy"
echo "           SOCKS5 Host: 127.0.0.1  Port: 1080"
echo ""
echo "  Chrome:  Use proxy extension or:"
echo "           --proxy-server=socks5://127.0.0.1:1080"
echo ""
echo "Press Ctrl+C to stop"
echo "========================================="
echo ""
./client -config client-config.json
RUNEOF
chmod +x run.sh
ok "run.sh created"

# Step 6: Create systemd-style service (for Termux:Boot)
mkdir -p "${HOME}/.termux/boot"
cat > "${HOME}/.termux/boot/dpi-evasion.sh" << 'BOOTEOF'
#!/bin/bash
termux-wake-lock
cd ~/dpi-evasion
./client -config client-config.json &
BOOTEOF
chmod +x "${HOME}/.termux/boot/dpi-evasion.sh"
ok "Auto-start on boot configured (install Termux:Boot app)"

echo ""
echo -e "${BOLD}${GREEN}=== Setup Complete ===${NC}"
echo ""
echo -e "  ${BOLD}1.${NC} Edit config: ${CYAN}nano ~/dpi-evasion/client-config.json${NC}"
echo -e "     Set your server IP, password, and mode"
echo ""
echo -e "  ${BOLD}2.${NC} Run client:   ${CYAN}cd ~/dpi-evasion && ./run.sh${NC}"
echo ""
echo -e "  ${BOLD}3.${NC} Configure browser SOCKS5 proxy: ${CYAN}127.0.0.1:1080${NC}"
echo ""
echo -e "  ${BOLD}4.${NC} (Optional) Install Termux:Boot for auto-start on boot"
echo ""
echo -e "  ${YELLOW}Server setup: run the relay server on your VPS first${NC}"
echo -e "  ${YELLOW}See certbot-setup.sh for TLS certificate setup${NC}"
echo ""
