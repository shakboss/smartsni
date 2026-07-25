#!/bin/bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
INSTALL_DIR="/opt/smartSNI"
SERVICE_NAME="sni"

ok()   { echo -e "  ${GREEN}✔${NC} $*"; }
fail() { echo -e "  ${RED}✘${NC} $*"; }
info() { echo -e "  ${YELLOW}►${NC} $*"; }

[[ "$(id -u)" -ne 0 ]] && { echo -e "${RED}Run with sudo${NC}"; exit 1; }

# --- Menu ---
if [[ "${1:-}" == "--uninstall" ]]; then
    echo -e "\n${RED}Uninstalling SmartSNI...${NC}"
    systemctl stop $SERVICE_NAME 2>/dev/null || true
    systemctl disable $SERVICE_NAME 2>/dev/null || true
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    systemctl daemon-reload
    crontab -l 2>/dev/null | grep -v "certbot renew" | crontab - 2>/dev/null || true
    rm -rf "$INSTALL_DIR"
    userdel smart-sni 2>/dev/null || true
    echo -e "${GREEN}✔ Done. Certificates not removed.${NC}"
    exit 0
fi

if [[ "${1:-}" == "--status" ]]; then
    systemctl status $SERVICE_NAME 2>/dev/null || echo -e "${RED}Not installed${NC}"
    exit 0
fi

if [[ "${1:-}" == "--help" ]]; then
    echo "Usage:"
    echo "  sudo bash install.sh --domain example.com --email you@email.com"
    echo "  sudo bash install.sh --uninstall"
    echo "  sudo bash install.sh --status"
    exit 0
fi

# --- Parse args ---
DOMAIN="" EMAIL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)  DOMAIN="$2"; shift 2 ;;
        --email)   EMAIL="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -z "$DOMAIN" ]]; then
    read -p "  Domain: " DOMAIN
    [[ -z "$DOMAIN" ]] && { echo "Domain required"; exit 1; }
    read -p "  Email for Let's Encrypt (Enter to skip): " EMAIL
fi

echo -e "\n${CYAN}Installing SmartSNI for $DOMAIN${NC}\n"

# --- Detect package manager ---
PM="apt"
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    [[ "$ID" == "centos" || "$ID" == "rhel" ]] && PM="yum"
    [[ "$ID" == "fedora" || "$ID" == "rocky" || "$ID" == "almalinux" ]] && PM="dnf"
fi

# --- Install packages ---
info "Installing packages..."
export DEBIAN_FRONTEND=noninteractive
$PM update -y >/dev/null 2>&1 || true

PKGS="python3 python3-pip python3-venv git jq curl wget certbot libcap2-bin net-tools"
[[ "$PM" == "yum" || "$PM" == "dnf" ]] && PKGS="python3 python3-pip git jq curl wget certbot libcap net-tools"

for pkg in $PKGS; do
    DEBIAN_FRONTEND=noninteractive $PM install -y --no-install-recommends "$pkg" >/dev/null 2>&1 || true
done
ok "Packages installed"

# --- Copy files ---
info "Deploying files..."
mkdir -p "$INSTALL_DIR"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
ok "Files copied"

# --- Secret ---
SECRET=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
echo "SMARTSNI_SECRET=$SECRET" > "$INSTALL_DIR/.env"
chmod 600 "$INSTALL_DIR/.env"
ok "Secret generated"

# --- SSL Certificate ---
info "Getting SSL certificate..."
systemctl stop nginx 2>/dev/null || true
systemctl stop sni 2>/dev/null || true

CERT_FLAG="--register-unsafely-without-email"
[[ -n "$EMAIL" ]] && CERT_FLAG="--email $EMAIL"

if certbot certonly --standalone -d "$DOMAIN" $CERT_FLAG --non-interactive --agree-tos >/dev/null 2>&1; then
    ok "SSL certificate obtained"
else
    fail "Certbot failed. Make sure DNS points to this server and port 80 is free."
    exit 1
fi

# --- Generate config ---
info "Generating config..."
MYIP=$(hostname -I | awk '{print $1}')
TRIGGER="bypass.$DOMAIN"

cat > "$INSTALL_DIR/config.json" <<EOF
{
  "host": "$DOMAIN",
  "reload_interval_minutes": 1,
  "domains": {},
  "trigger_domains": ["$TRIGGER"],
  "domain_rotation_minutes": 60,
  "cloudflare": {"enabled": false, "zone_id": "", "api_token": ""},
  "domain_fronting": {"enabled": false, "front_host": "", "front_sni": "", "upstream_host": ""},
  "bypass_settings": {
    "enabled": true,
    "mode": "websocket",
    "trigger_sni": "$TRIGGER",
    "tunnel_path": "/wstunnel",
    "padding_size_range": [10, 100],
    "delay_ms_range": [5, 200],
    "detect_mobile_networks": false,
    "geoip_db_path": "",
    "mobile_carrier_names": [],
    "multiplexing": true,
    "idle_timeout_seconds": 120,
    "socks_host": "127.0.0.1",
    "socks_port": 1080
  }
}
EOF
ok "Config written"

# --- Copy certs so smart-sni user can read them ---
CERTS_DIR="$INSTALL_DIR/certs"
mkdir -p "$CERTS_DIR"
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$CERTS_DIR/fullchain.pem"
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$CERTS_DIR/privkey.pem"
chmod 644 "$CERTS_DIR"/*.pem

# --- Python venv ---
info "Setting up Python..."
cd "$INSTALL_DIR"
python3 -m venv venv >/dev/null 2>&1
source venv/bin/activate
pip install --upgrade pip >/dev/null 2>&1
pip install -r requirements.txt >/dev/null 2>&1
deactivate
ok "Python ready"

# --- Service user ---
useradd --system --shell /usr/sbin/nologin --home-dir "$INSTALL_DIR" smart-sni 2>/dev/null || true
REAL_PYTHON=$(readlink -f "$INSTALL_DIR/venv/bin/python3")
setcap cap_net_bind_service=+ep "$REAL_PYTHON" 2>/dev/null || true
chown -R smart-sni:smart-sni "$INSTALL_DIR"
ok "User created"

# --- Systemd ---
cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=SmartSNI
After=network.target

[Service]
User=smart-sni
Group=smart-sni
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStart=$INSTALL_DIR/venv/bin/python main.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable $SERVICE_NAME >/dev/null 2>&1
systemctl start $SERVICE_NAME
ok "Service started"

# --- Certbot renewal ---
(crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --deploy-hook 'cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $INSTALL_DIR/certs/fullchain.pem && cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $INSTALL_DIR/certs/privkey.pem && systemctl restart $SERVICE_NAME'") | sort -u | crontab - 2>/dev/null
ok "Auto-renewal set"

# --- Done ---
echo ""
sleep 2
if systemctl is-active --quiet $SERVICE_NAME; then
    echo -e "${GREEN}✔ SmartSNI is running!${NC}"
else
    fail "Service failed. Check: journalctl -u $SERVICE_NAME"
fi

echo ""
echo -e "  ${BOLD}Domain:${NC}   $DOMAIN"
echo -e "  ${BOLD}Trigger:${NC}  $TRIGGER"
echo -e "  ${BOLD}Secret:${NC}   ${SECRET:0:8}...${SECRET: -4}"
echo -e "  ${BOLD}Config:${NC}   $INSTALL_DIR/config.json"
echo -e "  ${BOLD}Logs:${NC}     journalctl -u $SERVICE_NAME -f"
echo ""
echo -e "  ${YELLOW}Android: host=$DOMAIN, trigger=$TRIGGER, secret=<full secret above>${NC}"
echo ""
