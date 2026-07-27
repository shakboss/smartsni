#!/bin/bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info() { echo -e "${CYAN}►${NC} $*"; }
ok()   { echo -e "${GREEN}✔${NC} $*"; }
fail() { echo -e "${RED}✘${NC} $*"; }

DOMAIN="${1:-}"
EMAIL="${2:-}"

if [[ -z "$DOMAIN" ]]; then
    echo "Usage: $0 <domain> [email]"
    echo "  sudo bash certbot-setup.sh cdn.example.com admin@example.com"
    exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}Run with sudo${NC}"
    exit 1
fi

info "Obtaining SSL certificate for $DOMAIN..."

systemctl stop nginx 2>/dev/null || true

CERT_FLAG="--register-unsafely-without-email"
[[ -n "$EMAIL" ]] && CERT_FLAG="--email $EMAIL"

if certbot certonly --standalone -d "$DOMAIN" $CERT_FLAG --non-interactive --agree-tos; then
    ok "Certificate obtained"
else
    fail "Certbot failed. Ensure DNS points to this server and port 80 is free."
    exit 1
fi

mkdir -p "$INSTALL_DIR/certs"
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$INSTALL_DIR/certs/fullchain.pem"
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$INSTALL_DIR/certs/privkey.pem"
chmod 644 "$INSTALL_DIR/certs/fullchain.pem"
chmod 600 "$INSTALL_DIR/certs/privkey.pem"
ok "Certs copied to $INSTALL_DIR/certs/"

(crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --deploy-hook 'cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $INSTALL_DIR/certs/fullchain.pem && cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $INSTALL_DIR/certs/privkey.pem'") | sort -u | crontab - 2>/dev/null
ok "Auto-renewal cron job set"

echo ""
ok "Done! Update config.json with your domain and cert paths."
echo "  certPath: $INSTALL_DIR/certs/fullchain.pem"
echo "  keyPath:  $INSTALL_DIR/certs/privkey.pem"
