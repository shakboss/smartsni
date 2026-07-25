#!/bin/bash
# ============================================================================
# SmartSNI Installer v2.0
# ============================================================================
# Usage:
#   Interactive:   sudo bash install.sh
#   Auto-install:  sudo bash install.sh --domain example.com --email admin@example.com
#   Uninstall:     sudo bash install.sh --uninstall
#   Status:        sudo bash install.sh --status
#   Update:        sudo bash install.sh --update
#   Logs:          sudo bash install.sh --logs
#
# Auto-install flags:
#   --domain DOMAIN          Primary server domain (required for auto-install)
#   --email EMAIL            Email for Let's Encrypt (recommended)
#   --trigger TRIGGER        Trigger domain (default: bypass.DOMAIN)
#   --fallbacks LIST         Comma-separated fallback domains
#   --mode MODE              Bypass mode: websocket|shape (default: websocket)
#   --secret SECRET          Auth secret (auto-generated if omitted)
#   --fronting               Enable domain fronting
#   --cloudflare             Enable Cloudflare support
#   --mobile-detect          Enable mobile carrier detection
#   --carriers LIST          Comma-separated carrier names
#   --skip-security          Skip security hardening
#   --skip-firewall          Skip firewall setup
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colors & UI
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

INSTALL_DIR="/opt/smartSNI"
SERVICE_NAME="sni"
LOG_FILE="/tmp/smartsni-install.log"

# ---------------------------------------------------------------------------
# UI Functions
# ---------------------------------------------------------------------------
print_banner() {
    echo -e "${CYAN}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║         SmartSNI Server Installer v2.0              ║"
    echo "  ║         DPI Bypass & Tunnel Proxy                  ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

info()    { echo -e "  ${BLUE}[INFO]${NC}    $*"; }
success() { echo -e "  ${GREEN}[OK]${NC}      $*"; }
warn()    { echo -e "  ${YELLOW}[WARN]${NC}    $*"; }
error()   { echo -e "  ${RED}[ERROR]${NC}   $*"; }
step()    { echo -e "\n${BOLD}${CYAN}──> $*${NC}"; }
ok()      { echo -e "  ${GREEN}✔${NC} $*"; }
fail()    { echo -e "  ${RED}✘${NC} $*"; }

spinner() {
    local pid=$1
    local msg="${2:-Working...}"
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CYAN}%s${NC} %s" "${spin:i++%${#spin}:1}" "$msg"
        sleep 0.1
    done
    printf "\r"
}

progress() {
    local current=$1 total=$2 msg=$3
    local pct=$((current * 100 / total))
    local filled=$((pct / 5))
    local empty=$((20 - filled))
    local bar=""
    local i
    for ((i=0; i<filled; i++)); do bar+="#"; done
    for ((i=0; i<empty; i++)); do bar+=" "; done
    printf "\r  ${CYAN}[%s]${NC} %d%% %s" "$bar" "$pct" "$msg"
    [[ $current -eq $total ]] && echo
}

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        error "This script must be run as root."
        echo -e "  Run: ${BOLD}sudo bash install.sh${NC}"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Detect distribution & package manager
# ---------------------------------------------------------------------------
detect_distro() {
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect Linux distribution."
        exit 1
    fi
    source /etc/os-release
    DISTRO_ID="${ID}"
    DISTRO_NAME="${PRETTY_NAME:-$ID}"
    PM="apt"
    if [[ "$DISTRO_ID" == "centos" ]] || [[ "$DISTRO_ID" == "rhel" ]]; then PM="yum"; fi
    if [[ "$DISTRO_ID" == "fedora" ]] || [[ "$DISTRO_ID" == "rocky" ]] || [[ "$DISTRO_ID" == "almalinux" ]]; then PM="dnf"; fi
    success "Detected: ${DISTRO_NAME} (package manager: ${PM})"
}

# ---------------------------------------------------------------------------
# System requirements check
# ---------------------------------------------------------------------------
check_system_requirements() {
    step "Checking system requirements"

    local issues=0

    # CPU cores
    local cores
    cores=$(nproc 2>/dev/null || echo 1)
    if [[ $cores -ge 2 ]]; then
        ok "CPU cores: $cores"
    else
        warn "CPU cores: $cores (recommended: 2+)"
    fi

    # RAM
    local ram_mb
    ram_mb=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}' || echo 0)
    if [[ $ram_mb -ge 512 ]]; then
        ok "RAM: ${ram_mb}MB"
    elif [[ $ram_mb -ge 256 ]]; then
        warn "RAM: ${ram_mb}MB (recommended: 512MB+)"
    else
        error "RAM: ${ram_mb}MB (minimum: 256MB)"
        ((issues++))
    fi

    # Disk space
    local disk_free
    disk_free=$(df -m / 2>/dev/null | awk 'NR==2{print $4}' || echo 0)
    if [[ $disk_free -ge 1 ]]; then
        ok "Disk free: ${disk_free}MB"
    else
        error "Disk free: ${disk_free}MB (need at least 500MB)"
        ((issues++))
    fi

    # Python 3
    if command -v python3 &>/dev/null; then
        local pyver
        pyver=$(python3 --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
        local py_major py_minor
        py_major=$(echo "$pyver" | cut -d. -f1)
        py_minor=$(echo "$pyver" | cut -d. -f2)
        if [[ $py_major -ge 3 ]] && [[ $py_minor -ge 10 ]]; then
            ok "Python: $pyver"
        else
            warn "Python: $pyver (recommended: 3.10+)"
        fi
    else
        error "Python 3 not found"
        ((issues++))
    fi

    # systemd
    if pidof systemd &>/dev/null || [[ -d /run/systemd/system ]]; then
        ok "Systemd: available"
    else
        warn "Systemd not detected (service management may not work)"
    fi

    # Internet connectivity
    if ping -c 1 -W 3 1.1.1.1 &>/dev/null; then
        ok "Internet: connected"
    else
        error "No internet connection"
        ((issues++))
    fi

    if [[ $issues -gt 0 ]]; then
        error "$issues critical issue(s) found. Fix them before installing."
        exit 1
    fi

    success "System requirements check passed"
}

# ---------------------------------------------------------------------------
# Install dependencies
# ---------------------------------------------------------------------------
install_dependencies() {
    step "Installing system packages"

    $PM update -y >>"$LOG_FILE" 2>&1

    local packages=("python3" "python3-pip" "python3-venv" "git" "jq" "curl" "wget" "certbot" "libcap2-bin" "ufw" "fail2ban" "net-tools")

    # CentOS/RHEL adjustments
    if [[ "$PM" == "yum" ]] || [[ "$PM" == "dnf" ]]; then
        packages=("python3" "python3-pip" "git" "jq" "curl" "wget" "certbot" "libcap" "firewalld" "fail2ban" "net-tools")
    fi

    local total=${#packages[@]}
    local count=0
    for pkg in "${packages[@]}"; do
        ((count++))
        progress $count $total "Installing $pkg"
        if $PM install -y "$pkg" >>"$LOG_FILE" 2>&1; then
            :
        else
            warn "Could not install $pkg (may not be available on this distro)"
        fi
    done

    # Ensure python3-venv is available
    if ! python3 -c "import venv" &>/dev/null; then
        if [[ "$PM" == "apt" ]]; then
            $PM install -y python3-venv >>"$LOG_FILE" 2>&1 || true
        fi
    fi

    success "System packages installed"
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
preflight_checks() {
    step "Pre-flight checks"

    local issues=0

    # Port 443 check
    if ss -tlnp | grep -q ':443 '; then
        local port_proc
        port_proc=$(ss -tlnp | grep ':443 ' | head -1)
        error "Port 443 is in use: $port_proc"
        error "Stop the service using port 443 first (e.g., 'sudo systemctl stop nginx')"
        ((issues++))
    else
        ok "Port 443: available"
    fi

    # Port 853 check
    if ss -tlnp | grep -q ':853 '; then
        warn "Port 853 (DoT) is already in use"
    else
        ok "Port 853: available"
    fi

    # DNS resolution for the domain
    if [[ -n "${DOMAIN:-}" ]]; then
        local server_ip public_ip
        server_ip=$(dig +short "$DOMAIN" 2>/dev/null | head -1)
        public_ip=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "")

        if [[ -n "$server_ip" ]]; then
            ok "DNS: $DOMAIN resolves to $server_ip"
            if [[ -n "$public_ip" ]]; then
                if [[ "$server_ip" == "$public_ip" ]]; then
                    ok "DNS: matches server IP ($public_ip)"
                else
                    warn "DNS: $DOMAIN ($server_ip) does not match server IP ($public_ip)"
                    warn "Make sure DNS is pointing to this server before using the service"
                fi
            fi
        else
            warn "DNS: Could not resolve $DOMAIN (may not be configured yet)"
        fi
    fi

    if [[ $issues -gt 0 ]]; then
        error "$issues issue(s) must be fixed before installing."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Security hardening
# ---------------------------------------------------------------------------
harden_security() {
    step "Security hardening"

    # --- UFW Firewall ---
    if [[ "${SKIP_FIREWALL:-}" != "true" ]]; then
        info "Configuring UFW firewall"
        if command -v ufw &>/dev/null; then
            # Reset to defaults
            ufw --force reset >>"$LOG_FILE" 2>&1 || true

            # Default policies
            ufw default deny incoming >>"$LOG_FILE" 2>&1
            ufw default allow outgoing >>"$LOG_FILE" 2>&1

            # Allow SSH (critical - don't lock yourself out!)
            local ssh_port
            ssh_port=$(ss -tlnp | grep -oP ':\K\d+(?=.*sshd)' | head -1)
            [[ -z "$ssh_port" ]] && ssh_port=22
            ufw allow "$ssh_port/tcp" comment "SSH" >>"$LOG_FILE" 2>&1
            ok "SSH port $ssh_port allowed"

            # Allow SmartSNI ports
            ufw allow 443/tcp comment "SmartSNI TLS" >>"$LOG_FILE" 2>&1
            ufw allow 853/tcp comment "SmartSNI DoT" >>"$LOG_FILE" 2>&1
            ok "Ports 443, 853 allowed"

            # Enable UFW
            ufw --force enable >>"$LOG_FILE" 2>&1
            ok "UFW firewall enabled"
        else
            warn "UFW not available, skipping firewall setup"
        fi
    else
        info "Skipping firewall setup (--skip-firewall)"
    fi

    # --- Kernel security tuning ---
    info "Applying kernel security parameters"
    cat > /etc/sysctl.d/99-smartsni-security.conf <<'SYSEOF'
# SmartSNI security hardening
# Prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore source-routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Reduce TIME_WAIT
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# Increase connection tracking
net.netfilter.nf_conntrack_max = 262144

# TCP keepalive (detect dead connections faster)
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3

# Increase max connections
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 4096
SYSEOF
    sysctl -p /etc/sysctl.d/99-smartsni-security.conf >>"$LOG_FILE" 2>&1
    ok "Kernel security parameters applied"

    # --- fail2ban ---
    if command -v fail2ban-client &>/dev/null; then
        info "Configuring fail2ban"
        cat > /etc/fail2ban/jail.local <<'F2BEOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 3
bantime = 7200
F2BEOF
        systemctl enable fail2ban >>"$LOG_FILE" 2>&1 || true
        systemctl restart fail2ban >>"$LOG_FILE" 2>&1 || true
        ok "fail2ban configured (SSH protection active)"
    else
        warn "fail2ban not available, skipping"
    fi

    success "Security hardening complete"
}

# ---------------------------------------------------------------------------
# Generate config.json
# ---------------------------------------------------------------------------
generate_config() {
    local domain="$1"
    local trigger_sni="$2"
    local fallbacks="$3"
    local mode="$4"
    local socks_host="$5"
    local socks_port="$6"
    local enable_fronting="$7"
    local enable_cloudflare="$8"
    local enable_mobile="$9"
    local carriers="${10}"
    local myip

    myip=$(hostname -I | awk '{print $1}')

    info "Generating configuration..."

    # Start with base config
    local config
    config=$(jq -n \
        --arg host "$domain" \
        --arg myip "$myip" \
        '{
            "host": $host,
            "reload_interval_minutes": 1,
            "domains": {},
            "trigger_domains": [],
            "domain_rotation_minutes": 60,
            "cloudflare": { "enabled": false, "zone_id": "", "api_token": "" },
            "domain_fronting": { "enabled": false, "front_host": "", "front_sni": "", "upstream_host": "" },
            "bypass_settings": {
                "enabled": false,
                "mode": "shape",
                "trigger_sni": "",
                "tunnel_path": "",
                "padding_size_range": [10, 100],
                "delay_ms_range": [5, 200],
                "detect_mobile_networks": false,
                "geoip_db_path": "",
                "mobile_carrier_names": [],
                "multiplexing": true,
                "idle_timeout_seconds": 120
            }
        }')

    # Build trigger domains list
    local trigger_domains_json
    trigger_domains_json=$(jq -n --arg primary "$trigger_sni" --arg fallbacks "$fallbacks" \
        '[$primary] + (if $fallbacks != "" then ($fallbacks | split(",") | map(select(. != "" | . != null))) else [] end)')

    # Enable bypass
    config=$(echo "$config" | jq \
        --arg trigger_sni "$trigger_sni" \
        --arg mode "$mode" \
        --arg tunnel_path "/wstunnel" \
        --argjson trigger_domains "$trigger_domains_json" \
        '.bypass_settings.enabled = true |
         .bypass_settings.trigger_sni = $trigger_sni |
         .bypass_settings.mode = $mode |
         .bypass_settings.tunnel_path = $tunnel_path |
         .trigger_domains = $trigger_domains')

    # Websocket mode extras
    if [[ "$mode" == "websocket" ]]; then
        config=$(echo "$config" | jq \
            --arg host "$socks_host" \
            --argjson port "$socks_port" \
            '.bypass_settings.socks_host = $host |
             .bypass_settings.socks_port = $port')
    fi

    # Domain fronting
    if [[ "$enable_fronting" == "true" ]]; then
        config=$(echo "$config" | jq \
            '.domain_fronting.enabled = true |
             .domain_fronting.front_host = "cdn.jsdelivr.net" |
             .domain_fronting.front_sni = "cdn.jsdelivr.net" |
             .domain_fronting.upstream_host = "'"$trigger_sni"'"')
    fi

    # Cloudflare
    if [[ "$enable_cloudflare" == "true" ]]; then
        config=$(echo "$config" | jq \
            '.cloudflare.enabled = true')
    fi

    # Mobile detection
    if [[ "$enable_mobile" == "true" ]]; then
        local carrier_json
        carrier_json=$(echo "$carriers" | tr ',' '\n' | jq -R . | jq -s .)
        config=$(echo "$config" | jq \
            --argjson carriers "$carrier_json" \
            --arg geoip_path "$INSTALL_DIR/GeoLite2-ASN.mmdb" \
            '.bypass_settings.detect_mobile_networks = true |
             .bypass_settings.geoip_db_path = $geoip_path |
             .bypass_settings.mobile_carrier_names = $carriers')
    fi

    echo "$config" | jq '.' > "$INSTALL_DIR/config.json"
    ok "Configuration generated"
}

# ---------------------------------------------------------------------------
# Main install function
# ---------------------------------------------------------------------------
do_install() {
    local domain=""
    local email=""
    local trigger_sni=""
    local fallbacks=""
    local mode="websocket"
    local secret=""
    local socks_host="127.0.0.1"
    local socks_port=1080
    local enable_fronting="false"
    local enable_cloudflare="false"
    local enable_mobile="false"
    local carriers="at&t,verizon,sprint,t-mobile,tigo,Digicel,bmobile,Claro"
    local skip_security="false"

    # Parse auto-install flags
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain)      domain="$2"; shift 2 ;;
            --email)       email="$2"; shift 2 ;;
            --trigger)     trigger_sni="$2"; shift 2 ;;
            --fallbacks)   fallbacks="$2"; shift 2 ;;
            --mode)        mode="$2"; shift 2 ;;
            --secret)      secret="$2"; shift 2 ;;
            --fronting)    enable_fronting="true"; shift ;;
            --cloudflare)  enable_cloudflare="true"; shift ;;
            --mobile-detect) enable_mobile="true"; shift ;;
            --carriers)    carriers="$2"; shift 2 ;;
            --skip-security) skip_security="true"; shift ;;
            --skip-firewall) SKIP_FIREWALL="true"; shift ;;
            *) error "Unknown flag: $1"; exit 1 ;;
        esac
    done

    # Interactive prompts if not provided via flags
    if [[ -z "$domain" ]]; then
        clear
        print_banner
        echo -e "  ${BOLD}Let's set up your SmartSNI server.${NC}\n"
        read -p "  Domain name (e.g., home.example.com): " domain
        [[ -z "$domain" ]] && { error "Domain is required"; exit 1; }

        read -p "  Email for Let's Encrypt certificates [optional, Enter to skip]: " email

        read -p "  Bypass mode [1] websocket (recommended)  [2] shape: " mode_choice
        [[ "$mode_choice" == "2" ]] && mode="shape"

        if [[ "$mode" == "websocket" ]]; then
            read -p "  SOCKS5 proxy host [default: 127.0.0.1]: " socks_host_input
            [[ -n "$socks_host_input" ]] && socks_host="$socks_host_input"

            read -p "  SOCKS5 proxy port [default: 1080]: " socks_port_input
            [[ -n "$socks_port_input" ]] && socks_port="$socks_port_input"
        fi

        # Auto-generate trigger domain
        trigger_sni="bypass.${domain}"
        read -p "  Trigger domain [default: $trigger_sni]: " trigger_input
        [[ -n "$trigger_input" ]] && trigger_sni="$trigger_input"

        read -p "  Fallback trigger domains, comma-separated [optional]: " fallbacks

        echo ""
        read -p "  Enable mobile carrier detection? (y/n) [y]: " mobile_input
        [[ "$mobile_input" != "n" && "$mobile_input" != "N" ]] && enable_mobile="true"
    else
        print_banner
        info "Auto-install mode"
        [[ -z "$trigger_sni" ]] && trigger_sni="bypass.${domain}"
    fi

    # Generate secret if not provided
    if [[ -z "$secret" ]]; then
        secret=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
    fi

    DOMAIN="$domain"

    # Show summary
    echo ""
    step "Installation Summary"
    echo -e "  ${BOLD}Domain:${NC}         $domain"
    echo -e "  ${BOLD}Trigger SNI:${NC}    $trigger_sni"
    echo -e "  ${BOLD}Mode:${NC}           $mode"
    echo -e "  ${BOLD}Multiplexing:${NC}   enabled"
    echo -e "  ${BOLD}Secret:${NC}         ${secret:0:8}...${secret: -4}"
    echo -e "  ${BOLD}Install dir:${NC}    $INSTALL_DIR"
    echo ""

    if [[ -z "${DOMAIN:-}" ]] || [[ -t 0 ]]; then
        read -p "  Continue with installation? (y/n): " confirm
        [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { info "Installation cancelled."; exit 0; }
    fi

    # Start installation
    echo ""
    step "Starting installation"
    echo "  Log file: $LOG_FILE"
    echo ""

    # 1. System requirements
    detect_distro
    check_system_requirements

    # 2. Install packages
    install_dependencies

    # 3. Pre-flight checks
    preflight_checks

    # 4. Copy files
    step "Deploying application files"
    mkdir -p "$INSTALL_DIR"
    SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
    cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
    ok "Files copied to $INSTALL_DIR"

    # 5. Generate secret
    step "Setting up authentication"
    echo "SMARTSNI_SECRET=$secret" > "$INSTALL_DIR/.env"
    chmod 600 "$INSTALL_DIR/.env"
    chown root:root "$INSTALL_DIR/.env"
    ok "Secret stored in $INSTALL_DIR/.env"

    # 6. SSL Certificate
    step "Obtaining SSL certificate"
    systemctl stop nginx 2>/dev/null || true
    systemctl stop sni 2>/dev/null || true

    local cert_email_flag=""
    if [[ -n "$email" ]]; then
        cert_email_flag="--email $email"
    else
        cert_email_flag="--register-unsafely-without-email"
    fi

    if certbot certonly --standalone -d "$domain" $cert_email_flag --non-interactive --agree-tos >>"$LOG_FILE" 2>&1; then
        ok "SSL certificate obtained for $domain"
    else
        error "Certbot failed. Ensure DNS points to this server and port 80 is accessible."
        error "You can retry later with: certbot certonly --standalone -d $domain"
        exit 1
    fi

    # 7. Generate config
    generate_config "$domain" "$trigger_sni" "$fallbacks" "$mode" "$socks_host" "$socks_port" \
        "$enable_fronting" "$enable_cloudflare" "$enable_mobile" "$carriers"

    # 8. Download GeoIP database if mobile detection enabled
    if [[ "$enable_mobile" == "true" ]]; then
        step "Downloading GeoIP database"
        if wget -q -O "$INSTALL_DIR/GeoLite2-ASN.mmdb" \
            "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb" >>"$LOG_FILE" 2>&1; then
            ok "GeoLite2-ASN database downloaded"
        else
            warn "GeoIP download failed. Mobile detection will be disabled."
        fi
    fi

    # 9. Python environment
    step "Setting up Python environment"
    cd "$INSTALL_DIR"
    python3 -m venv venv >>"$LOG_FILE" 2>&1
    source venv/bin/activate
    pip install --upgrade pip >>"$LOG_FILE" 2>&1
    pip install -r requirements.txt >>"$LOG_FILE" 2>&1
    deactivate
    ok "Python venv ready with $(wc -l < requirements.txt) packages"

    # 10. Create service user
    step "Creating service user"
    useradd --system --shell /usr/sbin/nologin --home-dir "$INSTALL_DIR" smart-sni 2>/dev/null || true
    setcap cap_net_bind_service=+ep "$INSTALL_DIR/venv/bin/python3"
    chown -R smart-sni:smart-sni "$INSTALL_DIR"
    ok "User 'smart-sni' configured"

    # 11. Systemd service
    step "Creating systemd service"
    cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOL
[Unit]
Description=SmartSNI DPI Bypass Proxy
After=network.target
Wants=network-online.target

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
NoNewPrivileges=true
TimeoutStopSec=30
LimitNOFILE=65536

# Security sandboxing
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOL
    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME} >>"$LOG_FILE" 2>&1
    ok "Systemd service created"

    # 12. Security hardening
    if [[ "$skip_security" != "true" ]]; then
        harden_security
    else
        info "Skipping security hardening (--skip-security)"
    fi

    # 13. Start service
    step "Starting SmartSNI service"
    systemctl start ${SERVICE_NAME}
    sleep 2

    if systemctl is-active --quiet ${SERVICE_NAME}; then
        ok "SmartSNI service is running"
    else
        error "Service failed to start. Checking logs..."
        journalctl -u ${SERVICE_NAME} --no-pager -n 20
        exit 1
    fi

    # 14. Certbot auto-renewal
    step "Setting up certificate auto-renewal"
    (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --deploy-hook 'systemctl restart ${SERVICE_NAME}'") | sort -u | crontab -
    ok "Auto-renewal cron installed (daily at 3 AM)"

    # 15. Health check
    step "Running health checks"
    do_health_check

    # Done!
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          Installation Complete!                      ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Service:${NC}    systemctl status ${SERVICE_NAME}"
    echo -e "  ${BOLD}Logs:${NC}       journalctl -u ${SERVICE_NAME} -f"
    echo -e "  ${BOLD}Config:${NC}     $INSTALL_DIR/config.json"
    echo -e "  ${BOLD}Secret:${NC}     $INSTALL_DIR/.env"
    echo -e "  ${BOLD}Domain:${NC}     $domain"
    echo -e "  ${BOLD}Secret:${NC}     ${secret:0:8}...${secret: -4}"
    echo ""
    echo -e "  ${DIM}Android client: Set server host to $domain${NC}"
    echo -e "  ${DIM}Android client: Set trigger SNIs to $trigger_sni${NC}"
    echo -e "  ${DIM}Android client: Set auth secret to the full secret above${NC}"
    echo ""
}

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
do_health_check() {
    local ok_count=0
    local total=4

    # Service running
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        ok "Service is running"
        ((ok_count++))
    else
        fail "Service is NOT running"
    fi

    # Port 443 listening
    if ss -tlnp | grep -q ':443 '; then
        ok "Port 443 is listening"
        ((ok_count++))
    else
        fail "Port 443 is NOT listening"
    fi

    # Port 853 listening (DoT)
    if ss -tlnp | grep -q ':853 '; then
        ok "Port 853 (DoT) is listening"
        ((ok_count++))
    else
        fail "Port 853 (DoT) is NOT listening"
    fi

    # TLS certificate valid
    if [[ -d "/etc/letsencrypt/live/${DOMAIN:-}" ]]; then
        local expiry
        expiry=$(openssl x509 -enddate -noout -in "/etc/letsencrypt/live/${DOMAIN:-}/fullchain.pem" 2>/dev/null | cut -d= -f2)
        if [[ -n "$expiry" ]]; then
            ok "TLS certificate valid until: $expiry"
            ((ok_count++))
        else
            fail "TLS certificate check failed"
        fi
    else
        fail "No TLS certificate found for ${DOMAIN:-unknown}"
    fi

    echo ""
    info "Health check: $ok_count/$total passed"
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
do_uninstall() {
    print_banner
    step "Uninstalling SmartSNI"

    if [[ -t 0 ]]; then
        read -p "  This will remove ALL SmartSNI files. Continue? (y/n): " confirm
        [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { info "Uninstall cancelled."; exit 0; }
    fi

    # Stop service
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    systemctl disable ${SERVICE_NAME} 2>/dev/null || true
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    systemctl daemon-reload
    ok "Service removed"

    # Remove certbot cron
    crontab -l 2>/dev/null | grep -v "certbot renew" | crontab - 2>/dev/null || true
    ok "Certbot cron removed"

    # Remove fail2ban jail
    rm -f /etc/fail2ban/jail.local 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true
    ok "fail2ban config removed"

    # Remove sysctl config
    rm -f /etc/sysctl.d/99-smartsni-security.conf
    sysctl --system >>"$LOG_FILE" 2>&1 || true
    ok "Kernel parameters restored"

    # Remove UFW rules
    if command -v ufw &>/dev/null; then
        ufw delete allow 443/tcp 2>/dev/null || true
        ufw delete allow 853/tcp 2>/dev/null || true
        ok "Firewall rules removed"
    fi

    # Remove files
    rm -rf "$INSTALL_DIR"
    ok "Application files removed"

    # Remove user
    userdel smart-sni 2>/dev/null || true
    ok "Service user removed"

    echo ""
    success "SmartSNI has been completely uninstalled."
    echo -e "  ${DIM}Note: SSL certificates were NOT removed.${NC}"
    echo -e "  ${DIM}Remove them with: sudo certbot delete --cert-name ${DOMAIN:-your-domain}${NC}"
}

# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------
do_update() {
    print_banner
    step "Updating SmartSNI"

    if [[ ! -d "$INSTALL_DIR" ]]; then
        error "SmartSNI is not installed at $INSTALL_DIR"
        exit 1
    fi

    SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

    info "Backing up config..."
    cp "$INSTALL_DIR/config.json" "/tmp/config.json.bak.$(date +%s)"
    cp "$INSTALL_DIR/.env" "/tmp/.env.bak.$(date +%s)" 2>/dev/null || true

    info "Copying updated files..."
    cp -r "$SCRIPT_DIR"/*.py "$INSTALL_DIR/"
    cp -r "$SCRIPT_DIR"/requirements.txt "$INSTALL_DIR/"
    ok "Files updated"

    info "Updating Python packages..."
    cd "$INSTALL_DIR"
    source venv/bin/activate
    pip install --upgrade pip >>"$LOG_FILE" 2>&1
    pip install -r requirements.txt >>"$LOG_FILE" 2>&1
    deactivate
    ok "Packages updated"

    chown -R smart-sni:smart-sni "$INSTALL_DIR"

    info "Restarting service..."
    systemctl restart ${SERVICE_NAME}
    sleep 2

    if systemctl is-active --quiet ${SERVICE_NAME}; then
        success "SmartSNI updated and running!"
    else
        error "Service failed after update. Restoring config..."
        cp "/tmp/config.json.bak."* "$INSTALL_DIR/config.json" 2>/dev/null || true
        systemctl start ${SERVICE_NAME}
    fi
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------
do_status() {
    print_banner
    echo ""

    # Service status
    if systemctl is-active --quiet ${SERVICE_NAME} 2>/dev/null; then
        echo -e "  ${GREEN}●${NC} Service: ${GREEN}running${NC}"
    else
        echo -e "  ${RED}●${NC} Service: ${RED}stopped${NC}"
    fi

    # Port status
    echo ""
    echo -e "  ${BOLD}Ports:${NC}"
    for port in 443 853; do
        if ss -tlnp | grep -q ":${port} "; then
            echo -e "    ${GREEN}●${NC} $port: listening"
        else
            echo -e "    ${RED}●${NC} $port: not listening"
        fi
    done

    # Certificate status
    echo ""
    echo -e "  ${BOLD}SSL Certificate:${NC}"
    if [[ -d "/etc/letsencrypt/live" ]]; then
        for cert_dir in /etc/letsencrypt/live/*/; do
            local cert_name
            cert_name=$(basename "$cert_dir")
            local expiry
            expiry=$(openssl x509 -enddate -noout -in "${cert_dir}fullchain.pem" 2>/dev/null | cut -d= -f2)
            if [[ -n "$expiry" ]]; then
                echo -e "    ${GREEN}●${NC} $cert_name: expires $expiry"
            fi
        done
    else
        echo -e "    ${YELLOW}●${NC} No certificates found"
    fi

    # Firewall status
    echo ""
    echo -e "  ${BOLD}Firewall:${NC}"
    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1)
        echo -e "    ${GREEN}●${NC} UFW: $ufw_status"
    else
        echo -e "    ${YELLOW}●${NC} UFW: not installed"
    fi

    # Config
    echo ""
    if [[ -f "$INSTALL_DIR/config.json" ]]; then
        local host
        host=$(jq -r '.host // "unknown"' "$INSTALL_DIR/config.json" 2>/dev/null)
        local mode
        mode=$(jq -r '.bypass_settings.mode // "unknown"' "$INSTALL_DIR/config.json" 2>/dev/null)
        local mux
        mux=$(jq -r '.bypass_settings.multiplexing // false' "$INSTALL_DIR/config.json" 2>/dev/null)
        echo -e "  ${BOLD}Config:${NC}"
        echo -e "    Host:         $host"
        echo -e "    Mode:         $mode"
        echo -e "    Multiplexing: $mux"
    fi
}

# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------
main() {
    LOG_FILE=$(mktemp /tmp/smartsni-install.XXXXXX.log)

    if [[ $# -gt 0 ]]; then
        case "$1" in
            --uninstall|-u)
                check_root
                do_uninstall
                ;;
            --status|-s)
                do_status
                ;;
            --update)
                check_root
                do_update
                ;;
            --logs|-l)
                journalctl -u ${SERVICE_NAME} -f
                ;;
            --health)
                DOMAIN=$(jq -r '.host // ""' "$INSTALL_DIR/config.json" 2>/dev/null)
                do_health_check
                ;;
            --help|-h)
                print_banner
                echo -e "  ${BOLD}Usage:${NC}"
                echo "    sudo bash install.sh                     Interactive install"
                echo "    sudo bash install.sh --domain example.com Auto-install"
                echo "    sudo bash install.sh --uninstall         Remove SmartSNI"
                echo "    sudo bash install.sh --update            Update to latest"
                echo "    sudo bash install.sh --status            Check status"
                echo "    sudo bash install.sh --logs              View live logs"
                echo "    sudo bash install.sh --health            Run health check"
                echo ""
                echo -e "  ${BOLD}Auto-install flags:${NC}"
                echo "    --domain DOMAIN        Server domain (required)"
                echo "    --email EMAIL          Let's Encrypt email"
                echo "    --trigger DOMAIN       Trigger SNI (default: bypass.DOMAIN)"
                echo "    --fallbacks LIST       Fallback domains (comma-sep)"
                echo "    --mode websocket|shape Bypass mode (default: websocket)"
                echo "    --secret SECRET        Auth secret (auto-generated)"
                echo "    --fronting             Enable domain fronting"
                echo "    --cloudflare           Enable Cloudflare"
                echo "    --mobile-detect        Enable carrier detection"
                echo "    --skip-security        Skip security hardening"
                echo "    --skip-firewall        Skip firewall setup"
                ;;
            --domain|--email|--trigger|--fallbacks|--mode|--secret|--carriers)
                # Auto-install flags - pass everything to do_install
                check_root
                do_install "$@"
                ;;
            --fronting|--cloudflare|--mobile-detect|--skip-security|--skip-firewall)
                # Boolean flags - pass everything to do_install
                check_root
                do_install "$@"
                ;;
            --*)
                # Any other --flag: check if it looks like an auto-install flag
                # by scanning all arguments for --domain
                if echo "$@" | grep -q -- '--domain'; then
                    check_root
                    do_install "$@"
                else
                    error "Unknown flag: $1 (use --help for usage)"
                    exit 1
                fi
                ;;
        esac
        return
    fi

    # Interactive menu
    check_root
    clear
    print_banner
    echo -e "  ${BOLD}Select an option:${NC}\n"
    echo -e "    ${CYAN}1)${NC} Install SmartSNI"
    echo -e "    ${CYAN}2)${NC} Uninstall"
    echo -e "    ${CYAN}3)${NC} Update"
    echo -e "    ${CYAN}4)${NC} Check Status"
    echo -e "    ${CYAN}5)${NC} View Logs"
    echo -e "    ${CYAN}6)${NC} Health Check"
    echo -e "    ${CYAN}0)${NC} Exit"
    echo ""

    local status_str=""
    if systemctl is-active --quiet ${SERVICE_NAME} 2>/dev/null; then
        status_str="${GREEN}[Running]${NC}"
    else
        status_str="${RED}[Stopped]${NC}"
    fi
    echo -e "  Status: $status_str"
    echo ""

    read -p "  Choice: " choice
    case "$choice" in
        1) do_install ;;
        2) do_uninstall ;;
        3) do_update ;;
        4) do_status ;;
        5) journalctl -u ${SERVICE_NAME} -f ;;
        6) DOMAIN=$(jq -r '.host // ""' "$INSTALL_DIR/config.json" 2>/dev/null); do_health_check ;;
        0) exit 0 ;;
        *) error "Invalid choice"; exit 1 ;;
    esac
}

main "$@"
