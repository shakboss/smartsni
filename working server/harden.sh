#!/bin/bash
# ============================================================================
# SmartSNI Security Hardening Script
# ============================================================================
# Run separately after install: sudo bash harden.sh
# Removes with: sudo bash harden.sh --remove
# ============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}✔${NC} $*"; }
fail() { echo -e "  ${RED}✘${NC} $*"; }
info() { echo -e "  ${YELLOW}►${NC} $*"; }
step() { echo -e "\n${CYAN}${BOLD}── $*${NC}"; }

[[ "$(id -u)" -ne 0 ]] && { echo -e "${RED}Run with sudo${NC}"; exit 1; }

# --- Remove mode ---
if [[ "${1:-}" == "--remove" ]]; then
    echo -e "\n${YELLOW}Removing security hardening...${NC}"

    rm -f /etc/sysctl.d/99-smartsni-security.conf
    sysctl --system >/dev/null 2>&1 || true
    ok "Kernel params restored"

    if command -v ufw &>/dev/null; then
        ufw delete allow 443/tcp 2>/dev/null || true
        ufw delete allow 853/tcp 2>/dev/null || true
        ok "Firewall rules removed"
    fi

    rm -f /etc/fail2ban/jail.local 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true
    ok "fail2ban config removed"

    echo -e "\n${GREEN}✔ Hardening removed.${NC}"
    exit 0
fi

echo -e "\n${CYAN}${BOLD}SmartSNI Security Hardening${NC}\n"

# ==========================================================================
# 1. FIREWALL (UFW)
# ==========================================================================
step "1/4  Firewall (UFW)"

if command -v ufw &>/dev/null; then
    info "Configuring UFW..."
    ufw --force reset >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1

    # Find SSH port
    SSH_PORT=$(ss -tlnp | grep -oP ':\K\d+(?=.*sshd)' | head -1)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=22
    ufw allow "$SSH_PORT/tcp" comment "SSH" >/dev/null 2>&1
    ok "SSH port $SSH_PORT allowed"

    ufw allow 443/tcp comment "SmartSNI TLS" >/dev/null 2>&1
    ufw allow 853/tcp comment "SmartSNI DoT" >/dev/null 2>&1
    ok "Ports 443, 853 allowed"

    ufw --force enable >/dev/null 2>&1
    ok "UFW enabled"
else
    info "Installing UFW..."
    export DEBIAN_FRONTEND=noninteractive
    if command -v apt &>/dev/null; then
        apt install -y ufw >/dev/null 2>&1
    elif command -v dnf &>/dev/null; then
        dnf install -y ufw >/dev/null 2>&1
    elif command -v yum &>/dev/null; then
        yum install -y ufw >/dev/null 2>&1
    fi

    if command -v ufw &>/dev/null; then
        ufw --force reset >/dev/null 2>&1 || true
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        SSH_PORT=$(ss -tlnp | grep -oP ':\K\d+(?=.*sshd)' | head -1)
        [[ -z "$SSH_PORT" ]] && SSH_PORT=22
        ufw allow "$SSH_PORT/tcp" comment "SSH" >/dev/null 2>&1
        ufw allow 443/tcp comment "SmartSNI TLS" >/dev/null 2>&1
        ufw allow 853/tcp comment "SmartSNI DoT" >/dev/null 2>&1
        ufw --force enable >/dev/null 2>&1
        ok "UFW installed and enabled"
    else
        fail "Could not install UFW - install manually: apt install ufw"
    fi
fi

# ==========================================================================
# 2. KERNEL HARDENING (sysctl)
# ==========================================================================
step "2/4  Kernel Security"

cat > /etc/sysctl.d/99-smartsni-security.conf <<'EOF'
# Anti-spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Block redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block source routing
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

# Faster connection cleanup
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# More connections
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 4096

# TCP keepalive
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
EOF

sysctl -p /etc/sysctl.d/99-smartsni-security.conf >/dev/null 2>&1
ok "Kernel parameters applied"

# ==========================================================================
# 3. FAIL2BAN
# ==========================================================================
step "3/4  Fail2ban (SSH Protection)"

if ! command -v fail2ban-client &>/dev/null; then
    info "Installing fail2ban..."
    export DEBIAN_FRONTEND=noninteractive
    if command -v apt &>/dev/null; then
        apt install -y fail2ban >/dev/null 2>&1
    elif command -v dnf &>/dev/null; then
        dnf install -y fail2ban >/dev/null 2>&1
    elif command -v yum &>/dev/null; then
        yum install -y fail2ban >/dev/null 2>&1
    fi
fi

if command -v fail2ban-client &>/dev/null; then
    cat > /etc/fail2ban/jail.local <<'EOF'
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
EOF
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban >/dev/null 2>&1 || true
    ok "fail2ban active (3 retries = 2hr ban)"
else
    fail "Could not install fail2ban"
fi

# ==========================================================================
# 4. SSH HARDENING
# ==========================================================================
step "4/4  SSH Hardening"

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_BACKUP="/etc/ssh/sshd_config.bak.smartsni"

if [[ -f "$SSHD_CONFIG" ]] && [[ ! -f "$SSHD_BACKUP" ]]; then
    cp "$SSHD_CONFIG" "$SSHD_BACKUP"
    ok "SSH config backed up"
fi

# Apply hardening if not already applied
if ! grep -q "# SmartSNI hardening" "$SSHD_CONFIG" 2>/dev/null; then
    cat >> "$SSHD_CONFIG" <<'EOF'

# SmartSNI hardening
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
    systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1 || true
    ok "SSH hardened (key-only, no root password)"
    echo -e "  ${YELLOW}⚠ Make sure you have SSH key access before disconnecting!${NC}"
else
    ok "SSH already hardened"
fi

# ==========================================================================
# SUMMARY
# ==========================================================================
echo -e "\n${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Security Hardening Complete                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Applied:${NC}"
echo -e "    ✔ UFW firewall (deny all, allow SSH+443+853)"
echo -e "    ✔ Kernel hardening (SYN flood, redirects, spoofing)"
echo -e "    ✔ Fail2ban (SSH brute-force protection)"
echo -e "    ✔ SSH hardened (key-only auth)"
echo ""
echo -e "  ${YELLOW}Remove all hardening: sudo bash harden.sh --remove${NC}"
echo ""
