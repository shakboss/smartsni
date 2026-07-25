#!/bin/bash

# --- Pre-flight Checks ---
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
INSTALL_DIR="/opt/smartSNI"

detect_distribution() {
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        pm="apt"
        [ "${ID}" = "centos" ] && pm="yum"
        [ "${ID}" = "fedora" ] && pm="dnf"
    else
        echo "Unsupported distribution!"
        exit 1
    fi
}

install_dependencies() {
    detect_distribution
    $pm update -y
    local packages=("nginx" "git" "jq" "certbot" "python3-certbot-nginx" "python3-pip" "python3-venv")
    if [[ "$pm" == "apt" ]]; then
        packages+=("libcap2-bin")
    elif [[ "$pm" == "yum" || "$pm" == "dnf" ]]; then
        packages+=("libcap")
    fi
    
    is_installed() {
        if [[ "$pm" == "apt" ]]; then
            dpkg -s "$1" &> /dev/null
        elif [[ "$pm" == "yum" || "$pm" == "dnf" ]]; then
            rpm -q "$1" &> /dev/null
        fi
    }

    for package in "${packages[@]}"; do
        if ! is_installed "$package"; then
            echo "$package is not installed. Installing..."
            $pm install -y "$package"
        else
            echo "$package is already installed."
        fi
    done
}

install() {
    if systemctl is-active --quiet sni.service; then
        echo "The SNI service is already installed and active."
        exit 0
    else
        install_dependencies
        myip=$(hostname -I | awk '{print $1}')
        echo "Copying project files to $INSTALL_DIR..."
        mkdir -p "$INSTALL_DIR"
        cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
        
        clear
        read -p "Enter your domain: " domain
        read -p "Enter the domain names separated by commas (example: google,youtube): " site_list
        IFS=',' read -ra sites <<< "$site_list"
        
        new_domains="{"
        for ((i = 0; i < ${#sites[@]}; i++)); do
            new_domains+="\"${sites[i]}\": \"$myip\""
            if [ $i -lt $((${#sites[@]}-1)) ]; then
                new_domains+=", "
            fi
        done
        new_domains+="}"
        
        json_content="{ \"host\": \"$domain\", \"domains\": $new_domains }"

        echo "$json_content" | jq '.' > "$INSTALL_DIR/config.json"

        read -p "Do you want to enable advanced DPI bypass features? (y/n): " enable_bypass
        if [[ "$enable_bypass" == "y" || "$enable_bypass" == "Y" ]]; then
            default_trigger="bypass.$domain"
            read -p "Enter the primary trigger domain (e.g., $default_trigger): " trigger_sni
            [ -z "$trigger_sni" ] && trigger_sni=$default_trigger

            read -p "Enter fallback trigger domains, comma-separated (e.g., cdn.$domain,mail2.$domain) [optional]: " fallback_domains

            trigger_domains_json=$(jq -n --arg primary "$trigger_sni" --arg fallbacks "$fallback_domains" \
                '[$primary] + (if $fallbacks != "" then ($fallbacks | split(",") | map(select(. != ""))) else [] end)')

            read -p "Domain rotation interval in minutes [default: 60]: " rotation_minutes
            [ -z "$rotation_minutes" ] && rotation_minutes=60

            read -p "Choose bypass mode [1] shape (default) [2] websocket: " bypass_mode_choice
            local bypass_mode="shape"
            local tunnel_path=""
            if [[ "$bypass_mode_choice" == "2" ]]; then
                bypass_mode="websocket"
                read -p "Enter the WebSocket tunnel path (e.g., /wstunnel): " tunnel_path
                [ -z "$tunnel_path" ] && tunnel_path="/wstunnel"

                read -p "Enter the SOCKS5 proxy host [default: 127.0.0.1]: " socks_host
                [ -z "$socks_host" ] && socks_host="127.0.0.1"

                read -p "Enter the SOCKS5 proxy port [default: 1080]: " socks_port
                [ -z "$socks_port" ] && socks_port=1080

                # Generate a random secret for authentication
                bypass_secret=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
                read -p "Enter a secret key for bypass auth [default: $bypass_secret]: " user_secret
                [ ! -z "$user_secret" ] && bypass_secret=$user_secret
            fi

            bypass_config=$(jq -n \
                --argjson trigger_domains "$trigger_domains_json" \
                --argjson rotation "$rotation_minutes" \
                --arg trigger_sni "$trigger_sni" \
                --arg mode "$bypass_mode" \
                --arg tunnel_path "$tunnel_path" \
                '{ "trigger_domains": $trigger_domains, "domain_rotation_minutes": $rotation, "bypass_settings": { "enabled": true, "mode": $mode, "trigger_sni": $trigger_sni, "tunnel_path": $tunnel_path, "padding_size_range": [10, 100], "delay_ms_range": [5, 20] } }')
            if [[ "$bypass_mode" == "websocket" ]]; then
                bypass_config=$(echo "$bypass_config" | jq --arg host "$socks_host" --argjson port "$socks_port" --arg secret "$bypass_secret" '.bypass_settings += { "socks_host": $host, "socks_port": $port, "bypass_secret": $secret }')
            fi
            jq --argjson bypass "$bypass_config" '. + $bypass' "$INSTALL_DIR/config.json" > "$INSTALL_DIR/config.tmp" && mv "$INSTALL_DIR/config.tmp" "$INSTALL_DIR/config.json"

            echo "Bypass features enabled with trigger domains: $trigger_sni"
            echo "Domain rotation interval: ${rotation_minutes} minutes"
            echo "Bypass mode set to: $bypass_mode"
            if [[ "$bypass_mode" == "websocket" ]]; then
                echo "Your WebSocket bypass secret is: $bypass_secret"
            fi

            read -p "Do you want to enable domain fronting to hide the real server behind a CDN? (y/n): " enable_fronting
            if [[ "$enable_fronting" == "y" || "$enable_fronting" == "Y" ]]; then
                default_front_host="cdn.jsdelivr.net"
                read -p "Enter CDN front host [default: $default_front_host]: " front_host
                [ -z "$front_host" ] && front_host=$default_front_host

                read -p "Enter CDN TLS SNI [default: $front_host]: " front_sni
                [ -z "$front_sni" ] && front_sni=$front_host

                read -p "Enter upstream host (your server domain) [default: $trigger_sni]: " upstream_host
                [ -z "$upstream_host" ] && upstream_host=$trigger_sni

                fronting_config=$(jq -n \
                    --arg front_host "$front_host" \
                    --arg front_sni "$front_sni" \
                    --arg upstream "$upstream_host" \
                    '{ "domain_fronting": { "enabled": true, "front_host": $front_host, "front_sni": $front_sni, "upstream_host": $upstream } }')

                jq --argjson front "$fronting_config" '. + $front' "$INSTALL_DIR/config.json" > "$INSTALL_DIR/config.tmp" && mv "$INSTALL_DIR/config.tmp" "$INSTALL_DIR/config.json"

                echo "Domain fronting enabled: TLS SNI=$front_sni, Host=$upstream_host"
            fi

            read -p "Do you want to enable Cloudflare proxy support? (y/n): " enable_cf
            if [[ "$enable_cf" == "y" || "$enable_cf" == "Y" ]]; then
                read -p "Enter Cloudflare Zone ID: " cf_zone
                read -p "Enter Cloudflare API Token: " cf_token

                cf_config=$(jq -n \
                    --arg zone "$cf_zone" \
                    --arg token "$cf_token" \
                    '{ "cloudflare": { "enabled": true, "zone_id": $zone, "api_token": $token } }')

                jq --argjson cf "$cf_config" '. + $cf' "$INSTALL_DIR/config.json" > "$INSTALL_DIR/config.tmp" && mv "$INSTALL_DIR/config.tmp" "$INSTALL_DIR/config.json"

                echo "Cloudflare proxy support enabled."
            fi

            read -p "Do you want to enable automatic bypass for mobile networks? (y/n): " enable_mobile_detect
            if [[ "$enable_mobile_detect" == "y" || "$enable_mobile_detect" == "Y" ]]; then
                echo "Downloading GeoLite2-ASN database..."
                # Using a reliable public mirror for the database
                wget -O "$INSTALL_DIR/GeoLite2-ASN.mmdb" https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb
                
                default_carriers="at&t,verizon,sprint,t-mobile"
                read -p "Enter mobile carrier names to detect, separated by commas (default: $default_carriers): " carrier_list
                [ -z "$carrier_list" ] && carrier_list=$default_carriers

                # Convert comma-separated string to a JSON array string
                carrier_json_array=$(echo "$carrier_list" | tr ',' '\n' | jq -R . | jq -s .)

                mobile_config=$(jq -n \
                    --argjson carriers "$carrier_json_array" \
                    "{ \"bypass_settings\": { \"detect_mobile_networks\": true, \"geoip_db_path\": \"$INSTALL_DIR/GeoLite2-ASN.mmdb\", \"mobile_carrier_names\": \$carriers } }")

                jq -s '.[0] * .[1]' "$INSTALL_DIR/config.json" <(echo "$mobile_config") > "$INSTALL_DIR/config.tmp" && mv "$INSTALL_DIR/config.tmp" "$INSTALL_DIR/config.json"

                echo "Mobile network detection enabled."
            fi
        fi

        # Nginx is no longer needed as the Python app listens on 443 directly.
        # We just need it for the certbot challenge.
        echo "Stopping Nginx to obtain SSL certificate..."
        systemctl stop nginx || true # Ignore error if not running

        if ! certbot certonly --standalone -d "$domain" --register-unsafely-without-email --non-interactive --agree-tos; then
            echo "Certbot failed to obtain a certificate. Please check your domain and DNS settings."
            exit 1
        fi

        # --- Security Hardening: Create a dedicated user for the service ---
        useradd --system --shell /usr/sbin/nologin --home-dir "$INSTALL_DIR" smart-sni || echo "User smart-sni already exists."

        echo "Setting up Python environment..."
        cd "$INSTALL_DIR"
        python3 -m venv venv
        source venv/bin/activate
        pip install -r requirements.txt
        deactivate

        # Set the capability on the Python binary so it can bind to port 443
        setcap cap_net_bind_service=+ep "$INSTALL_DIR/venv/bin/python3"

        # Set final permissions
        chown -R smart-sni:smart-sni "$INSTALL_DIR"

        cat > /etc/systemd/system/sni.service <<EOL
[Unit]
Description=Smart SNI Service (Python)
After=network.target

[Service]
User=smart-sni
Group=smart-sni
WorkingDirectory=$INSTALL_DIR
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStart=$INSTALL_DIR/venv/bin/python main.py
Restart=always
RestartSec=3
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOL

        systemctl daemon-reload
        systemctl enable sni.service
        systemctl start sni.service

        if systemctl is-active --quiet sni.service; then
            echo "The SNI service is now active."
        else
            echo "The SNI service failed to start. Check logs with 'journalctl -u sni.service'"
        fi
    fi
}

uninstall() {
    if [ ! -f "/etc/systemd/system/sni.service" ]; then
        echo "The service is not installed."
        return
    fi
    systemctl stop sni.service
    systemctl disable sni.service
    rm /etc/systemd/system/sni.service
    rm -rf "$INSTALL_DIR"
    userdel smart-sni
    systemctl daemon-reload
    echo "Uninstallation completed successfully."
}

display_sites() {
    config_file="$INSTALL_DIR/config.json"
    if [ ! -f "$config_file" ]; then
        echo "Error: config.json not found. Please Install first."
    fi
    jq -r '.domains | keys[]' "$config_file"
}

check_status() {
    if systemctl is-active --quiet sni.service; then
        echo "[Service Is Active]"
    else
        echo "[Service Is Not Active]"
    fi
}

restart_service() {
    echo "Restarting the SNI service..."
    systemctl restart sni.service
    echo "Service restart command issued. Checking status:"
    sleep 1
    systemctl status sni.service
}

view_logs() {
    echo "Displaying live logs for sni.service. Press Ctrl+C to exit."
    journalctl -u sni.service -f
}


clear
echo "By --> Peyman * Github.com/Ptechgithub * "
echo "--*-* SMART SNI PROXY (Python Edition) *-*--"
echo ""
echo "Select an option:"
echo " 1) Install"
echo " 2) Uninstall"
echo " 3) Restart Service"
echo " 4) Check Status"
echo " 5) View Logs"
echo " 6) Show Sites (from config)"
echo " 0) Exit"
echo "----$(check_status)----"
read -p "Enter your choice: " choice
case "$choice" in
    1) install ;;
    2) uninstall ;;
    3) restart_service ;;
    4) systemctl status sni.service ;;
    5) view_logs ;;
    6) display_sites ;;
    0) exit ;;
    *) echo "Invalid choice." ;;
esac