#!/bin/bash

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
        echo "Copying local project files to /root/smartSNI..."
        mkdir -p /root/smartSNI
        cp -r ./* /root/smartSNI/

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

        echo "$json_content" | jq '.' > /root/smartSNI/config.json

        read -p "Do you want to enable advanced DPI bypass features? (y/n): " enable_bypass
        if [[ "$enable_bypass" == "y" || "$enable_bypass" == "Y" ]]; then
            default_trigger="bypass.$domain"
            read -p "Enter the trigger domain for bypass (e.g., $default_trigger): " trigger_sni
            [ -z "$trigger_sni" ] && trigger_sni=$default_trigger

            read -p "Choose bypass mode [1] shape (default) [2] websocket: " bypass_mode_choice
            local bypass_mode="shape"
            local tunnel_path=""
            if [[ "$bypass_mode_choice" == "2" ]]; then
                bypass_mode="websocket"
                read -p "Enter the WebSocket tunnel path (e.g., /wstunnel): " tunnel_path
                [ -z "$tunnel_path" ] && tunnel_path="/wstunnel"
            fi

            bypass_config=$(jq -n \
                --arg trigger_sni "$trigger_sni" \
                --arg mode "$bypass_mode" \
                --arg tunnel_path "$tunnel_path" \
                '{ "bypass_settings": { "enabled": true, "mode": $mode, "trigger_sni": $trigger_sni, "tunnel_path": $tunnel_path, "padding_size_range": [10, 100], "delay_ms_range": [5, 20] } }')

            jq --argjson bypass "$bypass_config" '. + $bypass' /root/smartSNI/config.json > /root/smartSNI/config.tmp && mv /root/smartSNI/config.tmp /root/smartSNI/config.json

            echo "Bypass features enabled with trigger SNI: $trigger_sni"
            echo "Bypass mode set to: $bypass_mode"
        fi

        # Nginx is no longer needed as the Python app listens on 443 directly.
        # We just need it for the certbot challenge.
        echo "Stopping Nginx to obtain SSL certificate..."
        systemctl stop nginx

        certbot certonly --standalone -d "$domain" --register-unsafely-without-email --non-interactive --agree-tos

        echo "Setting up Python environment..."
        cd /root/smartSNI
        python3 -m venv venv
        source venv/bin/activate
        pip install -r requirements.txt
        deactivate

        cat > /etc/systemd/system/sni.service <<EOL
[Unit]
Description=Smart SNI Service (Python)
After=network.target

[Service]
User=root
WorkingDirectory=/root/smartSNI
ExecStart=/root/smartSNI/venv/bin/python main.py
Restart=always
RestartSec=3

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
    rm -rf /root/smartSNI
    systemctl daemon-reload
    echo "Uninstallation completed successfully."
}

display_sites() {
    config_file="/root/smartSNI/config.json"
    if [ -f "$config_file" ]; then
        echo "Current list of sites in $config_file:"
        jq -r '.domains | keys[]' "$config_file"
    else
        echo "Error: config.json not found. Please Install first."
    fi
}

check_status() {
    if systemctl is-active --quiet sni.service; then
        echo "[Service Is Active]"
    else
        echo "[Service Is Not Active]"
    fi
}


clear
echo "By --> Peyman * Github.com/Ptechgithub * "
echo "--*-* SMART SNI PROXY (Python Edition) *-*--"
echo ""
echo "Select an option:"
echo "1) Install"
echo "2) Uninstall"
echo "3) Show Sites"
echo "0) Exit"
echo "----$(check)----"
read -p "Enter your choice: " choice
case "$choice" in
    1) install ;;
    2) uninstall ;;
    3) display_sites ;;
    0) exit ;;
    *) echo "Invalid choice." ;;
esac