# Smart SNI and DNS Proxy Server

This is a multi-functional Python-based server that combines a DNS-over-HTTPS (DoH) server, a DNS-over-TLS (DoT) server, and a smart SNI proxy. The SNI proxy includes features designed to camouflage traffic and bypass restrictive networks and Deep Packet Inspection (DPI). It is built using modern asynchronous libraries (`asyncio`, `FastAPI`, `httpx`) for high performance.

## Features

- **DNS-over-HTTPS (DoH):** Accepts and processes DNS queries over HTTPS.
- **DNS-over-TLS (DoT):** Accepts and processes DNS queries over TLS.
- **Smart DPI Bypass:** Camouflages traffic using two modes:
  - **`shape`**: Adds random padding and delays to traffic packets.
  - **`websocket`**: Tunnels traffic over a standard WebSocket connection, mimicking real-time web traffic.
- **Custom Domain Handling:** Matches DNS queries to a list of specified domains and returns corresponding IP addresses.
- **SNI Proxy:** Proxies non-matching domains to their respective addresses.
- **Configurable & Hot-Reloadable:** Uses a `config.json` file that can be reloaded without restarting the server.

## How to Configure Your Server

Configuration is managed through the `config.json` file. The `install.sh` script will help you create a basic configuration, but you can edit it manually for more advanced setups.

Here is a full example of `config.json`:

```json
{
  "host": "your.host.com",
  "reload_interval_minutes": 1,
  "domains": {
    "google": "YOUR_SERVER_IP",
    "youtube": "YOUR_SERVER_IP"
  },
  "bypass_settings": {
    "enabled": true,
    "mode": "websocket",
    "trigger_sni": "bypass.your.host.com",
    "tunnel_path": "/wstunnel",
    "detect_mobile_networks": true,
    "geoip_db_path": "/root/smartSNI/GeoLite2-ASN.mmdb",
    "mobile_carrier_names": ["at&t", "verizon", "sprint", "t-mobile"]
  }
}
```

Replace the IP addresses with your server's public IP to ensure transparent proxying(Here it's 1.2.3.4).\
\
You can use this code to proxy all domains(its not recommended)

```json
{
  "host": "your.host.com",
  "domains": {
    ".": "1.2.3.4"
  }
}
```

## TLS Certificates

The server requires TLS certificates to function. The `install.sh` script handles this automatically using Certbot and Let's Encrypt. Certificates are expected at `/etc/letsencrypt/live/your.host.com/`.


## Manual Setup

1. Download the project files and navigate into the project directory on your server.
2. To run the interactive installer, execute: `bash install.sh`

## Using the WebSocket Client

To use the `websocket` bypass mode, you can use the provided `client.sh` wrapper script, which simplifies running the `smart_client.py`.

### 1. Setup the Client

On your local machine (not the server):

1.  **Edit `client.sh`**: Open the `client.sh` script and replace the placeholder values for `SERVER_IP` and `TRIGGER_SNI` with your actual server details.
2.  **Make it Executable**:
    ```bash
    chmod +x client.sh
    ```
3.  **Install Dependencies**: The script will automatically prompt you to install dependencies on its first run if they are missing. You can also do it manually:
    ```bash
    pip install -r client_requirements.txt
    ```

### 2. Run the Client

The script tunnels your terminal's standard input/output through the server.

**Example: Making an HTTP request to `example.com` through the tunnel:**

```bash
echo -e "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" | ./client.sh example.com:80
```

## Credits

Special thanks to Peyman for the auto install script.
