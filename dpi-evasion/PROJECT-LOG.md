# DPI Evasion Relay — Project Log & Setup Guide

> A production-grade DPI (Deep Packet Inspection) evasion relay system built in Go,
> designed to bypass Digicel and bmobile network censorship in Trinidad and Tobago.

---

## Table of Contents

1. [Development Log](#development-log)
2. [What This System Does](#what-this-system-does)
3. [Architecture Overview](#architecture-overview)
4. [File Reference](#file-reference)
5. [Server Setup (VPS)](#server-setup-vps)
6. [Client Setup (Termux/Android)](#client-setup-termuxandroid)
7. [Configuration Reference](#configuration-reference)
8. [How the DPI Evasion Works](#how-the-dpi-evasion-works)

---

## Development Log

### Phase 1 — Initial Plan (Node.js → Go)

Started with a Node.js plan for a DPI evasion relay. After analysis, the language was
switched to **Go** for these reasons:

- Goroutines for concurrent connection handling (thousands of parallel relays)
- Single static binary deployment (no runtime dependencies)
- Lower memory footprint (~5MB vs ~50MB Node.js)
- TLS/crypto primitives in the standard library
- ~10x faster XOR operations for payload obfuscation

### Phase 2 — Base Server (`server.go`)

Built the main HTTPS server with WebSocket relay:

- TLS 1.2+ server with modern cipher suites (AES-GCM, ChaCha20-Poly1305, ECDHE)
- WebSocket upgrade on `/wstunnel` path
- Binary framing protocol: `[type:1][stream_id:4][length:4][payload]`
- Frame types: NEW_STREAM (0x01), DATA (0x02), CLOSE (0x03), KEEPALIVE (0x04), PADDING (0x05)
- Bidirectional relay between WebSocket and TCP target
- Fake frame injection to obscure real traffic patterns
- Random padding on data frames (configurable min/max bytes)
- Bimodal delay: 80% fast (<5ms), 20% slow (50-500ms) mimics Chrome
- Session rotation every 30 minutes (force reconnection)
- Per-IP sliding-window rate limiting (10 req/60s default)
- Optional Bearer token authentication
- Cover website: "FastCDN" — full CDN marketing page served at `/`
- `/health` returns 204, `/api/v1/status` returns JSON stats
- Self-signed cert fallback if Let's Encrypt certs not found

### Phase 3 — Library Packages (`lib/`)

**`lib/protocol.go`** — Binary framing:
- `ParseFrame(data)` — parse raw bytes into Frame struct
- `BuildFrame(type, streamID, payload)` — serialize frame
- `ParseStreamPayload(payload)` — extract host + port from NEW_STREAM
- `BuildStreamPayload(host, port)` — build NEW_STREAM payload

**`lib/obfuscation.go`** — Traffic obfuscation:
- `AddPadding(data, min, max)` — prepend random padding bytes
- `StripPadding(data)` — remove padding, return inner payload
- `BimodalDelay(minMs, maxMs)` — Chrome-like delay distribution
- `GenerateFakePayload(min, max)` — realistic JSON payloads:
  - `video_stats` (views, bitrate, buffer)
  - `chat_message` (username, text, timestamp)
  - `heartbeat` (CPU, memory, uptime)
  - `stream_event` (type, quality, latency)
  - Random binary fallback
- `FakeFrameScheduler` — goroutine that sends fake frames on a timer

**`lib/fronting.go`** — Domain fronting config:
- `FrontingConfig` struct with frontHost, frontSni, allowedOrigins
- `ValidateFronting(config)` — validate configuration
- `IsAllowedOrigin(origin, config)` — check CORS origin

**`lib/shadowtls.go`** — ShadowTLS protocol (most complex):
- Raw TLS record parsing: `ReadTLSRecord`, `WriteTLSRecord`
- SNI extraction from ClientHello: `ExtractSNI`
- ServerRandom extraction from ServerHello: `ExtractServerRandom`
- XOR key derivation: `DeriveXORKey(password, serverRandom)` → `SHA256(password || serverRandom)`
- XOR stream cipher: `XORCrypt(data, key)` — repeating XOR with key
- HMAC-SHA256 authentication: `ComputeAuthHash(password, clientRandom, serverRandom)`
- Constant-time auth verification: `VerifyAuth`
- Target parsing from auth payload: `ParseTargetFromAuth`
- TLS alert sending: `SendTLSAlert`
- Full handshake proxy: `proxyFullHandshake` — forwards ClientHello to real server, relays ServerHello + Finished back
- `ShadowTLSServer` struct — manages listener, config, connections

### Phase 4 — Cert Utility (`certutil.go`)

- Generates ECDSA P-256 self-signed certificates
- Used automatically when Let's Encrypt certs are not found
- Subject: `O=FastCDN Inc., CN=<domain>`

### Phase 5 — Client (`cmd/client/`)

**`cmd/client/main.go`** — Entry point:
- Loads config from `client-config.json`
- Creates transport (ShadowTLS or WebSocket)
- Starts SOCKS5 listener on 127.0.0.1:1080
- Accepts connections, reads SOCKS5 CONNECT request
- Connects to relay server via transport
- Bidirectional relay between local app ↔ relay server
- Stats reporting every 60 seconds

**`cmd/client/socks5.go`** — SOCKS5 protocol:
- `ReadSOCKS5Client(conn)` — parse SOCKS5 handshake + CONNECT request
- `SendSOCKS5Success(conn)` — send success response
- `SendSOCKS5Error(conn, code)` — send error response

**`cmd/client/transport.go`** — Transport implementations:
- `ShadowTLSTransport` — TLS connect to server, send HMAC auth + target, XOR-encrypted relay
- `WebSocketTransport` — WebSocket connect, send NEW_STREAM frame, mux relay
- `XORConn` wrapper — transparent encrypt/decrypt on Read/Write
- `WSConn` wrapper — WebSocket ↔ stream adapter

**`cmd/client/client-config.json`** — Default config template

### Phase 6 — Deployment Scripts

**`certbot-setup.sh`** — Let's Encrypt certificate setup:
- Takes domain + email as arguments
- Runs certbot in standalone mode
- Copies certs to `certs/` directory
- Sets up cron job for auto-renewal

**`termux-setup.sh`** — Android/Termux installation:
- Installs Go via pkg
- Copies project files to `~/dpi-evasion`
- Builds client binary
- Creates `client-config.json` if missing
- Creates `run.sh` launcher script
- Sets up Termux:Boot auto-start at `~/.termux/boot/dpi-evasion.sh`

### Phase 7 — Build & Verification

- `go build -o dpi-relay .` — server binary compiles clean (9.6MB)
- `go build -o client ./cmd/client/` — client binary compiles clean (8.1MB)
- `go vet ./...` — no issues found
- Smoke test: server starts, serves FastCDN cover page on HTTPS, accepts ShadowTLS connections

**Build fixes applied:**
- Removed unused `"io"` import from `cmd/client/main.go`
- Rewrote `cmd/client/transport.go` to use `TLSUnique` from `tls.ConnectionState` instead of
  `MasterSecret`/`ServerRandom` (not exposed by Go's TLS library) for key derivation
- Added server status response reading in ShadowTLS client (reads 1-byte status after auth)

---

## What This System Does

This system lets you route internet traffic through your own VPS, making it look like
normal HTTPS connections to Digicel's and bmobile's DPI systems.

**Problem:** Digicel/bmobile in Trinidad and Tobago use Deep Packet Inspection to detect
and block VPNs, proxies, and censorship circumvention tools. They look for:

- Non-standard TLS handshakes
- Protocol signatures (Shadowsocks, V2Ray, WireGuard, etc.)
- Unusual traffic patterns (constant data flow, fixed-size packets)
- Known proxy server IPs

**Solution:** Our relay makes ALL traffic look like a normal HTTPS connection to a
legitimate CDN website:

1. **Cover website** — Any browser hitting port 443 sees a "FastCDN" marketing page
2. **ShadowTLS** — TLS handshake is proxied through microsoft.com, so DPI sees a
   valid Microsoft certificate
3. **Traffic obfuscation** — Fake frames, random padding, and Chrome-like delays
   prevent traffic analysis
4. **Password auth** — Hidden inside TLS Application Data using HMAC-SHA256

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        YOUR VPS                                 │
│                                                                 │
│  Port 443 (ShadowTLS)          Port 8443 (WebSocket+TLS)       │
│  ┌──────────────────┐          ┌──────────────────┐             │
│  │ ShadowTLS Server │          │ HTTPS Server     │             │
│  │                  │          │  ├─ Cover page   │             │
│  │ 1. Accept TCP    │          │  ├─ /wstunnel    │             │
│  │ 2. Read ClientHello          │  ├─ /health     │             │
│  │ 3. Proxy to microsoft.com   │  └─ /api/status  │             │
│  │    (DPI sees MS cert)       │                  │             │
│  │ 4. Verify HMAC auth         │  WebSocket       │             │
│  │ 5. XOR-encrypted relay      │  Relay + Fake    │             │
│  └──────────────────┘          │  Frames + Pad    │             │
│                                └──────────────────┘             │
└─────────────────────────────────────────────────────────────────┘
         ▲                            ▲
         │ TLS (looks like            │ WSS (looks like
         │ microsoft.com)             │ normal HTTPS)
         │                            │
┌────────┴────────────────────────────┴────────────────────────────┐
│                     ANDROID (Termux)                             │
│                                                                  │
│  ┌──────────────────────────────────────────────────────┐        │
│  │ SOCKS5 Proxy (127.0.0.1:1080)                       │        │
│  │                                                      │        │
│  │ Browser → SOCKS5 → Client → Transport → VPS → Target│        │
│  │                                                      │        │
│  │ Modes:                                               │        │
│  │   shadowtls (port 443) — stealthier                 │        │
│  │   websocket (port 8443) — fallback with mux         │        │
│  └──────────────────────────────────────────────────────┘        │
│                                                                  │
│  Apps using SOCKS5: Firefox, Chrome (proxy), curl, etc.          │
└──────────────────────────────────────────────────────────────────┘
```

### Dual-Channel Design

| Channel | Port | Transport | Best For |
|---------|------|-----------|----------|
| **ShadowTLS** | 443 | Raw TLS → microsoft.com + HMAC auth + XOR relay | Primary. Harder to detect. DPI sees real Microsoft cert. |
| **WebSocket+TLS** | 8443 | TLS + WebSocket mux + fake frames + padding | Fallback. Multiplexed streams. Good if ShadowTLS blocked. |

---

## File Reference

```
dpi-evasion/
├── server.go                  # Main server (HTTPS + WS relay + ShadowTLS launcher)
├── certutil.go                # Self-signed cert generation (ECDSA P-256)
├── go.mod                     # Module: github.com/smartsni/dpi-evasion
├── go.sum
├── config.json                # Server configuration
├── dpi-relay                  # Compiled server binary (Linux amd64)
├── client                     # Compiled client binary (Linux amd64)
│
├── lib/
│   ├── protocol.go            # Binary framing: ParseFrame, BuildFrame
│   ├── obfuscation.go         # Padding, delays, fake frames, FakeFrameScheduler
│   ├── fronting.go            # Domain fronting config & validation
│   └── shadowtls.go           # ShadowTLS: TLS record parsing, SNI, HMAC auth,
│                              #   XOR cipher, handshake proxy, ShadowTLSServer
│
├── cmd/client/
│   ├── main.go                # SOCKS5 listener + relay handler + stats
│   ├── socks5.go              # SOCKS5 protocol: handshake, CONNECT, errors
│   ├── transport.go           # ShadowTLSTransport, WebSocketTransport, XORConn, WSConn
│   └── client-config.json     # Client config template
│
├── certs/                     # TLS certificates (gitignored in production)
│   ├── dev-cert.pem           # Dev self-signed cert
│   └── dev-key.pem            # Dev self-signed key
│
├── certbot-setup.sh           # Let's Encrypt certificate setup
├── termux-setup.sh            # Termux/Android installation script
└── PROJECT-LOG.md             # This file
```

---

## Server Setup (VPS)

### Prerequisites

- Ubuntu 20.04+ or Debian 11+ VPS
- Domain name pointed at your VPS IP (for Let's Encrypt)
- Go 1.21+ installed (`go version` to check)

### Step 1 — Get the Code

```bash
git clone <your-repo-url> dpi-evasion
cd dpi-evasion
```

Or copy the files manually to your VPS.

### Step 2 — Install Go (if not installed)

```bash
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Step 3 — Get TLS Certificates

**Option A: Let's Encrypt (recommended for production)**

```bash
sudo bash certbot-setup.sh cdn.yourdomain.com admin@yourdomain.com
```

This will:
- Obtain a free Let's Encrypt certificate
- Copy it to `certs/fullchain.pem` and `certs/privkey.pem`
- Set up auto-renewal cron job

**Option B: Self-signed (for testing only)**

Skip this step — the server automatically generates self-signed certs if the Let's Encrypt
certs are not found.

### Step 4 — Configure

Edit `config.json`:

```json
{
  "server": {
    "port": 443,
    "host": "0.0.0.0",
    "domain": "cdn.yourdomain.com",
    "certPath": "certs/fullchain.pem",
    "keyPath": "certs/privkey.pem"
  },
  "domain_fronting": {
    "enabled": false
  },
  "obfuscation": {
    "minPadding": 16,
    "maxPadding": 128,
    "minDelayMs": 0,
    "maxDelayMs": 50,
    "fakeFrameIntervalMs": 3000,
    "fakeFrameSizeMin": 32,
    "fakeFrameSizeMax": 256
  },
  "relay": {
    "idleTimeoutSec": 120,
    "maxConnections": 200,
    "bufferSize": 65536,
    "sessionRotationMin": 30
  },
  "rateLimit": {
    "maxPerIp": 10,
    "windowSec": 60
  },
  "auth": {
    "enabled": false,
    "secret": ""
  },
  "shadowtls": {
    "enabled": true,
    "listenPort": 443,
    "password": "CHANGE_ME_TO_A_STRONG_PASSWORD",
    "handshakeServer": "www.microsoft.com",
    "handshakePort": 443,
    "strictMode": false
  }
}
```

**IMPORTANT:** Change `"password"` to a strong, unique password. This is the shared
secret between server and client.

### Step 5 — Build & Run

```bash
go build -o dpi-relay .
./dpi-relay config.json
```

**Production with systemd:**

```bash
sudo tee /etc/systemd/system/dpi-relay.service << 'EOF'
[Unit]
Description=DPI Evasion Relay
After=network.target

[Service]
Type=simple
User=nobody
WorkingDirectory=/opt/dpi-evasion
ExecStart=/opt/dpi-evasion/dpi-relay /opt/dpi-evasion/config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable dpi-relay
sudo systemctl start dpi-relay
```

### Step 6 — Verify

```bash
# Test cover page
curl -sk https://localhost/

# Test ShadowTLS (should accept TLS handshake)
openssl s_client -connect localhost:443 -servername microsoft.com

# Test WebSocket endpoint
curl -sk -i https://localhost:8443/wstunnel
```

---

## Client Setup (Termux/Android)

### Prerequisites

- Android phone with Termux installed (from F-Droid, NOT Play Store)
- Termux:Boot app (optional, for auto-start)

### Option A — Automatic Setup

```bash
# In Termux:
cd /path/to/dpi-evasion   # where the source code is
bash termux-setup.sh
```

This will install Go, build the client, and create all config files.

### Option B — Manual Setup

```bash
# Install Go
pkg install golang

# Setup project
mkdir -p ~/dpi-evasion/cmd/client ~/dpi-evasion/lib
# Copy all .go files and go.mod to the right places

# Build
cd ~/dpi-evasion
go build -o client ./cmd/client/

# Create config
cat > client-config.json << 'EOF'
{
  "server": "YOUR_VPS_IP",
  "port": 443,
  "password": "CHANGE_ME_TO_A_STRONG_PASSWORD",
  "sni": "www.microsoft.com",
  "mode": "shadowtls",
  "wsPath": "/wstunnel",
  "secret": "",
  "socksPort": 1080
}
EOF

# Run
./client -config client-config.json
```

### Step 2 — Edit Config

```bash
nano ~/dpi-evasion/client-config.json
```

Set:
- `server` — your VPS IP address
- `password` — must match the server's `shadowtls.password`
- `mode` — `"shadowtls"` (recommended) or `"websocket"`
- `socksPort` — default 1080, change if needed

### Step 3 — Run

```bash
cd ~/dpi-evasion && ./run.sh
```

Or directly:

```bash
cd ~/dpi-evasion && ./client -config client-config.json
```

### Step 4 — Configure Browser

**Firefox (Android):**
1. Settings → General → Network Settings
2. Manual Proxy Configuration
3. SOCKS Host: `127.0.0.1`  Port: `1080`
4. SOCKS v5 ✓

**Chrome (Android):**
Chrome doesn't have built-in proxy settings. Use one of:
- **Proxy Helper** app (from Play Store) — set SOCKS5 127.0.0.1:1080
- **Tor Browser** (has built-in proxy settings)
- Or run Chrome with: `--proxy-server=socks5://127.0.0.1:1080`

**All system traffic (optional):**
- **ProxyDroid** app (requires root) — route all Android traffic through SOCKS5
- Or set up a local WiFi hotspot with proxy settings

### Step 5 — Auto-Start on Boot (Optional)

1. Install **Termux:Boot** from F-Droid
2. The `termux-setup.sh` script already creates the boot script at
   `~/.termux/boot/dpi-evasion.sh`
3. Open Termux:Boot once to activate it
4. The client will start automatically when your phone boots

---

## Configuration Reference

### Server Config (`config.json`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.port` | int | 443 | HTTPS/WebSocket listen port |
| `server.host` | string | 0.0.0.0 | Bind address |
| `server.domain` | string | - | Domain name for cover page |
| `server.certPath` | string | - | TLS certificate path |
| `server.keyPath` | string | - | TLS private key path |
| `domain_fronting.enabled` | bool | false | Enable domain fronting |
| `domain_fronting.frontHost` | string | - | CDN front host |
| `domain_fronting.frontSni` | string | - | CDN front SNI |
| `obfuscation.minPadding` | int | 16 | Min random padding bytes |
| `obfuscation.maxPadding` | int | 128 | Max random padding bytes |
| `obfuscation.minDelayMs` | int | 0 | Min relay delay (ms) |
| `obfuscation.maxDelayMs` | int | 50 | Max relay delay (ms) |
| `obfuscation.fakeFrameIntervalMs` | int | 3000 | Fake frame send interval |
| `obfuscation.fakeFrameSizeMin` | int | 32 | Min fake frame size |
| `obfuscation.fakeFrameSizeMax` | int | 256 | Max fake frame size |
| `relay.idleTimeoutSec` | int | 120 | Close idle connections after |
| `relay.maxConnections` | int | 200 | Max concurrent connections |
| `relay.bufferSize` | int | 65536 | Read/write buffer size |
| `relay.sessionRotationMin` | int | 30 | Force reconnect interval |
| `rateLimit.maxPerIp` | int | 10 | Max requests per IP per window |
| `rateLimit.windowSec` | int | 60 | Rate limit window |
| `auth.enabled` | bool | false | Enable Bearer token auth |
| `auth.secret` | string | - | Shared auth token |
| `shadowtls.enabled` | bool | true | Enable ShadowTLS listener |
| `shadowtls.listenPort` | int | 443 | ShadowTLS port |
| `shadowtls.password` | string | - | Shared password (server+client) |
| `shadowtls.handshakeServer` | string | www.microsoft.com | TLS handshake proxy target |
| `shadowtls.handshakePort` | int | 443 | Handshake target port |
| `shadowtls.strictMode` | bool | false | Drop connections on auth fail |

### Client Config (`client-config.json`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server` | string | - | VPS IP address or hostname |
| `port` | int | 443 | Server port |
| `password` | string | - | Shared password |
| `sni` | string | www.microsoft.com | TLS SNI for ShadowTLS |
| `mode` | string | shadowtls | `"shadowtls"` or `"websocket"` |
| `wsPath` | string | /wstunnel | WebSocket path (for websocket mode) |
| `secret` | string | - | Bearer token (for websocket mode) |
| `socksPort` | int | 1080 | Local SOCKS5 listen port |

---

## How the DPI Evasion Works

### Layer 1 — TLS Camouflage (ShadowTLS)

When Digicel's DPI inspects a connection to port 443:

1. It sees a TLS ClientHello with `SNI: www.microsoft.com`
2. The server proxies the TLS handshake through actual microsoft.com
3. DPI sees a valid TLS ServerHello with a real Microsoft certificate
4. DPI sees proper Finished messages from both sides
5. **Result: DPI concludes this is a legitimate HTTPS connection to Microsoft**

After the handshake, the first Application Data record contains:
- HMAC-SHA256 authentication (password + handshake randoms)
- Target host and port for the actual connection

### Layer 2 — Traffic Obfuscation

Even if DPI tries to analyze the data pattern:

- **Random padding** on every data frame (16-128 bytes) prevents fixed-size detection
- **Bimodal delays** (80% instant, 20% delayed 50-500ms) mimic Chrome's behavior
- **Fake frames** are injected every 3 seconds with realistic JSON payloads:
  - `{"type":"video_stats","views":142857,"bitrate":4500,"buffer_ms":120}`
  - `{"type":"chat_message","user":"viewer_3847","text":"great stream!","ts":1719456789}`
  - `{"type":"heartbeat","cpu":23.5,"mem_mb":512,"uptime":86400}`
- **Session rotation** forces reconnection every 30 minutes, preventing long-session analysis

### Layer 3 — Cover Traffic

The server doubles as a legitimate-looking website:

- Any HTTPS request to `/` returns a full "FastCDN" marketing website
- `/robots.txt` exists with standard bot rules
- `/health` returns 204 (like a real CDN health endpoint)
- `/api/v1/status` returns JSON stats (looks like a CDN API)
- WebSocket upgrades are silently intercepted — DPI only sees the initial HTTP request

### Layer 4 — XOR Encryption

After authentication, all relay data is XOR-encrypted with a key derived from:
`SHA256(password || serverRandom)`

This prevents content inspection of the tunneled data. The XOR key is unique per
connection because `serverRandom` changes with each TLS handshake.

### Why This Beats Digicel/bmobile DPI

| DPI Technique | How We Defeat It |
|---------------|------------------|
| SNI-based blocking | SNI is `www.microsoft.com` — can't block without blocking Microsoft |
| Certificate inspection | Real Microsoft cert via proxied handshake |
| Protocol signature detection | No known protocol signatures (custom binary framing) |
| Traffic pattern analysis | Fake frames + random padding + bimodal delays |
| Long session profiling | Session rotation every 30 minutes |
| IP reputation blocking | Runs on any VPS with a domain + Let's Encrypt cert |
| Deep packet inspection | XOR encryption prevents content reading |
| Behavioral analysis | Traffic pattern matches Chrome browsing behavior |

---

## Troubleshooting

**Server won't start — "bind: permission denied"**
Port 443 requires root. Either run with `sudo` or use high ports (e.g., 8443) for testing.

**Client connects but no data flows**
Check that server and client have the same password. The password must match exactly.

**"read ClientHello failed" in server logs**
Client is connecting but sending invalid data. Make sure client `mode` is `"shadowtls"` and
`port` matches the server's `shadowtls.listenPort`.

**Connection drops after a few minutes**
Check `relay.idleTimeoutSec` — if no data flows for this duration, the connection closes.
Keep-alive pings should prevent this (client sends them automatically).

**DPI still detecting connections**
- Try changing `shadowtls.handshakeServer` to a different large site (e.g., `www.apple.com`)
- Ensure `shadowtls.strictMode` is `false` (failed auth goes to cover traffic, not rejection)
- Check that the domain on port 443 has a valid Let's Encrypt cert

---

*Last updated: 2026-07-27*
*Built for bypassing Digicel/bmobile DPI in Trinidad and Tobago*
