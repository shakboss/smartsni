import asyncio
import base64
import json
import logging
import os
import random
import ssl
import struct
from typing import Any, Dict, Optional

import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import geoip2.database
import geoip2.errors
import httpx
import uvicorn
from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect

# --- Globals ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration and state
config: Dict[str, Any] = {}
config_lock = asyncio.Lock()
geoip_reader: Optional[geoip2.database.Reader] = None

# Upstream DoH client
doh_client = httpx.AsyncClient(timeout=10.0)


# --- Configuration ---
class BypassSettings:
    def __init__(self, data: Dict[str, Any]):
        self.enabled = data.get("enabled", False)
        self.mode = data.get("mode", "shape")
        self.trigger_sni = data.get("trigger_sni", "")
        self.tunnel_path = data.get("tunnel_path", "")
        self.padding_size_range = data.get("padding_size_range", [0, 0])
        self.delay_ms_range = data.get("delay_ms_range", [0, 0])
        self.detect_mobile_networks = data.get("detect_mobile_networks", False)
        self.mobile_carrier_names = data.get("mobile_carrier_names", [])
        self.geoip_db_path = data.get("geoip_db_path", "")
        self.socks_host = data.get("socks_host", "127.0.0.1")
        self.bypass_secret = data.get("bypass_secret", None)
        self.socks_port = data.get("socks_port", 1080)

class DomainFrontingSettings:
    def __init__(self, data: Dict[str, Any]):
        self.enabled = data.get("enabled", False)
        self.front_host = data.get("front_host", "")
        self.front_sni = data.get("front_sni", "")
        self.upstream_host = data.get("upstream_host", "")

class CloudflareSettings:
    def __init__(self, data: Dict[str, Any]):
        self.enabled = data.get("enabled", False)
        self.zone_id = data.get("zone_id", "")
        self.api_token = data.get("api_token", "")

# Domain rotation state
active_trigger_domain_index = 0
domain_rotation_task = None


async def load_config(filename: str) -> (Dict[str, Any], Optional[geoip2.database.Reader]):
    """Loads config and associated resources."""
    logging.info(f"Loading configuration from {filename}...")
    try:
        with open(filename, 'r') as f:
            new_config_data = json.load(f)

        new_geoip_reader = None
        bypass_settings_data = new_config_data.get("bypass_settings")
        if bypass_settings_data:
            bypass = BypassSettings(bypass_settings_data)
            if bypass.enabled and bypass.detect_mobile_networks and bypass.geoip_db_path:
                try:
                    new_geoip_reader = geoip2.database.Reader(bypass.geoip_db_path)
                    logging.info(f"Successfully loaded GeoIP database from {bypass.geoip_db_path}")
                except Exception as e:
                    logging.error(f"Failed to load GeoIP database: {e}. Mobile detection disabled.")
                    new_config_data["bypass_settings"]["detect_mobile_networks"] = False

        return new_config_data, new_geoip_reader
    except Exception as e:
        logging.error(f"Failed to load or parse config file {filename}: {e}")
        return None, None


async def reload_config_periodically():
    """Periodically reloads the configuration."""
    global config, geoip_reader
    while True:
        reload_interval = config.get("reload_interval_minutes", 1)
        if reload_interval <= 0:
            reload_interval = 1

        await asyncio.sleep(reload_interval * 60)

        logging.info("Checking for configuration updates...")
        new_config_data, new_geoip_reader = await load_config("config.json")

        if new_config_data:
            async with config_lock:
                if geoip_reader:
                    geoip_reader.close()
                config = new_config_data
                geoip_reader = new_geoip_reader
            logging.info("Configuration reloaded successfully.")


async def rotate_domains():
    """Periodically rotates the active trigger domain."""
    global active_trigger_domain_index
    while True:
        await asyncio.sleep(60)

        async with config_lock:
            domains = config.get("trigger_domains", [])
            rotation_minutes = config.get("domain_rotation_minutes", 60)

        if len(domains) <= 1:
            continue

        await asyncio.sleep(rotation_minutes * 60)

        async with config_lock:
            domains = config.get("trigger_domains", [])
            if domains:
                active_trigger_domain_index = (active_trigger_domain_index + 1) % len(domains)
                new_domain = domains[active_trigger_domain_index]
                config["bypass_settings"]["trigger_sni"] = new_domain
                logging.info(f"Domain rotated to: {new_domain}")


async def get_active_trigger_domain() -> str:
    async with config_lock:
        domains = config.get("trigger_domains", [])
        if domains:
            return domains[active_trigger_domain_index % len(domains)]
        return config.get("bypass_settings", {}).get("trigger_sni", "")


# --- DNS Logic ---
def find_value_by_key_contains(m: Dict[str, str], substr: str) -> Optional[str]:
    substr_lower = substr.lower()
    for key, value in m.items():
        if key.lower() in substr_lower:
            return value
    return None


async def process_dns_query(query_bytes: bytes) -> bytes:
    """Processes a DNS query and returns a response."""
    try:
        msg = dns.message.from_wire(query_bytes)
        if not msg.question:
            raise ValueError("No DNS question in query")

        question = msg.question[0]
        domain_name = question.name.to_text(omit_final_dot=True)

        # Check local domains
        async with config_lock:
            domains_map = config.get("domains", {})

        ip_str = find_value_by_key_contains(domains_map, domain_name)
        if ip_str:
            answer = dns.rrset.from_text(question.name, 3600, dns.rdataclass.IN, dns.rdatatype.A, ip_str)
            msg.answer.append(answer)
            msg.flags |= dns.flags.AA | dns.flags.QR
            return msg.to_wire()

        # Forward to upstream DoH
        headers = {'content-type': 'application/dns-message'}
        upstream_doh = config.get("upstream_doh", "https://1.1.1.1/dns-query")
        resp = await doh_client.post(upstream_doh, content=query_bytes, headers=headers)
        resp.raise_for_status()
        return resp.content

    except Exception as e:
        logging.error(f"Error processing DNS query: {e}")
        # Create an error response
        error_msg = dns.message.make_response(dns.message.from_wire(query_bytes))
        error_msg.set_rcode(dns.rcode.SERVFAIL)
        return error_msg.to_wire()


# --- DoT Server ---
async def handle_dot_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handles a single DoT connection."""
    try:
        len_bytes = await reader.readexactly(2)
        msg_len = struct.unpack('!H', len_bytes)[0]
        query_bytes = await reader.readexactly(msg_len)

        response_bytes = await process_dns_query(query_bytes)

        writer.write(struct.pack('!H', len(response_bytes)))
        writer.write(response_bytes)
        await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass  # Client disconnected
    except Exception as e:
        logging.error(f"DoT connection error: {e}")
    finally:
        writer.close()
        await writer.wait_closed()


async def start_dot_server():
    """Starts the DNS-over-TLS server."""
    host = config.get("host")
    if not host:
        logging.error("Cannot start DoT server: 'host' not defined in config.")
        return

    cert_path = config.get("dot_cert_path", f"/etc/letsencrypt/live/{host}/fullchain.pem")
    key_path = config.get("dot_key_path", f"/etc/letsencrypt/live/{host}/privkey.pem")

    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        logging.error(f"TLS certificates not found for DoT server (cert: '{cert_path}', key: '{key_path}'). DoT will not start.")
        return

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(cert_path, key_path)

    server = await asyncio.start_server(
        handle_dot_connection, '0.0.0.0', 853, ssl=ssl_context
    )
    logging.info("DoT server listening on 0.0.0.0:853")
    async with server:
        await server.serve_forever()


# --- SNI Proxy and Bypass Logic ---
def parse_sni(client_hello: bytes) -> Optional[str]:
    """
    A highly defensive parser for SNI from a TLS ClientHello.
    """
    try:
        # 1. Check for TLS Handshake record header (5 bytes)
        if len(client_hello) < 5:
            return None
        if client_hello[0] != 0x16:  # Content Type: Handshake
            return None
        
        # 2. Check for ClientHello handshake header (4 bytes)
        if len(client_hello) < 9:
            return None
        if client_hello[5] != 0x01:  # Handshake Type: ClientHello
            return None

        # 3. Find the start of the extensions
        offset = 43  # Start of Session ID length field
        
        # Skip Session ID
        if offset >= len(client_hello): return None
        session_id_len = client_hello[offset]
        offset += 1 + session_id_len

        # Find Cipher Suites and skip them
        if offset + 2 > len(client_hello): return None
        cipher_suites_len = int.from_bytes(client_hello[offset:offset+2], 'big')
        offset += 2 + cipher_suites_len

        # Find Compression Methods and skip them
        if offset + 1 > len(client_hello): return None
        compression_methods_len = client_hello[offset]
        offset += 1 + compression_methods_len

        # We are now at the extensions length field
        if offset + 2 > len(client_hello): return None
        extensions_len = int.from_bytes(client_hello[offset:offset+2], 'big')
        offset += 2
        
        # 4. Loop through extensions to find 'server_name'
        end_of_extensions = offset + extensions_len
        while offset + 4 <= end_of_extensions:
            ext_type = int.from_bytes(client_hello[offset:offset+2], 'big')
            ext_len = int.from_bytes(client_hello[offset+2:offset+4], 'big')

            if ext_type == 0:  # server_name extension
                sni_offset = offset + 4
                if sni_offset + 5 > end_of_extensions: return None # Min length for list len, type, name len
                
                name_type_offset = sni_offset + 2
                if client_hello[name_type_offset] != 0: return None # 0 = host_name

                name_len_offset = name_type_offset + 1
                name_len = int.from_bytes(client_hello[name_len_offset:name_len_offset+2], 'big')

                name_offset = name_len_offset + 2
                if name_offset + name_len > end_of_extensions: return None
                
                return client_hello[name_offset : name_offset + name_len].decode('utf-8')

            offset += 4 + ext_len

        return None # SNI extension not found
    except (IndexError, struct.error, UnicodeDecodeError) as e:
        return None


async def shape_and_relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, settings: BypassSettings):
    """Relays traffic with padding and delay."""
    try:
        while not reader.at_eof():
            data = await reader.read(4096)
            if not data:
                break

            data_to_write = data
            if settings.padding_size_range and settings.padding_size_range[1] > 0:
                min_pad, max_pad = settings.padding_size_range
                pad_size = random.randint(min_pad, max_pad)
                data_to_write += b'\x00' * pad_size

            writer.write(data_to_write)
            await writer.drain()

            if settings.delay_ms_range and settings.delay_ms_range[1] > 0:
                min_delay, max_delay = settings.delay_ms_range
                delay = random.randint(min_delay, max_delay) / 1000.0
                await asyncio.sleep(delay)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        writer.close()


async def obfuscate_and_relay_ws(source_reader: asyncio.StreamReader, dest_ws: WebSocket, settings: BypassSettings):
    """Reads from a stream and sends over a WebSocket with padding.

    Padding format: [data] + [4-byte big-endian pad_length] + [random_padding]
    The Android client strips padding using the 4-byte length suffix.
    This prevents traffic analysis based on packet sizes.
    """
    try:
        while not source_reader.at_eof():
            data = await source_reader.read(2048)
            if not data:
                break

            if settings.padding_size_range and settings.padding_size_range[1] > 0:
                min_pad, max_pad = settings.padding_size_range
                pad_size = random.randint(min_pad, max_pad)
                padding = os.urandom(pad_size)
                pad_len_bytes = pad_size.to_bytes(4, 'big')
                data += pad_len_bytes + padding

            await dest_ws.send_bytes(data)
    except (WebSocketDisconnect, ConnectionResetError):
        pass


async def relay_streams(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Simple bidirectional relay."""
    try:
        while not reader.at_eof():
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        writer.close()


async def handle_socks5_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[tuple[str, int]]:
    """
    Performs a SOCKS5 handshake to get the target destination from the client.
    Returns (host, port) on success, None on failure.
    """
    try:
        # SOCKS5 handshake: VER, NMETHODS, METHODS
        ver_nmethods = await reader.readexactly(2)
        if ver_nmethods[0] != 0x05: return None # VER != 5
        methods_count = ver_nmethods[1]
        methods = await reader.readexactly(methods_count)
        # We only support NO AUTHENTICATION REQUIRED (0x00)
        if 0x00 not in methods: return None
        # Send server choice: VER, METHOD
        writer.write(b'\x05\x00')
        await writer.drain()

        # SOCKS5 request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
        ver_cmd_rsv_atyp = await reader.readexactly(4)
        if ver_cmd_rsv_atyp[0] != 0x05 or ver_cmd_rsv_atyp[1] != 0x01: return None # VER=5, CMD=1 (CONNECT)

        atyp = ver_cmd_rsv_atyp[3]
        if atyp == 0x03: # Domain name
            domain_len = (await reader.readexactly(1))[0]
            target_host = (await reader.readexactly(domain_len)).decode()
        elif atyp == 0x01: # IPv4
            target_host = ".".join(str(b) for b in await reader.readexactly(4))
        else: # IPv6 or unsupported
            return None

        target_port = int.from_bytes(await reader.readexactly(2), 'big')
        return target_host, target_port
    except (asyncio.IncompleteReadError, ConnectionResetError, UnicodeDecodeError):
        return None

async def handle_connection(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
    """Main entry point for incoming connections on port 443."""
    full_client_hello = b''
    server_name = None
    try:
        # 1. Read the 5-byte TLS record header to get the length of the ClientHello.
        header = await asyncio.wait_for(client_reader.readexactly(5), timeout=5.0)
        if header[0] != 0x16:  # 0x16 = Handshake
            logging.warning("Incoming connection is not a TLS handshake. Closing.")
            return

        record_len = int.from_bytes(header[3:5], 'big')

        # 2. Read the rest of the record in chunks to be more robust.
        record_body = b''
        bytes_to_read = record_len
        while bytes_to_read > 0:
            chunk = await asyncio.wait_for(client_reader.read(bytes_to_read), timeout=5.0)
            if not chunk: break # Connection closed prematurely
            record_body += chunk
            bytes_to_read -= len(chunk)

        # 3. We now have the full ClientHello packet.
        full_client_hello = header + record_body

        server_name = parse_sni(full_client_hello)

        if not server_name:
            logging.warning("SNI not found or could not be parsed. Closing connection.")
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 20\r\n\r\nSNI extension missing")
            await client_writer.drain()
            return

        # --- Routing Logic ---
        proxy_mode = "direct"
        target_host = ""
        target_port = 443
        use_bypass = False

        async with config_lock:
            current_host = config.get("host", "")
            bypass_settings_data = config.get("bypass_settings")
            bypass = BypassSettings(bypass_settings_data) if bypass_settings_data else None
            trigger_domains = config.get("trigger_domains", [])

        if bypass and bypass.enabled:
            sni_lower = server_name.lower()
            is_trigger = sni_lower == bypass.trigger_sni.lower() or any(
                sni_lower == td.lower() for td in trigger_domains
            )
            if is_trigger:
                use_bypass = True
            elif bypass.detect_mobile_networks and geoip_reader:
                peer_addr = client_writer.get_extra_info('peername')
                if peer_addr:
                    ip_str = peer_addr[0]
                    try:
                        record = geoip_reader.isp(ip_str)
                        client_isp = record.isp.lower()
                        client_org = record.organization.lower()
                        for carrier in bypass.mobile_carrier_names:
                            if carrier.lower() in client_isp or carrier.lower() in client_org:
                                logging.info(f"Mobile network detected for IP {ip_str} (ISP: {record.isp}). Activating bypass.")
                                use_bypass = True
                                break
                    except geoip2.errors.AddressNotFoundError:
                        pass  # IP not in database
                    except Exception as e:
                        logging.warning(f"GeoIP lookup failed for {ip_str}: {e}")

        if use_bypass:
            if bypass.mode == "websocket":
                proxy_mode = "websocket_forward"
                target_host = "127.0.0.1"
                target_port = 8080  # Internal FastAPI/Uvicorn server
                logging.info(f"Bypass: WebSocket mode activated for SNI: {server_name}")
            else:  # 'shape' mode for TLS-in-TLS
                # The 'shape' mode with a trigger_sni implies a SOCKS5 handshake will be sent by the client
                # inside the TLS tunnel to specify the real destination.
                try:
                    socks_target = await handle_socks5_handshake(client_reader, client_writer)
                    if not socks_target:
                        logging.warning(f"SOCKS5 handshake failed for SNI {server_name}")
                        return
                    target_host, target_port = socks_target

                    # Send reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
                    client_writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                    await client_writer.drain()

                    proxy_mode = "shape"
                    logging.info(f"Bypass: Shape/SOCKS mode activated for SNI: {server_name} -> {target_host}:{target_port}")
                except (asyncio.IncompleteReadError, ConnectionResetError):
                    return # Client disconnected during SOCKS handshake

        else:  # direct proxy
            if server_name.lower() == current_host.lower():
                target_host = "127.0.0.1"
                target_port = 853
            else:
                target_host = server_name
                target_port = 443

        if proxy_mode == "shape" and not use_bypass:
            # This is the mobile-detect case for 'shape' mode. The target is the SNI itself.
            target_host = server_name
            target_port = 443
            logging.info(f"Bypass: Shape mode activated for mobile network -> {target_host}:{target_port}")

        backend_reader, backend_writer = await asyncio.open_connection(target_host, target_port)
        backend_writer.write(full_client_hello)
        await backend_writer.drain()

        if proxy_mode == "shape":
            # Relay with obfuscation
            task1 = asyncio.create_task(shape_and_relay(client_reader, backend_writer, bypass))
            task2 = asyncio.create_task(shape_and_relay(backend_reader, client_writer, bypass))
        else:  # direct and websocket_forward
            # Simple relay without obfuscation
            task1 = asyncio.create_task(relay_streams(client_reader, backend_writer))
            task2 = asyncio.create_task(relay_streams(backend_reader, client_writer))

        await asyncio.gather(task1, task2)

    except (ConnectionRefusedError, asyncio.TimeoutError):
        logging.warning(f"Could not connect to target for SNI: {server_name}")
    except Exception as e:
        if server_name:
            logging.error(f"Error in handle_connection for SNI {server_name}: {e}")
    finally:
        client_writer.close()


async def start_sni_proxy():
    server = await asyncio.start_server(handle_connection, '0.0.0.0', 443)
    logging.info("SNI proxy listening on 0.0.0.0:443")
    async with server:
        await server.serve_forever()


# --- FastAPI App (DoH, Website, and WebSocket) ---
app = FastAPI()

COVER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureMail - Encrypted Communications</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
        .container { max-width: 800px; margin: 0 auto; padding: 40px 20px; }
        header { text-align: center; padding: 60px 0 40px; }
        h1 { font-size: 2.5rem; color: #38bdf8; margin-bottom: 12px; }
        .subtitle { color: #94a3b8; font-size: 1.1rem; }
        .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 24px; margin-top: 40px; }
        .feature { background: #1e293b; border-radius: 12px; padding: 24px; border: 1px solid #334155; }
        .feature h3 { color: #38bdf8; margin-bottom: 8px; }
        .feature p { color: #94a3b8; font-size: 0.9rem; line-height: 1.5; }
        footer { text-align: center; padding: 40px 0; color: #475569; font-size: 0.85rem; }
        a { color: #38bdf8; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>SecureMail</h1>
            <p class="subtitle">Enterprise-grade encrypted communications platform</p>
        </header>
        <div class="features">
            <div class="feature">
                <h3>End-to-End Encryption</h3>
                <p>All messages are encrypted with AES-256-GCM. Only you and your recipient can read them.</p>
            </div>
            <div class="feature">
                <h3>Zero-Knowledge Architecture</h3>
                <p>We never have access to your encryption keys or message content.</p>
            </div>
            <div class="feature">
                <h3>Secure File Sharing</h3>
                <p>Share files up to 2GB with automatic encryption and expiration policies.</p>
            </div>
            <div class="feature">
                <h3>Team Workspaces</h3>
                <p>Create encrypted channels for your team with role-based access control.</p>
            </div>
        </div>
        <footer>
            <p>&copy; 2024 SecureMail. All rights reserved. | <a href="/privacy">Privacy</a> | <a href="/terms">Terms</a></p>
        </footer>
    </div>
</body>
</html>"""


@app.get("/dns-query")
@app.post("/dns-query")
async def doh_handler(request: Request):
    if request.method == "POST":
        query_bytes = await request.body()
    else:  # GET
        dns_param = request.query_params.get("dns")
        if not dns_param:
            return Response(content="Missing 'dns' query parameter", status_code=400)
        try:
            query_bytes = base64.urlsafe_b64decode(dns_param + '=' * (4 - len(dns_param) % 4))
        except Exception:
            return Response(content="Invalid 'dns' query parameter", status_code=400)

    response_bytes = await process_dns_query(query_bytes)
    return Response(content=response_bytes, media_type="application/dns-message")


@app.get("/{full_path:path}")
async def website_handler(request: Request, full_path: str):
    return Response(content=COVER_HTML, media_type="text/html")


@app.websocket("/{full_path:path}")
async def websocket_handler(websocket: WebSocket, full_path: str):
    async with config_lock:
        bypass_settings_data = config.get("bypass_settings")
        bypass = BypassSettings(bypass_settings_data) if bypass_settings_data else None
        fronting_data = config.get("domain_fronting", {})
        fronting = DomainFrontingSettings(fronting_data) if fronting_data else None
        cf_data = config.get("cloudflare", {})
        cf = CloudflareSettings(cf_data) if cf_data else None

    if not (bypass and bypass.enabled and bypass.mode == "websocket"):
        await websocket.close(code=4004)
        return

    path_matches = f"/{full_path}".startswith(bypass.tunnel_path)
    if not path_matches:
        await websocket.close(code=4004)
        return

    # Domain fronting: check X-Forwarded-Host for the real upstream target
    effective_host = websocket.headers.get("Host", "")
    forwarded_host = websocket.headers.get("X-Forwarded-Host", "")
    if fronting and fronting.enabled and forwarded_host:
        effective_host = forwarded_host
        logging.info(f"Domain fronting: Host={effective_host}, Front={websocket.headers.get('Host')}")

    # Cloudflare: trust CF-Connecting-IP for real client IP
    real_client_ip = None
    if cf and cf.enabled:
        cf_ip = websocket.headers.get("CF-Connecting-IP")
        if cf_ip:
            real_client_ip = cf_ip

    # 1. Authentication
    if bypass.bypass_secret:
        auth_header = websocket.headers.get("Authorization")
        if not auth_header or auth_header != f"Bearer {bypass.bypass_secret}":
            logging.warning(f"WebSocket bypass: Failed authentication for path /{full_path}")
            await websocket.close(code=4001)
            return

    await websocket.accept()
    logging.info(f"WebSocket bypass: Client authenticated and connected successfully.")

    # 2. Send a welcome message to confirm protocol framing
    await websocket.send_json({"type": "hello", "status": "connected"})


    # --- MODIFICATION FOR VPN/SOCKS CLIENT ---
    # Instead of reading a target from a header, we forward all traffic
    # from this WebSocket to a local SOCKS5 proxy server.
    # These settings are now configurable in config.json
    socks_host = bypass.socks_host
    socks_port = bypass.socks_port
    target_log_name = f"{socks_host}:{socks_port} (SOCKS Proxy)"
    # --- END MODIFICATION ---

    try:
        reader, writer = await asyncio.open_connection(socks_host, socks_port)
        logging.info(f"WebSocket bypass: Tunneling to {target_log_name}")

        # This direction (client -> server) doesn't need obfuscation,
        # as the client-side will handle that. We just relay binary frames.
        async def ws_to_socks(ws: WebSocket, socks_writer: asyncio.StreamWriter):
            try:
                while True:
                    data = await ws.receive_bytes()
                    if data:
                        socks_writer.write(data)
                        await socks_writer.drain()
            except WebSocketDisconnect:
                pass
            finally:
                socks_writer.close()

        task_c2s = asyncio.create_task(ws_to_socks(websocket, writer))

        # Relay from SOCKS to WebSocket, applying traffic shaping for camouflage.
        task_s2c = asyncio.create_task(obfuscate_and_relay_ws(reader, websocket, bypass))

        await asyncio.gather(task_c2s, task_s2c)

    except Exception as e:
        logging.error(f"WebSocket bypass error for target {target_log_name}: {e}")
    finally:
        logging.info(f"WebSocket bypass: Tunnel to {target_log_name} closed")


# --- Main Entry Point ---
async def main():
    global config, geoip_reader

    initial_config, initial_geoip = await load_config("config.json")
    if not initial_config:
        logging.critical("Could not load initial configuration. Exiting.")
        return
    config = initial_config
    geoip_reader = initial_geoip

    asyncio.create_task(reload_config_periodically())
    asyncio.create_task(rotate_domains())
    asyncio.create_task(start_dot_server())
    asyncio.create_task(start_sni_proxy())

    uvicorn_config = uvicorn.Config(app, host="127.0.0.1", port=8080, log_level="info")
    server = uvicorn.Server(uvicorn_config)
    logging.info("DoH/WebSocket server listening on 127.0.0.1:8080")
    await server.serve()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Server shutting down.")
    except OSError as e:
        if e.errno == 98: # Address already in use
            logging.critical("Port 443 is already in use. Please stop the other service and try again.")
        else:
            logging.critical(f"An OS error occurred: {e}")