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
        resp = await doh_client.post("https://1.1.1.1/dns-query", content=query_bytes, headers=headers)
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

    cert_path = f"/etc/letsencrypt/live/{host}/fullchain.pem"
    key_path = f"/etc/letsencrypt/live/{host}/privkey.pem"

    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        logging.error(f"TLS certificates not found for DoT server at {cert_path}. DoT will not start.")
        return

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(cert_path, key_path)

    server = await asyncio.start_server(
        handle_dot_connection, '127.0.0.1', 853, ssl=ssl_context
    )
    logging.info("DoT server listening on 127.0.0.1:853")
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


async def handle_connection(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
    """Main entry point for incoming connections on port 443."""
    peek_buffer = b''
    server_name = None
    try:
        # 1. Read the 5-byte TLS record header to get the length of the ClientHello.
        header = await asyncio.wait_for(client_reader.readexactly(5), timeout=5.0)
        if header[0] != 0x16:  # 0x16 = Handshake
            logging.warning("Incoming connection is not a TLS handshake. Closing.")
            return

        record_len = int.from_bytes(header[3:5], 'big')

        # 2. Read the rest of the record.
        record_body = await asyncio.wait_for(client_reader.readexactly(record_len), timeout=5.0)

        # 3. We now have the full ClientHello packet.
        peek_buffer = header + record_body

        server_name = parse_sni(peek_buffer)

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

        if bypass and bypass.enabled:
            if bypass.trigger_sni and server_name.lower() == bypass.trigger_sni.lower():
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
                logging.info(f"WebSocket bypass activated for SNI: {server_name}")
            else:  # shape mode
                proxy_mode = "shape"
                target_host = server_name
                target_port = 443
                logging.info(f"Shape bypass activated for SNI: {server_name}")
        else:  # direct proxy
            if server_name.lower() == current_host.lower():
                target_host = "127.0.0.1"
                target_port = 853
            else:
                target_host = server_name
                target_port = 443

        backend_reader, backend_writer = await asyncio.open_connection(target_host, target_port)
        backend_writer.write(peek_buffer)
        await backend_writer.drain()

        if proxy_mode == "shape":
            task1 = asyncio.create_task(shape_and_relay(client_reader, backend_writer, bypass))
            task2 = asyncio.create_task(shape_and_relay(backend_reader, client_writer, bypass))
        else:  # direct and websocket_forward
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


# --- FastAPI App (DoH and WebSocket) ---
app = FastAPI()


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


@app.websocket("/{full_path:path}")
async def websocket_handler(websocket: WebSocket, full_path: str):
    async with config_lock:
        bypass_settings_data = config.get("bypass_settings")
        bypass = BypassSettings(bypass_settings_data) if bypass_settings_data else None

    if not (bypass and bypass.enabled and bypass.mode == "websocket" and f"/{full_path}" == bypass.tunnel_path):
        await websocket.close(code=1008)  # Policy Violation
        return

    await websocket.accept()

    target = websocket.headers.get("Bypass-Target")
    if not target:
        logging.warning("WebSocket bypass: Missing Bypass-Target header")
        await websocket.close(code=1008)
        return

    try:
        host, port_str = target.split(":")
        port = int(port_str)
    except ValueError:
        logging.warning(f"WebSocket bypass: Invalid Bypass-Target format: {target}")
        await websocket.close(code=1008)
        return

    try:
        reader, writer = await asyncio.open_connection(host, port)
        logging.info(f"WebSocket bypass: Tunneling to {target}")

        async def ws_to_tcp(ws: WebSocket, tcp_writer: asyncio.StreamWriter):
            try:
                while True:
                    data = await ws.receive_bytes()
                    tcp_writer.write(data)
                    await tcp_writer.drain()
            except WebSocketDisconnect:
                pass
            finally:
                tcp_writer.close()

        async def tcp_to_ws(tcp_reader: asyncio.StreamReader, ws: WebSocket):
            try:
                while not tcp_reader.at_eof():
                    data = await tcp_reader.read(4096)
                    if not data: break
                    await ws.send_bytes(data)
            except (WebSocketDisconnect, ConnectionResetError):
                pass
            finally:
                await ws.close()

        task1 = asyncio.create_task(ws_to_tcp(websocket, writer))
        task2 = asyncio.create_task(tcp_to_ws(reader, websocket))
        await asyncio.gather(task1, task2)

    except Exception as e:
        logging.error(f"WebSocket bypass error for target {target}: {e}")
    finally:
        logging.info(f"WebSocket bypass: Tunnel to {target} closed")


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