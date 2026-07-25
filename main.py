import asyncio
import base64
import json
import logging
import math
import os
import random
import signal
import ssl
import struct
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

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
from fastapi.responses import HTMLResponse

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
DEBUG = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
LOG_LEVEL = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
if DEBUG:
    logging.getLogger("uvicorn.access").setLevel(logging.DEBUG)
    logging.getLogger("uvicorn").setLevel(logging.DEBUG)
    logging.debug("Debug mode enabled via DEBUG env var")


# ---------------------------------------------------------------------------
# Rate Limiter (sliding window per IP)
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, max_connections: int = 30, window_seconds: int = 60):
        self.max_connections = max_connections
        self.window_seconds = window_seconds
        self._hits: Dict[float, List[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def allow(self, ip: str) -> bool:
        async with self._lock:
            now = time.monotonic()
            cutoff = now - self.window_seconds
            self._hits[ip] = [t for t in self._hits[ip] if t > cutoff]
            if len(self._hits[ip]) >= self.max_connections:
                logging.warning(f"Rate limit exceeded for {ip}: {len(self._hits[ip])} connections in {self.window_seconds}s")
                return False
            self._hits[ip].append(now)
            return True

    async def cleanup(self):
        while True:
            await asyncio.sleep(self.window_seconds * 2)
            async with self._lock:
                now = time.monotonic()
                cutoff = now - self.window_seconds
                stale = [ip for ip, times in self._hits.items() if not times or times[-1] <= cutoff]
                for ip in stale:
                    del self._hits[ip]


# ---------------------------------------------------------------------------
# Application State (replaces scattered globals)
# ---------------------------------------------------------------------------
class AppState:
    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.config_lock = asyncio.Lock()
        self.geoip_reader: Optional[geoip2.database.Reader] = None
        self.doh_client = httpx.AsyncClient(timeout=10.0)
        self.sni_map: Dict[int, str] = {}
        self.active_trigger_domain_index = 0
        self.bypass_settings_cache: Optional["BypassSettings"] = None
        self.rate_limiter = RateLimiter()
        self.mux_sessions: Dict[str, "MuxServerSession"] = {}
        self.mux_lock = asyncio.Lock()
        self._shutting_down = False

    def cache_bypass_settings(self):
        bypass_data = self.config.get("bypass_settings")
        if bypass_data:
            self.bypass_settings_cache = BypassSettings(bypass_data)

    def get_bypass(self) -> Optional["BypassSettings"]:
        if self.bypass_settings_cache:
            return self.bypass_settings_cache
        bypass_data = self.config.get("bypass_settings")
        if bypass_data:
            self.bypass_settings_cache = BypassSettings(bypass_data)
            return self.bypass_settings_cache
        return None


state = AppState()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
class BypassSettings:
    def __init__(self, data: Dict[str, Any]):
        self.enabled: bool = data.get("enabled", False)
        self.mode: str = data.get("mode", "shape")
        self.trigger_sni: str = data.get("trigger_sni", "")
        self.tunnel_path: str = data.get("tunnel_path", "")
        self.padding_size_range: List[int] = data.get("padding_size_range", [0, 0])
        self.delay_ms_range: List[int] = data.get("delay_ms_range", [0, 0])
        self.detect_mobile_networks: bool = data.get("detect_mobile_networks", False)
        self.mobile_carrier_names: List[str] = data.get("mobile_carrier_names", [])
        self.geoip_db_path: str = data.get("geoip_db_path", "")
        self.socks_host: str = data.get("socks_host", "127.0.0.1")
        self.socks_port: int = data.get("socks_port", 1080)
        self.multiplexing: bool = data.get("multiplexing", True)
        self.idle_timeout_seconds: int = data.get("idle_timeout_seconds", 120)
        # Secret from env var falls back to config (for backwards compat)
        self.bypass_secret: Optional[str] = os.environ.get(
            "SMARTSNI_SECRET", data.get("bypass_secret", None)
        )


class DomainFrontingSettings:
    def __init__(self, data: Dict[str, Any]):
        self.enabled: bool = data.get("enabled", False)
        self.front_host: str = data.get("front_host", "")
        self.front_sni: str = data.get("front_sni", "")
        self.upstream_host: str = data.get("upstream_host", "")


class CloudflareSettings:
    def __init__(self, data: Dict[str, Any]):
        self.enabled: bool = data.get("enabled", False)
        self.zone_id: str = data.get("zone_id", "")
        self.api_token: str = data.get("api_token", "")


def _mask_secret(val: Optional[str]) -> str:
    if not val:
        return "<none>"
    if len(val) <= 6:
        return "***"
    return val[:3] + "*" * (len(val) - 6) + val[-3:]


async def load_config(filename: str) -> Tuple[Optional[Dict[str, Any]], Optional[geoip2.database.Reader]]:
    logging.info(f"Loading configuration from {filename}...")
    try:
        with open(filename, "r") as f:
            new_config_data = json.load(f)
        logging.debug(f"Config loaded: {len(new_config_data)} keys: {list(new_config_data.keys())}")

        new_geoip_reader = None
        bypass_settings_data = new_config_data.get("bypass_settings")
        if bypass_settings_data:
            bypass = BypassSettings(bypass_settings_data)
            logging.debug(
                f"Bypass: enabled={bypass.enabled}, mode={bypass.mode}, "
                f"trigger_sni={bypass.trigger_sni}, secret={_mask_secret(bypass.bypass_secret)}, "
                f"multiplexing={bypass.multiplexing}"
            )
            if bypass.enabled and bypass.detect_mobile_networks and bypass.geoip_db_path:
                try:
                    new_geoip_reader = geoip2.database.Reader(bypass.geoip_db_path)
                    logging.info(f"GeoIP database loaded from {bypass.geoip_db_path}")
                except Exception as e:
                    logging.error(f"GeoIP load failed: {e}. Mobile detection disabled.")
                    new_config_data["bypass_settings"]["detect_mobile_networks"] = False

        return new_config_data, new_geoip_reader
    except Exception as e:
        logging.error(f"Config load failed ({filename}): {e}")
        return None, None


async def reload_config_periodically():
    while True:
        reload_interval = state.config.get("reload_interval_minutes", 1)
        if reload_interval <= 0:
            reload_interval = 1
        await asyncio.sleep(reload_interval * 60)

        logging.info("Checking for configuration updates...")
        new_config_data, new_geoip_reader = await load_config("config.json")
        if new_config_data:
            async with state.config_lock:
                if state.geoip_reader:
                    state.geoip_reader.close()
                state.config = new_config_data
                state.geoip_reader = new_geoip_reader
                state.cache_bypass_settings()
            logging.info("Configuration reloaded.")
        else:
            logging.warning("Config reload failed, keeping current config.")


async def rotate_domains():
    while True:
        await asyncio.sleep(60)
        async with state.config_lock:
            domains = state.config.get("trigger_domains", [])
            rotation_minutes = state.config.get("domain_rotation_minutes", 60)
        if len(domains) <= 1:
            continue
        await asyncio.sleep(rotation_minutes * 60)
        async with state.config_lock:
            domains = state.config.get("trigger_domains", [])
            if domains:
                state.active_trigger_domain_index = (state.active_trigger_domain_index + 1) % len(domains)
                new_domain = domains[state.active_trigger_domain_index]
                state.config["bypass_settings"]["trigger_sni"] = new_domain
                state.cache_bypass_settings()
                logging.info(f"Domain rotated to: {new_domain}")


async def get_active_trigger_domain() -> str:
    async with state.config_lock:
        domains = state.config.get("trigger_domains", [])
        if domains:
            return domains[state.active_trigger_domain_index % len(domains)]
        return state.config.get("bypass_settings", {}).get("trigger_sni", "")


# ---------------------------------------------------------------------------
# DNS Logic
# ---------------------------------------------------------------------------
def find_value_by_key_contains(m: Dict[str, str], substr: str) -> Optional[str]:
    substr_lower = substr.lower()
    for key, value in m.items():
        if key.lower() in substr_lower:
            return value
    return None


async def process_dns_query(query_bytes: bytes) -> bytes:
    try:
        msg = dns.message.from_wire(query_bytes)
        if not msg.question:
            raise ValueError("No DNS question in query")

        question = msg.question[0]
        domain_name = question.name.to_text(omit_final_dot=True)
        logging.debug(f"DNS query: {domain_name} (type={dns.rdatatype.to_text(question.rdtype)})")

        async with state.config_lock:
            domains_map = state.config.get("domains", {})

        ip_str = find_value_by_key_contains(domains_map, domain_name)
        if ip_str:
            logging.debug(f"DNS local match: {domain_name} -> {ip_str}")
            answer = dns.rrset.from_text(question.name, 3600, dns.rdataclass.IN, dns.rdatatype.A, ip_str)
            msg.answer.append(answer)
            msg.flags |= dns.flags.AA | dns.flags.QR
            return msg.to_wire()

        headers = {"content-type": "application/dns-message"}
        async with state.config_lock:
            upstream_doh = state.config.get("upstream_doh", "https://1.1.1.1/dns-query")
        logging.debug(f"DNS forwarding to: {upstream_doh}")
        resp = await state.doh_client.post(upstream_doh, content=query_bytes, headers=headers)
        resp.raise_for_status()
        return resp.content

    except Exception as e:
        logging.error(f"DNS query error: {e}")
        error_msg = dns.message.make_response(dns.message.from_wire(query_bytes))
        error_msg.set_rcode(dns.rcode.SERVFAIL)
        return error_msg.to_wire()


# ---------------------------------------------------------------------------
# DoT Server (RFC 7858 - multi-query support)
# ---------------------------------------------------------------------------
async def handle_dot_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    client_addr = writer.get_extra_info("peername")
    logging.debug(f"DoT connection from {client_addr}")
    try:
        while True:
            len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=60)
            msg_len = struct.unpack("!H", len_bytes)[0]
            if msg_len == 0:
                break
            logging.debug(f"DoT reading {msg_len} bytes query from {client_addr}")
            query_bytes = await reader.readexactly(msg_len)

            response_bytes = await process_dns_query(query_bytes)

            writer.write(struct.pack("!H", len(response_bytes)))
            writer.write(response_bytes)
            await writer.drain()
            logging.debug(f"DoT sent {len(response_bytes)} bytes response to {client_addr}")
    except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.TimeoutError):
        logging.debug(f"DoT client {client_addr} disconnected")
    except Exception as e:
        logging.error(f"DoT error from {client_addr}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()


async def start_dot_server():
    host = state.config.get("host")
    if not host:
        logging.error("Cannot start DoT: 'host' not in config.")
        return

    install_dir = pathlib.Path(os.environ.get("INSTALL_DIR", "/opt/smartSNI"))
    local_certs = install_dir / "certs"
    cert_path = state.config.get("dot_cert_path", "")
    key_path = state.config.get("dot_key_path", "")
    if not cert_path or not os.path.exists(cert_path):
        cert_path = str(local_certs / "fullchain.pem")
    if not key_path or not os.path.exists(key_path):
        key_path = str(local_certs / "privkey.pem")
    if not os.path.exists(cert_path):
        cert_path = f"/etc/letsencrypt/live/{host}/fullchain.pem"
        key_path = f"/etc/letsencrypt/live/{host}/privkey.pem"

    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        logging.error(f"DoT TLS certs not found ({cert_path}, {key_path}). DoT will not start.")
        return

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(cert_path, key_path)

    server = await asyncio.start_server(handle_dot_connection, "0.0.0.0", 853, ssl=ssl_context)
    logging.info("DoT server listening on 0.0.0.0:853")
    async with server:
        await server.serve_forever()


# ---------------------------------------------------------------------------
# SNI Parser
# ---------------------------------------------------------------------------
def parse_sni(client_hello: bytes) -> Optional[str]:
    try:
        if len(client_hello) < 5 or client_hello[0] != 0x16:
            return None
        if len(client_hello) < 9 or client_hello[5] != 0x01:
            return None

        offset = 43
        if offset >= len(client_hello):
            return None
        session_id_len = client_hello[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(client_hello):
            return None
        cipher_suites_len = int.from_bytes(client_hello[offset : offset + 2], "big")
        offset += 2 + cipher_suites_len

        if offset + 1 > len(client_hello):
            return None
        compression_methods_len = client_hello[offset]
        offset += 1 + compression_methods_len

        if offset + 2 > len(client_hello):
            return None
        extensions_len = int.from_bytes(client_hello[offset : offset + 2], "big")
        offset += 2

        end_of_extensions = offset + extensions_len
        while offset + 4 <= end_of_extensions:
            ext_type = int.from_bytes(client_hello[offset : offset + 2], "big")
            ext_len = int.from_bytes(client_hello[offset + 2 : offset + 4], "big")

            if ext_type == 0:  # server_name
                sni_offset = offset + 4
                if sni_offset + 5 > end_of_extensions:
                    return None
                name_type_offset = sni_offset + 2
                if client_hello[name_type_offset] != 0:
                    return None
                name_len_offset = name_type_offset + 1
                name_len = int.from_bytes(client_hello[name_len_offset : name_len_offset + 2], "big")
                name_offset = name_len_offset + 2
                if name_offset + name_len > end_of_extensions:
                    return None
                return client_hello[name_offset : name_offset + name_len].decode("utf-8")

            offset += 4 + ext_len

        return None
    except (IndexError, struct.error, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------------
# Traffic Shaping (improved: bimodal timing, always random padding)
# ---------------------------------------------------------------------------
def _bimodal_delay_ms(delay_range: List[int]) -> float:
    """Bimodal distribution: most packets fast, occasional longer delays.
    80% chance of < 5ms, 20% chance of 50-200ms (mimics real browser behavior)."""
    if random.random() < 0.80:
        return random.uniform(0.0, 5.0)
    return random.uniform(max(delay_range[0], 50), max(delay_range[1], 200))


def _apply_padding(data: bytes, pad_range: List[int]) -> bytes:
    """Apply random padding with 4-byte length prefix. Always uses random bytes."""
    if not pad_range or pad_range[1] <= 0:
        return data
    min_pad, max_pad = pad_range
    pad_size = random.randint(min_pad, max_pad)
    padding = os.urandom(pad_size)
    return data + pad_size.to_bytes(4, "big") + padding


async def shape_and_relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, settings: "BypassSettings"):
    total_bytes = 0
    try:
        while not reader.at_eof():
            data = await reader.read(4096)
            if not data:
                break

            data_to_write = data
            if settings.padding_size_range and settings.padding_size_range[1] > 0:
                min_pad, max_pad = settings.padding_size_range
                pad_size = random.randint(min_pad, max_pad)
                data_to_write += os.urandom(pad_size)  # Random bytes, not \x00

            writer.write(data_to_write)
            await writer.drain()
            total_bytes += len(data)

            if settings.delay_ms_range and settings.delay_ms_range[1] > 0:
                delay = _bimodal_delay_ms(settings.delay_ms_range) / 1000.0
                await asyncio.sleep(delay)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        logging.debug(f"shape_and_relay finished: {total_bytes} bytes")
        writer.close()


async def obfuscate_and_relay_ws(source_reader: asyncio.StreamReader, dest_ws: WebSocket, settings: "BypassSettings"):
    total_bytes = 0
    try:
        while not source_reader.at_eof():
            data = await source_reader.read(2048)
            if not data:
                break
            data = _apply_padding(data, settings.padding_size_range)
            await dest_ws.send_bytes(data)
            total_bytes += len(data)
    except (WebSocketDisconnect, ConnectionResetError):
        pass
    finally:
        logging.debug(f"obfuscate_and_relay_ws finished: {total_bytes} bytes")


async def relay_streams(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, idle_timeout: int = 120):
    total_bytes = 0
    try:
        while not reader.at_eof():
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=idle_timeout)
            except asyncio.TimeoutError:
                logging.debug(f"relay_streams: idle timeout ({idle_timeout}s)")
                break
            if not data:
                break
            writer.write(data)
            await writer.drain()
            total_bytes += len(data)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        logging.debug(f"relay_streams finished: {total_bytes} bytes")
        writer.close()


# ---------------------------------------------------------------------------
# SOCKS5 Handshake
# ---------------------------------------------------------------------------
async def handle_socks5_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[Tuple[str, int]]:
    try:
        ver_nmethods = await reader.readexactly(2)
        if ver_nmethods[0] != 0x05:
            return None
        methods_count = ver_nmethods[1]
        methods = await reader.readexactly(methods_count)
        if 0x00 not in methods:
            return None
        writer.write(b"\x05\x00")
        await writer.drain()

        ver_cmd_rsv_atyp = await reader.readexactly(4)
        if ver_cmd_rsv_atyp[0] != 0x05 or ver_cmd_rsv_atyp[1] != 0x01:
            return None

        atyp = ver_cmd_rsv_atyp[3]
        if atyp == 0x03:
            domain_len = (await reader.readexactly(1))[0]
            target_host = (await reader.readexactly(domain_len)).decode()
        elif atyp == 0x01:
            target_host = ".".join(str(b) for b in await reader.readexactly(4))
        else:
            return None

        target_port = int.from_bytes(await reader.readexactly(2), "big")
        logging.debug(f"SOCKS5 connect: {target_host}:{target_port}")
        return target_host, target_port
    except (asyncio.IncompleteReadError, ConnectionResetError, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------------
# SNI Callback
# ---------------------------------------------------------------------------
def _sni_callback(ssl_sock, server_name, ssl_context):
    try:
        peer = ssl_sock.getpeername()
        state.sni_map[peer] = server_name
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Multiplexer Protocol (server-side)
# ---------------------------------------------------------------------------
# Frame format: [type:1][stream_id:4][length:4][payload]
FRAME_TYPE_NEW_STREAM = 0x01
FRAME_TYPE_DATA = 0x02
FRAME_TYPE_CLOSE = 0x03
FRAME_TYPE_FIN = 0x04
FRAME_HDR_SIZE = 9  # 1 + 4 + 4

MUX_STATUS_OK = 0x00
MUX_STATUS_ERR = 0x01


class MuxServerSession:
    def __init__(self, websocket: WebSocket, settings: BypassSettings):
        self.ws = websocket
        self.settings = settings
        self.streams: Dict[int, asyncio.StreamWriter] = {}
        self._lock = asyncio.Lock()

    async def handle(self):
        reader_task = asyncio.create_task(self._read_loop())
        await reader_task

    async def _read_loop(self):
        try:
            while True:
                data = await self.ws.receive_bytes()
                if len(data) < FRAME_HDR_SIZE:
                    continue
                frame_type = data[0]
                stream_id = int.from_bytes(data[1:5], "big")
                frame_len = int.from_bytes(data[5:9], "big")
                payload = data[9 : 9 + frame_len] if frame_len > 0 else b""

                if frame_type == FRAME_TYPE_NEW_STREAM:
                    asyncio.create_task(self._handle_new_stream(stream_id, payload))
                elif frame_type == FRAME_TYPE_DATA:
                    asyncio.create_task(self._handle_data(stream_id, payload))
                elif frame_type == FRAME_TYPE_CLOSE:
                    await self._handle_close(stream_id)
                elif frame_type == FRAME_TYPE_FIN:
                    await self._handle_fin(stream_id)
        except WebSocketDisconnect:
            pass
        finally:
            await self._cleanup_all()

    async def _handle_new_stream(self, stream_id: int, payload: bytes):
        """Parse target_host:port from payload, connect, send status."""
        try:
            if len(payload) < 3:
                await self._send_status(stream_id, MUX_STATUS_ERR)
                return
            host_len = payload[0]
            if len(payload) < 1 + host_len + 2:
                await self._send_status(stream_id, MUX_STATUS_ERR)
                return
            host = payload[1 : 1 + host_len].decode("ascii")
            port = int.from_bytes(payload[1 + host_len : 3 + host_len], "big")

            logging.info(f"MUX stream {stream_id}: connecting to {host}:{port}")
            reader, writer = await asyncio.open_connection(host, port)
            async with self._lock:
                self.streams[stream_id] = writer

            await self._send_status(stream_id, MUX_STATUS_OK)
            asyncio.create_task(self._relay_backend_to_ws(stream_id, reader))
        except Exception as e:
            logging.error(f"MUX stream {stream_id} connect failed: {e}")
            await self._send_status(stream_id, MUX_STATUS_ERR)

    async def _handle_data(self, stream_id: int, payload: bytes):
        async with self._lock:
            writer = self.streams.get(stream_id)
        if writer:
            try:
                writer.write(payload)
                await writer.drain()
            except Exception:
                await self._handle_close(stream_id)

    async def _handle_close(self, stream_id: int):
        async with self._lock:
            writer = self.streams.pop(stream_id, None)
        if writer:
            writer.close()

    async def _handle_fin(self, stream_id: int):
        async with self._lock:
            writer = self.streams.get(stream_id)
        if writer:
            try:
                writer.close()
            except Exception:
                pass
            async with self._lock:
                self.streams.pop(stream_id, None)
        await self._send_frame(FRAME_TYPE_FIN, stream_id, b"")

    async def _send_status(self, stream_id: int, status: int):
        await self._send_frame(FRAME_TYPE_NEW_STREAM, stream_id, bytes([status]))

    async def _send_frame(self, frame_type: int, stream_id: int, payload: bytes):
        hdr = bytes([frame_type]) + stream_id.to_bytes(4, "big") + len(payload).to_bytes(4, "big")
        data = hdr + payload
        try:
            await self.ws.send_bytes(_apply_padding(data, self.settings.padding_size_range))
        except WebSocketDisconnect:
            pass

    async def _relay_backend_to_ws(self, stream_id: int, reader: asyncio.StreamReader):
        try:
            while not reader.at_eof():
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=self.settings.idle_timeout_seconds)
                except asyncio.TimeoutError:
                    logging.debug(f"MUX stream {stream_id}: backend idle timeout")
                    break
                if not data:
                    break
                await self._send_frame(FRAME_TYPE_DATA, stream_id, data)
            await self._send_frame(FRAME_TYPE_FIN, stream_id, b"")
        except (asyncio.IncompleteReadError, ConnectionResetError):
            await self._send_frame(FRAME_TYPE_FIN, stream_id, b"")
        finally:
            await self._handle_close(stream_id)

    async def _cleanup_all(self):
        async with self._lock:
            for sid, writer in self.streams.items():
                try:
                    writer.close()
                except Exception:
                    pass
            self.streams.clear()


# ---------------------------------------------------------------------------
# SNI Proxy
# ---------------------------------------------------------------------------
async def handle_connection(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
    server_name = None
    peer_addr = client_writer.get_extra_info("peername")
    logging.debug(f"New TLS connection from {peer_addr}")

    try:
        transport = client_writer.transport
        sock = transport.get_extra_info("socket")
        if sock:
            server_name = state.sni_map.pop(peer_addr, None)
            if not server_name:
                server_name = getattr(sock, '_smart_sni', None)

        if not server_name:
            logging.warning(f"SNI not found for {peer_addr}. Closing.")
            return

        logging.info(f"SNI: {server_name}")

        proxy_mode = "direct"
        target_host = ""
        target_port = 443
        use_bypass = False

        async with state.config_lock:
            current_host = state.config.get("host", "")
            bypass = state.get_bypass()
            trigger_domains = state.config.get("trigger_domains", [])

        if bypass and bypass.enabled:
            sni_lower = server_name.lower()
            is_trigger = sni_lower == bypass.trigger_sni.lower() or any(
                sni_lower == td.lower() for td in trigger_domains
            )
            if is_trigger:
                use_bypass = True
            elif bypass.detect_mobile_networks and state.geoip_reader and peer_addr:
                ip_str = peer_addr[0]
                try:
                    record = state.geoip_reader.isp(ip_str)
                    client_isp = record.isp.lower()
                    client_org = record.organization.lower()
                    for carrier in bypass.mobile_carrier_names:
                        if carrier.lower() in client_isp or carrier.lower() in client_org:
                            logging.info(f"Mobile network detected ({record.isp}). Bypass active.")
                            use_bypass = True
                            break
                except geoip2.errors.AddressNotFoundError:
                    logging.debug(f"GeoIP: {ip_str} not found")
                except Exception as e:
                    logging.warning(f"GeoIP lookup failed for {ip_str}: {e}")

        if use_bypass:
            if bypass.mode == "websocket":
                proxy_mode = "websocket_forward"
                target_host = "127.0.0.1"
                target_port = 8080
                logging.info(f"Bypass: WebSocket mode for {server_name}")
            else:
                try:
                    socks_target = await handle_socks5_handshake(client_reader, client_writer)
                    if not socks_target:
                        logging.warning(f"SOCKS5 handshake failed for {server_name}")
                        return
                    target_host, target_port = socks_target
                    client_writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                    await client_writer.drain()
                    proxy_mode = "shape"
                    logging.info(f"Bypass: Shape mode for {server_name} -> {target_host}:{target_port}")
                except (asyncio.IncompleteReadError, ConnectionResetError):
                    return
        else:
            if server_name.lower() == current_host.lower():
                proxy_mode = "cover"
                target_host = "127.0.0.1"
                target_port = 8080
            else:
                target_host = server_name
                target_port = 443

        if proxy_mode == "shape" and not use_bypass:
            target_host = server_name
            target_port = 443

        idle_timeout = bypass.idle_timeout_seconds if bypass else 120
        logging.debug(f"SNI proxy: {server_name} mode={proxy_mode} -> {target_host}:{target_port}")

        if proxy_mode == "direct":
            try:
                target_ssl = ssl.create_default_context()
                backend_reader, backend_writer = await asyncio.open_connection(target_host, target_port, ssl=target_ssl)
                logging.info(f"Direct TLS relay to {target_host}:{target_port}")
            except Exception as e:
                logging.warning(f"Could not connect to {target_host}:{target_port}: {e}")
                return
        else:
            backend_reader, backend_writer = await asyncio.open_connection(target_host, target_port)
            logging.info(f"Relay to {target_host}:{target_port}")

        if proxy_mode == "shape":
            task1 = asyncio.create_task(shape_and_relay(client_reader, backend_writer, bypass))
            task2 = asyncio.create_task(shape_and_relay(backend_reader, client_writer, bypass))
        else:
            task1 = asyncio.create_task(relay_streams(client_reader, backend_writer, idle_timeout))
            task2 = asyncio.create_task(relay_streams(backend_reader, client_writer, idle_timeout))

        await asyncio.gather(task1, task2)

    except (ConnectionRefusedError, asyncio.TimeoutError):
        logging.warning(f"Connection failed for SNI: {server_name}")
    except Exception as e:
        if server_name:
            logging.error(f"Error for SNI {server_name}: {e}")
    finally:
        logging.debug(f"Connection closed for {server_name}")
        client_writer.close()


async def start_sni_proxy():
    import pathlib

    ssl_context = None
    install_dir = pathlib.Path(os.environ.get("INSTALL_DIR", "/opt/smartSNI"))
    local_certs = install_dir / "certs"

    cert_paths = [
        (local_certs / "fullchain.pem", local_certs / "privkey.pem"),
    ]
    letsencrypt_dir = pathlib.Path("/etc/letsencrypt/live")
    async with state.config_lock:
        domains_to_try = [state.config.get("host", "")] + state.config.get("trigger_domains", [])
    for domain in domains_to_try:
        if domain:
            cert_paths.append((letsencrypt_dir / domain / "fullchain.pem", letsencrypt_dir / domain / "privkey.pem"))

    for cert_path, key_path in cert_paths:
        if cert_path.exists() and key_path.exists():
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(str(cert_path), str(key_path))
            ssl_context.set_servername_callback(_sni_callback)
            logging.info(f"SNI proxy: certs from {cert_path}")
            break

    if ssl_context:
        server = await asyncio.start_server(handle_connection, "0.0.0.0", 443, ssl=ssl_context)
        logging.info("SNI proxy listening on 0.0.0.0:443")
    else:
        logging.warning("No TLS certs found. SNI proxy cannot start on port 443.")
        return

    async with server:
        await server.serve_forever()


# ---------------------------------------------------------------------------
# FastAPI App (DoH, Cover Website, WebSocket with multiplexing)
# ---------------------------------------------------------------------------
app = FastAPI()


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.monotonic()
    method = request.method
    path = request.url.path
    client = request.client.host if request.client else "unknown"
    logging.debug(f"--> {method} {path} from {client}")
    try:
        response = await call_next(request)
        elapsed_ms = (time.monotonic() - start) * 1000
        logging.debug(f"<-- {method} {path} {response.status_code} ({elapsed_ms:.1f}ms)")
        return response
    except Exception as e:
        elapsed_ms = (time.monotonic() - start) * 1000
        logging.error(f"<-- {method} {path} ERROR ({elapsed_ms:.1f}ms): {e}")
        raise


# --- Cover Website ---
ROBOTS_TXT = """User-agent: *
Disallow: /wstunnel
Disallow: /api/
Disallow: /dns-query
"""

COVER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureMail - Encrypted Communications</title>
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
        .container { max-width: 800px; margin: 0, auto; padding: 40px 20px; }
        header { text-align: center; padding: 60px 0 40px; }
        h1 { font-size: 2.5rem; color: #38bdf8; margin-bottom: 12px; }
        .subtitle { color: #94a3b8; font-size: 1.1rem; }
        .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 24px; margin-top: 40px; }
        .feature { background: #1e293b; border-radius: 12px; padding: 24px; border: 1px solid #334155; }
        .feature h3 { color: #38bdf8; margin-bottom: 8px; }
        .feature p { color: #94a3b8; font-size: 0.9rem; line-height: 1.5; }
        .inbox-preview { margin-top: 40px; background: #1e293b; border-radius: 12px; border: 1px solid #334155; overflow: hidden; }
        .inbox-header { padding: 16px 24px; border-bottom: 1px solid #334155; color: #38bdf8; font-weight: 600; }
        .inbox-item { padding: 12px 24px; border-bottom: 1px solid #1e293b22; display: flex; justify-content: space-between; }
        .inbox-item:hover { background: #1e293b88; }
        .inbox-sender { color: #e2e8f0; font-weight: 500; }
        .inbox-subject { color: #94a3b8; font-size: 0.85rem; }
        .inbox-time { color: #475569; font-size: 0.8rem; white-space: nowrap; }
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
        <div class="inbox-preview">
            <div class="inbox-header">Inbox (3 messages)</div>
            <div class="inbox-item"><div><div class="inbox-sender">Security Team</div><div class="inbox-subject">Your monthly security report is ready</div></div><div class="inbox-time">2h ago</div></div>
            <div class="inbox-item"><div><div class="inbox-sender">Workspace</div><div class="inbox-subject">New shared document: Q4 Planning</div></div><div class="inbox-time">5h ago</div></div>
            <div class="inbox-item"><div><div class="inbox-sender">System</div><div class="inbox-subject">Encryption key rotation completed</div></div><div class="inbox-time">1d ago</div></div>
        </div>
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


@app.get("/robots.txt")
async def robots_txt():
    return Response(content=ROBOTS_TXT, media_type="text/plain")


@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)


@app.get("/dns-query")
@app.post("/dns-query")
async def doh_handler(request: Request):
    if request.method == "POST":
        query_bytes = await request.body()
    else:
        dns_param = request.query_params.get("dns")
        if not dns_param:
            return Response(content="Missing 'dns' query parameter", status_code=400)
        try:
            query_bytes = base64.urlsafe_b64decode(dns_param + "=" * (4 - len(dns_param) % 4))
        except Exception:
            return Response(content="Invalid 'dns' query parameter", status_code=400)

    response_bytes = await process_dns_query(query_bytes)
    return Response(content=response_bytes, media_type="application/dns-message")


@app.get("/{full_path:path}")
async def website_handler(request: Request, full_path: str):
    return Response(content=COVER_HTML, media_type="text/html")


@app.websocket("/{full_path:path}")
async def websocket_handler(websocket: WebSocket, full_path: str):
    logging.debug(f"WebSocket attempt: path=/{full_path}")
    async with state.config_lock:
        bypass = state.get_bypass()
        fronting_data = state.config.get("domain_fronting", {})
        fronting = DomainFrontingSettings(fronting_data) if fronting_data else None
        cf_data = state.config.get("cloudflare", {})
        cf = CloudflareSettings(cf_data) if cf_data else None

    if not (bypass and bypass.enabled and bypass.mode == "websocket"):
        await websocket.close(code=4004)
        return

    path_matches = f"/{full_path}".startswith(bypass.tunnel_path)
    if not path_matches:
        await websocket.close(code=4004)
        return

    # Domain fronting
    effective_host = websocket.headers.get("Host", "")
    forwarded_host = websocket.headers.get("X-Forwarded-Host", "")
    if fronting and fronting.enabled and forwarded_host:
        effective_host = forwarded_host

    # Cloudflare real IP
    real_client_ip = None
    if cf and cf.enabled:
        cf_ip = websocket.headers.get("CF-Connecting-IP")
        if cf_ip:
            real_client_ip = cf_ip

    # Rate limiting
    client_ip = real_client_ip or (websocket.client.host if websocket.client else "unknown")
    if not await state.rate_limiter.allow(client_ip):
        logging.warning(f"Rate limited: {client_ip}")
        await websocket.close(code=429)
        return

    # Authentication
    if bypass.bypass_secret:
        auth_header = websocket.headers.get("Authorization")
        if not auth_header or auth_header != f"Bearer {bypass.bypass_secret}":
            logging.warning(f"Auth failed for /{full_path} from {client_ip}")
            await websocket.close(code=4001)
            return
        logging.debug("WebSocket: auth OK")

    await websocket.accept()
    logging.info(f"WebSocket: client connected ({client_ip})")

    # Send hello
    hello_msg = {"type": "hello", "status": "connected"}
    if bypass.multiplexing:
        hello_msg["multiplexing"] = True
    await websocket.send_json(hello_msg)

    # Detect protocol: first bytes tell us if it's multiplexed or SOCKS5
    try:
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=30)
        if "bytes" in first_msg:
            first_data = first_msg["bytes"]
        elif "text" in first_msg:
            first_data = first_msg["text"].encode()
        else:
            await websocket.close(code=4000)
            return
    except asyncio.TimeoutError:
        logging.warning("Client did not send initial data within 30s")
        await websocket.close(code=4008)
        return

    # Detect multiplexing: frame type 0x01
    if len(first_data) >= FRAME_HDR_SIZE and first_data[0] == FRAME_TYPE_NEW_STREAM:
        logging.info("Client uses multiplexed protocol")
        session = MuxServerSession(websocket, bypass)
        async with state.mux_lock:
            state.mux_sessions[client_ip] = session
        try:
            # Process the first frame, then continue reading
            stream_id = int.from_bytes(first_data[1:5], "big")
            frame_len = int.from_bytes(first_data[5:9], "big")
            payload = first_data[9 : 9 + frame_len] if frame_len > 0 else b""
            asyncio.create_task(session._handle_new_stream(stream_id, payload))
            await session._read_loop()
        finally:
            async with state.mux_lock:
                state.mux_sessions.pop(client_ip, None)
        return

    # Fallback: SOCKS5 over WebSocket (legacy path)
    logging.info("Client uses legacy SOCKS5-over-WebSocket")
    socks_host = bypass.socks_host
    socks_port = bypass.socks_port
    target_log_name = f"{socks_host}:{socks_port} (SOCKS)"

    try:
        reader, writer = await asyncio.open_connection(socks_host, socks_port)

        async def ws_to_socks(ws: WebSocket, socks_writer: asyncio.StreamWriter):
            total = 0
            try:
                # Process the first message we already received
                if first_data:
                    socks_writer.write(first_data)
                    await socks_writer.drain()
                    total += len(first_data)
                while True:
                    msg = await ws.receive()
                    if "bytes" in msg:
                        data = msg["bytes"]
                    elif "text" in msg:
                        data = msg["text"].encode()
                    else:
                        break
                    if data:
                        socks_writer.write(data)
                        await socks_writer.drain()
                        total += len(data)
            except WebSocketDisconnect:
                pass
            finally:
                logging.debug(f"ws_to_socks: {total} bytes")
                socks_writer.close()

        task_c2s = asyncio.create_task(ws_to_socks(websocket, writer))
        task_s2c = asyncio.create_task(obfuscate_and_relay_ws(reader, websocket, bypass))
        await asyncio.gather(task_c2s, task_s2c)

    except Exception as e:
        logging.error(f"WebSocket bypass error: {e}")
    finally:
        logging.info(f"WebSocket: tunnel closed for {client_ip}")


# ---------------------------------------------------------------------------
# Main Entry Point (with graceful shutdown)
# ---------------------------------------------------------------------------
async def shutdown_handler(loop):
    logging.info("Shutdown signal received...")
    state._shutting_down = True

    # Cancel background tasks
    for task in asyncio.all_tasks():
        if task is not asyncio.current_task():
            task.cancel()

    # Close active mux sessions
    async with state.mux_lock:
        for session in state.mux_sessions.values():
            await session._cleanup_all()
        state.mux_sessions.clear()

    # Close resources
    await state.doh_client.aclose()
    if state.geoip_reader:
        state.geoip_reader.close()

    logging.info("Shutdown complete.")


async def main():
    logging.info(f"SmartSNI server starting... (debug={'ON' if DEBUG else 'OFF'})")

    initial_config, initial_geoip = await load_config("config.json")
    if not initial_config:
        logging.critical("Could not load initial configuration. Exiting.")
        return
    state.config = initial_config
    state.geoip_reader = initial_geoip
    state.cache_bypass_settings()

    # Log masked config summary
    bypass = state.get_bypass()
    if bypass:
        logging.info(
            f"Bypass: enabled={bypass.enabled}, mode={bypass.mode}, "
            f"multiplexing={bypass.multiplexing}, secret={_mask_secret(bypass.bypass_secret)}, "
            f"pad={bypass.padding_size_range}, delay={bypass.delay_ms_range}, "
            f"idle_timeout={bypass.idle_timeout_seconds}s"
        )

    asyncio.create_task(reload_config_periodically())
    asyncio.create_task(rotate_domains())
    asyncio.create_task(start_dot_server())
    asyncio.create_task(start_sni_proxy())
    asyncio.create_task(state.rate_limiter.cleanup())

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown_handler(loop)))

    log_level = "debug" if DEBUG else "info"
    uvicorn_config = uvicorn.Config(app, host="127.0.0.1", port=8080, log_level=log_level)
    server = uvicorn.Server(uvicorn_config)
    logging.info("DoH/WebSocket server listening on 127.0.0.1:8080")
    await server.serve()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Server shutting down.")
    except OSError as e:
        if e.errno == 98:
            logging.critical("Port 443 is already in use.")
        else:
            logging.critical(f"OS error: {e}")
