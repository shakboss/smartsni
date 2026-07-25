import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import pathlib
import random
import secrets
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
# HMAC Auth Helper
# ---------------------------------------------------------------------------
def _hmac_sign(message: str, secret: str) -> str:
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def _hmac_verify(message: str, signature: str, secret: str) -> bool:
    expected = _hmac_sign(message, secret)
    return hmac.compare_digest(expected, signature)


def _generate_session_token(secret: str) -> Tuple[str, float]:
    timestamp = time.time()
    nonce = secrets.token_hex(16)
    payload = f"{timestamp}:{nonce}"
    sig = _hmac_sign(payload, secret)
    token = base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()
    return token, timestamp


def _verify_session_token(token: str, secret: str, max_age: int = 3600) -> bool:
    try:
        decoded = base64.urlsafe_b64decode(token + "==").decode()
        parts = decoded.split(":")
        if len(parts) != 3:
            return False
        timestamp_str, nonce, sig = parts
        timestamp = float(timestamp_str)
        if time.time() - timestamp > max_age:
            return False
        return _hmac_verify(f"{timestamp_str}:{nonce}", sig, secret)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# IP Normalization (IPv6-aware)
# ---------------------------------------------------------------------------
def _normalize_ip(ip_str: str) -> str:
    try:
        addr = ipaddress.ip_address(ip_str)
        if isinstance(addr, ipaddress.IPv6Address):
            mapped = addr.ipv4_mapped
            if mapped:
                return str(mapped)
            return str(addr.ipv6_mapped or addr)
        return str(addr)
    except ValueError:
        return ip_str


# ---------------------------------------------------------------------------
# Rate Limiter (sliding window per IP, IPv6-aware)
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, max_connections: int = 30, window_seconds: int = 60):
        self.max_connections = max_connections
        self.window_seconds = window_seconds
        self._hits: Dict[str, List[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def allow(self, ip: str) -> bool:
        normalized = _normalize_ip(ip)
        async with self._lock:
            now = time.monotonic()
            cutoff = now - self.window_seconds
            self._hits[normalized] = [t for t in self._hits[normalized] if t > cutoff]
            if len(self._hits[normalized]) >= self.max_connections:
                logging.warning(
                    f"Rate limit exceeded for {normalized}: "
                    f"{len(self._hits[normalized])} connections in {self.window_seconds}s"
                )
                return False
            self._hits[normalized].append(now)
            return True

    async def cleanup(self):
        while True:
            await asyncio.sleep(self.window_seconds * 2)
            async with self._lock:
                now = time.monotonic()
                cutoff = now - self.window_seconds
                stale = [
                    ip for ip, times in self._hits.items()
                    if not times or times[-1] <= cutoff
                ]
                for ip in stale:
                    del self._hits[ip]


# ---------------------------------------------------------------------------
# Application State
# ---------------------------------------------------------------------------
class AppState:
    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.config_lock = asyncio.Lock()
        self.geoip_reader: Optional[geoip2.database.Reader] = None
        self.doh_client = httpx.AsyncClient(timeout=10.0)
        self.active_trigger_domain_index = 0
        self.bypass_settings_cache: Optional["BypassSettings"] = None
        self.rate_limiter = RateLimiter()
        self.mux_sessions: Dict[str, "MuxServerSession"] = {}
        self.mux_lock = asyncio.Lock()
        self._shutting_down = False
        self._sni_ssl_context: Optional[ssl.SSLContext] = None
        self._mux_key: bytes = os.urandom(32)

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

    @property
    def mux_key(self) -> bytes:
        secret = self.get_bypass().bypass_secret if self.get_bypass() else None
        if secret:
            return hashlib.sha256(secret.encode()).digest()
        return self._mux_key


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
        self.socks_username: str = data.get("socks_username", "")
        self.socks_password: str = data.get("socks_password", "")
        self.multiplexing: bool = data.get("multiplexing", True)
        self.idle_timeout_seconds: int = data.get("idle_timeout_seconds", 120)
        self.bypass_secret: Optional[str] = os.environ.get(
            "SMARTSNI_SECRET", data.get("bypass_secret", None)
        )
        self.fronting_enabled: bool = data.get("fronting_enabled", False)
        self.fronting_hosts: List[str] = data.get("fronting_hosts", [])


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


# ---------------------------------------------------------------------------
# TLS Fingerprint Hardening
# ---------------------------------------------------------------------------
def _create_hardened_ssl_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))

    # Nginx-like cipher suite order to mimic a real web server
    ctx.set_ciphers(
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES128-SHA256"
    )

    # TLS 1.2 + 1.3 only
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    # Server picks cipher order
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.options |= ssl.OP_SINGLE_ECDH_USE

    # ALPN support (http/1.1 only — bridge does not terminate HTTP/2)
    ctx.set_alpn_protocols(["http/1.1"])

    # Session tickets
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    return ctx


def _create_outbound_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ctx.options |= ssl.OP_NO_COMPRESSION
    return ctx


async def load_config(filename: str) -> Tuple[Optional[Dict[str, Any]], Optional[geoip2.database.Reader]]:
    logging.info(f"Loading configuration from {filename}...")
    try:
        with open(filename, "r") as f:
            new_config_data = json.load(f)
        logging.debug(f"Config loaded: {len(new_config_data)} keys")

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
                state.active_trigger_domain_index = (
                    (state.active_trigger_domain_index + 1) % len(domains)
                )
                new_domain = domains[state.active_trigger_domain_index]
                state.config["bypass_settings"]["trigger_sni"] = new_domain
                state.cache_bypass_settings()
                logging.info(f"Domain rotated to: {new_domain}")


# ---------------------------------------------------------------------------
# DNS Logic (exact match instead of substring)
# ---------------------------------------------------------------------------
def _exact_dns_match(domains_map: Dict[str, str], query_domain: str) -> Optional[str]:
    q = query_domain.lower().rstrip(".")
    for key, value in domains_map.items():
        if key.lower().rstrip(".") == q:
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

        ip_str = _exact_dns_match(domains_map, domain_name)
        if ip_str:
            logging.debug(f"DNS local match: {domain_name} -> {ip_str}")
            answer = dns.rrset.from_text(
                question.name, 3600, dns.rdataclass.IN, dns.rdatatype.A, ip_str
            )
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
# DoT Server (RFC 7858)
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

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(cert_path, key_path)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

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
        cipher_suites_len = int.from_bytes(client_hello[offset:offset + 2], "big")
        offset += 2 + cipher_suites_len

        if offset + 1 > len(client_hello):
            return None
        compression_methods_len = client_hello[offset]
        offset += 1 + compression_methods_len

        if offset + 2 > len(client_hello):
            return None
        extensions_len = int.from_bytes(client_hello[offset:offset + 2], "big")
        offset += 2

        end_of_extensions = offset + extensions_len
        while offset + 4 <= end_of_extensions:
            ext_type = int.from_bytes(client_hello[offset:offset + 2], "big")
            ext_len = int.from_bytes(client_hello[offset + 2:offset + 4], "big")

            if ext_type == 0:  # server_name
                sni_offset = offset + 4
                if sni_offset + 5 > end_of_extensions:
                    return None
                name_type_offset = sni_offset + 2
                if client_hello[name_type_offset] != 0:
                    return None
                name_len_offset = name_type_offset + 1
                name_len = int.from_bytes(
                    client_hello[name_len_offset:name_len_offset + 2], "big"
                )
                name_offset = name_len_offset + 2
                if name_offset + name_len > end_of_extensions:
                    return None
                return client_hello[name_offset:name_offset + name_len].decode("utf-8")

            offset += 4 + ext_len

        return None
    except (IndexError, struct.error, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------------
# Traffic Shaping (bimodal timing, random padding for WS only)
# ---------------------------------------------------------------------------
def _bimodal_delay_ms(delay_range: List[int]) -> float:
    r = random.random()
    if r < 0.80:
        return random.uniform(0.0, 5.0)
    elif r < 0.95:
        return random.uniform(max(delay_range[0], 10), max(delay_range[1], 80))
    else:
        return random.uniform(max(delay_range[1], 150), max(delay_range[1] * 3, 400))


def _apply_padding(data: bytes, pad_range: List[int]) -> bytes:
    if not pad_range or pad_range[1] <= 0:
        return data
    min_pad, max_pad = pad_range
    pad_size = random.randint(min_pad, max_pad)
    padding = os.urandom(pad_size)
    return data + pad_size.to_bytes(4, "big") + padding


def _strip_padding(data: bytes) -> Optional[bytes]:
    if len(data) < 4:
        return data
    pad_size = int.from_bytes(data[-4:], "big")
    if pad_size > 0 and len(data) >= 4 + pad_size:
        return data[:-(4 + pad_size)]
    return data


async def _relay_bridge_to_backend(
    bridge: "TLSBridge", backend_writer: asyncio.StreamWriter, settings=None
):
    total_bytes = 0
    try:
        while True:
            data = await bridge.read(4096)
            if not data:
                break
            # FIX: No padding at application layer - it corrupts backend data.
            # Shaping (delays) is applied but raw bytes go through unmodified.
            backend_writer.write(data)
            await backend_writer.drain()
            total_bytes += len(data)
            if settings and settings.delay_ms_range and settings.delay_ms_range[1] > 0:
                delay = _bimodal_delay_ms(settings.delay_ms_range) / 1000.0
                await asyncio.sleep(delay)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        logging.debug(f"bridge->backend relay: {total_bytes} bytes")
        backend_writer.close()


async def _relay_backend_to_bridge(
    backend_reader: asyncio.StreamReader,
    bridge: "TLSBridge",
    settings=None,
    idle_timeout: int = 120,
):
    total_bytes = 0
    try:
        while not backend_reader.at_eof():
            try:
                data = await asyncio.wait_for(
                    backend_reader.read(4096), timeout=idle_timeout
                )
            except asyncio.TimeoutError:
                logging.debug(f"backend->bridge relay: idle timeout ({idle_timeout}s)")
                break
            if not data:
                break
            await bridge.write(data)
            total_bytes += len(data)
            # FIX: Bidirectional shaping - also shape response traffic
            if settings and settings.delay_ms_range and settings.delay_ms_range[1] > 0:
                delay = _bimodal_delay_ms(settings.delay_ms_range) / 1000.0
                await asyncio.sleep(delay)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        logging.debug(f"backend->bridge relay: {total_bytes} bytes")


async def obfuscate_and_relay_ws(
    source_reader: asyncio.StreamReader, dest_ws: WebSocket, settings: "BypassSettings"
):
    total_bytes = 0
    try:
        while not source_reader.at_eof():
            data = await source_reader.read(2048)
            if not data:
                break
            data = _apply_padding(data, settings.padding_size_range)
            await dest_ws.send_bytes(data)
            total_bytes += len(data)
            if settings.delay_ms_range and settings.delay_ms_range[1] > 0:
                delay = _bimodal_delay_ms(settings.delay_ms_range) / 1000.0
                await asyncio.sleep(delay)
    except (WebSocketDisconnect, ConnectionResetError):
        pass
    finally:
        logging.debug(f"obfuscate_and_relay_ws finished: {total_bytes} bytes")


# ---------------------------------------------------------------------------
# SOCKS5 Handshake
# ---------------------------------------------------------------------------
async def handle_socks5_handshake(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> Optional[Tuple[str, int]]:
    try:
        ver_nmethods = await reader.readexactly(2)
        if ver_nmethods[0] != 0x05:
            return None
        methods_count = ver_nmethods[1]
        methods = await reader.readexactly(methods_count)

        # Support no-auth (0x00) and username/password (0x02)
        if 0x02 in methods:
            writer.write(b"\x05\x02")
            await writer.drain()
            auth_ver = (await reader.readexactly(1))[0]
            if auth_ver != 0x01:
                return None
            ulen = (await reader.readexactly(1))[0]
            username = (await reader.readexactly(ulen)).decode()
            plen = (await reader.readexactly(1))[0]
            password = (await reader.readexactly(plen)).decode()
            async with state.config_lock:
                bypass = state.get_bypass()
            expected_user = bypass.socks_username if bypass else ""
            expected_pass = bypass.socks_password if bypass else ""
            if not expected_user or username != expected_user or password != expected_pass:
                writer.write(b"\x05\x01")
                await writer.drain()
                return None
            writer.write(b"\x05\x00")
            await writer.drain()
        elif 0x00 in methods:
            writer.write(b"\x05\x00")
            await writer.drain()
        else:
            return None

        ver_cmd_rsv_atyp = await reader.readexactly(4)
        if ver_cmd_rsv_atyp[0] != 0x05 or ver_cmd_rsv_atyp[1] != 0x01:
            return None

        atyp = ver_cmd_rsv_atyp[3]
        if atyp == 0x03:
            domain_len = (await reader.readexactly(1))[0]
            target_host = (await reader.readexactly(domain_len)).decode()
        elif atyp == 0x01:
            target_host = ".".join(
                str(b) for b in await reader.readexactly(4)
            )
        elif atyp == 0x04:
            addr_data = await reader.readexactly(16)
            target_host = ":".join(
                f"{addr_data[i]:02x}{addr_data[i+1]:02x}"
                for i in range(0, 16, 2)
            )
        else:
            return None

        target_port = int.from_bytes(await reader.readexactly(2), "big")
        logging.debug(f"SOCKS5 connect: {target_host}:{target_port}")
        return target_host, target_port
    except (asyncio.IncompleteReadError, ConnectionResetError, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------------
# Multiplexer Protocol (obfuscated frames)
# ---------------------------------------------------------------------------
FRAME_TYPE_NEW_STREAM = 0x01
FRAME_TYPE_DATA = 0x02
FRAME_TYPE_CLOSE = 0x03
FRAME_TYPE_FIN = 0x04
FRAME_HDR_SIZE = 9

MUX_STATUS_OK = 0x00
MUX_STATUS_ERR = 0x01


def _mux_xor(data: bytes, key: bytes, stream_id: int) -> bytes:
    if not key:
        return data
    key_stream = bytearray()
    counter = stream_id
    while len(key_stream) < len(data):
        key_stream.extend(
            ((key[i % len(key)] ^ ((counter >> (8 * (i % 4))) & 0xFF))
             for i in range(32))
        )
        counter += 1
    return bytes(a ^ b for a, b in zip(data, bytes(key_stream[:len(data)])))


class MuxServerSession:
    def __init__(self, websocket: WebSocket, settings: BypassSettings, mux_key: bytes):
        self.ws = websocket
        self.settings = settings
        self.mux_key = mux_key
        self.streams: Dict[int, asyncio.StreamWriter] = {}
        self._lock = asyncio.Lock()

    async def _read_loop(self):
        try:
            while True:
                data = await self.ws.receive_bytes()
                if len(data) < FRAME_HDR_SIZE:
                    continue

                raw = _strip_padding(data)
                if raw is None or len(raw) < FRAME_HDR_SIZE:
                    continue

                frame_type = raw[0]
                stream_id = int.from_bytes(raw[1:5], "big")
                frame_len = int.from_bytes(raw[5:9], "big")
                payload = raw[9:9 + frame_len] if frame_len > 0 else b""

                if self.mux_key and len(payload) > 0:
                    payload = _mux_xor(payload, self.mux_key, stream_id)

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
        try:
            if len(payload) < 3:
                await self._send_status(stream_id, MUX_STATUS_ERR)
                return
            host_len = payload[0]
            if len(payload) < 1 + host_len + 2:
                await self._send_status(stream_id, MUX_STATUS_ERR)
                return
            host = payload[1:1 + host_len].decode("ascii")
            port = int.from_bytes(payload[1 + host_len:3 + host_len], "big")

            logging.debug(f"MUX stream {stream_id}: connecting to {host}:{port}")
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
        if self.mux_key and len(payload) > 0:
            payload = _mux_xor(payload, self.mux_key, stream_id)
        hdr = (
            bytes([frame_type])
            + stream_id.to_bytes(4, "big")
            + len(payload).to_bytes(4, "big")
        )
        data = hdr + payload
        try:
            await self.ws.send_bytes(
                _apply_padding(data, self.settings.padding_size_range)
            )
        except WebSocketDisconnect:
            pass

    async def _relay_backend_to_ws(self, stream_id: int, reader: asyncio.StreamReader):
        try:
            while not reader.at_eof():
                try:
                    data = await asyncio.wait_for(
                        reader.read(4096),
                        timeout=self.settings.idle_timeout_seconds,
                    )
                except asyncio.TimeoutError:
                    logging.debug(f"MUX stream {stream_id}: backend idle timeout")
                    break
                if not data:
                    break
                await self._send_frame(FRAME_TYPE_DATA, stream_id, data)
                if self.settings.delay_ms_range and self.settings.delay_ms_range[1] > 0:
                    delay = _bimodal_delay_ms(self.settings.delay_ms_range) / 1000.0
                    await asyncio.sleep(delay)
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
# TLS Bridge (MemoryBIO-based)
# ---------------------------------------------------------------------------
class TLSBridge:
    def __init__(
        self,
        ssl_context: ssl.SSLContext,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        initial_data: bytes = b"",
    ):
        self._ssl_context = ssl_context
        self._client_reader = client_reader
        self._client_writer = client_writer
        self._initial_data = initial_data
        self._bio_in = ssl.MemoryBIO()
        self._bio_out = ssl.MemoryBIO()
        self._ssl_obj: Optional[ssl.SSLObject] = None
        self._handshake_complete = asyncio.Event()

    async def do_handshake(self) -> Optional[str]:
        self._ssl_obj = self._ssl_context.wrap_bio(
            self._bio_in, self._bio_out, server_side=True
        )

        if self._initial_data:
            self._bio_in.write(self._initial_data)

        try:
            for i in range(32):
                try:
                    self._ssl_obj.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    pass

                out = self._bio_out.read()
                if out:
                    self._client_writer.write(out)
                    await self._client_writer.drain()

                try:
                    data = await asyncio.wait_for(
                        self._client_reader.read(65536), timeout=5.0
                    )
                except asyncio.TimeoutError:
                    return None
                if not data:
                    return None
                self._bio_in.write(data)
            else:
                logging.warning("TLS handshake: too many rounds")
                return None
        except Exception as e:
            logging.warning(f"TLS handshake failed: {e}")
            return None

        out = self._bio_out.read()
        if out:
            self._client_writer.write(out)
            await self._client_writer.drain()

        self._handshake_complete.set()
        return True

    async def read(self, n: int = 65536) -> bytes:
        while True:
            try:
                data = self._ssl_obj.read(n)
                if data:
                    return data
            except ssl.SSLWantReadError:
                pass
            try:
                raw = await asyncio.wait_for(
                    self._client_reader.read(65536), timeout=120
                )
            except asyncio.TimeoutError:
                return b""
            if not raw:
                return b""
            self._bio_in.write(raw)
            out = self._bio_out.read()
            if out:
                self._client_writer.write(out)
                await self._client_writer.drain()

    async def write(self, data: bytes):
        self._ssl_obj.write(data)
        out = self._bio_out.read()
        if out:
            self._client_writer.write(out)
            await self._client_writer.drain()

    def is_handshake_done(self) -> bool:
        return self._handshake_complete.is_set()


# ---------------------------------------------------------------------------
# SNI Proxy (main TCP handler)
# ---------------------------------------------------------------------------
async def handle_connection(
    client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
):
    server_name = None
    peer_addr = client_writer.get_extra_info("peername")
    logging.debug(f"New TCP connection from {peer_addr}")

    bridge = None
    try:
        header = await asyncio.wait_for(client_reader.readexactly(5), timeout=5.0)
        if header[0] != 0x16:
            logging.debug("Not a TLS record. Closing.")
            client_writer.close()
            return

        record_len = int.from_bytes(header[3:5], "big")
        body = await asyncio.wait_for(
            client_reader.readexactly(record_len), timeout=5.0
        )
        full_record = header + body

        server_name = parse_sni(full_record)

        if not server_name:
            logging.debug("SNI not found in ClientHello. Closing.")
            client_writer.close()
            return

        logging.debug(f"SNI: {server_name}")

        ssl_ctx = state._sni_ssl_context
        if not ssl_ctx:
            logging.error("No SSL context available")
            client_writer.close()
            return

        bridge = TLSBridge(
            ssl_ctx, client_reader, client_writer, initial_data=full_record
        )
        handshake_ok = await bridge.do_handshake()
        if not handshake_ok:
            logging.debug("TLS handshake failed. Closing.")
            client_writer.close()
            return

        proxy_mode = "direct"
        target_host = ""
        target_port = 443
        use_bypass = False

        async with state.config_lock:
            current_host = state.config.get("host", "")
            bypass = state.get_bypass()
            trigger_domains = state.config.get("trigger_domains", [])
            cf_data = state.config.get("cloudflare", {})
            cf = CloudflareSettings(cf_data) if cf_data else None

        if bypass and bypass.enabled:
            sni_lower = server_name.lower()
            is_trigger = sni_lower == bypass.trigger_sni.lower() or any(
                sni_lower == td.lower() for td in trigger_domains
            )
            if is_trigger:
                use_bypass = True
            elif (
                bypass.detect_mobile_networks
                and state.geoip_reader
                and peer_addr
            ):
                ip_str = peer_addr[0]
                try:
                    record = state.geoip_reader.isp(ip_str)
                    client_isp = record.isp.lower()
                    client_org = record.organization.lower()
                    for carrier in bypass.mobile_carrier_names:
                        if (
                            carrier.lower() in client_isp
                            or carrier.lower() in client_org
                        ):
                            logging.debug(
                                f"Mobile network detected ({record.isp})."
                            )
                            use_bypass = True
                            break
                except geoip2.errors.AddressNotFoundError:
                    logging.debug(f"GeoIP: {ip_str} not found")
                except Exception as e:
                    logging.debug(f"GeoIP lookup failed for {ip_str}: {e}")

        if use_bypass:
            if bypass.mode == "websocket":
                proxy_mode = "websocket_forward"
                target_host = "127.0.0.1"
                target_port = 8080
                logging.debug(f"Bypass: WebSocket mode for {server_name}")
            else:
                try:
                    socks_target = await handle_socks5_handshake(
                        client_reader, client_writer
                    )
                    if not socks_target:
                        logging.debug(f"SOCKS5 handshake failed for {server_name}")
                        return
                    target_host, target_port = socks_target
                    client_writer.write(
                        b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                    )
                    await client_writer.drain()
                    proxy_mode = "shape"
                    logging.debug(
                        f"Bypass: Shape mode for {server_name} -> {target_host}:{target_port}"
                    )
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

        idle_timeout = bypass.idle_timeout_seconds if bypass else 120

        if proxy_mode == "direct":
            try:
                target_ssl = _create_outbound_ssl_context()
                backend_reader, backend_writer = await asyncio.open_connection(
                    target_host, target_port, ssl=target_ssl
                )
                logging.debug(f"Direct TLS relay to {target_host}:{target_port}")
            except Exception as e:
                logging.debug(
                    f"Could not connect to {target_host}:{target_port}: {e}"
                )
                return
        else:
            backend_reader, backend_writer = await asyncio.open_connection(
                target_host, target_port
            )
            logging.debug(f"Relay to {target_host}:{target_port}")

        if proxy_mode == "shape":
            task1 = asyncio.create_task(
                _relay_bridge_to_backend(bridge, backend_writer, bypass)
            )
            task2 = asyncio.create_task(
                _relay_backend_to_bridge(
                    backend_reader, bridge, bypass, idle_timeout
                )
            )
        else:
            task1 = asyncio.create_task(
                _relay_backend_to_bridge(
                    backend_reader, bridge, None, idle_timeout
                )
            )
            task2 = asyncio.create_task(
                _relay_bridge_to_backend(bridge, backend_writer, None)
            )

        await asyncio.gather(task1, task2)

    except (ConnectionRefusedError, asyncio.TimeoutError) as e:
        logging.debug(f"Connection failed for SNI={server_name}: {type(e).__name__}")
    except Exception as e:
        logging.debug(f"Error for SNI={server_name}: {e}")
    finally:
        logging.debug(f"Connection closed for SNI={server_name}")
        try:
            client_writer.close()
        except Exception:
            pass


async def start_sni_proxy():
    ssl_context = None
    install_dir = pathlib.Path(os.environ.get("INSTALL_DIR", "/opt/smartSNI"))
    local_certs = install_dir / "certs"

    cert_paths = [
        (local_certs / "fullchain.pem", local_certs / "privkey.pem"),
    ]
    letsencrypt_dir = pathlib.Path("/etc/letsencrypt/live")
    async with state.config_lock:
        domains_to_try = [state.config.get("host", "")] + state.config.get(
            "trigger_domains", []
        )
    for domain in domains_to_try:
        if domain:
            cert_paths.append(
                (
                    letsencrypt_dir / domain / "fullchain.pem",
                    letsencrypt_dir / domain / "privkey.pem",
                )
            )

    for cert_path, key_path in cert_paths:
        if cert_path.exists() and key_path.exists():
            ssl_context = _create_hardened_ssl_context(str(cert_path), str(key_path))
            logging.info(f"SNI proxy: hardened TLS context from {cert_path}")
            break

    if ssl_context:
        state._sni_ssl_context = ssl_context
        server = await asyncio.start_server(handle_connection, "0.0.0.0", 443)
        logging.info("SNI proxy listening on 0.0.0.0:443")
    else:
        logging.warning("No TLS certs found. SNI proxy cannot start on port 443.")
        return

    async with server:
        await server.serve_forever()


# ---------------------------------------------------------------------------
# FastAPI App (DoH, Cover Website, WebSocket)
# ---------------------------------------------------------------------------
app = FastAPI()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    start = time.monotonic()
    method = request.method
    path = request.url.path
    client = request.client.host if request.client else "unknown"
    logging.debug(f"--> {method} {path} from {client}")
    try:
        response = await call_next(request)
        elapsed_ms = (time.monotonic() - start) * 1000
        logging.debug(
            f"<-- {method} {path} {response.status_code} ({elapsed_ms:.1f}ms)"
        )

        # Add realistic security headers
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        if path.startswith("/dns-query"):
            response.headers["Cache-Control"] = "no-cache, no-store"
        else:
            response.headers["Cache-Control"] = (
                "public, max-age=3600, stale-while-revalidate=86400"
            )

        return response
    except Exception as e:
        elapsed_ms = (time.monotonic() - start) * 1000
        logging.error(
            f"<-- {method} {path} ERROR ({elapsed_ms:.1f}ms): {e}"
        )
        raise


# --- Cover Website ---
ROBOTS_TXT = """User-agent: *
Allow: /

Sitemap: /sitemap.xml
"""

COVER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureMail - Encrypted Communications</title>
    <meta name="description" content="Enterprise-grade encrypted communications platform with end-to-end encryption">
    <meta name="theme-color" content="#0f172a">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
        .container{max-width:900px;margin:0 auto;padding:40px 20px}
        nav{display:flex;justify-content:space-between;align-items:center;padding:16px 0;border-bottom:1px solid #1e293b}
        .logo{font-size:1.2rem;font-weight:700;color:#38bdf8}
        .nav-links{display:flex;gap:24px}
        .nav-links a{color:#94a3b8;text-decoration:none;font-size:0.9rem}
        .nav-links a:hover{color:#38bdf8}
        header{text-align:center;padding:60px 0 40px}
        h1{font-size:2.5rem;color:#38bdf8;margin-bottom:12px}
        .subtitle{color:#94a3b8;font-size:1.1rem}
        .inbox-preview{margin-top:40px;background:#1e293b;border-radius:12px;border:1px solid #334155;overflow:hidden}
        .inbox-header{padding:16px 24px;border-bottom:1px solid #334155;color:#38bdf8;font-weight:600;display:flex;justify-content:space-between}
        .inbox-item{padding:12px 24px;border-bottom:1px solid #1e293b22;display:flex;justify-content:space-between;cursor:pointer;transition:background 0.15s}
        .inbox-item:hover{background:#1e293b88}
        .inbox-sender{color:#e2e8f0;font-weight:500}
        .inbox-subject{color:#94a3b8;font-size:0.85rem}
        .inbox-time{color:#475569;font-size:0.8rem;white-space:nowrap}
        .features{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:24px;margin-top:40px}
        .feature{background:#1e293b;border-radius:12px;padding:24px;border:1px solid #334155;transition:border-color 0.2s}
        .feature:hover{border-color:#38bdf844}
        .feature i{color:#38bdf8;font-size:1.5rem;margin-bottom:12px}
        .feature h3{margin-bottom:8px;font-size:1rem}
        .feature p{color:#94a3b8;font-size:0.85rem;line-height:1.6}
        footer{text-align:center;padding:40px 0;color:#475569;font-size:0.85rem;border-top:1px solid #1e293b;margin-top:40px}
        a{color:#38bdf8;text-decoration:none}
        @keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
        .inbox-preview,.features{animation:fadeIn 0.5s ease-out}
    </style>
</head>
<body>
    <div class="container">
        <nav>
            <div class="logo"><i class="fas fa-shield-halved"></i> SecureMail</div>
            <div class="nav-links">
                <a href="/pricing">Pricing</a>
                <a href="/docs">Docs</a>
                <a href="/login">Sign In</a>
            </div>
        </nav>
        <header>
            <h1>SecureMail</h1>
            <p class="subtitle">Enterprise-grade encrypted communications platform</p>
        </header>
        <div class="inbox-preview">
            <div class="inbox-header">
                <span>Inbox (3 messages)</span>
                <span style="color:#475569;font-size:0.8rem"><i class="fas fa-sync-alt"></i> Just now</span>
            </div>
            <div class="inbox-item"><div><div class="inbox-sender">Security Team</div><div class="inbox-subject">Your monthly security report is ready for review</div></div><div class="inbox-time">2h ago</div></div>
            <div class="inbox-item"><div><div class="inbox-sender">Workspace</div><div class="inbox-subject">New shared document: Q4 Planning</div></div><div class="inbox-time">5h ago</div></div>
            <div class="inbox-item"><div><div class="inbox-sender">System</div><div class="inbox-subject">Encryption key rotation completed</div></div><div class="inbox-time">1d ago</div></div>
        </div>
        <div class="features">
            <div class="feature"><i class="fas fa-lock"></i><h3>End-to-End Encryption</h3><p>All messages encrypted with AES-256-GCM. Only you and your recipient can read them.</p></div>
            <div class="feature"><i class="fas fa-eye-slash"></i><h3>Zero-Knowledge</h3><p>We never have access to your encryption keys or message content.</p></div>
            <div class="feature"><i class="fas fa-file-shield"></i><h3>Secure Sharing</h3><p>Share files up to 2GB with automatic encryption and expiration.</p></div>
            <div class="feature"><i class="fas fa-users"></i><h3>Team Workspaces</h3><p>Encrypted channels for your team with role-based access control.</p></div>
        </div>
        <footer>
            <p>&copy; 2025 SecureMail. All rights reserved. | <a href="/privacy">Privacy</a> | <a href="/terms">Terms</a></p>
        </footer>
    </div>
    <script>
    if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js').catch(function(){})}
    document.querySelectorAll('.inbox-item').forEach(function(el){el.addEventListener('click',function(){window.location.href='/login'})});
    </script>
</body>
</html>"""


@app.get("/robots.txt")
async def robots_txt():
    return Response(content=ROBOTS_TXT, media_type="text/plain")


@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)


@app.get("/sitemap.xml")
async def sitemap():
    content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>
  <url><loc>/pricing</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>
  <url><loc>/docs</loc><changefreq>weekly</changefreq><priority>0.7</priority></url>
  <url><loc>/privacy</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>
  <url><loc>/terms</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>
</urlset>"""
    return Response(content=content, media_type="application/xml")


@app.get("/privacy")
async def privacy_page():
    return Response(
        content=COVER_HTML.replace(
            "<title>SecureMail - Encrypted Communications</title>",
            "<title>Privacy Policy - SecureMail</title>",
        ),
        media_type="text/html",
    )


@app.get("/terms")
async def terms_page():
    return Response(
        content=COVER_HTML.replace(
            "<title>SecureMail - Encrypted Communications</title>",
            "<title>Terms of Service - SecureMail</title>",
        ),
        media_type="text/html",
    )


@app.get("/dns-query")
@app.post("/dns-query")
async def doh_handler(request: Request):
    if request.method == "POST":
        query_bytes = await request.body()
    else:
        dns_param = request.query_params.get("dns")
        if not dns_param:
            return Response(
                content="Missing 'dns' query parameter", status_code=400
            )
        try:
            query_bytes = base64.urlsafe_b64decode(
                dns_param + "=" * (4 - len(dns_param) % 4)
            )
        except Exception:
            return Response(
                content="Invalid 'dns' query parameter", status_code=400
            )

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
        cf_data = state.config.get("cloudflare", {})
        cf = CloudflareSettings(cf_data) if cf_data else None

    if not (bypass and bypass.enabled and bypass.mode == "websocket"):
        await websocket.close(code=4004)
        return

    path_matches = f"/{full_path}".startswith(bypass.tunnel_path)
    if not path_matches:
        await websocket.close(code=4004)
        return

    # Domain fronting via Host header (not X-Forwarded-Host)
    effective_host = websocket.headers.get("Host", "")
    if bypass.fronting_enabled and bypass.fronting_hosts:
        if effective_host not in bypass.fronting_hosts:
            logging.debug(f"Fronting: Host={effective_host} not in allowed list")
            await websocket.close(code=4003)
            return

    # Cloudflare real IP
    real_client_ip = None
    if cf and cf.enabled:
        cf_ip = websocket.headers.get("CF-Connecting-IP")
        if cf_ip:
            real_client_ip = cf_ip

    # Rate limiting
    client_ip = real_client_ip or (
        websocket.client.host if websocket.client else "unknown"
    )
    if not await state.rate_limiter.allow(client_ip):
        logging.warning(f"Rate limited: {client_ip}")
        await websocket.close(code=429)
        return

    # HMAC-based auth
    if bypass.bypass_secret:
        auth_header = websocket.headers.get("Authorization")
        if not auth_header:
            logging.debug(f"Auth missing for /{full_path} from {client_ip}")
            await websocket.close(code=4001)
            return
        # Support both static token and HMAC session token
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if token == bypass.bypass_secret:
                pass  # static secret match
            elif _verify_session_token(token, bypass.bypass_secret, max_age=3600):
                pass  # valid session token
            else:
                logging.debug(f"Auth failed for /{full_path} from {client_ip}")
                await websocket.close(code=4001)
                return
        else:
            logging.debug(f"Auth failed for /{full_path} from {client_ip}")
            await websocket.close(code=4001)
            return
        logging.debug("WebSocket: auth OK")

    await websocket.accept()
    logging.info(f"WebSocket: client connected ({client_ip})")

    # Obfuscated hello: send a binary greeting instead of plaintext JSON
    hello_payload = bytearray([0x48, 0x45, 0x4C, 0x4C, 0x4F])  # "HELLO"
    if bypass.multiplexing:
        hello_payload.append(0x01)  # mux flag
    else:
        hello_payload.append(0x00)
    hello_payload.extend(os.urandom(4))  # random padding
    await websocket.send_bytes(bytes(hello_payload))

    # Detect protocol: first bytes
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

    # Detect multiplexing
    if len(first_data) >= FRAME_HDR_SIZE and first_data[0] in (
        FRAME_TYPE_NEW_STREAM,
        FRAME_TYPE_DATA,
        FRAME_TYPE_CLOSE,
        FRAME_TYPE_FIN,
    ):
        logging.debug("Client uses multiplexed protocol")
        session = MuxServerSession(websocket, bypass, state.mux_key)
        async with state.mux_lock:
            state.mux_sessions[client_ip] = session
        try:
            raw = _strip_padding(first_data)
            if raw and len(raw) >= FRAME_HDR_SIZE:
                stream_id = int.from_bytes(raw[1:5], "big")
                frame_len = int.from_bytes(raw[5:9], "big")
                payload = raw[9:9 + frame_len] if frame_len > 0 else b""
                if state.mux_key and len(payload) > 0:
                    payload = _mux_xor(payload, state.mux_key, stream_id)
                asyncio.create_task(
                    session._handle_new_stream(stream_id, payload)
                )
            await session._read_loop()
        finally:
            async with state.mux_lock:
                state.mux_sessions.pop(client_ip, None)
        return

    # Fallback: SOCKS5 over WebSocket
    logging.debug("Client uses legacy SOCKS5-over-WebSocket")
    socks_host = bypass.socks_host
    socks_port = bypass.socks_port

    try:
        extra_args = {}
        if bypass.socks_username:
            extra_args["socks_username"] = bypass.socks_username
            extra_args["socks_password"] = bypass.socks_password

        reader, writer = await asyncio.open_connection(socks_host, socks_port)

        async def ws_to_socks(ws: WebSocket, socks_writer: asyncio.StreamWriter):
            total = 0
            try:
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
        task_s2c = asyncio.create_task(
            obfuscate_and_relay_ws(reader, websocket, bypass)
        )
        await asyncio.gather(task_c2s, task_s2c)

    except Exception as e:
        logging.debug(f"WebSocket bypass error: {e}")
    finally:
        logging.info(f"WebSocket: tunnel closed for {client_ip}")


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------
async def shutdown_handler(loop):
    logging.info("Shutdown signal received...")
    state._shutting_down = True

    for task in asyncio.all_tasks():
        if task is not asyncio.current_task():
            task.cancel()

    async with state.mux_lock:
        for session in state.mux_sessions.values():
            await session._cleanup_all()
        state.mux_sessions.clear()

    await state.doh_client.aclose()
    if state.geoip_reader:
        state.geoip_reader.close()

    logging.info("Shutdown complete.")


async def main():
    logging.info(
        f"SmartSNI server starting... (debug={'ON' if DEBUG else 'OFF'})"
    )

    initial_config, initial_geoip = await load_config("config.json")
    if not initial_config:
        logging.critical("Could not load initial configuration. Exiting.")
        return
    state.config = initial_config
    state.geoip_reader = initial_geoip
    state.cache_bypass_settings()

    bypass = state.get_bypass()
    if bypass:
        logging.info(
            f"Bypass: enabled={bypass.enabled}, mode={bypass.mode}, "
            f"multiplexing={bypass.multiplexing}, "
            f"secret={_mask_secret(bypass.bypass_secret)}, "
            f"pad={bypass.padding_size_range}, "
            f"delay={bypass.delay_ms_range}, "
            f"idle_timeout={bypass.idle_timeout_seconds}s"
        )

    asyncio.create_task(reload_config_periodically())
    asyncio.create_task(rotate_domains())
    asyncio.create_task(start_dot_server())
    asyncio.create_task(start_sni_proxy())
    asyncio.create_task(state.rate_limiter.cleanup())

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(
            sig, lambda: asyncio.create_task(shutdown_handler(loop))
        )

    log_level = "debug" if DEBUG else "info"
    uvicorn_config = uvicorn.Config(
        app, host="127.0.0.1", port=8080, log_level=log_level
    )
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
