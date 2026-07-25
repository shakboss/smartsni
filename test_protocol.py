#!/usr/bin/env python3
"""
Protocol test: simulates the Android client's exact behavior against the server.
Connects through the SNI proxy on port 443 with TLS, same as the Android client.
"""

import asyncio
import struct
import ssl
import sys
import random

import websockets

SERVER = "home.shaktt.xyz"
WS_PORT = 443
SECRET = "A9wZtP4qE7rV2sY6jK1bC3fH5gN8xU0d"
TRIGGER_SNI = "mail.shaktt.xyz"
TARGET_HOST = "1.1.1.1"
TARGET_PORT = 80

PASSED = 0
FAILED = 0


def log(ok, msg):
    global PASSED, FAILED
    tag = "PASS" if ok else "FAIL"
    if ok:
        PASSED += 1
    else:
        FAILED += 1
    print(f"  [{tag}] {msg}")


def strip_padding(data: bytes) -> bytes:
    if len(data) < 4:
        return data
    pad_size = struct.unpack(">I", data[-4:])[0]
    if pad_size <= 0 or pad_size > len(data) - 4:
        return data
    return data[:len(data) - 4 - pad_size]


def make_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def do_socks5_handshake(ws):
    """Performs full SOCKS5 handshake over a WebSocket. Returns True on success."""
    # Receive server hello
    msg = await asyncio.wait_for(ws.recv(), timeout=5)
    if not (isinstance(msg, str) and "hello" in msg):
        return False

    # SOCKS5 greeting
    await ws.send(bytes([0x05, 0x01, 0x00]))

    raw = await asyncio.wait_for(ws.recv(), timeout=5)
    if not isinstance(raw, bytes):
        return False
    resp = strip_padding(raw)
    if not (len(resp) == 2 and resp[0] == 0x05 and resp[1] == 0x00):
        return False

    # SOCKS5 CONNECT
    target_bytes = TARGET_HOST.encode("ascii")
    connect_req = bytearray([0x05, 0x01, 0x00, 0x03])
    connect_req.append(len(target_bytes))
    connect_req.extend(target_bytes)
    connect_req.extend(struct.pack(">H", TARGET_PORT))
    await ws.send(bytes(connect_req))

    raw = await asyncio.wait_for(ws.recv(), timeout=5)
    if not isinstance(raw, bytes):
        return False
    resp = strip_padding(raw)
    if not (len(resp) >= 10 and resp[0] == 0x05 and resp[1] == 0x00):
        return False

    return True


async def test_ws_connect():
    print("\n=== Test 1: WebSocket Connection & Auth ===")
    url = f"wss://{SERVER}:{WS_PORT}/wstunnel"
    headers = {
        "Host": TRIGGER_SNI,
        "Authorization": f"Bearer {SECRET}",
    }
    ssl_ctx = make_ssl_context()

    try:
        async with websockets.connect(url, additional_headers=headers, ssl=ssl_ctx, open_timeout=10) as ws:
            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            log(isinstance(msg, str) and "hello" in msg, f"Server hello: {msg.strip()[:60]}")
    except Exception as e:
        log(False, f"Connection failed: {e}")


async def test_auth_reject():
    print("\n=== Test 2: Auth Rejection ===")
    url = f"wss://{SERVER}:{WS_PORT}/wstunnel"
    headers = {"Host": TRIGGER_SNI, "Authorization": "Bearer WRONG_SECRET"}
    ssl_ctx = make_ssl_context()

    try:
        async with websockets.connect(url, additional_headers=headers, ssl=ssl_ctx, open_timeout=10) as ws:
            log(False, "Should have been rejected")
    except Exception as e:
        log(True, f"Rejected: {type(e).__name__}")


async def test_wrong_path():
    print("\n=== Test 3: Wrong Path Rejection ===")
    url = f"wss://{SERVER}:{WS_PORT}/wrong/path"
    headers = {"Host": TRIGGER_SNI, "Authorization": f"Bearer {SECRET}"}
    ssl_ctx = make_ssl_context()

    try:
        async with websockets.connect(url, additional_headers=headers, ssl=ssl_ctx, open_timeout=10) as ws:
            log(False, "Should have been rejected")
    except Exception as e:
        log(True, f"Rejected: {type(e).__name__}")


async def test_padding():
    print("\n=== Test 4: Padding Consistency ===")
    url = f"wss://{SERVER}:{WS_PORT}/wstunnel"
    headers = {"Host": TRIGGER_SNI, "Authorization": f"Bearer {SECRET}"}
    ssl_ctx = make_ssl_context()

    try:
        async with websockets.connect(url, additional_headers=headers, ssl=ssl_ctx, open_timeout=10) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)  # hello
            await ws.send(bytes([0x05, 0x01, 0x00]))

            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            log(isinstance(raw, bytes) and len(raw) >= 16, f"Method selection padded: {len(raw)} bytes (min 16)")

            stripped = strip_padding(raw)
            log(len(stripped) == 2 and stripped == b'\x05\x00', f"Stripped correctly: {stripped.hex()}")
    except Exception as e:
        log(False, f"Padding test failed: {e}")


async def test_socks5():
    print("\n=== Test 5: SOCKS5 Handshake ===")
    url = f"wss://{SERVER}:{WS_PORT}/wstunnel"
    headers = {"Host": TRIGGER_SNI, "Authorization": f"Bearer {SECRET}"}
    ssl_ctx = make_ssl_context()

    try:
        async with websockets.connect(url, additional_headers=headers, ssl=ssl_ctx, open_timeout=10) as ws:
            ok = await do_socks5_handshake(ws)
            log(ok, f"SOCKS5 handshake through WebSocket")
            return ok
    except Exception as e:
        log(False, f"SOCKS5 handshake failed: {e}")
        return False


async def test_data_relay():
    print("\n=== Test 6: Data Relay (HTTP through tunnel) ===")
    url = f"wss://{SERVER}:{WS_PORT}/wstunnel"
    headers = {"Host": TRIGGER_SNI, "Authorization": f"Bearer {SECRET}"}
    ssl_ctx = make_ssl_context()

    try:
        async with websockets.connect(url, additional_headers=headers, ssl=ssl_ctx, open_timeout=10) as ws:
            ok = await do_socks5_handshake(ws)
            if not ok:
                log(False, "Tunnel setup failed")
                return

            log(True, "Tunnel established")

            http_req = f"GET / HTTP/1.1\r\nHost: {TARGET_HOST}\r\nConnection: close\r\n\r\n"
            await ws.send(http_req.encode())
            log(True, f"Sent HTTP GET to {TARGET_HOST}:{TARGET_PORT}")

            total_data = b""
            try:
                while True:
                    raw = await asyncio.wait_for(ws.recv(), timeout=10)
                    if isinstance(raw, bytes):
                        stripped = strip_padding(raw)
                        total_data += stripped
                    if b"\r\n\r\n" in total_data or len(total_data) > 10000:
                        break
            except asyncio.TimeoutError:
                pass

            if total_data:
                first_line = total_data.split(b"\r\n")[0].decode(errors="replace")
                log(b"HTTP/" in total_data[:20], f"HTTP response: {first_line[:80]}")
                log(len(total_data) > 50, f"Received {len(total_data)} bytes through tunnel")
            else:
                log(False, "No data received")
    except Exception as e:
        log(False, f"Data relay failed: {e}")


async def main():
    print(f"Testing SmartSNI protocol against {SERVER}:{WS_PORT}")
    print(f"Target: {TARGET_HOST}:{TARGET_PORT}")

    await test_ws_connect()
    await test_auth_reject()
    await test_wrong_path()
    await test_padding()
    handshake_ok = await test_socks5()
    if handshake_ok:
        await test_data_relay()

    print(f"\n{'='*50}")
    print(f"Results: {PASSED} passed, {FAILED} failed")
    return FAILED == 0


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
