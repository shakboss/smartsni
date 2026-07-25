#!/usr/bin/env python3
"""Minimal SOCKS5 proxy with optional auth for testing."""
import asyncio
import struct
import socket
import os
import json

SOCKS_USER = os.environ.get("SOCKS_USER", "")
SOCKS_PASS = os.environ.get("SOCKS_PASS", "")


async def handle_client(reader, writer):
    try:
        header = await reader.readexactly(2)
        if header[0] != 0x05:
            writer.close()
            return
        nmethods = header[1]
        methods = await reader.readexactly(nmethods)

        if SOCKS_USER and SOCKS_PASS:
            if 0x02 not in methods:
                writer.write(b'\x05\xff')
                await writer.drain()
                writer.close()
                return
            writer.write(b'\x05\x02')
            await writer.drain()
            auth_ver = (await reader.readexactly(1))[0]
            if auth_ver != 0x01:
                writer.close()
                return
            ulen = (await reader.readexactly(1))[0]
            username = (await reader.readexactly(ulen)).decode()
            plen = (await reader.readexactly(1))[0]
            password = (await reader.readexactly(plen)).decode()
            if username != SOCKS_USER or password != SOCKS_PASS:
                writer.write(b'\x05\x01')
                await writer.drain()
                writer.close()
                return
            writer.write(b'\x05\x00')
            await writer.drain()
        else:
            if 0x00 not in methods:
                writer.write(b'\x05\xff')
                await writer.drain()
                writer.close()
                return
            writer.write(b'\x05\x00')
            await writer.drain()

        req = await reader.readexactly(4)
        ver, cmd, rsv, atyp = req
        if ver != 0x05 or cmd != 0x01:
            writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            writer.close()
            return

        if atyp == 0x01:
            addr_data = await reader.readexactly(4)
            addr = socket.inet_ntoa(addr_data)
        elif atyp == 0x03:
            length = (await reader.readexactly(1))[0]
            addr = (await reader.readexactly(length)).decode()
        elif atyp == 0x04:
            addr_data = await reader.readexactly(16)
            addr = socket.inet_ntop(socket.AF_INET6, addr_data)
        else:
            writer.close()
            return

        port_data = await reader.readexactly(2)
        port = struct.unpack('>H', port_data)[0]

        try:
            remote_reader, remote_writer = await asyncio.open_connection(addr, port)
        except Exception:
            writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            writer.close()
            return

        writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        await writer.drain()

        async def relay(src, dst):
            try:
                while True:
                    data = await src.read(4096)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass

        await asyncio.gather(
            relay(reader, remote_writer),
            relay(remote_reader, writer)
        )
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle_client, '127.0.0.1', 1080)
    auth_info = f" (user={SOCKS_USER})" if SOCKS_USER else ""
    print(f"SOCKS5 proxy listening on 127.0.0.1:1080{auth_info}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
