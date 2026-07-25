#!/usr/bin/env python3
"""Minimal SOCKS5 proxy for testing. Listens on 127.0.0.1:1080."""
import asyncio
import struct
import socket

async def handle_client(reader, writer):
    try:
        # SOCKS5 greeting
        header = await reader.readexactly(2)
        if header[0] != 0x05:
            writer.close()
            return
        nmethods = header[1]
        await reader.readexactly(nmethods)

        # Reply: no auth required
        writer.write(b'\x05\x00')
        await writer.drain()

        # SOCKS5 request
        req = await reader.readexactly(4)
        ver, cmd, rsv, atyp = req
        if ver != 0x05 or cmd != 0x01:
            writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            writer.close()
            return

        if atyp == 0x01:  # IPv4
            addr_data = await reader.readexactly(4)
            addr = socket.inet_ntoa(addr_data)
        elif atyp == 0x03:  # Domain
            length = (await reader.readexactly(1))[0]
            addr = (await reader.readexactly(length)).decode()
        elif atyp == 0x04:  # IPv6
            addr_data = await reader.readexactly(16)
            addr = socket.inet_ntop(socket.AF_INET6, addr_data)
        else:
            writer.close()
            return

        port_data = await reader.readexactly(2)
        port = struct.unpack('>H', port_data)[0]

        # Connect to target
        try:
            remote_reader, remote_writer = await asyncio.open_connection(addr, port)
        except Exception:
            writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            writer.close()
            return

        # Success reply
        writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        await writer.drain()

        # Bidirectional relay
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
    print("SOCKS5 proxy listening on 127.0.0.1:1080")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
