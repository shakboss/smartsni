#!/usr/bin/env python3
"""
dpi-lab - Deep Packet Inspection analysis & evasion-testing toolkit.

Two probe tracks:

  TRACK A (kernel sockets, reliable)  - content-level DPI detection.
    Real TCP connections carrying hand-crafted TLS ClientHellos / HTTP
    requests. Lets us answer "what triggers the block" (SNI value, SNI
    presence, TLS fingerprint, HTTP Host header) without our own TCP stack
    fighting the network.

  TRACK B (raw sockets, consensus)    - camouflage validation.
    We build IP/TCP from scratch so we can split/pad/obfuscate the payload
    across segments (the classic anti-DPI fragmentation tricks). Because
    aggressive middleboxes mangle non-kernel TCP, every raw result is run
    N times and reported as consensus, plus a control probe tells us when
    raw results are untrustworthy.

ALWAYS: only against networks/servers you own or are authorized to test.
"""

import argparse
import os
import random
import socket
import struct
import sys
import time

# ======================================================================
# x25519 (RFC 7748) - so the ClientHello carries a real keyshare and
# servers reply with a genuine ServerHello instead of a parse alert.
# ======================================================================
_P = 2 ** 255 - 19
_A24 = 121665
_X25519_BASE = 9


def _clamp(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def x25519(scalar, u=_X25519_BASE):
    k = _clamp(scalar)
    x1 = u % _P
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k[t // 8] >> (t % 8)) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = (x1 * (da - cb) ** 2) % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, _P - 2, _P)) % _P


def x25519_public(secret):
    return x25519(secret).to_bytes(32, "little")


# ======================================================================
# IP / TCP building + parsing
# ======================================================================

def csum(data):
    if len(data) & 1:
        data += b"\x00"
    n = len(data) // 2
    s = sum(struct.unpack(f"!{n}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def ip_header(src, dst, proto, total_len, ident):
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ident, 0x4000, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )


def tcp_header(sport, dport, seq, ack, flags, window=64240, opts=b""):
    hl = 20 + len(opts)
    return struct.pack("!HHIIBBHHH",
                       sport, dport, seq, ack,
                       (hl // 4) << 4, flags, window, 0, 0) + opts


def tcp_packet(src, dst, sport, dport, seq, ack, flags, payload=b"", opts=b"", ident=0):
    ip = ip_header(src, dst, 6, 20 + 20 + len(opts) + len(payload), ident)
    tcp = tcp_header(sport, dport, seq, ack, flags, opts=opts)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + \
        struct.pack("!BBH", 0, 6, 20 + len(opts) + len(payload))
    tcp_ck = csum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", tcp_ck) + tcp[18:]
    return ip + tcp + payload


def parse_ip(pkt):
    if len(pkt) < 20:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if len(pkt) < ihl:
        return None
    return {"proto": pkt[9], "ttl": pkt[8],
            "src": socket.inet_ntoa(pkt[12:16]),
            "dst": socket.inet_ntoa(pkt[16:20]),
            "payload": pkt[ihl:]}


def parse_tcp(pkt):
    h = struct.unpack("!HHIIBBHHH", pkt[:20])
    data_off = (h[4] >> 4) * 4
    return {"sport": h[0], "dport": h[1], "seq": h[2], "ack": h[3],
            "flags": h[5], "window": h[6], "payload": pkt[data_off:]}


def parse_tcp_opts(pkt):
    doff = (pkt[12] >> 4) * 4
    o = pkt[20:doff]
    out = {}
    i = 0
    while i < len(o):
        k = o[i]
        if k == 0:
            break
        if k == 1:
            i += 1
            continue
        ln = o[i + 1]
        if k == 2 and ln == 4:
            out["mss"] = struct.unpack("!H", o[i + 2:i + 4])[0]
        elif k == 3 and ln == 3:
            out["wscale"] = o[i + 2]
        elif k == 8 and ln == 10:
            out["tsval"], out["tsecr"] = struct.unpack("!II", o[i + 2:i + 10])
        i += ln
    return out


# ======================================================================
# raw-socket mini TCP stack (Track B)
# ======================================================================
TH_SYN, TH_ACK, TH_RST, TH_PSH, TH_FIN = 0x02, 0x10, 0x04, 0x08, 0x01


class RawTCP:
    def __init__(self, src_ip, dst_ip, sport, dport, timeout=3.0):
        self.src, self.dst = src_ip, dst_ip
        self.sport, self.dport = sport, dport
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.ident = random.randint(1000, 60000)

    def send(self, seq, ack, flags, payload=b"", opts=b""):
        self.ident = (self.ident + 1) & 0xFFFF
        self.sock.sendto(tcp_packet(self.src, self.dst, self.sport, self.dport,
                                    seq, ack, flags, payload, opts, self.ident),
                         (self.dst, 0))

    def recv(self, deadline):
        while time.time() < deadline:
            try:
                self.sock.settimeout(max(0.01, deadline - time.time()))
                pkt, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                return None
            ip = parse_ip(pkt)
            if not ip or ip["proto"] != 6:
                continue
            t = parse_tcp(ip["payload"])
            if not t or t["dport"] != self.sport or t["sport"] != self.dport:
                continue
            return {"ip": ip, "tcp": t}
        return None

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def raw_connect_probe(src_ip, dst_ip, sport, dport, segments, wait=3.0):
    """Full TCP handshake (SYN with realistic options), then send payload as
    `segments` separate TCP segments. Returns an outcome dict."""
    r = RawTCP(src_ip, dst_ip, sport, dport, timeout=wait)
    base_seq = random.randint(1, 0xFFFFFFF)
    tsval = int(time.time()) & 0xFFFFFFFF
    syn_opts = struct.pack("!BBH", 2, 4, 1460) + \
        struct.pack("!BB", 4, 2) + \
        struct.pack("!BBBB", 3, 3, 7, 0) + \
        struct.pack("!BBII", 8, 10, tsval, 0)
    r.send(base_seq, 0, TH_SYN, opts=syn_opts)
    deadline = time.time() + wait
    out = {"rst": False, "rst_ttl": None, "rst_src": None, "rst_injected": False,
           "server_data": False, "server_ttl": None, "timeout": True, "note": ""}
    synack = r.recv(deadline)
    if synack is None:
        r.close()
        return dict(out, note="no SYN-ACK (filtered/dropped)")
    t = synack["tcp"]
    server_ttl = synack["ip"]["ttl"]
    if t["flags"] & TH_RST:
        r.close()
        return dict(out, rst=True, rst_ttl=server_ttl, rst_src=synack["ip"]["src"],
                    timeout=False, note="RST on SYN (closed/filtered)")
    if not (t["flags"] & TH_ACK):
        r.close()
        return dict(out, note="SYN-ACK without ACK flag")
    opts = parse_tcp_opts(synack["ip"]["payload"])
    sseq = t["seq"]
    seq, ack = base_seq + 1, sseq + 1
    data_tsval = int(time.time()) & 0xFFFFFFFF
    data_opts = b""
    if "tsval" in opts:
        data_opts = struct.pack("!BBII", 8, 10, data_tsval, opts["tsval"])
    out["timeout"] = False
    for part in segments:
        r.send(seq, ack, TH_ACK | TH_PSH, part, opts=data_opts)
        seq += len(part)
        if len(segments) > 1:
            time.sleep(0.004)
    while time.time() < deadline:
        pkt = r.recv(deadline)
        if pkt is None:
            break
        t = pkt["tcp"]
        if t["flags"] & TH_RST:
            out["rst"] = True
            out["rst_ttl"] = pkt["ip"]["ttl"]
            out["rst_src"] = pkt["ip"]["src"]
            if pkt["ip"]["src"] != r.dst or pkt["ip"]["ttl"] != server_ttl:
                out["rst_injected"] = True
        elif t["payload"] and not out["server_data"]:
            out["server_data"] = True
            out["server_ttl"] = pkt["ip"]["ttl"]
    r.close()
    return out


# ======================================================================
# TLS ClientHello construction
# ======================================================================

def build_client_hello(sni=None, pad_to=None, tls13=True, fake_session=True,
                       grease=False, keyshare=True, ech=False):
    rand = bytes(random.randrange(256) for _ in range(32))
    sess = b"\x00"
    if fake_session:
        sess = b"\x20" + bytes(random.randrange(256) for _ in range(32))

    grease_values = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a]
    ciphers = [0x1301, 0x1302, 0x1303]
    if not tls13:
        ciphers = [0xC02F, 0xC02B, 0xC02C, 0xCC13, 0xCC14, 0x009C, 0x009D]
    if grease:
        ciphers = [grease_values[0]] + ciphers + [grease_values[1]]

    ext = b""
    if sni:
        try:
            host = sni.encode("ascii")
        except UnicodeEncodeError:
            host = sni.encode("idna")
        ext += struct.pack("!HHH", 0x0000, len(host) + 5, len(host) + 3)
        ext += b"\x00" + struct.pack("!H", len(host)) + host

    if ech:
        # encrypted_client_hello (0xFE0D): well-formed envelope, random inner
        # (no real HPKE, so real servers reply "unsupported" alert instead of
        # blocking - which is exactly the DPI signal we want).
        cfg_id = random.randrange(256)
        enc = bytes(random.randrange(256) for _ in range(16))
        payload = bytes(random.randrange(256) for _ in range(64))
        ech_body = struct.pack("!B", cfg_id) + \
            struct.pack("!H", len(enc)) + enc + \
            struct.pack("!H", len(payload)) + payload
        ext += struct.pack("!HH", 0xFE0D, len(ech_body)) + ech_body

    groups = struct.pack("!H", 8) + struct.pack("!8H", 0x001D, 0x0017, 0x0018,
                                                0x0019, 0x001E, 0x0021, 0x0100,
                                                0x0101)
    ext += struct.pack("!HH", 0x000A, len(groups)) + groups
    epts = b"\x01\x00"
    ext += struct.pack("!HH", 0x000B, len(epts)) + epts
    sigs = struct.pack("!H", 10) + struct.pack("!5H", 0x0804, 0x0403, 0x0503,
                                               0x0809, 0x080A)
    ext += struct.pack("!HH", 0x000D, len(sigs)) + sigs

    if tls13:
        svs = b"\x04\x03\x04\x03\x03"
        ext += struct.pack("!HH", 0x002B, len(svs)) + svs
        pskm = b"\x01\x01"
        ext += struct.pack("!HH", 0x002D, len(pskm)) + pskm
        if keyshare:
            ks = b"\x00\x1d\x00\x20" + x25519_public(bytes(random.randrange(256) for _ in range(32)))
            ext += struct.pack("!HH", 0x0029, len(ks) + 2) + struct.pack("!H", len(ks)) + ks
        if grease:
            ext += struct.pack("!H", grease_values[2])
            ext += struct.pack("!H", grease_values[3])

    body = struct.pack("!H", 0x0303) + rand + sess
    body += struct.pack("!H", len(ciphers) * 2) + b"".join(struct.pack("!H", c) for c in ciphers)
    body += b"\x01\x00"
    body += struct.pack("!H", len(ext)) + ext

    if pad_to:
        # pad extension (0x0015) sized so the whole record lands on pad_to.
        # drop the old ext-length field too (2 bytes) so it is not duplicated.
        pad = max(0, pad_to - 13 - len(body))
        pext = struct.pack("!HH", 0x0015, pad) + b"\x00" * pad
        body = body[:len(body) - len(ext) - 2] + struct.pack("!H", len(ext) + 4 + pad) + ext + pext

    msg = b"\x01" + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 0x16, 0x0301, len(msg)) + msg


def build_variants(blocked, control):
    """name -> bytes for kernel-socket TLS content probes."""
    return {
        "TLS1.3 + SNI=%s" % blocked:          build_client_hello(sni=blocked),
        "TLS1.3 + SNI=%s (ctrl)" % control:    build_client_hello(sni=control),
        "TLS1.3, no SNI":                     build_client_hello(sni=None),
        "TLS1.3, GREASE+keyshare":            build_client_hello(sni=blocked, grease=True),
        "ECH cover SNI + ext":                build_client_hello(sni=control, ech=True),
        "ECH target SNI + ext":               build_client_hello(sni=blocked, ech=True),
        "TLS1.2 + SNI=%s" % blocked:          build_client_hello(sni=blocked, tls13=False),
        "TLS1.2, no SNI":                     build_client_hello(sni=None, tls13=False),
        "SNI %s. (trailing dot)" % blocked:    build_client_hello(sni=blocked + "."),
        "SNI %s.. (double dot)" % blocked:     build_client_hello(sni=blocked + ".."),
        "pad to 300":                         build_client_hello(sni=blocked, pad_to=300),
        "pad to 512":                         build_client_hello(sni=blocked, pad_to=512),
        "pad to 1000":                        build_client_hello(sni=blocked, pad_to=1000),
        "pad to 1400":                        build_client_hello(sni=blocked, pad_to=1400),
    }


def frag_plans(ch):
    n = len(ch)
    return {
        "frag: 1+rest":      [ch[:1], ch[1:]],
        "frag: 2+rest":      [ch[:2], ch[2:]],
        "frag: 3+rest":      [ch[:3], ch[3:]],
        "frag: 5+rest":      [ch[:5], ch[5:]],
        "frag: thirds":      [ch[:n // 3], ch[n // 3:2 * n // 3], ch[2 * n // 3:]],
    }


# ======================================================================
# kernel-socket probes (Track A)
# ======================================================================

def kernel_tls_probe(ip, port, ch, timeout=3.0):
    """Connect and send a ClientHello over real TCP. Classifies response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((ip, port))
    except socket.timeout:
        s.close()
        return {"kind": "timeout", "detail": "connect timeout (filtered)"}
    except (ConnectionRefusedError, ConnectionResetError):
        s.close()
        return {"kind": "rst", "detail": "RST on connect"}
    except OSError as e:
        s.close()
        return {"kind": "error", "detail": str(e)}
    try:
        s.send(ch)
    except ConnectionResetError:
        s.close()
        return {"kind": "rst", "detail": "RST on send (after ClientHello)"}
    except OSError as e:
        s.close()
        return {"kind": "error", "detail": str(e)}
    out = b""
    while time.time() - t0 < timeout:
        try:
            d = s.recv(4096)
        except ConnectionResetError:
            s.close()
            return {"kind": "rst", "detail": "ECONNRESET while waiting (RST injected)"}
        except socket.timeout:
            s.close()
            return {"kind": "timeout", "detail": "no server bytes"}
        if not d:
            break
        out += d
        if out[:1] == b"\x16":
            break
    s.close()
    if not out:
        return {"kind": "close", "detail": "server closed, no data"}
    t = out[0]
    if t == 0x16:
        return {"kind": "serverhello", "detail": f"ServerHello ({len(out)}B)"}
    if t == 0x15:
        return {"kind": "alert", "detail": f"TLS alert ({len(out)}B)"}
    return {"kind": "data", "detail": f"record type {t:#x} ({len(out)}B)"}


def kernel_http_probe(ip, port, req, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((ip, port))
    except socket.timeout:
        s.close()
        return {"kind": "timeout", "detail": "connect timeout"}
    except (ConnectionRefusedError, ConnectionResetError):
        s.close()
        return {"kind": "rst", "detail": "RST on connect"}
    except OSError as e:
        s.close()
        return {"kind": "error", "detail": str(e)}
    try:
        s.send(req)
    except ConnectionResetError:
        s.close()
        return {"kind": "rst", "detail": "RST on send"}
    out = b""
    try:
        while time.time() - t0 < timeout:
            d = s.recv(4096)
            if not d:
                break
            out += d
            if b"\r\n\r\n" in out:
                break
    except ConnectionResetError:
        s.close()
        return {"kind": "rst", "detail": "ECONNRESET (Host-header DPI?)"}
    except socket.timeout:
        pass
    s.close()
    if not out:
        return {"kind": "close", "detail": "no response"}
    if out.startswith(b"HTTP/"):
        return {"kind": "http", "detail": out.split(b"\r\n", 1)[0].decode(errors="replace")}
    return {"kind": "data", "detail": repr(out[:40])}


# ======================================================================
# DNS / UDP / ICMP / port scan
# ======================================================================

def dns_query(name, server, port=53, tcp=False, timeout=3.0):
    tid = random.randint(0, 0xFFFF)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.rstrip(".").split("."))
    q += b"\x00" + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q
    try:
        if tcp:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((server, port))
            s.send(struct.pack("!H", len(query)) + query)
            data = b""
            while len(data) < 2:
                data += s.recv(4096)
            ln = struct.unpack("!H", data[:2])[0]
            while len(data) < 2 + ln:
                data += s.recv(4096)
            s.close()
            data = data[2:]
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(query, (server, port))
            data, _ = s.recvfrom(65535)
            s.close()
    except Exception:
        return None
    return parse_dns(data)


def parse_dns(data):
    if len(data) < 12:
        return None
    flags = struct.unpack("!H", data[2:4])[0]
    qd, an = struct.unpack("!HH", data[4:8])
    rcode = flags & 0x0F
    off = 12
    for _ in range(qd):
        while data[off] != 0:
            off += data[off] + 1
        off += 5
    answers = []
    for _ in range(an):
        if off + 2 > len(data):
            break
        if data[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while data[off] != 0:
                off += data[off] + 1
            off += 1
        if off + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == 1 and len(rdata) == 4:
            answers.append(socket.inet_ntoa(rdata))
    return {"rcode": rcode, "answers": answers}


def udp_probe(server, dport, payload=b"", timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.sendto(payload, (server, dport))
        data, _ = s.recvfrom(65535)
        return {"reply": True, "bytes": len(data), "rtt": time.time() - t0}
    except socket.timeout:
        return {"reply": False, "bytes": 0, "rtt": timeout}
    finally:
        s.close()


def icmp_port_unreachable(target, dport, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(0.05)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.sendto(b"probe", (target, dport))
    except Exception:
        pass
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            pkt, _ = s.recvfrom(65535)
        except socket.timeout:
            continue
        ip = parse_ip(pkt)
        if not ip or ip["proto"] != 1 or ip["src"] != target:
            continue
        if pkt[20] == 3 and pkt[21] == 3:
            return True
    return False


def tcp_connect(host, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        return {"open": True, "rtt": time.time() - t0}
    except socket.timeout:
        return {"open": None, "rtt": timeout}
    except (ConnectionRefusedError, OSError):
        return {"open": False, "rtt": time.time() - t0}
    finally:
        s.close()


def resolve(host):
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except Exception:
        return None


def detect_resolver():
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    return line.split()[1]
    except Exception:
        pass
    return None


# ======================================================================
# classification + reporting
# ======================================================================

def classify_kernel(res):
    k = res["kind"]
    if k == "serverhello":
        return "SERVER HELLO - not blocked"
    if k == "alert":
        return "TLS alert (server replied) - not blocked"
    if k == "rst":
        return "RST / reset - blocked or reset"
    if k == "timeout":
        return "TIMEOUT - filtered / silent drop"
    if k == "close":
        return "closed, no data"
    return f"{k}: {res['detail']}"


def classify_raw(res):
    if res["timeout"] and not res["rst"]:
        return "TIMEOUT"
    if res["rst"]:
        inj = " INJECTED" if res.get("rst_injected") else ""
        src = f" from {res['rst_src']}" if res.get("rst_src") else ""
        if res["server_data"]:
            return f"RST after data{src} (ttl={res['rst_ttl']}){inj}"
        return f"RST, no data{src} (ttl={res['rst_ttl']}){inj}"
    if res["server_data"]:
        return f"SERVER DATA (ttl={res['server_ttl']})"
    return "no data, no RST"


def consensus(results):
    """results: list of classify strings -> (label, confidence)"""
    if not results:
        return ("n/a", 0)
    from collections import Counter
    c = Counter(results)
    top, n = c.most_common(1)[0]
    return (top, n / len(results))


# ======================================================================
# test runners
# ======================================================================

def run_baseline(args, rp):
    data = {}
    rp.section("BASELINE reachability")
    for port in (80, 443, 8443, 853, 8080, 53, 22, 137, 161):
        r = tcp_connect(args.target, port, args.timeout)
        if r["open"]:
            rp.kv(f"tcp/{port}", f"OPEN  {r['rtt']*1000:.0f}ms")
        elif r["open"] is False:
            rp.kv(f"tcp/{port}", "closed (RST)")
        else:
            rp.kv(f"tcp/{port}", "filtered (silent drop)")
        data[f"tcp/{port}"] = r["open"]

    rp.section("BASELINE UDP / QUIC / ICMP")
    quic = udp_probe(args.target, 443, quic_initial_payload(), args.timeout)
    rp.kv("udp/443 QUIC", "reply" if quic["reply"] else "no reply")
    icmp = icmp_port_unreachable(args.target, 55555, args.timeout)
    rp.kv("UDP egress", "UDP transits (ICMP unreach)" if icmp else "UDP dropped/silenced")
    data["quic_443"] = quic["reply"]
    data["udp_egress"] = icmp
    if not quic["reply"] and icmp:
        rp.kv("  hint", "QUIC/443 filtered while UDP works -> QUIC DPI")

    rp.section("TCP middlebox fingerprint (raw control)")
    self_ip = args.self_ip
    # run raw control vs kernel control on the same target:443 with good SNI
    ch = build_client_hello(sni=args.control or "example.com")
    k = kernel_tls_probe(args.ip, 443, ch, args.timeout)
    raw_outcomes = []
    raw_res = []
    for _ in range(args.repeats):
        res = raw_connect_probe(self_ip, args.ip, args.src_port or random.randint(20000, 60000),
                                443, [ch], args.wait)
        raw_res.append(res)
        raw_outcomes.append(classify_raw(res))
        time.sleep(0.2)
    top, conf = consensus(raw_outcomes)
    rp.kv("kernel control", classify_kernel(k))
    rp.kv(f"raw control x{args.repeats}", f"{top} (consensus {conf:.0%}, tries={raw_outcomes})")
    data["kernel_control"] = classify_kernel(k)
    data["raw_control"] = top
    data["raw_control_res"] = raw_res
    raw_trusted = not (k["kind"] in ("serverhello", "alert") and top.startswith("RST"))
    data["raw_trusted"] = raw_trusted
    if not raw_trusted:
        rp.kv("  !!!", "MIDDLEBOX mangles non-kernel TCP: raw/camouflage results are UNRELIABLE here. "
                       "Use kernel-based results as ground truth.")
    else:
        rp.kv("  ok", "raw TCP behaves like kernel TCP - camouflage tests are meaningful")
    rp.flush()
    return data


def run_dns(args, rp):
    rp.section("DNS behavior")
    data = {}
    resolvers = [detect_resolver(), "8.8.8.8", "1.1.1.1"]
    resolvers = [r for r in resolvers if r]
    ref = None
    for rsv in resolvers:
        for tcp in (False, True):
            res = dns_query(args.target, rsv, tcp=tcp, timeout=args.timeout)
            tag = f"{rsv}:{'tcp' if tcp else 'udp'}"
            if res is None:
                rp.kv("dns " + tag, "no response")
                data[tag] = None
            else:
                if ref is None:
                    ref = sorted(res["answers"])
                ans = ",".join(res["answers"]) if res["answers"] else f"(rcode={res['rcode']})"
                rp.kv("dns " + tag, ans)
                data[tag] = res["answers"]
    poisoned = ref is not None and any(
        tag in data and data[tag] and sorted(data[tag]) != ref
        for tag in data)
    data["poisoned"] = bool(poisoned)
    if poisoned:
        rp.kv("DNS POISONING", "resolver answers differ from reference -> blocked/spoofed DNS")
    rp.kv("note", "if any resolver answer differs from 8.8.8.8/1.1.1.1 -> DNS poisoning")
    rp.flush()
    return data


def run_tls(args, rp):
    rp.section(f"TLS content DPI on {args.target}:443 (kernel TCP = ground truth)")
    rp.flush()
    variants = build_variants(args.target, args.control or "example.com")
    results = {}
    for name, ch in variants.items():
        res = kernel_tls_probe(args.ip, 443, ch, args.timeout)
        results[name] = res
        print(f"    {name:<34} {classify_kernel(res)}")
        time.sleep(0.15)
    rp.section("TLS DPI classification")
    for name, res in results.items():
        rp.kv(name, classify_kernel(res))
    rp.flush()
    return results


def run_http(args, rp):
    rp.section(f"HTTP Host-header DPI on {args.target}:80")
    rp.flush()
    tests = {
        "Host: target":       f"GET / HTTP/1.1\r\nHost: {args.target}\r\nConnection: close\r\n\r\n",
        "Host: control":      f"GET / HTTP/1.1\r\nHost: {args.control or 'example.com'}\r\nConnection: close\r\n\r\n",
        "Host: IP literal":   f"GET / HTTP/1.1\r\nHost: {args.ip}\r\nConnection: close\r\n\r\n",
        "no UA, Host target": f"GET / HTTP/1.1\r\nHost: {args.target}\r\nConnection: close\r\n\r\n",
        "Host UPPER":         f"GET / HTTP/1.1\r\nHost: {args.target.upper()}\r\nConnection: close\r\n\r\n",
        "HTTP/2 preface":     f"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    }
    results = {}
    for name, req in tests.items():
        res = kernel_http_probe(args.ip, 80, req.encode(), args.timeout)
        print(f"    {name:<24} {classify_kernel(res)}")
        rp.kv(name, classify_kernel(res))
        results[name] = classify_kernel(res)
        time.sleep(0.1)
    rp.flush()
    return results


def run_frag(args, rp):
    rp.section(f"Raw camouflage matrix on {args.target}:443 ({args.repeats}x consensus)")
    rp.flush()
    self_ip = args.self_ip
    ch = build_client_hello(sni=args.target)
    plans = frag_plans(ch)
    plans["single (control)"] = [ch]
    plans["pad to 300"] = [build_client_hello(sni=args.target, pad_to=300)]
    plans["pad to 512"] = [build_client_hello(sni=args.target, pad_to=512)]
    plans["pad to 1000"] = [build_client_hello(sni=args.target, pad_to=1000)]
    plans["GREASE"] = [build_client_hello(sni=args.target, grease=True)]
    plans["no SNI"] = [build_client_hello(sni=None)]
    data = {}
    for name, segs in plans.items():
        outcomes = []
        for _ in range(args.repeats):
            res = raw_connect_probe(self_ip, args.ip, args.src_port or random.randint(20000, 60000),
                                    443, segs, args.wait)
            outcomes.append(classify_raw(res))
            time.sleep(0.2)
        top, conf = consensus(outcomes)
        print(f"    {name:<24} {top:<34} consensus {conf:.0%}  {outcomes}")
        rp.kv("frag " + name, f"{top} (consensus {conf:.0%})")
        data[name] = top
    rp.flush()
    return data


def dns_query_payload():
    tid = random.randint(0, 0xFFFF)
    q = b"".join(bytes([len(l)]) + l.encode() for l in ["example", "com"])
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q + b"\x00" + struct.pack("!HH", 1, 1)


def quic_initial_payload():
    return b"\xc0" + b"\x00" * 11 + bytes(random.randrange(256) for _ in range(8))


def run_udp(args, rp):
    rp.section(f"UDP DPI matrix on {args.target}")
    rp.flush()
    data = {}
    real_payload = {53: dns_query_payload, 443: quic_initial_payload}
    for p in (53, 123, 443, 1194, 4500, 51820, 8080):
        payload = real_payload[p]() if p in real_payload else b"\x00" * 4
        r = udp_probe(args.ip, p, payload, args.timeout)
        tag = f"udp/{p}"
        rp.kv(tag, "reply" if r["reply"] else "no reply")
        data[tag] = r["reply"]
    for p in (53, 443):
        t = tcp_connect(args.ip, p, args.timeout)
        u = udp_probe(args.ip, p, real_payload[p](), args.timeout)
        if t["open"] and not u["reply"]:
            rp.kv(f"  udp/{p} blocked", "TCP open but UDP silent -> per-port UDP DPI (QUIC/DNS throttle)")
    rp.flush()
    return data


def run_scan(args, rp):
    rp.section(f"Open-port scan of {args.target}")
    rp.flush()
    ports = [20, 21, 22, 23, 25, 53, 67, 80, 110, 123, 137, 139, 143, 161, 443,
             445, 465, 500, 587, 853, 990, 993, 995, 1194, 1433, 1723, 2049, 2083,
             2087, 3128, 3306, 3389, 5432, 5900, 6379, 8080, 8081, 8443, 8888, 9000,
             9090, 9443, 10000, 11211, 27017, 50000]
    open_ports = []
    for p in ports:
        r = tcp_connect(args.target, p, args.timeout)
        if r["open"]:
            open_ports.append(p)
    if args.scan_full:
        for p in range(1, 65536):
            if p in ports:
                continue
            if tcp_connect(args.target, p, 0.35)["open"]:
                open_ports.append(p)
    print("  open:", ", ".join(map(str, sorted(open_ports))) if open_ports else "none")
    rp.kv("open ports", ", ".join(map(str, sorted(open_ports))) if open_ports else "none")
    rp.kv("scanned", "common-50" if not args.scan_full else "all 1-65535")
    rp.flush()
    return {"open": open_ports, "full": args.scan_full}


# ======================================================================
# auto-diagnosis (rule-based "AI"): cross-reference everything and tell
# the user what the network blocks and which evasion actually passed.
# ======================================================================

def _verdict(res):
    if not res or not isinstance(res, dict):
        return "unknown"
    if res.get("kind") in ("serverhello", "alert"):
        return "ok"
    if res.get("kind") in ("rst", "timeout"):
        return "blocked"
    return "unknown"


def run_diagnose(args, rp, results):
    rp.section("DIAGNOSIS: what the network blocks + what evades it")
    rp.flush()
    tls = results.get("tls", {})
    http = results.get("http", {})
    udp = results.get("udp", {})
    dns = results.get("dns", {})
    base = results.get("baseline", {})
    frag = results.get("frag", {})
    raw_trusted = base.get("raw_trusted", True)
    blocked = []

    def v(name):
        return _verdict(tls.get(name))

    k, ctrl = f"TLS1.3 + SNI={args.target}", f"TLS1.3 + SNI={args.control} (ctrl)"
    bad, good, nosni = v(k), v(ctrl), v("TLS1.3, no SNI")
    grease, t12 = v("TLS1.3, GREASE+keyshare"), v(f"TLS1.2 + SNI={args.target}")
    echc, eche = v("ECH cover SNI + ext"), v("ECH target SNI + ext")

    # --- TLS vectors ------------------------------------------------
    if bad == "blocked":
        if good == "ok":
            blocked.append(("SNI-value blocking (target SNI RST, control SNI ok)",
                ["ECH with cover outer SNI", "domain fronting via CDN",
                 "client-side ClientHello fragmentation"]))
        elif nosni == "ok":
            blocked.append(("SNI-presence blocking (RST only when an SNI is sent)",
                ["no-SNI / ALPN-only TLS if the server allows",
                 "ECH (removes the visible SNI)"]))
        elif good == "blocked":
            blocked.append(("Broad blocking (RST for all SNI incl. control): IP/ASN or TLS fingerprint DPI",
                ["browser-mimic ClientHello (GREASE+keyshare)",
                 "no-SNI / ALPN TLS", "TLS1.2 fallback", "different IP / CDN / VPN-over-443"]))
        elif nosni == "blocked":
            blocked.append(("TLS fingerprint DPI (control SNI passes, no-SNI RST)",
                ["browser-mimic ClientHello (GREASE+keyshare)",
                 "real browser stack (uTLS-style)", "different TLS version/profile"]))
        if t12 == "ok":
            blocked[-1][1].append("TLS1.2 target variant already passes -> pin TLS1.2")
        if echc == "ok":
            blocked[-1][1].insert(0, "ECH+cover SNI CONFIRMED WORKING (passes)")
        elif eche == "ok" and echc == "blocked":
            blocked[-1][1].insert(0, "ECH works with cover outer SNI but NOT target outer SNI")
    elif bad == "ok":
        rp.kv("TLS", "no TLS-level blocking detected (all variants accepted)")

    # --- HTTP Host ------------------------------------------------
    ht, hc = http.get("Host: target"), http.get("Host: control")
    if ht and ht.startswith("RST") and hc and not hc.startswith("RST"):
        blocked.append(("HTTP Host-header blocking (Host: target RST, control ok)",
            ["HTTPS (encrypted)", "HTTP/2 h2c if the server allows",
             "DoH/DoT so names resolve without HTTP", "domain fronting"]))
    if http.get("Host: IP literal", "").startswith("RST") and not (ht or "").startswith("RST"):
        blocked.append(("HTTP Host: IP-literal blocked - Host value DPI",
            ["use the real domain Host header"]))

    # --- UDP / QUIC ------------------------------------------------
    if base.get("tcp/443") is True and udp.get("udp/443") is False:
        blocked.append(("UDP/443 (QUIC) blocked while TCP/443 open",
            ["force TCP transports: HTTP/1.1, HTTP/2, DoT/853, DoH/443",
             "VPN/SSH tunnel over TCP 443"]))
    if base.get("tcp/53") is True and udp.get("udp/53") is False:
        blocked.append(("UDP DNS filtered while TCP works",
            ["DoH/DoT encrypted DNS", "resolver over TCP 53"]))

    # --- DNS ------------------------------------------------------
    if dns.get("poisoned"):
        blocked.append(("DNS poisoning (answers differ across resolvers)",
            ["DoH/DoT encrypted DNS", "dnscrypt-proxy", "pin static hosts / IP-direct"]))

    # --- raw camouflage ---------------------------------------------
    if not raw_trusted:
        rp.kv("raw", "raw/camouflage untrusted: middlebox mangles non-kernel TCP")

    def pas(c):
        return isinstance(c, str) and c.startswith("SERVER DATA")

    single = frag.get("single (control)", "")
    if raw_trusted and frag and single:
        if pas(single):
            badf = [n for n, c in frag.items() if c.startswith("RST") and n != "single (control)"]
            rp.kv("frag", ("single CH passes, some frag variants RST -> DPI reassembles; "
                           "fragmentation is NOT a reliable bypass here"
                           if badf else "no CH-level blocking to evade"))
        else:
            goodf = [n for n, c in frag.items() if pas(c)]
            if goodf:
                blocked.append(("camouflage confirmed: single CH blocked, fragmented variants pass",
                    ["client-side ClientHello fragmentation",
                     "split the TCP segment at the SNI boundary"]))
            else:
                rp.kv("frag", "all raw variants blocked/unusable")

    # --- report -----------------------------------------------------
    if not blocked:
        rp.kv("result", "no blocking vectors detected")
    else:
        rp.kv("blocked vectors", str(len(blocked)))
        for desc, recs in blocked:
            print(f"  BLOCKED: {desc}")
            print(f"    TRY:    {recs[0]}")
            for extra in recs[1:]:
                print(f"            - {extra}")
            print()
    rp.flush()
    return {"blocked_vectors": [d for d, _ in blocked],
            "advice": [r for _, r in blocked]}


# ======================================================================
# main
# ======================================================================

class Reporter:
    def __init__(self, out=None):
        self.lines = []
        self.out = out

    def section(self, title):
        self.lines.append("")
        self.lines.append("=" * 62)
        self.lines.append(title)
        self.lines.append("=" * 62)

    def kv(self, k, v):
        self.lines.append(f"  {k:<30} {v}")

    def flush(self):
        text = "\n".join(self.lines)
        print(text)
        if self.out:
            self.out.write(text + "\n")
            self.out.flush()
        self.lines = []


# ======================================================================
# offline self-test: no network, no root needed
# ======================================================================

def run_selftest():
    fails = []

    def check(name, cond):
        print(f"  [{'ok' if cond else 'FAIL'}] {name}")
        if not cond:
            fails.append(name)

    print("== dpi-lab selftest (offline) ==")
    k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = int.from_bytes(bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"), "little")
    expect = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    check("x25519 RFC 7748 vector", x25519(k, u).to_bytes(32, "little").hex() == expect)

    h = ip_header("192.168.0.1", "8.8.8.8", 6, 40, 1)
    c = csum(h)
    check("IPv4 checksum roundtrip", csum(h[:10] + struct.pack("!H", c) + h[12:]) == 0)

    pkt = tcp_packet("192.168.0.1", "8.8.8.8", 1234, 443, 1, 1, TH_SYN | TH_ACK, b"")
    t = parse_tcp(parse_ip(pkt)["payload"])
    check("TCP parse roundtrip", t["sport"] == 1234 and t["dport"] == 443 and
          (t["flags"] & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))

    for pad in (300, 512, 1000):
        check(f"ClientHello pad_to={pad}", len(build_client_hello(sni="example.com", pad_to=pad)) == pad)

    check("ECH ext present", b"\xfe\x0d" in build_client_hello(sni="example.com", ech=True))
    vs = build_variants("blocked.example", "good.example")
    check("variants unique", len(vs) == len(set(vs)))

    print("PASS" if not fails else f"FAILED: {', '.join(fails)}")
    sys.exit(1 if fails else 0)


def main():
    ap = argparse.ArgumentParser(description="DPI lab: probe, classify, evade.")
    ap.add_argument("--target", help="host being filtered (domain or IP)")
    ap.add_argument("--ip", help="resolved target IP (auto if omitted)")
    ap.add_argument("--control", default="example.com", help="known-good control host")
    ap.add_argument("--self-ip", help="local source IP (auto-detect)")
    ap.add_argument("--src-port", type=int, help="source port for raw probes")
    ap.add_argument("--timeout", type=float, default=1.5, help="socket timeout s")
    ap.add_argument("--wait", type=float, default=2.5, help="raw listen window s")
    ap.add_argument("--repeats", type=int, default=3, help="raw consensus runs")
    ap.add_argument("--mode", nargs="+", default=["all"],
                    choices=["baseline", "dns", "tls", "http", "udp", "frag", "scan",
                             "diagnose", "all"])
    ap.add_argument("--scan-full", action="store_true")
    ap.add_argument("--selftest", action="store_true", help="offline packet-builder validation")
    ap.add_argument("--out", help="also write the text report to this file")
    ap.add_argument("--json", dest="json_out", help="write a structured JSON report to this file")
    args = ap.parse_args()

    if args.selftest:
        run_selftest()
        return

    if not args.target:
        args.target = input("Target host to test (domain or IP): ").strip()
    if not args.target:
        sys.exit(1)
    args.ip = args.ip or resolve(args.target)
    if not args.ip:
        print(f"cannot resolve {args.target}")
        sys.exit(1)
    if not args.self_ip:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            args.self_ip = s.getsockname()[0]
        finally:
            s.close()
    if os.geteuid() != 0:
        print("need root for raw sockets")
        sys.exit(1)

    print(f"# dpi-lab  target={args.target} ({args.ip})  control={args.control}  self={args.self_ip}")
    out_f = open(args.out, "w") if args.out else None
    rp = Reporter(out_f)
    modes = set(args.mode)
    if "all" in modes:
        modes = {"baseline", "dns", "tls", "http", "udp", "frag", "scan", "diagnose"}

    results = {}
    for m in ("baseline", "dns", "tls", "http", "udp", "frag", "scan"):
        if m in modes:
            res = globals()[f"run_{m}"](args, rp)
            if isinstance(res, dict):
                results[m] = res
    if "diagnose" in modes:
        results["diagnose"] = run_diagnose(args, rp, results)

    if out_f:
        out_f.close()
    if args.json_out:
        import json as _json
        with open(args.json_out, "w") as f:
            _json.dump({"target": args.target, "ip": args.ip,
                        "control": args.control, "self_ip": args.self_ip,
                        "results": results}, f, indent=2, default=str)
        print(f"JSON report -> {args.json_out}")


if __name__ == "__main__":
    main()
