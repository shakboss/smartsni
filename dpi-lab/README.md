# dpi-lab

Deep Packet Inspection (DPI) analysis + evasion-testing toolkit for Linux.
Pure Python 3, zero dependencies, needs `root` (raw sockets). Run it only
against networks/servers you own or are authorized to test.

**Running from a mobile network:** run this on a machine (or rooted
Android Termux) whose traffic egresses via the carrier you want to test.
The `INJECTED` RST signal and the raw-control sanity check are what expose
carrier-grade DPI that the normal browser never sees.

## What it does

Two probe tracks work together so results stay trustworthy even when a
middlebox is hostile:

| Track | Transport | Answers |
|-------|-----------|---------|
| **A: kernel sockets** | normal TCP (real stack) | *what* triggers the block: SNI value, SNI presence, TLS fingerprint, HTTP Host header |
| **B: raw sockets** | our own IP/TCP stack | *does* a camouflage survive: fragmentation, padding, GREASE, no-SNI |

Every raw result is run N times and reported as a consensus, and a `raw
control` probe (same ClientHello over both stacks) tells you when the
middlebox mangles non-kernel TCP so badly that raw results are
unreliable.

## Usage

```sh
sudo python3 dpi_probe.py --target <blocked-host> --control <working-host> --mode all
```

`--mode` picks: `baseline` (ports, UDP/QUIC, middlebox fingerprint),
`dns` (poisoning check), `tls` (SNI/fingerprint matrix incl. ECH variants),
`http` (Host matrix), `udp` (per-port UDP DPI matrix), `frag`
(camouflage matrix), `scan` (open-port recon), `diagnose` (auto block
vector + evasion recommendations), `all`.

Other flags: `--ip` (skip DNS), `--self-ip`, `--src-port`, `--timeout`,
`--wait`, `--repeats N` (raw consensus count, default 3), `--scan-full`
(1-65535), `--out report.txt` (also write the text report to a file),
`--json report.json` (structured machine-readable report), and
`--selftest` (offline validation of x25519, checksums, padding — no
root or network needed).

## Auto-diagnosis

`--mode diagnose` (or `all`) cross-references every probe and prints what
the network is blocking and which evasion already passed, e.g.:

```
BLOCKED: SNI-value blocking (target SNI RST, control SNI ok)
  TRY:    ECH+cover SNI CONFIRMED WORKING (passes)
          - ECH with cover outer SNI
          - domain fronting via CDN
          - client-side ClientHello fragmentation
          - TLS1.2 target variant already passes -> pin TLS1.2
```

Run once, then re-run after applying an evasion and diff the JSON to
confirm it worked (`--json` + `diff`).

## Reading the report

* `tcp/443 filtered (silent drop)` — port blocked or not listening.
* `RST / reset - blocked or reset` on a probe variant while the control
  variant gets `TLS alert` / `SERVER HELLO` — that variant is what DPI
  keys on (e.g. target-SNI RSTs, control-SNI doesn't => SNI-based DPI).
* `INJECTED` on a raw RST line means the RST's source IP or TTL differs
  from the real server — signature of a middlebox (carrier DPI) sending
  forged resets, not the server.
* `MIDDLEBOX mangles non-kernel TCP` — the network resets hand-crafted
  TCP; trust Track A results, treat `frag` results as inconclusive.
* `UDP dropped/silenced` while TCP works — UDP/QUIC filtered (the
  classic HTTP/3 kill).
* `ECH cover SNI + ext` passing while target-SNI RSTs confirms an ECH
  evasion works against that DPI.

## Evasion cheat-sheet (match finding to fix)

**SNI-value blocking** (RST only when target SNI is sent):
* TLS 1.3 with Encrypted Client Hello (ECH / ESNI) — hides SNI. The
  `ECH cover SNI + ext` probe tests this against your network.
* Domain fronting via a CDN that allows custom Host headers.
* Client-side fragmentation of the ClientHello so the SNI never appears
  in one packet (what `--mode frag` tests).
* Any SNI-less TLS (ALPN services) if the service allows it.

**TLS-fingerprint blocking** (RST even with no SNI / control SNI):
* Mimic a real browser ClientHello (GREASE, x25519 keyshare, normal
  cipher order) — the `GREASE+keyshare` variant tests this.
* Avoid TLS client versions/ciphers that fingerprint as "odd".

**HTTP Host-header blocking:**
* DNS over HTTPS / TLS, or IPv6, or HTTP/2 (cleartext h2c is rare).

**UDP / QUIC blocking:**
* Use TCP-based transports (HTTP/1.1, HTTP/2, DoT/853, DoH/443).
* WireGuard/OpenVPN over TCP 443 as an encrypted fallback.

**DNS poisoning** (resolver answers differ from 8.8.8.8/1.1.1.1):
* DoH/DoT (encrypted DNS) or `dnsmasq` + upstream over TCP.

**General note:** the most robust long-term "camouflage" is a full
transport that looks like ordinary HTTPS (e.g. HTTP/2 over TLS 1.3 on
port 443 with ECH), because it defeats SNI, fingerprint, and Host DPI
simultaneously.
