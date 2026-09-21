"""Synthetic captures, built byte by byte in code.

Every fixture in this project is generated here. No capture taken from a real
network is used or shipped: addresses come from the ranges reserved for
documentation (RFC 5737 for IPv4, RFC 3849 for IPv6, RFC 2606 for names) and
MAC addresses are locally administered.

The builders are also what ``tools/make_demo.py`` uses to write
``examples/demo.pcapng`` and what the fuzzer mutates.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass

# Documentation addresses (RFC 5737, RFC 3849, RFC 2606).
CLIENT_IP = "192.0.2.10"
ROUTER_IP = "192.0.2.1"
SERVER_IP = "198.51.100.23"
OTHER_IP = "203.0.113.57"
CLIENT_IP6 = "2001:db8::10"
SERVER_IP6 = "2001:db8:2::23"
CLIENT_MAC = "02:00:5e:10:00:0a"
ROUTER_MAC = "02:00:5e:10:00:01"
SERVER_NAME = "www.example.com"

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100


def mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


def ipv4_bytes(text: str) -> bytes:
    return bytes(int(part) for part in text.split("."))


def ipv6_bytes(text: str) -> bytes:
    import ipaddress
    return ipaddress.IPv6Address(text).packed


def checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


# --------------------------------------------------------------------------
# frames
# --------------------------------------------------------------------------

def ethernet(payload: bytes, *, dst: str = ROUTER_MAC, src: str = CLIENT_MAC,
             ethertype: int = ETHERTYPE_IPV4) -> bytes:
    return mac(dst) + mac(src) + struct.pack(">H", ethertype) + payload


def vlan(payload: bytes, vid: int = 100, priority: int = 0,
         ethertype: int = ETHERTYPE_IPV4) -> bytes:
    tci = (priority << 13) | vid
    return struct.pack(">HH", tci, ethertype) + payload


def ipv4(payload: bytes, *, src: str = CLIENT_IP, dst: str = SERVER_IP, proto: int = 17,
         ttl: int = 64, ident: int = 0x1234, flags: int = 0x4000,
         options: bytes = b"") -> bytes:
    ihl = 5 + len(options) // 4
    header = struct.pack(">BBHHHBBH", 0x40 | ihl, 0, ihl * 4 + len(payload), ident, flags,
                         ttl, proto, 0) + ipv4_bytes(src) + ipv4_bytes(dst) + options
    header = header[:10] + struct.pack(">H", checksum16(header)) + header[12:]
    return header + payload


def ipv6(payload: bytes, *, src: str = CLIENT_IP6, dst: str = SERVER_IP6,
         next_header: int = 17, hop_limit: int = 64, flow: int = 0x12345) -> bytes:
    return (struct.pack(">IHBB", 0x60000000 | flow, len(payload), next_header, hop_limit)
            + ipv6_bytes(src) + ipv6_bytes(dst) + payload)


def ipv6_fragment(payload: bytes, *, next_header: int, offset: int, more: bool,
                  ident: int = 0xABCD, **kwargs: object) -> bytes:
    header = struct.pack(">BBHI", next_header, 0, (offset // 8) << 3 | int(more), ident)
    return ipv6(header + payload, next_header=44, **kwargs)  # type: ignore[arg-type]


def _pseudo_header(src: str, dst: str, proto: int, length: int, v6: bool) -> bytes:
    if v6:
        return ipv6_bytes(src) + ipv6_bytes(dst) + struct.pack(">IBBBB", length, 0, 0, 0, proto)
    return ipv4_bytes(src) + ipv4_bytes(dst) + struct.pack(">BBH", 0, proto, length)


def udp(payload: bytes, *, sport: int = 51000, dport: int = 53, src: str = CLIENT_IP,
        dst: str = SERVER_IP, v6: bool = False) -> bytes:
    length = 8 + len(payload)
    body = struct.pack(">HHHH", sport, dport, length, 0) + payload
    checksum = checksum16(_pseudo_header(src, dst, 17, length, v6) + body) or 0xFFFF
    return body[:6] + struct.pack(">H", checksum) + body[8:]


def tcp(payload: bytes = b"", *, sport: int = 52000, dport: int = 443, seq: int = 1,
        ack: int = 0, flags: int = 0x18, window: int = 64240, options: bytes = b"",
        src: str = CLIENT_IP, dst: str = SERVER_IP, v6: bool = False) -> bytes:
    offset = 5 + len(options) // 4
    body = (struct.pack(">HHIIBBHHH", sport, dport, seq, ack, offset << 4, flags, window, 0, 0)
            + options + payload)
    checksum = checksum16(_pseudo_header(src, dst, 6, len(body), v6) + body)
    return body[:16] + struct.pack(">H", checksum) + body[18:]


def arp(*, opcode: int = 1, sender_mac: str = CLIENT_MAC, sender_ip: str = CLIENT_IP,
        target_mac: str = "00:00:00:00:00:00", target_ip: str = ROUTER_IP) -> bytes:
    return (struct.pack(">HHBBH", 1, ETHERTYPE_IPV4, 6, 4, opcode) + mac(sender_mac)
            + ipv4_bytes(sender_ip) + mac(target_mac) + ipv4_bytes(target_ip))


def icmp_echo(*, request: bool = True, identifier: int = 0x1a2b, sequence: int = 1,
              payload: bytes = b"abcdefghijklmnop") -> bytes:
    body = struct.pack(">BBHHH", 8 if request else 0, 0, 0, identifier, sequence) + payload
    return body[:2] + struct.pack(">H", checksum16(body)) + body[4:]


def icmp_unreachable(quoted: bytes, *, code: int = 3) -> bytes:
    body = struct.pack(">BBHI", 3, code, 0, 0) + quoted
    return body[:2] + struct.pack(">H", checksum16(body)) + body[4:]


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------

def dns_name(name: str) -> bytes:
    if name in (".", ""):
        return b"\x00"
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def dns_query(name: str = SERVER_NAME, *, qtype: int = 1, txid: int = 0x1a2b,
              flags: int = 0x0100) -> bytes:
    return (struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0) + dns_name(name)
            + struct.pack(">HH", qtype, 1))


def dns_response(name: str = SERVER_NAME, *, answers: list[tuple[int, bytes]] | None = None,
                 txid: int = 0x1a2b, flags: int = 0x8180, ttl: int = 300) -> bytes:
    answers = answers if answers is not None else [(1, ipv4_bytes("198.51.100.23"))]
    body = struct.pack(">HHHHHH", txid, flags, 1, len(answers), 0, 0)
    body += dns_name(name) + struct.pack(">HH", 1, 1)
    for rtype, rdata in answers:
        # 0xC00C is a compression pointer back to the question's name at offset 12.
        body += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata
    return body


# --------------------------------------------------------------------------
# TLS
# --------------------------------------------------------------------------

def _vector(data: bytes, size: int) -> bytes:
    if size == 1:
        return bytes([len(data)]) + data
    if size == 2:
        return struct.pack(">H", len(data)) + data
    return struct.pack(">I", len(data))[1:] + data


def _extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">H", ext_type) + _vector(data, 2)


def tls_record(fragment: bytes, *, content_type: int = 22, version: int = 0x0303) -> bytes:
    return struct.pack(">BHH", content_type, version, len(fragment)) + fragment


def client_hello(server_name: str | None = SERVER_NAME, *, alpn: tuple[str, ...] = ("h2", "http/1.1"),
                 ciphers: tuple[int, ...] = (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0x00FF),
                 groups: tuple[int, ...] = (29, 23, 24), versions: tuple[int, ...] = (0x0304, 0x0303),
                 grease: bool = True, seed: int = 7) -> bytes:
    """A structurally valid TLS 1.3 ClientHello handshake message."""
    rng = random.Random(seed)
    extensions = b""
    if server_name is not None:
        host = server_name.encode()
        extensions += _extension(0, _vector(b"\x00" + _vector(host, 2), 2))
    extensions += _extension(11, _vector(b"\x00", 1))                       # ec_point_formats
    extensions += _extension(10, _vector(b"".join(struct.pack(">H", g) for g in groups), 2))
    extensions += _extension(35, b"")                                       # session_ticket
    extensions += _extension(16, _vector(b"".join(_vector(p.encode(), 1) for p in alpn), 2))
    extensions += _extension(13, _vector(b"".join(struct.pack(">H", s)
                                                  for s in (0x0403, 0x0804, 0x0401)), 2))
    extensions += _extension(43, _vector(b"".join(struct.pack(">H", v) for v in versions), 1))
    extensions += _extension(51, _vector(b"".join(struct.pack(">H", g) + _vector(
        bytes(rng.getrandbits(8) for _ in range(32)), 2) for g in groups[:1]), 2))
    extensions += _extension(23, b"")                                       # extended_master_secret
    extensions += _extension(65281, b"\x00")                                # renegotiation_info
    if grease:
        extensions = _extension(0x0A0A, b"") + extensions + _extension(0x1A1A, b"\x00\x00")
    suites = ((0x0A0A,) if grease else ()) + ciphers
    body = (struct.pack(">H", 0x0303)
            + bytes(rng.getrandbits(8) for _ in range(32))
            + _vector(bytes(rng.getrandbits(8) for _ in range(32)), 1)
            + _vector(b"".join(struct.pack(">H", c) for c in suites), 2)
            + _vector(b"\x00", 1)
            + _vector(extensions, 2))
    return b"\x01" + _vector(body, 3)


def server_hello(*, cipher: int = 0x1301, version: int = 0x0304, seed: int = 11,
                 alpn: str | None = None) -> bytes:
    rng = random.Random(seed)
    extensions = _extension(43, struct.pack(">H", version))
    if alpn is not None:
        extensions += _extension(16, _vector(_vector(alpn.encode(), 1), 2))
    extensions += _extension(51, struct.pack(">H", 29) + _vector(
        bytes(rng.getrandbits(8) for _ in range(32)), 2))
    body = (struct.pack(">H", 0x0303) + bytes(rng.getrandbits(8) for _ in range(32))
            + _vector(b"", 1) + struct.pack(">HB", cipher, 0) + _vector(extensions, 2))
    return b"\x02" + _vector(body, 3)


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def http_request(method: str = "GET", target: str = "/index.html", *, host: str = "example.com",
                 headers: tuple[tuple[str, str], ...] = (), body: bytes = b"") -> bytes:
    lines = [f"{method} {target} HTTP/1.1", f"Host: {host}",
             "User-Agent: unspool-demo/0.1", "Accept: */*"]
    lines += [f"{k}: {v}" for k, v in headers]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_response(status: int = 200, reason: str = "OK", *, body: bytes = b"",
                  content_type: str = "text/html; charset=utf-8",
                  headers: tuple[tuple[str, str], ...] = (), chunked: bool = False,
                  chunk_size: int = 16, trailers: tuple[tuple[str, str], ...] = ()) -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}", "Server: unspool-demo",
             f"Content-Type: {content_type}"]
    lines += [f"{k}: {v}" for k, v in headers]
    if chunked:
        lines.append("Transfer-Encoding: chunked")
        if trailers:
            lines.append("Trailer: " + ", ".join(k for k, _ in trailers))
        payload = b""
        for i in range(0, len(body), chunk_size):
            chunk = body[i:i + chunk_size]
            payload += f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
        payload += b"0\r\n" + "".join(f"{k}: {v}\r\n" for k, v in trailers).encode() + b"\r\n"
    else:
        lines.append(f"Content-Length: {len(body)}")
        payload = body
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + payload


# --------------------------------------------------------------------------
# pcapng
# --------------------------------------------------------------------------

def options(items: list[tuple[int, bytes]], endian: str = "<") -> bytes:
    """A pcapng option list: code, length, value, padded to 4 bytes, then opt_endofopt."""
    out = b"".join(struct.pack(endian + "HH", code, len(value)) + value
                   + b"\x00" * ((4 - len(value) % 4) % 4) for code, value in items)
    return out + struct.pack(endian + "HH", 0, 0) if items else b""


def block(block_type: int, body: bytes, endian: str = "<") -> bytes:
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    total = len(body) + 12
    return (struct.pack(endian + "II", block_type, total) + body
            + struct.pack(endian + "I", total))


def shb(endian: str = "<", *, opts: list[tuple[int, bytes]] | None = None,
        section_length: int = -1) -> bytes:
    body = struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, section_length)
    return block(0x0A0D0D0A, body + options(opts or [], endian), endian)


def idb(linktype: int = 1, snaplen: int = 262144, endian: str = "<",
        opts: list[tuple[int, bytes]] | None = None) -> bytes:
    body = struct.pack(endian + "HHI", linktype, 0, snaplen)
    return block(0x00000001, body + options(opts or [], endian), endian)


def epb(frame: bytes, *, interface: int = 0, timestamp: int = 0, endian: str = "<",
        original_length: int | None = None, opts: list[tuple[int, bytes]] | None = None) -> bytes:
    payload = frame + b"\x00" * ((4 - len(frame) % 4) % 4)
    body = (struct.pack(endian + "IIIII", interface, timestamp >> 32, timestamp & 0xFFFFFFFF,
                        len(frame), original_length if original_length is not None else len(frame))
            + payload + options(opts or [], endian))
    return block(0x00000006, body, endian)


def spb(frame: bytes, endian: str = "<", original_length: int | None = None) -> bytes:
    body = struct.pack(endian + "I", original_length if original_length is not None
                       else len(frame)) + frame
    return block(0x00000003, body, endian)


def nrb(records: list[tuple[int, bytes]], endian: str = "<") -> bytes:
    body = b"".join(struct.pack(endian + "HH", kind, len(value)) + value
                    + b"\x00" * ((4 - len(value) % 4) % 4) for kind, value in records)
    return block(0x00000004, body + struct.pack(endian + "HH", 0, 0), endian)


def isb(interface: int = 0, timestamp: int = 0, endian: str = "<",
        opts: list[tuple[int, bytes]] | None = None) -> bytes:
    body = struct.pack(endian + "III", interface, timestamp >> 32, timestamp & 0xFFFFFFFF)
    return block(0x00000005, body + options(opts or [], endian), endian)


def dsb(secrets: bytes = b"CLIENT_RANDOM 00 11\n", secrets_type: int = 0x544C534B,
        endian: str = "<") -> bytes:
    body = struct.pack(endian + "II", secrets_type, len(secrets)) + secrets
    body += b"\x00" * ((4 - len(secrets) % 4) % 4)
    return block(0x0000000A, body, endian)


@dataclass
class Packet:
    """One frame plus the timestamp to store with it (microseconds since the epoch)."""

    frame: bytes
    timestamp_us: int = 0
    interface: int = 0
    comment: str | None = None


def pcapng(packets: list[Packet], *, endian: str = "<", linktype: int = 1,
           snaplen: int = 262144, interfaces: list[int] | None = None,
           shb_options: list[tuple[int, bytes]] | None = None,
           extra_blocks: bytes = b"") -> bytes:
    """Assemble a pcapng file: SHB, one IDB per interface, then an EPB per packet."""
    out = shb(endian, opts=shb_options or [
        (3, b"unspool test suite"), (4, b"unspool synth"),
    ])
    for i, lt in enumerate(interfaces or [linktype]):
        out += idb(lt, snaplen, endian, opts=[(2, f"if{i}".encode()), (9, b"\x06")])
    out += extra_blocks
    for packet in packets:
        opts = [(1, packet.comment.encode())] if packet.comment else []
        out += epb(packet.frame, interface=packet.interface, timestamp=packet.timestamp_us,
                   endian=endian, opts=opts)
    return out


def pcap(packets: list[Packet], *, endian: str = "<", linktype: int = 1,
         snaplen: int = 262144, nanosecond: bool = False) -> bytes:
    """Assemble a classic pcap file."""
    magic = {("<", False): b"\xd4\xc3\xb2\xa1", (">", False): b"\xa1\xb2\xc3\xd4",
             ("<", True): b"\x4d\x3c\xb2\xa1", (">", True): b"\xa1\xb2\x3c\x4d"}[
        (endian, nanosecond)]
    out = magic + struct.pack(endian + "HHiIII", 2, 4, 0, 0, snaplen, linktype)
    for packet in packets:
        seconds, fraction = divmod(packet.timestamp_us, 1_000_000)
        if nanosecond:
            fraction *= 1000
        out += struct.pack(endian + "IIII", seconds, fraction, len(packet.frame),
                           len(packet.frame)) + packet.frame
    return out


# --------------------------------------------------------------------------
# ready-made exchanges
# --------------------------------------------------------------------------

def dns_exchange(name: str = SERVER_NAME, *, start_us: int = 0) -> list[Packet]:
    query = ethernet(ipv4(udp(dns_query(name), sport=51000, dport=53, dst=ROUTER_IP),
                          dst=ROUTER_IP))
    reply = ethernet(ipv4(udp(dns_response(name), sport=53, dport=51000, src=ROUTER_IP,
                              dst=CLIENT_IP), src=ROUTER_IP, dst=CLIENT_IP),
                     dst=CLIENT_MAC, src=ROUTER_MAC)
    return [Packet(query, start_us), Packet(reply, start_us + 21_000)]


def tls_exchange(server_name: str = SERVER_NAME, *, start_us: int = 0, sport: int = 52000,
                 split: bool = False) -> list[Packet]:
    """A TCP handshake and a TLS 1.3 hello exchange. ``split`` cuts the
    ClientHello across two segments, as a real one usually is."""
    def frame(payload: bytes, *, to_server: bool, seq: int, ack: int, flags: int = 0x18) -> bytes:
        if to_server:
            segment = tcp(payload, sport=sport, dport=443, seq=seq, ack=ack, flags=flags)
            return ethernet(ipv4(segment, proto=6))
        segment = tcp(payload, sport=443, dport=sport, seq=seq, ack=ack, flags=flags,
                      src=SERVER_IP, dst=CLIENT_IP)
        return ethernet(ipv4(segment, proto=6, src=SERVER_IP, dst=CLIENT_IP),
                        dst=CLIENT_MAC, src=ROUTER_MAC)

    hello = tls_record(client_hello(server_name))
    reply = tls_record(server_hello()) + tls_record(b"\x01", content_type=20)
    packets = [
        Packet(frame(b"", to_server=True, seq=1000, ack=0, flags=0x02), start_us),
        Packet(frame(b"", to_server=False, seq=5000, ack=1001, flags=0x12), start_us + 12_000),
        Packet(frame(b"", to_server=True, seq=1001, ack=5001, flags=0x10), start_us + 12_100),
    ]
    if split:
        cut = len(hello) // 2
        packets.append(Packet(frame(hello[:cut], to_server=True, seq=1001, ack=5001),
                              start_us + 12_200))
        packets.append(Packet(frame(hello[cut:], to_server=True, seq=1001 + cut, ack=5001),
                              start_us + 12_300))
    else:
        packets.append(Packet(frame(hello, to_server=True, seq=1001, ack=5001),
                              start_us + 12_200))
    packets.append(Packet(frame(reply, to_server=False, seq=5001, ack=1001 + len(hello)),
                          start_us + 24_000))
    return packets


def http_exchange(*, start_us: int = 0, sport: int = 52100, chunked: bool = True,
                  body: bytes = b"<html><body>unspool demo page</body></html>",
                  target: str = "/index.html", host: str = "example.com") -> list[Packet]:
    request = http_request(target=target, host=host)
    response = http_response(body=body, chunked=chunked)
    out = [
        Packet(ethernet(ipv4(tcp(b"", sport=sport, dport=80, seq=2000, flags=0x02), proto=6)),
               start_us),
        Packet(ethernet(ipv4(tcp(b"", sport=80, dport=sport, seq=9000, ack=2001, flags=0x12,
                                 src=SERVER_IP, dst=CLIENT_IP), proto=6, src=SERVER_IP,
                             dst=CLIENT_IP), dst=CLIENT_MAC, src=ROUTER_MAC),
               start_us + 11_000),
        Packet(ethernet(ipv4(tcp(request, sport=sport, dport=80, seq=2001, ack=9001), proto=6)),
               start_us + 11_200),
    ]
    # Split the response across two segments, the way a real one arrives.
    cut = len(response) // 2
    for i, part in enumerate((response[:cut], response[cut:])):
        out.append(Packet(
            ethernet(ipv4(tcp(part, sport=80, dport=sport, seq=9001 + i * cut,
                              ack=2001 + len(request), src=SERVER_IP, dst=CLIENT_IP), proto=6,
                          src=SERVER_IP, dst=CLIENT_IP), dst=CLIENT_MAC, src=ROUTER_MAC),
            start_us + 22_000 + i * 700))
    return out
