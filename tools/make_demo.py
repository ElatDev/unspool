"""Write examples/demo.pcapng, the capture used by the README and the tests' screenshot.

    python tools/make_demo.py

Every byte is generated here. The capture is a plausible few seconds of a
laptop's traffic -- name lookups, two TLS handshakes, a plain HTTP fetch, a
ping, some IPv6, a VLAN-tagged NTP packet and a video stream -- but no part of
it was ever on a real network: addresses come from the documentation ranges
(RFC 5737, RFC 3849) and the names from RFC 2606's example.* domains.

It also exercises the pcapng container itself: two interfaces, a packet
comment, a name resolution block and an interface statistics block.
"""

from __future__ import annotations

import random
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from tests import synth  # noqa: E402

OUT = ROOT / "examples" / "demo.pcapng"

START = int(datetime(2026, 9, 20, 14, 3, 11, tzinfo=timezone.utc).timestamp() * 1_000_000)
LAPTOP = synth.CLIENT_IP            # 192.0.2.10
ROUTER = synth.ROUTER_IP            # 192.0.2.1
WEB = "198.51.100.23"               # www.example.com
API = "198.51.100.77"               # api.example.net
VIDEO = "203.0.113.57"              # a video stream
LAPTOP6 = synth.CLIENT_IP6
WEB6 = "2001:db8:2::23"

rng = random.Random(20260920)


def at(offset_ms: float) -> int:
    return START + int(offset_ms * 1000)


def to_router(payload: bytes, *, ethertype: int = 0x0800) -> bytes:
    return synth.ethernet(payload, dst=synth.ROUTER_MAC, src=synth.CLIENT_MAC,
                          ethertype=ethertype)


def to_laptop(payload: bytes, *, ethertype: int = 0x0800) -> bytes:
    return synth.ethernet(payload, dst=synth.CLIENT_MAC, src=synth.ROUTER_MAC,
                          ethertype=ethertype)


def dns_pair(name: str, qtype: int, answers: list[tuple[int, bytes]], *, when: float,
             txid: int, port: int) -> list[synth.Packet]:
    query = synth.dns_query(name, qtype=qtype, txid=txid)
    reply = synth.dns_response(name, answers=answers, txid=txid)
    # The response's question section must echo the query's type.
    reply = reply[:12] + synth.dns_name(name) + struct.pack(">HH", qtype, 1) + \
        reply[12 + len(synth.dns_name(name)) + 4:]
    return [
        synth.Packet(to_router(synth.ipv4(synth.udp(query, sport=port, dport=53, dst=ROUTER),
                                          dst=ROUTER)), at(when)),
        synth.Packet(to_laptop(synth.ipv4(synth.udp(reply, sport=53, dport=port, src=ROUTER,
                                                    dst=LAPTOP), src=ROUTER, dst=LAPTOP)),
                     at(when + 11.4)),
    ]


# What a real SYN carries: MSS, SACK permitted, timestamps, window scale.
SYN_OPTIONS = (bytes([2, 4, 0x05, 0xB4]) + bytes([4, 2])
               + bytes([8, 10]) + struct.pack(">II", 0x1F2E3D4C, 0)
               + bytes([1]) + bytes([3, 3, 7]))


def tcp_session(server: str, port: int, client_port: int, client_payloads: list[bytes],
                server_payloads: list[bytes], *, start: float, step: float = 7.0,
                interface: int = 0) -> list[synth.Packet]:
    """A three-way handshake, the payloads, then a clean close."""
    packets: list[synth.Packet] = []
    seq, ack = 1000, 5000
    when = start

    def client(payload: bytes, flags: int) -> bytes:
        options = SYN_OPTIONS if flags & 0x02 else b""
        return to_router(synth.ipv4(synth.tcp(payload, sport=client_port, dport=port, seq=seq,
                                              ack=ack if flags & 0x10 else 0, flags=flags,
                                              options=options, dst=server), proto=6, dst=server))

    def server_frame(payload: bytes, flags: int) -> bytes:
        options = SYN_OPTIONS if flags & 0x02 else b""
        return to_laptop(synth.ipv4(synth.tcp(payload, sport=port, dport=client_port, seq=ack,
                                              ack=seq, flags=flags, options=options,
                                              src=server, dst=LAPTOP),
                                    proto=6, src=server, dst=LAPTOP))

    packets.append(synth.Packet(client(b"", 0x02), at(when), interface))
    seq += 1
    when += step * 2
    packets.append(synth.Packet(server_frame(b"", 0x12), at(when), interface))
    ack += 1
    when += 0.4
    packets.append(synth.Packet(client(b"", 0x10), at(when), interface))
    for payload in client_payloads:
        when += 0.6
        packets.append(synth.Packet(client(payload, 0x18), at(when), interface))
        seq += len(payload)
    for payload in server_payloads:
        when += step
        packets.append(synth.Packet(server_frame(payload, 0x18), at(when), interface))
        ack += len(payload)
        when += 0.3
        packets.append(synth.Packet(client(b"", 0x10), at(when), interface))
    when += 1.0
    packets.append(synth.Packet(client(b"", 0x11), at(when), interface))
    when += 0.5
    packets.append(synth.Packet(server_frame(b"", 0x11), at(when), interface))
    return packets


def build() -> list[synth.Packet]:
    packets: list[synth.Packet] = []

    # The laptop finds the router, then looks up the names it is about to use.
    packets.append(synth.Packet(
        synth.ethernet(synth.arp(target_ip=ROUTER), dst="ff:ff:ff:ff:ff:ff",
                       ethertype=0x0806), at(0)))
    packets.append(synth.Packet(
        synth.ethernet(synth.arp(opcode=2, sender_mac=synth.ROUTER_MAC, sender_ip=ROUTER,
                                 target_mac=synth.CLIENT_MAC, target_ip=LAPTOP),
                       dst=synth.CLIENT_MAC, src=synth.ROUTER_MAC, ethertype=0x0806), at(1.8)))

    packets += dns_pair("www.example.com", 1, [(1, synth.ipv4_bytes(WEB))],
                        when=4.0, txid=0x1a2b, port=51000)
    packets += dns_pair("www.example.com", 28, [(28, synth.ipv6_bytes(WEB6))],
                        when=4.3, txid=0x1a2c, port=51000)
    packets += dns_pair("api.example.net", 1, [(1, synth.ipv4_bytes(API))],
                        when=60.0, txid=0x2f01, port=51001)
    packets += dns_pair("cdn.example.org", 5,
                        [(5, synth.dns_name("edge.cdn.example.org")),
                         (1, synth.ipv4_bytes(VIDEO))], when=120.0, txid=0x3c44, port=51002)

    # A multicast DNS question, as every laptop on a home network asks.
    mdns = synth.dns_query("_services._dns-sd._udp.local", qtype=12, txid=0)
    packets.append(synth.Packet(
        synth.ethernet(synth.ipv4(synth.udp(mdns, sport=5353, dport=5353, dst="224.0.0.251"),
                                  dst="224.0.0.251", ttl=255), dst="01:00:5e:00:00:fb"),
        at(31.0)))

    # TLS 1.3 to www.example.com. The ClientHello is split across two segments,
    # which is what a real one does and what per-packet parsing alone would miss.
    hello = synth.tls_record(synth.client_hello("www.example.com"))
    cut = 340
    server_flight = (synth.tls_record(synth.server_hello(alpn="http/1.1"))
                     + synth.tls_record(b"\x01", content_type=20)
                     + synth.tls_record(bytes(rng.getrandbits(8) for _ in range(1180)),
                                        content_type=23))
    packets += tcp_session(WEB, 443, 52000, [hello[:cut], hello[cut:]],
                           [server_flight, bytes(rng.getrandbits(8) for _ in range(900))],
                           start=90.0)

    # A second handshake, this one negotiating HTTP/2.
    hello2 = synth.tls_record(synth.client_hello("api.example.net", alpn=("h2",)))
    packets += tcp_session(API, 443, 52001, [hello2],
                           [synth.tls_record(synth.server_hello(alpn="h2"))
                            + synth.tls_record(bytes(rng.getrandbits(8) for _ in range(600)),
                                               content_type=23)], start=180.0)

    # Plain HTTP, with a chunked response: the whole point of the HTTP decoder.
    page = (b"<!doctype html>\n<html><head><title>Example</title></head>\n"
            b"<body><h1>It works</h1><p>Served in chunks.</p></body></html>\n")
    packets += tcp_session("198.51.100.23", 80, 52002,
                           [synth.http_request("GET", "/index.html", host="example.com")],
                           [synth.http_response(body=page, chunked=True, chunk_size=48,
                                                trailers=(("X-Served-By", "demo"),))],
                           start=260.0)
    packets += tcp_session("198.51.100.23", 80, 52003,
                           [synth.http_request("POST", "/api/v1/notes", host="example.com",
                                               body=b'{"note":"synthetic"}')],
                           [synth.http_response(201, "Created", body=b'{"id":42}',
                                                content_type="application/json")],
                           start=420.0)

    # A ping, an IPv6 lookup, an IPv6 neighbour solicitation and a VLAN-tagged NTP packet.
    packets.append(synth.Packet(to_router(synth.ipv4(synth.icmp_echo(), proto=1, dst=WEB)),
                                at(150.0)))
    packets.append(synth.Packet(
        to_laptop(synth.ipv4(synth.icmp_echo(request=False), proto=1, src=WEB, dst=LAPTOP)),
        at(163.0)))
    v6_query = synth.udp(synth.dns_query("www.example.com", qtype=28, txid=0x4d55),
                         sport=51010, dport=53, src=LAPTOP6, dst="2001:db8::1", v6=True)
    packets.append(synth.Packet(
        to_router(synth.ipv6(v6_query, src=LAPTOP6, dst="2001:db8::1"), ethertype=0x86dd),
        at(210.0)))
    neighbour = struct.pack(">BBHI", 135, 0, 0, 0) + synth.ipv6_bytes("2001:db8::1")
    packets.append(synth.Packet(
        to_router(synth.ipv6(neighbour, src=LAPTOP6, dst="ff02::1:ff00:1", next_header=58),
                  ethertype=0x86dd), at(240.0)))
    ntp = struct.pack(">BBBb11I", 0x23, 3, 6, -23, *([0] * 11))
    packets.append(synth.Packet(
        to_router(synth.vlan(synth.ipv4(synth.udp(ntp, sport=123, dport=123, dst=ROUTER),
                                        dst=ROUTER), vid=20), ethertype=0x8100),
        at(300.0)))

    # A video stream on the second interface, so the capture has a busy talker.
    for i in range(40):
        payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(900, 1300)))
        packets.append(synth.Packet(
            to_laptop(synth.ipv4(synth.udp(payload, sport=443, dport=54000, src=VIDEO,
                                           dst=LAPTOP), src=VIDEO, dst=LAPTOP)),
            at(500.0 + i * 12.5), interface=1))

    packets.sort(key=lambda p: p.timestamp_us)
    packets[0].comment = "ARP for the default gateway, captured from a cold start"
    return packets


def main() -> None:
    packets = build()
    header = synth.shb(opts=[
        (3, b"Linux 6.11 (synthetic)"),
        (4, b"unspool tools/make_demo.py"),
        (1, b"Synthetic demo capture: documentation addresses only, no real traffic."),
    ])
    header += synth.idb(1, 262144, opts=[(2, b"wlan0"), (3, b"laptop wireless"), (9, b"\x06")])
    header += synth.idb(1, 262144, opts=[(2, b"wlan0.video"), (3, b"media stream"), (9, b"\x06")])
    body = synth.nrb([
        (1, synth.ipv4_bytes(WEB) + b"www.example.com\x00"),
        (1, synth.ipv4_bytes(API) + b"api.example.net\x00"),
        (2, synth.ipv6_bytes(WEB6) + b"www.example.com\x00"),
    ])
    out = header + body
    for packet in packets:
        opts = [(1, packet.comment.encode())] if packet.comment else []
        out += synth.epb(packet.frame, interface=packet.interface,
                         timestamp=packet.timestamp_us, opts=opts)
    out += synth.isb(0, packets[-1].timestamp_us, opts=[
        (4, struct.pack("<Q", len(packets))), (5, struct.pack("<Q", 0)),
    ])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(out)
    print(f"wrote {OUT.relative_to(ROOT)}: {len(packets)} packets, {len(out):,} bytes")


if __name__ == "__main__":
    main()
