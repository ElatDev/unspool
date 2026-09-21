"""Whole-capture statistics: what ``unspool summary`` prints."""

from __future__ import annotations

import os
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from . import capture as capture_mod
from . import linktypes
from .capture import Interface
from .errors import UnspoolError
from .layers import http, tls
from .packet import Packet
from .streams import Reassembler, TCPStream

#: Display order for protocol counts: outermost layers first.
PROTOCOL_ORDER = ("sll", "null", "eth", "llc", "vlan", "mpls", "pppoes", "ppp", "arp", "ip",
                  "ipv6", "gre", "icmp", "icmpv6", "tcp", "udp", "dns", "mdns", "llmnr",
                  "tls", "http")


@dataclass
class Endpoint:
    address: str
    packets_sent: int = 0
    bytes_sent: int = 0
    packets_received: int = 0
    bytes_received: int = 0

    @property
    def packets(self) -> int:
        return self.packets_sent + self.packets_received

    @property
    def bytes(self) -> int:
        return self.bytes_sent + self.bytes_received


@dataclass
class TLSServer:
    """What was seen for one server name across its TLS handshakes."""

    server_name: str
    handshakes: int = 0
    versions: Counter[str] = field(default_factory=Counter)
    alpn: Counter[str] = field(default_factory=Counter)
    ja4: Counter[str] = field(default_factory=Counter)


@dataclass
class HTTPRequest:
    method: str
    url: str
    status: int | None
    content_type: str | None
    body_length: int
    chunked: bool


@dataclass
class Summary:
    name: str
    format: str
    compression: str | None = None
    file_size: int | None = None
    sections: int = 0
    interfaces: list[Interface] = field(default_factory=list)
    blocks: Counter[str] = field(default_factory=Counter)
    packets: int = 0
    wire_bytes: int = 0
    captured_bytes: int = 0
    first_ns: int | None = None
    last_ns: int | None = None
    #: Number of frames containing each protocol (a frame counts once per protocol).
    protocols: Counter[str] = field(default_factory=Counter)
    linktypes: Counter[int] = field(default_factory=Counter)
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    dns_queries: Counter[tuple[str, str]] = field(default_factory=Counter)
    #: Values seen in responses, keyed by (name, record type).
    dns_answers: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    tls_servers: dict[str, TLSServer] = field(default_factory=dict)
    tls_without_sni: int = 0
    http_requests: list[HTTPRequest] = field(default_factory=list)
    tcp_streams: int = 0
    malformed: int = 0
    truncated_frames: int = 0
    #: Set when the file itself was damaged; the counts cover everything before it.
    error: str | None = None

    @property
    def duration(self) -> float | None:
        if self.first_ns is None or self.last_ns is None:
            return None
        return (self.last_ns - self.first_ns) / 1e9

    def protocol_counts(self) -> list[tuple[str, int]]:
        """Protocol counts, outermost layer first."""
        order = {name: i for i, name in enumerate(PROTOCOL_ORDER)}
        return sorted(self.protocols.items(),
                      key=lambda item: (order.get(item[0], len(order)), item[0]))

    def top_talkers(self, count: int = 5) -> list[Endpoint]:
        return sorted(self.endpoints.values(), key=lambda e: (-e.bytes, e.address))[:count]

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready representation (what ``unspool summary --json`` prints)."""
        return {
            "file": self.name,
            "format": self.format,
            "compression": self.compression,
            "file_size": self.file_size,
            "sections": self.sections,
            "interfaces": [
                {"linktype": i.linktype, "linktype_name": linktypes.name(i.linktype),
                 "snaplen": i.snaplen, "name": i.name} for i in self.interfaces
            ],
            "blocks": dict(self.blocks),
            "packets": self.packets,
            "wire_bytes": self.wire_bytes,
            "captured_bytes": self.captured_bytes,
            "first_timestamp_ns": self.first_ns,
            "last_timestamp_ns": self.last_ns,
            "duration_s": self.duration,
            "protocols": dict(self.protocol_counts()),
            "top_talkers": [
                {"address": e.address, "packets": e.packets, "bytes": e.bytes,
                 "packets_sent": e.packets_sent, "bytes_sent": e.bytes_sent}
                for e in self.top_talkers(10)
            ],
            "dns_queries": [
                {"name": name, "type": qtype, "count": n}
                for (name, qtype), n in self.dns_queries.most_common()
            ],
            "dns_answers": [{"name": name, "type": rtype, "values": sorted(values)}
                            for (name, rtype), values in sorted(self.dns_answers.items())],
            "tls_servers": [
                {"server_name": s.server_name, "handshakes": s.handshakes,
                 "versions": dict(s.versions), "alpn": dict(s.alpn), "ja4": dict(s.ja4)}
                for s in sorted(self.tls_servers.values(), key=lambda s: -s.handshakes)
            ],
            "tls_handshakes_without_sni": self.tls_without_sni,
            "http_requests": [vars(r) for r in self.http_requests],
            "tcp_streams": self.tcp_streams,
            "malformed_packets": self.malformed,
            "truncated_frames": self.truncated_frames,
            "error": self.error,
        }


def _interesting(first_payload: bytes) -> bool:
    return tls.looks_like_record(first_payload) or http.looks_like_http(first_payload)


def summarize(source: str | os.PathLike[str] | bytes | BinaryIO, *,
              max_stream_bytes: int = 4 * 1024 * 1024) -> Summary:
    """Read a whole capture and gather its statistics.

    A capture that is cut off or corrupt part-way still produces a summary of
    everything before the damage, with :attr:`Summary.error` set.
    """
    with capture_mod.open(source) as cap:
        size = None
        if isinstance(source, (str, os.PathLike)):
            size = Path(source).stat().st_size
        elif isinstance(source, (bytes, bytearray)):
            size = len(source)
        summary = Summary(cap.name, cap.format, cap.compression, size)
        streams = Reassembler(max_bytes=max_stream_bytes, keep=_interesting)
        try:
            _count(summary, cap.packets(), streams)
        except UnspoolError as exc:
            summary.error = str(exc)
        summary.interfaces = cap.interfaces
        summary.sections = len(cap.sections)
        if cap.format == "pcapng":
            summary.blocks = Counter(cap.reader.block_counts)  # type: ignore[union-attr]
    finished = streams.streams()
    summary.tcp_streams = sum(1 for _ in finished)
    for stream in finished:
        try:
            _application(summary, stream)
        except UnspoolError as exc:
            # One stream of nonsense must not cost the whole summary.
            summary.error = summary.error or f"stream {stream.index}: {exc}"
    return summary


def _count(summary: Summary, packets: Iterable[Packet], streams: Reassembler) -> None:
    for pkt in packets:
        frame = pkt.frame
        summary.packets += 1
        summary.wire_bytes += frame.original_length
        summary.captured_bytes += len(frame.data)
        summary.linktypes[frame.linktype] += 1
        if frame.truncated:
            summary.truncated_frames += 1
        if pkt.malformed:
            summary.malformed += 1
        ts = frame.timestamp_ns
        if ts is not None:
            if summary.first_ns is None or ts < summary.first_ns:
                summary.first_ns = ts
            if summary.last_ns is None or ts > summary.last_ns:
                summary.last_ns = ts
        summary.protocols.update(set(pkt.protocols))

        ip = pkt.ip
        if ip is not None:
            _endpoint(summary, ip.src).packets_sent += 1
            _endpoint(summary, ip.src).bytes_sent += frame.original_length
            _endpoint(summary, ip.dst).packets_received += 1
            _endpoint(summary, ip.dst).bytes_received += frame.original_length

        icmp = pkt.icmp
        quoted = icmp is not None and icmp.is_error
        dns = pkt.dns
        if dns is not None and not quoted:
            if not dns.is_response:
                for q in dns.questions:
                    summary.dns_queries[(q.name, q.type_name)] += 1
            else:
                for rr in dns.answers:
                    if rr.type in (1, 28, 5, 12, 33, 65):
                        key = (rr.name, rr.type_name)
                        summary.dns_answers.setdefault(key, set()).add(rr.value_text())
        if pkt.tcp is not None and not quoted:
            streams.add(pkt)


def _endpoint(summary: Summary, address: str) -> Endpoint:
    endpoint = summary.endpoints.get(address)
    if endpoint is None:
        endpoint = summary.endpoints[address] = Endpoint(address)
    return endpoint


def _application(summary: Summary, stream: TCPStream) -> None:
    client = stream.client_bytes
    if not client:
        return
    if tls.looks_like_record(client):
        _tls_stream(summary, client, stream.server_bytes)
    elif http.looks_like_http(client):
        _http_stream(summary, client, stream.server_bytes)


def _tls_stream(summary: Summary, client: bytes, server: bytes) -> None:
    hellos = [m.body for m in tls.parse_handshake_messages(tls.handshake_bytes(client))
              if isinstance(m.body, tls.ClientHello)]
    if not hellos:
        return
    hello = hellos[0]
    replies = [m.body for m in tls.parse_handshake_messages(tls.handshake_bytes(server))
               if isinstance(m.body, tls.ServerHello) and not m.body.is_hello_retry_request]
    if not hello.server_name:
        summary.tls_without_sni += 1
        return
    entry = summary.tls_servers.get(hello.server_name)
    if entry is None:
        entry = summary.tls_servers[hello.server_name] = TLSServer(hello.server_name)
    entry.handshakes += 1
    entry.ja4[hello.ja4()] += 1
    if replies:
        entry.versions[tls.version_name(replies[0].version)] += 1
        if replies[0].alpn:
            entry.alpn[replies[0].alpn] += 1
    else:
        entry.versions["(no reply)"] += 1


def _http_stream(summary: Summary, client: bytes, server: bytes) -> None:
    requests = [m for m in http.parse_stream(client) if m.is_request]
    responses = [m for m in http.parse_stream(server, requests=requests)
                 if m.status is not None and m.status >= 200]
    for i, req in enumerate(requests):
        resp = responses[i] if i < len(responses) else None
        summary.http_requests.append(HTTPRequest(
            method=req.method or "?",
            url=req.url or "?",
            status=resp.status if resp else None,
            content_type=resp.content_type if resp else None,
            body_length=len(resp.body) if resp else 0,
            chunked=resp.chunked if resp else False,
        ))
