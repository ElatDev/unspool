"""TCP stream reassembly.

Per-packet decoding sees one segment at a time, but a modern TLS ClientHello
(with a post-quantum key share) is bigger than one segment, and HTTP bodies
routinely span dozens. This module rebuilds each direction of each TCP
connection into a contiguous byte string by sequence number, so application
parsers can work on the stream the endpoints actually exchanged.

Handled: out-of-order arrival, retransmissions (including ones that overlap
and extend earlier data), sequence number wraparound, connections captured
mid-stream (no SYN), and port reuse (a fresh SYN starts a new stream). A hole
that is never filled ends that direction's usable data at the hole.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from .layers.network import IPv4, IPv6
from .layers.transport import TCP
from .packet import Packet

_MASK = 0xFFFFFFFF
#: Out-of-order segments held per direction before giving up on the gap.
MAX_PENDING_SEGMENTS = 4096


@dataclass
class HalfStream:
    """One direction of a connection."""

    data: bytearray = field(default_factory=bytearray)
    #: True if a hole in the sequence space was never filled; data stops there.
    gap: bool = False
    #: True if data was dropped because the stream hit the size cap.
    capped: bool = False
    fin: bool = False
    segments: int = 0
    _base: int | None = None
    _pending: dict[int, bytes] = field(default_factory=dict, repr=False)

    def syn(self, seq: int) -> None:
        self._base = (seq + 1) & _MASK

    def add(self, seq: int, payload: bytes, limit: int) -> None:
        self.segments += 1
        if self._base is None:
            self._base = seq  # joined mid-stream: the first byte we see is offset 0
        offset = (seq - self._base) & _MASK
        if offset >= 1 << 31:          # before the base: an old retransmission
            offset -= 1 << 32
        end = len(self.data)
        if offset > end:
            # Nothing is held once the cap is reached: the buffer can never grow
            # to meet it, so holding the segment would just consume memory.
            if not self.capped and len(self._pending) < MAX_PENDING_SEGMENTS:
                held = self._pending.get(offset, b"")
                if len(payload) > len(held):
                    self._pending[offset] = payload
            return
        self._append(payload[end - offset:], limit)
        if len(self.data) != end:
            # Only a segment that actually extended the buffer can let held
            # segments through, and draining scans them all.
            self._drain(limit)

    def _append(self, chunk: bytes, limit: int) -> None:
        if not chunk:
            return
        room = limit - len(self.data)
        if room <= 0:
            self.capped = True
            return
        if len(chunk) > room:
            chunk, self.capped = chunk[:room], True
        self.data += chunk

    def _drain(self, limit: int) -> None:
        while self._pending:
            end = len(self.data)
            ready = [off for off in self._pending if off <= end]
            if not ready:
                return
            for off in sorted(ready):
                chunk = self._pending.pop(off)
                end = len(self.data)
                if off + len(chunk) > end:
                    self._append(chunk[end - off:], limit)
            if self.capped:
                self._pending.clear()

    def finish(self) -> None:
        if self._pending and not self.capped:
            self.gap = True   # held segments that never joined up mean a real hole
        self._pending.clear()


@dataclass
class TCPStream:
    """A reassembled TCP connection. The client is whoever sent the SYN, or,
    for connections already open when the capture started, the first sender."""

    index: int
    client: tuple[str, int]
    server: tuple[str, int]
    client_data: HalfStream = field(default_factory=HalfStream)
    server_data: HalfStream = field(default_factory=HalfStream)
    first_frame: int = 0
    last_frame: int = 0
    packets: int = 0
    #: Whether the three-way handshake's SYN was captured.
    syn_seen: bool = False
    _client_isn: int | None = field(default=None, repr=False)

    @property
    def client_bytes(self) -> bytes:
        return bytes(self.client_data.data)

    @property
    def server_bytes(self) -> bytes:
        return bytes(self.server_data.data)


class Reassembler:
    """Feed packets in capture order with :meth:`add`; read :meth:`streams` at the end.

    ``max_bytes`` caps how much of each direction is kept. ``keep`` can reject
    a stream after seeing its first bytes (both directions' first payload), so
    a summary pass needn't hold bulk transfers it will never parse.
    """

    def __init__(self, max_bytes: int = 16 * 1024 * 1024,
                 keep: Callable[[bytes], bool] | None = None) -> None:
        self.max_bytes = max_bytes
        self.keep = keep
        self._streams: list[TCPStream] = []
        self._active: dict[tuple[tuple[str, int], tuple[str, int]], TCPStream] = {}
        self._rejected: set[int] = set()

    def add(self, pkt: Packet) -> None:
        tcp = pkt.tcp
        if tcp is None or pkt.icmp is not None:
            return  # (a TCP header inside an ICMP error is a quote, not traffic)
        endpoints = _endpoints(pkt, tcp)
        if endpoints is None:
            return
        src, dst = endpoints
        key = (src, dst) if src <= dst else (dst, src)
        stream = self._active.get(key)
        is_syn = tcp.syn and not tcp.has_ack
        if stream is not None and is_syn and stream._client_isn != tcp.seq \
                and (stream._client_isn is not None or stream.packets > 0):
            stream = None  # a new connection reusing the same ports
        if stream is None:
            # A capture that starts at the SYN/ACK still knows which side is
            # which: the SYN/ACK comes from the server.
            client, server = (dst, src) if tcp.syn and tcp.has_ack else (src, dst)
            stream = TCPStream(len(self._streams), client, server, first_frame=pkt.number)
            self._streams.append(stream)
            self._active[key] = stream
        stream.packets += 1
        stream.last_frame = pkt.number
        from_client = src == stream.client
        half = stream.client_data if from_client else stream.server_data
        if tcp.syn:
            half.syn(tcp.seq)
            if is_syn:
                stream.syn_seen = True
                stream._client_isn = tcp.seq
        if tcp.fin or tcp.rst:
            half.fin = True
        payload = tcp.payload
        if not payload or stream.index in self._rejected:
            return
        if self.keep is not None and not half.data and not half.segments \
                and not self.keep(payload):
            other = stream.server_data if from_client else stream.client_data
            if not other.data:
                self._rejected.add(stream.index)
                return
        seq = (tcp.seq + 1) & _MASK if tcp.syn else tcp.seq
        half.add(seq, payload, self.max_bytes)

    def add_all(self, packets: Iterable[Packet]) -> list[TCPStream]:
        for pkt in packets:
            self.add(pkt)
        return self.streams()

    def streams(self) -> list[TCPStream]:
        """All streams seen, in order of first packet, excluding rejected ones."""
        for stream in self._streams:
            stream.client_data.finish()
            stream.server_data.finish()
        return [s for s in self._streams if s.index not in self._rejected]


def _endpoints(pkt: Packet, tcp: TCP) -> tuple[tuple[str, int], tuple[str, int]] | None:
    """The two ends of the connection this packet belongs to.

    The ports come from the innermost TCP header, so the addresses must come
    from the IP header that encloses *it* — for a tunnelled packet the
    outermost addresses belong to the tunnel, not to the connection.
    """
    enclosing: IPv4 | IPv6 | None = None
    for layer in pkt.layers:
        if isinstance(layer, (IPv4, IPv6)):
            enclosing = layer
        elif layer is tcp:
            break
    if enclosing is None:
        return None
    return (enclosing.src, tcp.sport), (enclosing.dst, tcp.dport)

