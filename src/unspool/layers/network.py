"""Network-layer headers: IPv4, IPv6 (with extension headers), GRE, ICMP, ICMPv6."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .._cursor import Cursor
from ..errors import DecodeError
from .base import Layer, MalformedLayerError, ipv4_text, ipv6_text

PROTO_ICMP = 1
PROTO_IPIP = 4
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_IPV6 = 41
PROTO_GRE = 47
PROTO_ESP = 50
PROTO_AH = 51
PROTO_ICMPV6 = 58
PROTO_NONE = 59

PROTOCOL_NAMES = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 4: "IPIP", 6: "TCP", 17: "UDP", 41: "IPv6",
    43: "IPv6-Route", 44: "IPv6-Frag", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6",
    59: "IPv6-NoNxt", 60: "IPv6-Opts", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP",
    136: "UDPLite",
}


def protocol_name(number: int) -> str:
    return PROTOCOL_NAMES.get(number, str(number))


@dataclass(slots=True)
class IPv4(Layer):
    name: ClassVar[str] = "ip"
    version: ClassVar[int] = 4
    src: str
    dst: str
    protocol: int
    ttl: int
    total_length: int
    identification: int
    dscp: int
    ecn: int
    dont_fragment: bool
    more_fragments: bool
    #: Fragment offset in bytes (the header stores it in 8-byte units).
    fragment_offset: int
    header_length: int
    checksum: int
    options: bytes = b""

    @property
    def is_fragment(self) -> bool:
        return self.more_fragments or self.fragment_offset > 0

    def summary(self) -> str:
        return f"{self.src} → {self.dst} {protocol_name(self.protocol)}"


def parse_ipv4(data: bytes) -> tuple[IPv4, bytes]:
    if len(data) < 20:
        raise DecodeError(f"IPv4 header needs 20 bytes, have {len(data)}")
    first = data[0]
    ihl = (first & 0x0F) * 4
    total = (data[2] << 8) | data[3]
    frag = (data[6] << 8) | data[7]
    ip = IPv4(
        src=ipv4_text(data[12:16]), dst=ipv4_text(data[16:20]), protocol=data[9],
        ttl=data[8], total_length=total, identification=(data[4] << 8) | data[5],
        dscp=data[1] >> 2, ecn=data[1] & 0x03, dont_fragment=bool(frag & 0x4000),
        more_fragments=bool(frag & 0x2000), fragment_offset=(frag & 0x1FFF) * 8,
        header_length=ihl, checksum=(data[10] << 8) | data[11],
    )
    if first >> 4 != 4:
        # Something said this was IPv4 and it isn't. Report the layer anyway, as
        # Wireshark does, so the frame is not silently counted as link-layer only.
        raise MalformedLayerError(ip, f"IPv4 header has version {first >> 4}")
    if ihl < 20:
        raise MalformedLayerError(ip, f"IPv4 header length {ihl} is below 20")
    if ihl > len(data):
        raise MalformedLayerError(
            ip, f"IPv4 header length {ihl} exceeds the {len(data)} bytes captured")
    ip.options = data[20:ihl]
    if total == 0:
        end = len(data)  # TCP segmentation offload leaves the length zeroed
    elif total < ihl:
        raise MalformedLayerError(ip, f"IPv4 total length {total} is shorter than its header")
    else:
        end = total  # drops Ethernet padding; slicing past the end is harmless
    return ip, data[ihl:end]


@dataclass(slots=True)
class IPv6(Layer):
    name: ClassVar[str] = "ipv6"
    version: ClassVar[int] = 6
    src: str
    dst: str
    #: The upper-layer protocol, after walking any extension headers.
    protocol: int
    hop_limit: int
    payload_length: int
    traffic_class: int
    flow_label: int
    #: Extension header types in the order they appeared.
    extension_headers: tuple[int, ...] = ()
    fragment_offset: int = 0
    more_fragments: bool = False
    fragment_id: int | None = None

    @property
    def ttl(self) -> int:
        return self.hop_limit

    @property
    def is_fragment(self) -> bool:
        return self.fragment_id is not None and (self.more_fragments or self.fragment_offset > 0)

    def summary(self) -> str:
        return f"{self.src} → {self.dst} {protocol_name(self.protocol)}"


# Extension headers whose length byte counts 8-octet units beyond the first 8.
_EXT_8OCTET = frozenset({0, 43, 60, 135, 139, 140})
MAX_EXTENSION_HEADERS = 16


def parse_ipv6(data: bytes) -> tuple[IPv6, bytes]:
    if len(data) < 40:
        raise DecodeError(f"IPv6 header needs 40 bytes, have {len(data)}")
    if data[0] >> 4 != 6:
        raise DecodeError(f"IPv6 header has version {data[0] >> 4}")
    word = int.from_bytes(data[0:4], "big")
    plen = (data[4] << 8) | data[5]
    ip = IPv6(
        src=ipv6_text(data[8:24]), dst=ipv6_text(data[24:40]), protocol=data[6],
        hop_limit=data[7], payload_length=plen, traffic_class=(word >> 20) & 0xFF,
        flow_label=word & 0xFFFFF,
    )
    body = data[40:40 + plen] if plen else data[40:]  # 0 = jumbogram
    nxt = ip.protocol
    seen: list[int] = []
    pos = 0
    try:
        while nxt in _EXT_8OCTET or nxt in (44, PROTO_AH):
            if len(seen) >= MAX_EXTENSION_HEADERS:
                raise MalformedLayerError(ip, "too many IPv6 extension headers")
            seen.append(nxt)
            if pos + 8 > len(body):
                raise MalformedLayerError(ip, "IPv6 extension header runs past the packet")
            header_next = body[pos]
            if nxt == 44:  # Fragment header: fixed 8 bytes
                frag = (body[pos + 2] << 8) | body[pos + 3]
                ip.fragment_offset = (frag >> 3) * 8
                ip.more_fragments = bool(frag & 1)
                ip.fragment_id = int.from_bytes(body[pos + 4:pos + 8], "big")
                size = 8
            elif nxt == PROTO_AH:
                size = (body[pos + 1] + 2) * 4
            else:
                size = (body[pos + 1] + 1) * 8
            pos += size
            nxt = header_next
            if ip.fragment_offset:
                break  # a non-first fragment: what follows is not a header
    finally:
        ip.protocol = nxt
        ip.extension_headers = tuple(seen)
    if pos > len(body):
        raise MalformedLayerError(ip, "IPv6 extension header runs past the packet")
    return ip, body[pos:]


@dataclass(slots=True)
class GRE(Layer):
    name: ClassVar[str] = "gre"
    flags: int
    version: int
    protocol: int
    key: int | None = None
    sequence: int | None = None


def parse_gre(data: bytes) -> tuple[GRE, bytes]:
    cur = Cursor(data)
    flags_ver = cur.u16("GRE flags")
    gre = GRE(flags_ver & 0xFFF8, flags_ver & 0x0007, cur.u16("GRE protocol"))
    try:
        if flags_ver & 0xC000:        # checksum present or routing present
            cur.skip(4, "GRE checksum")
        if flags_ver & 0x2000:
            gre.key = cur.u32("GRE key")
        if flags_ver & 0x1000:
            gre.sequence = cur.u32("GRE sequence")
        if gre.version == 1 and flags_ver & 0x0080:
            cur.skip(4, "GRE acknowledgment")
        if flags_ver & 0x4000:        # source route entries, ended by a null SRE
            for _ in range(64):
                family, _off, length = cur.u16(), cur.u8(), cur.u8()
                if family == 0 and length == 0:
                    break
                cur.skip(length, "GRE SRE")
    except DecodeError as exc:
        raise MalformedLayerError(gre, str(exc)) from None
    return gre, cur.rest()


ICMP_TYPES = {
    0: "Echo (ping) reply", 3: "Destination unreachable", 4: "Source quench",
    5: "Redirect", 8: "Echo (ping) request", 9: "Router advertisement",
    10: "Router solicitation", 11: "Time-to-live exceeded", 12: "Parameter problem",
    13: "Timestamp request", 14: "Timestamp reply", 17: "Address mask request",
    18: "Address mask reply",
}
ICMP_ERRORS = frozenset({3, 4, 5, 11, 12})


@dataclass(slots=True)
class ICMP(Layer):
    name: ClassVar[str] = "icmp"
    type: int
    code: int
    checksum: int
    identifier: int | None = None
    sequence: int | None = None

    TYPES: ClassVar[dict[int, str]] = ICMP_TYPES

    @property
    def is_error(self) -> bool:
        return self.type in ICMP_ERRORS

    def summary(self) -> str:
        text = self.TYPES.get(self.type, f"type {self.type}")
        if self.identifier is not None:
            text += f" id=0x{self.identifier:04x}, seq={self.sequence}"
        elif self.code:
            text += f" (code {self.code})"
        return text


def parse_icmp(data: bytes) -> tuple[ICMP, bytes | None]:
    """Returns the ICMP layer and, for error messages, the quoted original datagram."""
    cur = Cursor(data)
    icmp = ICMP(cur.u8("ICMP type"), cur.u8("ICMP code"), cur.u16("ICMP checksum"))
    if icmp.type in (0, 8, 13, 14, 17, 18) and cur.remaining >= 4:
        icmp.identifier, icmp.sequence = cur.u16(), cur.u16()
    if icmp.is_error and len(data) > 8:
        return icmp, data[8:]
    return icmp, None


ICMPV6_TYPES = {
    1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
    4: "Parameter Problem", 128: "Echo (ping) request", 129: "Echo (ping) reply",
    130: "Multicast Listener Query", 131: "Multicast Listener Report",
    132: "Multicast Listener Done", 133: "Router Solicitation",
    134: "Router Advertisement", 135: "Neighbor Solicitation",
    136: "Neighbor Advertisement", 137: "Redirect", 143: "Multicast Listener Report v2",
}


@dataclass(slots=True)
class ICMPv6(Layer):
    name: ClassVar[str] = "icmpv6"
    type: int
    code: int
    checksum: int
    identifier: int | None = None
    sequence: int | None = None
    #: Target address of Neighbor Solicitation/Advertisement and Redirect.
    target: str | None = None

    TYPES: ClassVar[dict[int, str]] = ICMPV6_TYPES

    @property
    def is_error(self) -> bool:
        return self.type < 128

    def summary(self) -> str:
        text = self.TYPES.get(self.type, f"type {self.type}")
        if self.identifier is not None:
            text += f" id=0x{self.identifier:04x}, seq={self.sequence}"
        if self.target:
            text += f" for {self.target}"
        return text


def parse_icmpv6(data: bytes) -> tuple[ICMPv6, bytes | None]:
    cur = Cursor(data)
    icmp = ICMPv6(cur.u8("ICMPv6 type"), cur.u8("ICMPv6 code"), cur.u16("ICMPv6 checksum"))
    if icmp.type in (128, 129) and cur.remaining >= 4:
        icmp.identifier, icmp.sequence = cur.u16(), cur.u16()
    elif icmp.type in (135, 136, 137) and cur.remaining >= 20:
        cur.skip(4)
        icmp.target = ipv6_text(cur.take(16))
    if icmp.is_error and len(data) > 8:
        return icmp, data[8:]
    return icmp, None
