"""Link-layer headers: Ethernet, 802.1Q, 802.2 LLC/SNAP, Linux cooked capture,
BSD loopback, PPP, PPPoE and ARP."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .._cursor import Cursor
from ..errors import DecodeError
from .base import Layer, MalformedLayerError, ipv4_text, mac_text

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_RARP = 0x8035  # same packet format as ARP, opcodes 3 and 4
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_QINQ_OLD = 0x9100
ETHERTYPE_PPPOE_SESSION = 0x8864
ETHERTYPE_MPLS = 0x8847
ETHERTYPE_MPLS_MULTICAST = 0x8848

VLAN_TYPES = frozenset({ETHERTYPE_VLAN, ETHERTYPE_QINQ, ETHERTYPE_QINQ_OLD})


@dataclass(slots=True)
class Ethernet(Layer):
    name: ClassVar[str] = "eth"
    dst: str
    src: str
    #: EtherType, or for 802.3 frames the length field (<= 1500).
    type: int

    @property
    def is_8023(self) -> bool:
        return self.type <= 1500

    def summary(self) -> str:
        return f"{self.src} → {self.dst}"


def parse_ethernet(data: bytes) -> tuple[Ethernet, bytes]:
    if len(data) < 14:
        raise DecodeError(f"Ethernet header needs 14 bytes, frame has {len(data)}")
    eth = Ethernet(mac_text(data[0:6]), mac_text(data[6:12]),
                   (data[12] << 8) | data[13])
    payload = data[14:]
    if eth.type <= 1500:
        payload = payload[:eth.type]  # the length field lets us drop padding
    return eth, payload


@dataclass(slots=True)
class VLAN(Layer):
    """An 802.1Q (or 802.1ad) tag. Tags can stack: QinQ frames carry two."""

    name: ClassVar[str] = "vlan"
    priority: int
    dei: bool
    id: int
    type: int

    def summary(self) -> str:
        return f"VLAN {self.id}"


def parse_vlan(data: bytes) -> tuple[VLAN, bytes]:
    if len(data) < 4:
        raise DecodeError("802.1Q tag needs 4 bytes")
    tci = (data[0] << 8) | data[1]
    tag = VLAN(tci >> 13, bool(tci & 0x1000), tci & 0x0FFF, (data[2] << 8) | data[3])
    payload = data[4:]
    if tag.type <= 1500:
        payload = payload[:tag.type]
    return tag, payload


@dataclass(slots=True)
class LLC(Layer):
    """IEEE 802.2 LLC header, with the SNAP extension when DSAP=SSAP=0xAA."""

    name: ClassVar[str] = "llc"
    dsap: int
    ssap: int
    control: int
    oui: int | None = None
    pid: int | None = None

    @property
    def ethertype(self) -> int | None:
        """The encapsulated EtherType for SNAP frames with a zero OUI."""
        return self.pid if self.oui == 0 else None


def parse_llc(data: bytes) -> tuple[LLC, bytes]:
    cur = Cursor(data)
    dsap, ssap = cur.u8("DSAP"), cur.u8("SSAP")
    control = cur.u8("control")
    if control & 0x03 != 0x03:  # I and S frames have a 16-bit control field
        control |= cur.u8("control") << 8
    llc = LLC(dsap, ssap, control)
    if dsap == 0xAA and ssap == 0xAA:
        llc.oui = cur.u24("SNAP OUI")
        llc.pid = cur.u16("SNAP protocol")
    return llc, cur.rest()


@dataclass(slots=True)
class LinuxSLL(Layer):
    """Linux "cooked" capture header (``tcpdump -i any``), v1 or v2."""

    name: ClassVar[str] = "sll"
    packet_type: int
    arphrd: int
    address: str
    protocol: int
    interface_index: int | None = None

    PACKET_TYPES: ClassVar[dict[int, str]] = {
        0: "unicast to us", 1: "broadcast", 2: "multicast", 3: "unicast to another host",
        4: "sent by us",
    }

    def summary(self) -> str:
        return self.PACKET_TYPES.get(self.packet_type, f"packet type {self.packet_type}")


def parse_sll(data: bytes) -> tuple[LinuxSLL, bytes]:
    cur = Cursor(data)
    packet_type, arphrd, addr_len = cur.u16(), cur.u16(), cur.u16()
    address = cur.take(8, "SLL address")[:min(addr_len, 8)]
    layer = LinuxSLL(packet_type, arphrd, mac_text(address), cur.u16("SLL protocol"))
    return layer, cur.rest()


def parse_sll2(data: bytes) -> tuple[LinuxSLL, bytes]:
    cur = Cursor(data)
    protocol = cur.u16("SLL2 protocol")
    cur.skip(2, "SLL2 reserved")
    ifindex, arphrd = cur.u32("SLL2 interface"), cur.u16("SLL2 ARPHRD")
    packet_type, addr_len = cur.u8(), cur.u8()
    address = cur.take(8, "SLL2 address")[:min(addr_len, 8)]
    return LinuxSLL(packet_type, arphrd, mac_text(address), protocol, ifindex), cur.rest()


@dataclass(slots=True)
class Loopback(Layer):
    """BSD loopback (DLT_NULL): a 4-byte address family in the capturing host's byte order."""

    name: ClassVar[str] = "null"
    family: int


@dataclass(slots=True)
class OpenBSDLoopback(Loopback):
    """OpenBSD loopback (DLT_LOOP): the same, but always big-endian.

    Reported as ``null`` like its sibling, because that is what Wireshark calls
    both of them -- its ``loop`` is the Ethernet Configuration Test Protocol.
    """

    name: ClassVar[str] = "null"


#: Address families that mean IPv6, which every BSD numbered differently.
AF_INET6_VALUES = frozenset({10, 23, 24, 28, 30})


def parse_loopback(data: bytes, network_order: bool) -> tuple[Loopback, bytes]:
    if len(data) < 4:
        raise DecodeError("loopback header needs 4 bytes")
    family = int.from_bytes(data[:4], "big")
    if not network_order and family > 0xFFFF:
        family = int.from_bytes(data[:4], "little")
    layer = OpenBSDLoopback(family) if network_order else Loopback(family)
    return layer, data[4:]


@dataclass(slots=True)
class PPP(Layer):
    name: ClassVar[str] = "ppp"
    protocol: int

    PROTOCOLS: ClassVar[dict[int, str]] = {
        0x0021: "IPv4", 0x0057: "IPv6", 0xC021: "LCP", 0xC023: "PAP", 0xC223: "CHAP",
        0x8021: "IPCP", 0x8057: "IPv6CP", 0x80FD: "CCP",
    }

    def summary(self) -> str:
        return self.PROTOCOLS.get(self.protocol, f"PPP protocol 0x{self.protocol:04x}")


def parse_ppp(data: bytes) -> tuple[PPP, bytes]:
    cur = Cursor(data)
    if data[:2] == b"\xff\x03":  # HDLC-like address/control bytes
        cur.skip(2)
    first = cur.u8("PPP protocol")
    # Protocol-field compression: an odd first byte means a 1-byte protocol.
    protocol = first if first & 1 else (first << 8) | cur.u8("PPP protocol")
    return PPP(protocol), cur.rest()


@dataclass(slots=True)
class PPPoE(Layer):
    name: ClassVar[str] = "pppoes"
    version: int
    type: int
    code: int
    session_id: int
    length: int


def parse_pppoe_session(data: bytes) -> tuple[PPPoE, bytes]:
    cur = Cursor(data)
    ver_type = cur.u8("PPPoE version")
    layer = PPPoE(ver_type >> 4, ver_type & 0x0F, cur.u8(), cur.u16(), cur.u16())
    return layer, cur.rest()[:layer.length]


@dataclass(slots=True)
class MPLS(Layer):
    """An MPLS label stack: 20-bit label, 3-bit traffic class, 8-bit TTL each."""

    name: ClassVar[str] = "mpls"
    #: (label, traffic class, TTL) outermost first.
    labels: tuple[tuple[int, int, int], ...]

    def summary(self) -> str:
        return "MPLS " + "/".join(str(label) for label, _, _ in self.labels)


#: A label stack is 4 bytes per entry; this bounds a corrupt one.
MAX_MPLS_LABELS = 16


def parse_mpls(data: bytes) -> tuple[MPLS, bytes]:
    labels: list[tuple[int, int, int]] = []
    pos = 0
    while pos + 4 <= len(data) and len(labels) < MAX_MPLS_LABELS:
        entry = int.from_bytes(data[pos:pos + 4], "big")
        labels.append((entry >> 12, (entry >> 9) & 0x07, entry & 0xFF))
        pos += 4
        if entry & 0x100:       # bottom-of-stack bit
            break
    if not labels:
        raise DecodeError("MPLS label stack needs 4 bytes")
    return MPLS(tuple(labels)), data[pos:]


@dataclass(slots=True)
class ARP(Layer):
    name: ClassVar[str] = "arp"
    hardware_type: int
    protocol_type: int
    opcode: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str

    OPCODES: ClassVar[dict[int, str]] = {
        1: "request", 2: "reply", 3: "RARP request", 4: "RARP reply",
        8: "InARP request", 9: "InARP reply",
    }

    def summary(self) -> str:
        if self.opcode == 1:
            if self.sender_ip == self.target_ip:
                return f"ARP Announcement for {self.sender_ip}"
            return f"Who has {self.target_ip}? Tell {self.sender_ip}"
        if self.opcode == 2:
            return f"{self.sender_ip} is at {self.sender_mac}"
        return f"ARP {self.OPCODES.get(self.opcode, str(self.opcode))}"


def parse_arp(data: bytes) -> ARP:
    cur = Cursor(data)
    htype, ptype = cur.u16("ARP hardware type"), cur.u16("ARP protocol type")
    hlen, plen, opcode = cur.u8(), cur.u8(), cur.u16("ARP opcode")
    arp = ARP(htype, ptype, opcode, "", "", "", "")
    try:
        sha, spa = cur.take(hlen, "sender hardware address"), cur.take(plen, "sender address")
        tha, tpa = cur.take(hlen, "target hardware address"), cur.take(plen, "target address")
    except DecodeError as exc:
        raise MalformedLayerError(arp, str(exc)) from None
    arp.sender_mac, arp.target_mac = mac_text(sha), mac_text(tha)
    arp.sender_ip = ipv4_text(spa) if plen == 4 else spa.hex()
    arp.target_ip = ipv4_text(tpa) if plen == 4 else tpa.hex()
    return arp
