"""Decoding a frame into a stack of protocol layers."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TypeVar

from . import linktypes as lt
from .errors import DecodeError
from .frame import Frame
from .layers import dns as dns_mod
from .layers import http as http_mod
from .layers import link, network, transport
from .layers import tls as tls_mod
from .layers.base import Layer, MalformedLayerError
from .layers.dns import DNS
from .layers.http import HTTP
from .layers.link import ARP, Ethernet
from .layers.network import ICMP, ICMPv6, IPv4, IPv6
from .layers.tls import TLS
from .layers.transport import TCP, UDP

L = TypeVar("L", bound=Layer)

#: TCP ports Wireshark hands to its TLS dissector by default (``tshark -G decodes``).
TLS_TCP_PORTS = frozenset({
    324, 443, 465, 636, 802, 853, 993, 995, 1300, 2221, 2443, 3249, 3250, 3251,
    3252, 3496, 5061, 5671, 5684, 5868, 8883, 11207, 19999,
})
#: TCP ports Wireshark hands to its HTTP dissector by default. 631 is IPP,
#: which is HTTP carrying print jobs.
HTTP_TCP_PORTS = frozenset({80, 631, 1900, 2710, 2869, 3128, 3132, 3689, 5985, 8080,
                            8088, 11371})

_TCP_APPS: dict[int, str] = {53: "dns", 5353: "dns"}
_TCP_APPS.update(dict.fromkeys(TLS_TCP_PORTS, "tls"))
_TCP_APPS.update(dict.fromkeys(HTTP_TCP_PORTS, "http"))
_UDP_APPS = {53: "dns", 5353: "mdns", 5355: "llmnr"}

#: Tunnels, VLAN stacks and ICMP quotes can nest; this bounds how deep.
MAX_DEPTH = 12

_DISPLAY = {
    "eth": "Ethernet", "vlan": "802.1Q", "llc": "LLC", "sll": "SLL", "null": "Loopback",
    "mpls": "MPLS",
    "ppp": "PPP", "pppoes": "PPPoE", "arp": "ARP", "ip": "IPv4",
    "ipv6": "IPv6", "gre": "GRE", "icmp": "ICMP", "icmpv6": "ICMPv6", "tcp": "TCP",
    "udp": "UDP", "dns": "DNS", "mdns": "MDNS", "llmnr": "LLMNR", "tls": "TLS",
    "http": "HTTP",
}


@dataclass(eq=False)
class Packet:
    """A frame plus the protocol layers decoded from it, outermost first."""

    frame: Frame
    layers: list[Layer] = field(default_factory=list)
    #: Bytes after the last decoded header that no decoder claimed.
    payload: bytes = field(default=b"", repr=False)
    #: Why decoding stopped early, if it did ("tcp: header length 60 exceeds...").
    malformed: str | None = None

    # -- frame passthrough -------------------------------------------------

    @property
    def number(self) -> int:
        return self.frame.number

    @property
    def timestamp(self) -> float | None:
        return self.frame.timestamp

    @property
    def length(self) -> int:
        """Length on the wire."""
        return self.frame.original_length

    # -- layer access ------------------------------------------------------

    def get(self, kind: type[L]) -> L | None:
        """The first (outermost) layer of type ``kind``, or None."""
        for layer in self.layers:
            if isinstance(layer, kind):
                return layer
        return None

    def get_all(self, kind: type[L]) -> list[L]:
        return [layer for layer in self.layers if isinstance(layer, kind)]

    def __contains__(self, item: object) -> bool:
        if isinstance(item, str):
            return any(layer.name == item for layer in self.layers)
        if isinstance(item, type):
            return any(isinstance(layer, item) for layer in self.layers)
        return False

    def __iter__(self) -> Iterator[Layer]:
        return iter(self.layers)

    @property
    def protocols(self) -> tuple[str, ...]:
        """Layer names in order, e.g. ``("eth", "ip", "udp", "dns")``."""
        return tuple(layer.name for layer in self.layers)

    @property
    def eth(self) -> Ethernet | None:
        return self.get(Ethernet)

    @property
    def arp(self) -> ARP | None:
        return self.get(ARP)

    @property
    def ip(self) -> IPv4 | IPv6 | None:
        """The outermost IP header, v4 or v6."""
        for layer in self.layers:
            if isinstance(layer, (IPv4, IPv6)):
                return layer
        return None

    @property
    def tcp(self) -> TCP | None:
        return self.get(TCP)

    @property
    def udp(self) -> UDP | None:
        return self.get(UDP)

    @property
    def icmp(self) -> ICMP | ICMPv6 | None:
        for layer in self.layers:
            if isinstance(layer, (ICMP, ICMPv6)):
                return layer
        return None

    @property
    def dns(self) -> DNS | None:
        """DNS, mDNS or LLMNR message."""
        return self.get(DNS)

    @property
    def tls(self) -> TLS | None:
        return self.get(TLS)

    @property
    def http(self) -> HTTP | None:
        return self.get(HTTP)

    @property
    def src(self) -> str | None:
        ip = self.ip
        if ip is not None:
            return ip.src
        if self.arp is not None:
            return self.arp.sender_ip
        return self.eth.src if self.eth else None

    @property
    def dst(self) -> str | None:
        ip = self.ip
        if ip is not None:
            return ip.dst
        if self.arp is not None:
            return self.arp.target_ip
        return self.eth.dst if self.eth else None

    @property
    def sport(self) -> int | None:
        t = self.tcp or self.udp
        return t.sport if t else None

    @property
    def dport(self) -> int | None:
        t = self.tcp or self.udp
        return t.dport if t else None

    @property
    def highest_layer(self) -> Layer | None:
        return self.layers[-1] if self.layers else None

    @property
    def protocol_label(self) -> str:
        """Short protocol name for display, like Wireshark's Protocol column."""
        top = self.highest_layer
        if top is None:
            return lt.name(self.frame.linktype)
        if isinstance(top, TLS):
            hello = top.server_hello or top.client_hello
            if hello is not None:
                return tls_mod.version_name(hello.version).replace("TLS ", "TLSv")
        return _DISPLAY.get(top.name, top.name.upper())

    def summary(self) -> str:
        """One line describing the packet, like Wireshark's Info column."""
        top = self.highest_layer
        text = top.summary() if top is not None else f"{len(self.frame.data)} bytes"
        if isinstance(top, (IPv4, IPv6)) and top.is_fragment:
            text = f"Fragment of {network.protocol_name(top.protocol)} " \
                   f"(offset {top.fragment_offset})"
        if self.malformed:
            text += f" [Malformed: {self.malformed}]"
        return text


class Decoder:
    """Turns frames into packets.

    Keeps per-conversation state: once a TCP conversation is identified as
    TLS or HTTP from its content (not just its port), every later segment in
    that conversation is decoded the same way. That's how Wireshark behaves
    too, and it means TLS on port 8443 or HTTP on 8000 is recognised.
    """

    def __init__(self) -> None:
        self._tcp_apps: dict[tuple[str, int, str, int], str] = {}

    def decode(self, frame: Frame) -> Packet:
        pkt = Packet(frame)
        walk = _Walk(self, pkt)
        try:
            walk.link(frame.linktype, frame.data)
        except MalformedLayerError as exc:
            pkt.layers.append(exc.layer)
            pkt.malformed = f"{exc.layer.name}: {exc}"
        except DecodeError as exc:
            pkt.malformed = f"{walk.current}: {exc}"
        return pkt


def decode(frame: Frame) -> Packet:
    """Decode one frame with no conversation state (see :class:`Decoder`)."""
    return Decoder().decode(frame)


class _Walk:
    """One decode pass over a frame, outermost header inwards."""

    def __init__(self, decoder: Decoder, pkt: Packet) -> None:
        self.decoder = decoder
        self.pkt = pkt
        self.depth = 0
        self.quoted = False
        self.current = "frame"

    def add(self, layer: Layer) -> None:
        self.pkt.layers.append(layer)

    def rest(self, data: bytes) -> None:
        self.pkt.payload = data

    def descend(self) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise DecodeError(f"more than {MAX_DEPTH} nested headers")

    # -- link layer ----------------------------------------------------------

    def link(self, linktype: int, data: bytes) -> None:
        self.current = lt.name(linktype)
        if linktype == lt.ETHERNET:
            self.ethernet(data)
        elif linktype in (lt.NULL, lt.LOOP):
            layer, payload = link.parse_loopback(data, linktype == lt.LOOP)
            self.add(layer)
            if layer.family == 2:
                self.ipv4(payload)
            elif layer.family in link.AF_INET6_VALUES:
                self.ipv6(payload)
            elif layer.family > 1500:
                self.ethertype(layer.family, payload)
            else:
                self.rest(payload)
        elif linktype in (lt.RAW, lt.RAW_BSD, lt.RAW_OPENBSD):
            self.ip_by_version(data)
        elif linktype == lt.IPV4:
            self.ipv4(data)
        elif linktype == lt.IPV6:
            self.ipv6(data)
        elif linktype in (lt.LINUX_SLL, lt.LINUX_SLL2):
            parse = link.parse_sll if linktype == lt.LINUX_SLL else link.parse_sll2
            sll, payload = parse(data)
            self.add(sll)
            if sll.protocol == 0x0004:
                self.llc(payload)
            elif sll.protocol >= 0x0600:
                self.ethertype(sll.protocol, payload)
            else:
                self.rest(payload)
        elif linktype in (lt.PPP, lt.PPP_HDLC):
            self.ppp(data)
        else:
            self.rest(data)

    def ethernet(self, data: bytes) -> None:
        self.current = "eth"
        eth, payload = link.parse_ethernet(data)
        self.add(eth)
        if not eth.is_8023:
            self.ethertype(eth.type, payload)
        elif payload[:2] == b"\xff\xff":
            # Novell's "raw 802.3": no LLC header at all, straight into IPX,
            # which is recognised by IPX's checksum field being 0xFFFF.
            self.rest(payload)
        else:
            self.llc(payload)

    def ethertype(self, ethertype: int, data: bytes) -> None:
        self.descend()
        if ethertype == link.ETHERTYPE_IPV4:
            self.ipv4(data)
        elif ethertype == link.ETHERTYPE_IPV6:
            self.ipv6(data)
        elif ethertype in (link.ETHERTYPE_ARP, link.ETHERTYPE_RARP):
            self.current = "arp"
            self.add(link.parse_arp(data))
        elif ethertype in link.VLAN_TYPES:
            self.current = "vlan"
            tag, payload = link.parse_vlan(data)
            self.add(tag)
            if tag.type <= 1500:
                self.llc(payload)
            else:
                self.ethertype(tag.type, payload)
        elif ethertype == link.ETHERTYPE_PPPOE_SESSION:
            self.current = "pppoes"
            session, payload = link.parse_pppoe_session(data)
            self.add(session)
            self.ppp(payload)
        elif ethertype == 0x6558:  # transparent Ethernet bridging (GRE, VXLAN-ish)
            self.ethernet(data)
        elif ethertype in (link.ETHERTYPE_MPLS, link.ETHERTYPE_MPLS_MULTICAST):
            self.current = "mpls"
            stack, payload = link.parse_mpls(data)
            self.add(stack)
            version = payload[0] >> 4 if payload else 0
            if version in (4, 6):
                self.ip_by_version(payload)
            else:
                self.rest(payload)  # a pseudowire; its control word is not decoded
        else:
            self.rest(data)

    def llc(self, data: bytes) -> None:
        self.current = "llc"
        llc, payload = link.parse_llc(data)
        self.add(llc)
        if llc.ethertype is not None:
            self.ethertype(llc.ethertype, payload)
        else:
            self.rest(payload)

    def ppp(self, data: bytes) -> None:
        self.current = "ppp"
        ppp, payload = link.parse_ppp(data)
        self.add(ppp)
        if ppp.protocol == 0x0021:
            self.ipv4(payload)
        elif ppp.protocol == 0x0057:
            self.ipv6(payload)
        else:
            self.rest(payload)

    # -- network layer -------------------------------------------------------

    def ip_by_version(self, data: bytes) -> None:
        version = data[0] >> 4 if data else 0
        if version == 4:
            self.ipv4(data)
        elif version == 6:
            self.ipv6(data)
        else:
            self.current = "ip"
            raise DecodeError(f"raw IP packet has version {version}")

    def ipv4(self, data: bytes) -> None:
        self.descend()
        self.current = "ip"
        ip, payload = network.parse_ipv4(data)
        self.add(ip)
        if ip.fragment_offset:
            self.rest(payload)  # later fragments carry no transport header
        else:
            self.ip_payload(ip.protocol, payload, ip)

    def ipv6(self, data: bytes) -> None:
        self.descend()
        self.current = "ipv6"
        ip, payload = network.parse_ipv6(data)
        self.add(ip)
        if ip.fragment_offset:
            self.rest(payload)
        else:
            self.ip_payload(ip.protocol, payload, ip)

    def ip_payload(self, proto: int, data: bytes, ip: IPv4 | IPv6) -> None:
        if proto == network.PROTO_TCP:
            self.tcp(data, ip)
        elif proto == network.PROTO_UDP:
            self.udp(data)
        elif proto == network.PROTO_ICMP and isinstance(ip, IPv4):
            self.current = "icmp"
            icmp, quoted = network.parse_icmp(data)
            self.add(icmp)
            if quoted is not None:
                self.quote(quoted)
        elif proto == network.PROTO_ICMPV6:
            self.current = "icmpv6"
            icmp6, quoted = network.parse_icmpv6(data)
            self.add(icmp6)
            if quoted is not None:
                self.quote(quoted)
        elif proto == network.PROTO_IPIP:
            self.ipv4(data)
        elif proto == network.PROTO_IPV6:
            self.ipv6(data)
        elif proto == network.PROTO_GRE:
            self.current = "gre"
            gre, payload = network.parse_gre(data)
            self.add(gre)
            if gre.protocol == 0x880B:
                self.ppp(payload)
            else:
                self.ethertype(gre.protocol, payload)
        else:
            self.rest(data)

    def quote(self, data: bytes) -> None:
        """Decode the original datagram quoted inside an ICMP error.

        Quotes are usually cut short, so problems inside one don't make the
        packet itself malformed.
        """
        was_quoted, self.quoted = self.quoted, True
        try:
            self.ip_by_version(data)
        except MalformedLayerError as exc:
            self.add(exc.layer)
        except DecodeError:
            pass
        finally:
            self.quoted = was_quoted

    # -- transport and application ----------------------------------------

    def tcp(self, data: bytes, ip: IPv4 | IPv6) -> None:
        self.current = "tcp"
        if self.quoted and 8 <= len(data) < 20:
            # RFC 792 quotes only the first 8 bytes of the transport header.
            tcp = transport.TCP(int.from_bytes(data[0:2], "big"),
                                int.from_bytes(data[2:4], "big"),
                                int.from_bytes(data[4:8], "big"), 0, 0, 0, 0, 0, 0)
            self.add(tcp)
            return
        tcp, payload = transport.parse_tcp(data)
        self.add(tcp)
        if payload:
            self.tcp_app(ip, tcp, payload)

    def udp(self, data: bytes) -> None:
        self.current = "udp"
        udp, payload = transport.parse_udp(data)
        self.add(udp)
        if not payload:
            return
        app = _port_app(_UDP_APPS, udp.sport, udp.dport)
        if app is None:
            self.rest(payload)
            return
        self.current = app
        self.add(dns_mod.parse_dns(payload, protocol=app))

    def tcp_app(self, ip: IPv4 | IPv6, tcp: TCP, payload: bytes) -> None:
        key = _conversation(ip.src, tcp.sport, ip.dst, tcp.dport)
        known = self.decoder._tcp_apps
        app = known.get(key)
        if app is None:
            app = _port_app(_TCP_APPS, tcp.sport, tcp.dport)
            if app == "tls" and not tls_mod.looks_like_records(payload):
                # The port says TLS but these bytes cannot be a record. Wireshark's
                # dissector declines here too, and the port falls through to
                # whatever else recognises the payload.
                app = None
            if app is None:
                if tls_mod.looks_like_hello(payload):
                    # A hello is unmistakable, and it is how a connection that
                    # began as SMTP, IMAP, POP3 or LDAP turns into TLS after
                    # STARTTLS. Believe it on any port.
                    app = "tls"
                elif _unregistered(tcp.sport, tcp.dport):
                    # Weaker evidence is only trusted where no well-known
                    # protocol lives: a TLS-shaped record on port 389 is LDAP.
                    if tls_mod.looks_like_records(payload):
                        app = "tls"
                    elif http_mod.looks_like_http(payload):
                        app = "http"
            if app is not None and not self.quoted:
                # Remember it: later segments of this connection carry the middle
                # of a message and no longer look like anything on their own.
                known[key] = app
        if app is None:
            self.rest(payload)
            return
        self.current = app
        if app == "tls":
            self.add(tls_mod.parse_tls(payload))
        elif app == "http":
            self.add(http_mod.parse_http(payload))
        else:
            self.add(dns_mod.parse_dns(payload, tcp=True))


def _port_app(table: dict[int, str], sport: int, dport: int) -> str | None:
    # Like Wireshark, the lower port gets the first chance.
    low, high = (sport, dport) if sport <= dport else (dport, sport)
    return table.get(low) or table.get(high)


def _unregistered(sport: int, dport: int) -> bool:
    """True when neither port belongs to IANA's well-known range.

    Wireshark has a dissector for nearly every port below 1024, so its content
    heuristics effectively only run above that. Following the same rule keeps
    unspool from announcing TLS or HTTP where the traffic is really LDAP or
    SMTP -- protocols it does not decode and should not guess at.
    """
    return min(sport, dport) >= 1024


def _conversation(a: str, ap: int, b: str, bp: int) -> tuple[str, int, str, int]:
    return (a, ap, b, bp) if (a, ap) <= (b, bp) else (b, bp, a, ap)
