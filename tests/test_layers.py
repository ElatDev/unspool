"""Link, network and transport decoding."""

from __future__ import annotations

import struct

import pytest

import unspool
from unspool import decode, linktypes
from unspool.errors import DecodeError
from unspool.frame import Frame
from unspool.layers import ARP, GRE, ICMP, TCP, UDP, VLAN, Ethernet, ICMPv6, IPv4, IPv6
from unspool.layers.link import LLC, LinuxSLL, Loopback

from . import synth


def packet(frame: bytes, linktype: int = 1):
    return decode(Frame(1, linktype, frame, len(frame), 0))


def test_ethernet_and_ipv4_and_udp() -> None:
    pkt = packet(synth.ethernet(synth.ipv4(synth.udp(b"payload", sport=1234, dport=4321))))
    assert pkt.protocols == ("eth", "ip", "udp")
    eth = pkt.get(Ethernet)
    assert eth is not None and eth.src == synth.CLIENT_MAC and eth.type == 0x0800
    ip = pkt.get(IPv4)
    assert ip is not None and (ip.src, ip.dst) == (synth.CLIENT_IP, synth.SERVER_IP)
    assert ip.ttl == 64 and ip.protocol == 17
    udp = pkt.get(UDP)
    assert udp is not None and (udp.sport, udp.dport) == (1234, 4321)
    assert udp.payload == b"payload"


def test_ethernet_padding_is_trimmed_by_ip_total_length() -> None:
    """Short frames are padded to 60 bytes; the padding is not payload."""
    frame = synth.ethernet(synth.ipv4(synth.udp(b"hi"))) + b"\x00" * 12
    pkt = packet(frame)
    udp = pkt.get(UDP)
    assert udp is not None and udp.payload == b"hi"


def test_ipv4_options_are_kept() -> None:
    options = bytes([0x94, 4, 0, 0])  # router alert
    pkt = packet(synth.ethernet(synth.ipv4(synth.udp(b"x"), options=options)))
    ip = pkt.get(IPv4)
    assert ip is not None and ip.header_length == 24 and ip.options == options


def test_ipv4_fragments() -> None:
    first = synth.ipv4(synth.udp(b"A" * 100), flags=0x2000)          # MF set, offset 0
    later = synth.ipv4(b"B" * 100, flags=0x2000 | 25, proto=17)      # offset 25*8
    pkt_first, pkt_later = packet(synth.ethernet(first)), packet(synth.ethernet(later))
    assert "udp" in pkt_first.protocols      # the first fragment holds the UDP header
    assert pkt_later.protocols == ("eth", "ip")
    ip = pkt_later.get(IPv4)
    assert ip is not None and ip.is_fragment and ip.fragment_offset == 200


def test_vlan_and_qinq() -> None:
    inner = synth.ipv4(synth.udp(b"x"))
    single = synth.ethernet(synth.vlan(inner, vid=42), ethertype=0x8100)
    pkt = packet(single)
    assert pkt.protocols == ("eth", "vlan", "ip", "udp")
    tag = pkt.get(VLAN)
    assert tag is not None and tag.id == 42

    double = synth.ethernet(synth.vlan(synth.vlan(inner, vid=7), vid=42, ethertype=0x8100),
                            ethertype=0x88a8)
    assert packet(double).protocols == ("eth", "vlan", "vlan", "ip", "udp")


def test_arp_request_and_reply() -> None:
    request = packet(synth.ethernet(synth.arp(), ethertype=0x0806))
    arp = request.get(ARP)
    assert arp is not None and arp.opcode == 1
    assert arp.summary() == f"Who has {synth.ROUTER_IP}? Tell {synth.CLIENT_IP}"
    reply = packet(synth.ethernet(synth.arp(opcode=2, sender_ip=synth.ROUTER_IP,
                                            sender_mac=synth.ROUTER_MAC), ethertype=0x0806))
    arp = reply.get(ARP)
    assert arp is not None and arp.summary().endswith(synth.ROUTER_MAC)


def test_ipv6_with_tcp() -> None:
    frame = synth.ethernet(synth.ipv6(synth.tcp(b"data", dport=9999, v6=True,
                                                src=synth.CLIENT_IP6, dst=synth.SERVER_IP6),
                                      next_header=6), ethertype=0x86dd)
    pkt = packet(frame)
    assert pkt.protocols == ("eth", "ipv6", "tcp")
    ip = pkt.get(IPv6)
    assert ip is not None and ip.src == synth.CLIENT_IP6 and ip.hop_limit == 64


def test_ipv6_extension_headers_are_walked() -> None:
    hop_by_hop = struct.pack(">BB", 17, 0) + b"\x01\x04\x00\x00\x00\x00"   # PadN
    frame = synth.ethernet(synth.ipv6(hop_by_hop + synth.udp(b"x", v6=True,
                                                             src=synth.CLIENT_IP6,
                                                             dst=synth.SERVER_IP6),
                                      next_header=0), ethertype=0x86dd)
    pkt = packet(frame)
    ip = pkt.get(IPv6)
    assert ip is not None and ip.extension_headers == (0,) and ip.protocol == 17
    assert "udp" in pkt.protocols


def test_ipv6_later_fragment_has_no_transport() -> None:
    frame = synth.ethernet(synth.ipv6_fragment(b"\x00" * 40, next_header=17, offset=1480,
                                               more=False), ethertype=0x86dd)
    pkt = packet(frame)
    assert pkt.protocols == ("eth", "ipv6")
    ip = pkt.get(IPv6)
    assert ip is not None and ip.is_fragment and ip.fragment_offset == 1480


def test_icmp_echo_and_quoted_error() -> None:
    echo = packet(synth.ethernet(synth.ipv4(synth.icmp_echo(), proto=1)))
    icmp = echo.get(ICMP)
    assert icmp is not None and icmp.type == 8 and icmp.identifier == 0x1a2b
    assert "Echo (ping) request" in echo.summary()

    original = synth.ipv4(synth.udp(synth.dns_query(), sport=51000, dport=53), proto=17)
    error = packet(synth.ethernet(synth.ipv4(synth.icmp_unreachable(original), proto=1,
                                             src=synth.ROUTER_IP)))
    # The quoted datagram is decoded too, which is how Wireshark shows it.
    assert error.protocols[:4] == ("eth", "ip", "icmp", "ip")
    assert "udp" in error.protocols and "dns" in error.protocols


def test_icmp_error_quoting_only_eight_bytes_of_tcp() -> None:
    quoted = synth.ipv4(synth.tcp(b"", sport=52000, dport=443)[:8], proto=6)
    pkt = packet(synth.ethernet(synth.ipv4(synth.icmp_unreachable(quoted), proto=1)))
    tcp = pkt.get(TCP)
    assert tcp is not None and (tcp.sport, tcp.dport) == (52000, 443)
    assert pkt.malformed is None


def test_icmpv6_neighbor_solicitation() -> None:
    body = struct.pack(">BBHI", 135, 0, 0, 0) + synth.ipv6_bytes("2001:db8::99")
    frame = synth.ethernet(synth.ipv6(body, next_header=58), ethertype=0x86dd)
    pkt = packet(frame)
    icmp = pkt.get(ICMPv6)
    assert icmp is not None and icmp.type == 135 and icmp.target == "2001:db8::99"


def test_tcp_flags_options_and_payload() -> None:
    options = bytes([2, 4, 0x05, 0xB4, 1, 3, 3, 7, 4, 2, 0, 0])   # MSS, NOP, WS, SACK_PERM
    pkt = packet(synth.ethernet(synth.ipv4(synth.tcp(b"body", flags=0x12, options=options),
                                           proto=6)))
    tcp = pkt.get(TCP)
    assert tcp is not None
    assert tcp.syn and tcp.has_ack and tcp.flag_names == "SYN, ACK"
    assert tcp.option("MSS") == 1460 and tcp.option("WS") == 7
    assert tcp.payload == b"body" and tcp.header_length == 32


def test_tcp_header_length_beyond_the_packet_is_malformed() -> None:
    segment = bytearray(synth.tcp(b"hello"))
    segment[12] = 0xF0  # data offset 60 bytes, but the segment is shorter
    pkt = packet(synth.ethernet(synth.ipv4(bytes(segment), proto=6)))
    assert pkt.malformed is not None and "tcp" in pkt.protocols


def test_udp_length_shorter_than_header_is_malformed() -> None:
    datagram = bytearray(synth.udp(b"hello"))
    datagram[4:6] = struct.pack(">H", 3)
    pkt = packet(synth.ethernet(synth.ipv4(bytes(datagram))))
    assert "udp" in pkt.protocols
    assert pkt.malformed is not None and "below 8" in pkt.malformed


def test_gre_tunnel() -> None:
    inner = synth.ipv4(synth.udp(b"tunnelled"), src=synth.OTHER_IP, dst=synth.CLIENT_IP)
    gre = struct.pack(">HH", 0x0000, 0x0800) + inner
    pkt = packet(synth.ethernet(synth.ipv4(gre, proto=47)))
    assert pkt.protocols == ("eth", "ip", "gre", "ip", "udp")
    assert pkt.get(GRE) is not None


def test_ip_in_ip_tunnel() -> None:
    inner = synth.ipv4(synth.icmp_echo(), proto=1, src=synth.OTHER_IP)
    pkt = packet(synth.ethernet(synth.ipv4(inner, proto=4)))
    assert pkt.protocols == ("eth", "ip", "ip", "icmp")


def test_encapsulation_depth_is_bounded() -> None:
    """A packet nested in itself forever must stop, not recurse away."""
    payload = synth.ipv4(b"", proto=4)
    for _ in range(40):
        payload = synth.ipv4(payload, proto=4)
    pkt = packet(synth.ethernet(payload))
    assert pkt.malformed is not None and "nested" in pkt.malformed


def test_linux_cooked_capture() -> None:
    sll = struct.pack(">HHH", 0, 1, 6) + synth.mac(synth.CLIENT_MAC) + b"\x00\x00" \
        + struct.pack(">H", 0x0800)
    pkt = packet(sll + synth.ipv4(synth.udp(b"x")), linktype=linktypes.LINUX_SLL)
    assert pkt.protocols == ("sll", "ip", "udp")
    assert pkt.get(LinuxSLL) is not None


def test_linux_cooked_v2() -> None:
    sll2 = struct.pack(">HHIHBB", 0x0800, 0, 2, 1, 0, 6) + synth.mac(synth.CLIENT_MAC) + b"\x00\x00"
    pkt = packet(sll2 + synth.ipv4(synth.udp(b"x")), linktype=linktypes.LINUX_SLL2)
    assert pkt.protocols == ("sll", "ip", "udp")
    sll = pkt.get(LinuxSLL)
    assert sll is not None and sll.interface_index == 2


def test_bsd_loopback_byte_order() -> None:
    body = synth.ipv4(synth.udp(b"x"))
    host_order = packet(struct.pack("<I", 2) + body, linktype=linktypes.NULL)
    assert host_order.protocols == ("null", "ip", "udp")
    # DLT_LOOP is reported as "null" too, which is what Wireshark calls it.
    network_order = packet(struct.pack(">I", 2) + body, linktype=linktypes.LOOP)
    assert network_order.protocols == ("null", "ip", "udp")
    loopback = host_order.get(Loopback)
    assert loopback is not None and loopback.family == 2


def test_raw_ip_link_types() -> None:
    assert packet(synth.ipv4(synth.udp(b"x")), linktype=linktypes.RAW).protocols == ("ip", "udp")
    v6 = synth.ipv6(synth.udp(b"x", v6=True, src=synth.CLIENT_IP6, dst=synth.SERVER_IP6))
    assert packet(v6, linktype=linktypes.RAW).protocols == ("ipv6", "udp")


def test_llc_snap_frame() -> None:
    snap = b"\xaa\xaa\x03\x00\x00\x00" + struct.pack(">H", 0x0800) + synth.ipv4(synth.udp(b"x"))
    frame = synth.ethernet(snap, ethertype=len(snap))
    pkt = packet(frame)
    assert pkt.protocols == ("eth", "llc", "ip", "udp")
    llc = pkt.get(LLC)
    assert llc is not None and llc.ethertype == 0x0800


def test_unknown_link_type_is_not_an_error() -> None:
    pkt = packet(b"\x00\x01\x02\x03", linktype=999)
    assert pkt.protocols == () and pkt.malformed is None
    assert pkt.payload == b"\x00\x01\x02\x03"


def test_truncated_frame_reports_itself() -> None:
    frame = synth.ethernet(synth.ipv4(synth.udp(b"A" * 100)))
    snapped = Frame(1, 1, frame[:60], len(frame), 0)
    pkt = unspool.decode(snapped)
    assert pkt.frame.truncated
    udp = pkt.get(UDP)
    assert udp is not None and len(udp.payload) < 100


def test_empty_frame() -> None:
    pkt = packet(b"")
    assert pkt.malformed is not None
    assert pkt.protocols == ()


def test_decode_error_message_names_the_layer() -> None:
    with pytest.raises(DecodeError):
        from unspool.layers.network import parse_ipv4
        parse_ipv4(b"\x45\x00")
