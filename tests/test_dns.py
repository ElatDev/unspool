"""DNS decoding, and the name-compression traps in particular."""

from __future__ import annotations

import contextlib
import struct
import time

import pytest

from unspool.errors import DecodeError
from unspool.layers.base import MalformedLayerError
from unspool.layers.dns import EDNS, SOA, NameReader, parse_dns

from . import synth


def test_query_and_response() -> None:
    query = parse_dns(synth.dns_query("www.example.com", qtype=1))
    assert not query.is_response
    assert query.questions[0].name == "www.example.com"
    assert query.questions[0].type_name == "A"
    assert query.summary() == "Standard query 0x1a2b A www.example.com"

    response = parse_dns(synth.dns_response("www.example.com"))
    assert response.is_response and response.rcode == 0
    assert response.answers[0].type_name == "A"
    assert response.answers[0].value_text() == "198.51.100.23"
    assert response.answers[0].name == "www.example.com"   # from a compression pointer


def test_answer_types() -> None:
    answers = [
        (28, synth.ipv6_bytes("2001:db8::23")),
        (5, synth.dns_name("alias.example.net")),
        (15, struct.pack(">H", 10) + synth.dns_name("mail.example.net")),
        (16, b"\x0bv=spf1 -all"),
        (33, struct.pack(">HHH", 10, 20, 443) + synth.dns_name("svc.example.net")),
    ]
    message = parse_dns(synth.dns_response("example.com", answers=answers))
    values = [rr.value_text() for rr in message.answers]
    assert values[0] == "2001:db8::23"
    assert values[1] == "alias.example.net"
    assert values[2] == "10 mail.example.net"
    assert values[3] == "v=spf1 -all"
    assert values[4] == "10 20 443 svc.example.net"


def test_soa_record() -> None:
    rdata = (synth.dns_name("ns.example.com") + synth.dns_name("hostmaster.example.com")
             + struct.pack(">IIIII", 2026_09_20, 7200, 3600, 1209600, 300))
    message = parse_dns(synth.dns_response("example.com", answers=[(6, rdata)]))
    soa = message.answers[0].data
    assert isinstance(soa, SOA)
    assert soa.mname == "ns.example.com" and soa.serial == 2026_09_20


def test_edns_opt_record() -> None:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1)
    body = synth.dns_name("example.com") + struct.pack(">HH", 1, 1)
    # OPT: class carries the UDP payload size, TTL the flags, here DO=1.
    opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0x00008000, 0)
    message = parse_dns(header + body + opt)
    edns = message.edns
    assert isinstance(edns, EDNS)
    assert edns.udp_size == 4096 and edns.dnssec_ok


def test_root_name() -> None:
    message = parse_dns(synth.dns_query(".", qtype=2))
    assert message.questions[0].name == "<Root>"


def test_compression_pointer_loop_is_refused() -> None:
    """A name pointing at itself must not spin forever."""
    header = struct.pack(">HHHHHH", 1, 0, 1, 0, 0, 0)
    message = header + b"\xc0\x0c" + struct.pack(">HH", 1, 1)  # offset 12 is the pointer itself
    started = time.monotonic()
    with pytest.raises(MalformedLayerError, match="loop"):
        parse_dns(message)
    assert time.monotonic() - started < 1


def test_two_pointers_pointing_at_each_other() -> None:
    header = struct.pack(">HHHHHH", 1, 0, 1, 0, 0, 0)
    # offset 12 points at 14, which points back at 12
    message = header + b"\xc0\x0e" + b"\xc0\x0c" + struct.pack(">HH", 1, 1)
    with pytest.raises(MalformedLayerError, match="loop"):
        parse_dns(message)


def test_long_pointer_chain_is_capped() -> None:
    """Chained pointers that each advance are still bounded."""
    body = bytearray()
    base = 12
    count = 200
    for i in range(count):
        body += struct.pack(">H", 0xC000 | (base + 2 * (i + 1)))
    body += b"\x00"
    header = struct.pack(">HHHHHH", 1, 0, 1, 0, 0, 0)
    with pytest.raises(MalformedLayerError, match="compression pointers"):
        parse_dns(bytes(header + body))


def test_name_longer_than_255_bytes_is_refused() -> None:
    labels = b"".join(bytes([60]) + b"a" * 60 for _ in range(6)) + b"\x00"
    header = struct.pack(">HHHHHH", 1, 0, 1, 0, 0, 0)
    with pytest.raises(MalformedLayerError, match="longer than 255"):
        parse_dns(header + labels + struct.pack(">HH", 1, 1))


def test_forward_pointer_is_allowed() -> None:
    """Pointers usually go backwards, but forwards is not forbidden."""
    header = struct.pack(">HHHHHH", 1, 0, 1, 0, 0, 0)
    question = b"\x03www" + b"\xc0\x16" + struct.pack(">HH", 1, 1)
    padding = b"\x00" * (12 + len(question) - 22)
    message = header + question + padding + b"\x07example\x03com\x00"
    assert parse_dns(message).questions[0].name == "www.example.com"


def test_unsupported_label_type() -> None:
    header = struct.pack(">HHHHHH", 1, 0, 1, 0, 0, 0)
    with pytest.raises(MalformedLayerError, match="label type"):
        parse_dns(header + b"\x41\x00" + struct.pack(">HH", 1, 1))


def test_truncated_message() -> None:
    with pytest.raises(DecodeError):
        parse_dns(b"\x00\x01\x02")
    with pytest.raises(MalformedLayerError):
        parse_dns(synth.dns_query("example.com")[:-3])


def test_counts_larger_than_the_data() -> None:
    """A header claiming 65535 answers must not be believed."""
    header = struct.pack(">HHHHHH", 1, 0x8180, 0, 0xFFFF, 0, 0)
    with pytest.raises(MalformedLayerError):
        parse_dns(header + b"\x00")


def test_names_are_memoized_so_hostile_messages_stay_linear() -> None:
    """Thousands of records pointing at one long name must not cost quadratic time."""
    long_name = b"".join(bytes([40]) + b"n" * 40 for _ in range(5)) + b"\x00"
    header = struct.pack(">HHHHHH", 1, 0, 0xFFFF, 0, 0, 0)
    questions = (b"\xc0" + bytes([12 + len(long_name)]) + struct.pack(">HH", 1, 1))
    # Point every question at the same name and see that decoding stays quick.
    count = (65535 - len(long_name)) // 6
    message = header + long_name + questions * count
    started = time.monotonic()
    with contextlib.suppress(MalformedLayerError):
        parse_dns(message)
    assert time.monotonic() - started < 2


def test_label_escaping() -> None:
    reader = NameReader(b"\x00" * 12 + b"\x05a.b\x01c\x00")
    name, _ = reader.read(12)
    assert name == "a\\.b\\001c"


def test_mdns_and_llmnr_are_dns() -> None:
    message = parse_dns(synth.dns_query("_services._dns-sd._udp.local", qtype=12),
                        protocol="mdns")
    assert message.name == "mdns"
    assert message.questions[0].name.endswith(".local")
    assert parse_dns(synth.dns_query("wpad"), protocol="llmnr").name == "llmnr"


def test_dns_over_tcp_has_a_length_prefix() -> None:
    body = synth.dns_query("example.com")
    message = parse_dns(struct.pack(">H", len(body)) + body, tcp=True)
    assert message.questions[0].name == "example.com"
