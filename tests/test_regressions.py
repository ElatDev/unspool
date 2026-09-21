"""Bugs found after the fact, each with the case that found it.

Every test here failed before the fix beside it. Most came out of an
adversarial read of the parser; one came out of the fuzzer.
"""

from __future__ import annotations

import pytest

import unspool
from unspool import decode
from unspool.errors import DecodeError
from unspool.frame import Frame
from unspool.layers import MPLS, TLS, http
from unspool.streams import Reassembler
from unspool.summary import summarize

from . import synth


def segment(payload: bytes = b"", *, seq: int, to_server: bool = True, flags: int = 0x18,
            sport: int = 52000, dport: int = 80, number: int = 1):
    if to_server:
        frame = synth.ethernet(synth.ipv4(synth.tcp(payload, sport=sport, dport=dport, seq=seq,
                                                    flags=flags), proto=6))
    else:
        frame = synth.ethernet(synth.ipv4(synth.tcp(payload, sport=dport, dport=sport, seq=seq,
                                                    flags=flags, src=synth.SERVER_IP,
                                                    dst=synth.CLIENT_IP),
                                          proto=6, src=synth.SERVER_IP, dst=synth.CLIENT_IP))
    return decode(Frame(number, 1, frame, len(frame), number * 1000))


def test_absurdly_long_content_length_is_refused_not_crashed() -> None:
    """CPython refuses int() on more than 4300 digits; that must not escape."""
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: " + b"1" * 5000 + b"\r\n\r\n"
    with pytest.raises(DecodeError, match="Content-Length"):
        http.parse_message(raw)
    # And through the whole pipeline, where only UnspoolError may surface.
    frame = synth.ethernet(synth.ipv4(synth.tcp(raw, sport=80, dport=52000), proto=6))
    pkt = decode(Frame(1, 1, frame, len(frame), 0))
    assert "http" in pkt.protocols and pkt.malformed is not None


def test_several_transfer_encoding_lines_are_one_list() -> None:
    """RFC 9112 §6.1: the field lines combine; chunked last still means chunked."""
    raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"4\r\nWiki\r\n0\r\n\r\n")
    message, end = http.parse_message(raw)
    assert message.chunked and message.body == b"Wiki" and message.complete
    assert end == len(raw)


def test_successful_connect_response_has_no_body() -> None:
    """After a 2xx to CONNECT the bytes are the tunnel, not a body."""
    raw = (b"HTTP/1.1 200 Connection established\r\n\r\n"
           b"\x16\x03\x01\x00\x30 tunnelled TLS bytes, not a body")
    message, end = http.parse_message(raw, request_method="CONNECT")
    assert message.body == b"" and end == raw.index(b"\r\n\r\n") + 4


def test_port_reuse_after_a_stream_with_no_syn() -> None:
    """A fresh SYN starts a new stream even if the previous one lacked one."""
    packets = [segment(b"old connection", seq=7000, number=1),
               segment(b"", seq=500_000, flags=0x02, number=2),
               segment(b"new connection", seq=500_001, number=3)]
    reassembler = Reassembler()
    for pkt in packets:
        reassembler.add(pkt)
    streams = reassembler.streams()
    assert len(streams) == 2
    assert [s.client_bytes for s in streams] == [b"old connection", b"new connection"]


def test_capture_starting_at_the_syn_ack_knows_which_side_is_the_client() -> None:
    """The SYN/ACK comes from the server, so the other end is the client."""
    hello = synth.tls_record(synth.client_hello("late.example.com"))
    packets = [segment(b"", seq=5000, to_server=False, flags=0x12, dport=443, number=1),
               segment(b"", seq=1001, flags=0x10, dport=443, number=2),
               segment(hello, seq=1001, dport=443, number=3)]
    reassembler = Reassembler()
    for pkt in packets:
        reassembler.add(pkt)
    stream = reassembler.streams()[0]
    assert stream.client == (synth.CLIENT_IP, 52000)
    assert stream.server == (synth.SERVER_IP, 443)
    assert stream.client_bytes == hello


def test_a_capped_stream_holds_nothing_and_reports_no_gap() -> None:
    """Hitting max_bytes is not a hole, and must not buy unbounded memory."""
    reassembler = Reassembler(max_bytes=1024)
    for i in range(200):
        reassembler.add(segment(b"x" * 2000, seq=1 + i * 2000, number=i + 1))
    stream = reassembler.streams()[0]
    assert len(stream.client_bytes) == 1024
    assert stream.client_data.capped and not stream.client_data.gap
    assert not stream.client_data._pending


def test_tunnelled_connections_do_not_share_a_stream() -> None:
    """Inner connections are keyed on the addresses that enclose their ports."""
    def tunnelled(inner_src: str, inner_dst: str, payload: bytes, number: int):
        inner = synth.ipv4(synth.tcp(payload, sport=52000, dport=9999, seq=1000,
                                     src=inner_src, dst=inner_dst),
                           proto=6, src=inner_src, dst=inner_dst)
        frame = synth.ethernet(synth.ipv4(inner, proto=4, src="192.0.2.99", dst="198.51.100.99"))
        return decode(Frame(number, 1, frame, len(frame), number * 1000))

    reassembler = Reassembler()
    reassembler.add(tunnelled("192.0.2.10", "198.51.100.23", b"AAAA", 1))
    reassembler.add(tunnelled("192.0.2.11", "198.51.100.24", b"BBBB", 2))
    streams = reassembler.streams()
    assert len(streams) == 2
    assert {s.client[0] for s in streams} == {"192.0.2.10", "192.0.2.11"}


def test_a_broken_http_stream_does_not_lose_the_summary() -> None:
    """summarize() promises statistics even when something is malformed."""
    broken = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZZZ\r\n"
    packets = [
        *synth.dns_exchange(),
        synth.Packet(synth.ethernet(synth.ipv4(synth.tcp(synth.http_request(), sport=52000,
                                                         dport=80, seq=1), proto=6)), 100_000),
        synth.Packet(synth.ethernet(synth.ipv4(synth.tcp(broken, sport=80, dport=52000, seq=1,
                                                         src=synth.SERVER_IP,
                                                         dst=synth.CLIENT_IP),
                                               proto=6, src=synth.SERVER_IP,
                                               dst=synth.CLIENT_IP)), 120_000),
    ]
    summary = summarize(synth.pcapng(packets))
    assert summary.packets == 4
    assert summary.protocols["dns"] == 2
    assert summary.error is not None and "chunk" in summary.error


def test_cli_survives_a_broken_stream(tmp_path, capsys) -> None:
    from unspool.cli import main
    broken = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZZZ\r\n"
    packets = [
        synth.Packet(synth.ethernet(synth.ipv4(synth.tcp(synth.http_request(), sport=52000,
                                                         dport=80, seq=1), proto=6)), 1000),
        synth.Packet(synth.ethernet(synth.ipv4(synth.tcp(broken, sport=80, dport=52000, seq=1,
                                                         src=synth.SERVER_IP,
                                                         dst=synth.CLIENT_IP),
                                               proto=6, src=synth.SERVER_IP,
                                               dst=synth.CLIENT_IP)), 2000),
    ]
    path = tmp_path / "broken.pcapng"
    path.write_bytes(synth.pcapng(packets))
    assert main(["http", str(path), "--color", "never"]) == 0
    assert "stream" in capsys.readouterr().err


def test_heuristics_match_wiresharks() -> None:
    """The port-free heuristics are Wireshark's, so results can be compared."""
    from unspool.layers import tls
    # TLS: handshake or application data, a known record version, sane length.
    assert tls.looks_like_records(b"\x16\x03\x01\x02\x00" + b"\x00" * 10)
    assert tls.looks_like_records(b"\x17\x03\x03\x00\x70" + b"\x00" * 10)
    assert not tls.looks_like_records(b"\x14\x03\x03\x00\x01\x01")   # change cipher spec
    assert not tls.looks_like_records(b"\x16\x03\x04\x02\x00")       # 1.3 never on the wire
    assert not tls.looks_like_records(b"\x16\x03\x01\x00\x00")       # empty record
    # HTTP: the first line starts with HTTP/1. or ends with it.
    assert http.looks_like_http(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert http.looks_like_http(b"WEIRD /x HTTP/1.0\r\n\r\n")        # any token is a method
    assert not http.looks_like_http(b"GET / HTTP/1.1")               # no line end yet
    assert not http.looks_like_http(b"HTTP/1.1\r\n")                 # the bare-token case
    assert not http.looks_like_http(b"OPTIONS rtsp://x RTSP/1.0\r\n")


def test_extension_methods_parse() -> None:
    message, _ = http.parse_message(b"PURGE /page HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert message.method == "PURGE" and message.target == "/page"
    with pytest.raises(DecodeError):
        http.parse_message(b"GET\x01BAD /x HTTP/1.1\r\n\r\n")


def test_sysdig_style_capture_reports_no_packets_rather_than_failing() -> None:
    """pcapng blocks unspool does not decode are skipped, not guessed at."""
    event = synth.block(0x00000204, b"\x00" * 32)   # a sysdig event block
    data = synth.shb() + synth.idb() + event + event
    with unspool.open(data) as cap:
        assert list(cap.packets()) == []
        assert len(list(cap.blocks())) == 4


def test_mpls_label_stack() -> None:
    """An MPLS stack ends at the bottom-of-stack bit; IP follows it."""
    inner = synth.ipv4(synth.icmp_echo(), proto=1)
    stack = bytes.fromhex("0001d0ff") + bytes.fromhex("0001d1ff")   # two labels
    frame = synth.ethernet(stack + inner, ethertype=0x8847)
    pkt = decode(Frame(1, 1, frame, len(frame), 0))
    assert pkt.protocols == ("eth", "mpls", "ip", "icmp")
    mpls = pkt.get(MPLS)
    assert mpls is not None and len(mpls.labels) == 2
    assert mpls.labels[0][0] == 29 and mpls.labels[1][0] == 29


def test_novell_raw_802_3_is_not_llc() -> None:
    """802.3 frames whose payload starts 0xFFFF are raw IPX, not LLC."""
    ipx = b"\xff\xff" + b"\x00" * 28
    frame = synth.ethernet(ipx, ethertype=len(ipx))
    assert decode(Frame(1, 1, frame, len(frame), 0)).protocols == ("eth",)
    llc = b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + synth.ipv4(synth.udp(b"x"))
    frame = synth.ethernet(llc, ethertype=len(llc))
    assert decode(Frame(1, 1, frame, len(frame), 0)).protocols[:2] == ("eth", "llc")


def test_a_tls_port_carrying_something_else_is_not_tls() -> None:
    """Port 443 with plainly non-TLS bytes is not announced as TLS."""
    frame = synth.ethernet(synth.ipv4(synth.tcp(b"\x00", sport=60000, dport=443), proto=6))
    assert decode(Frame(1, 1, frame, len(frame), 0)).protocols == ("eth", "ip", "tcp")
    hello = synth.tls_record(synth.client_hello())
    frame = synth.ethernet(synth.ipv4(synth.tcp(hello, sport=60000, dport=443), proto=6))
    assert "tls" in decode(Frame(1, 1, frame, len(frame), 0)).protocols


def test_starttls_on_a_well_known_port_is_still_tls() -> None:
    """A hello is believed on any port: that is how STARTTLS looks."""
    hello = synth.tls_record(synth.client_hello("mail.example.com"))
    frame = synth.ethernet(synth.ipv4(synth.tcp(hello, sport=51000, dport=25), proto=6))
    pkt = decode(Frame(1, 1, frame, len(frame), 0))
    assert "tls" in pkt.protocols
    tls_layer = pkt.get(TLS)
    assert tls_layer is not None and tls_layer.client_hello is not None


def test_a_conversation_keeps_its_protocol_for_later_segments() -> None:
    """Later segments carry the middle of a message and look like nothing."""
    from unspool.packet import Decoder
    decoder = Decoder()
    hello = synth.tls_record(synth.client_hello())
    first = synth.ethernet(synth.ipv4(synth.tcp(hello, sport=60000, dport=9443, seq=1),
                                      proto=6))
    rest = synth.ethernet(synth.ipv4(synth.tcp(b"\x9f" * 40, sport=60000, dport=9443,
                                               seq=1 + len(hello)), proto=6))
    assert "tls" in decoder.decode(Frame(1, 1, first, len(first), 0)).protocols
    assert "tls" in decoder.decode(Frame(2, 1, rest, len(rest), 1000)).protocols
    # A decoder with no memory of the conversation sees only bytes.
    assert "tls" not in decode(Frame(2, 1, rest, len(rest), 1000)).protocols


def test_ja4_uses_zeros_when_nothing_is_left_to_hash() -> None:
    """With only SNI and ALPN present, JA4's last field is zeros, not a hash
    of the empty string (which is what tshark reports)."""
    from unspool.layers import tls as tls_mod
    body = synth.client_hello("only.example.com", alpn=(), grease=False)
    # Strip every extension except server_name by rebuilding a minimal hello.
    hello = tls_mod.parse_handshake_messages(body)[0].body
    assert isinstance(hello, tls_mod.ClientHello)
    bare = tls_mod.ClientHello(legacy_version=0x0303, random=b"\x00" * 32, session_id=b"",
                               cipher_suites=(0x1301,), compression_methods=b"\x00",
                               extensions=(tls_mod.Extension(0x0000, b""),),
                               server_name="only.example.com")
    assert bare.ja4().endswith("_000000000000")
