"""TCP reassembly: order, retransmission, wraparound, gaps."""

from __future__ import annotations

from unspool import decode
from unspool.frame import Frame
from unspool.layers import tls
from unspool.streams import Reassembler

from . import synth

CLIENT_PORT = 52000


def segment(payload: bytes = b"", *, seq: int, to_server: bool = True, flags: int = 0x18,
            sport: int = CLIENT_PORT, dport: int = 80, number: int = 1):
    if to_server:
        frame = synth.ethernet(synth.ipv4(synth.tcp(payload, sport=sport, dport=dport, seq=seq,
                                                    flags=flags), proto=6))
    else:
        frame = synth.ethernet(synth.ipv4(synth.tcp(payload, sport=dport, dport=sport, seq=seq,
                                                    flags=flags, src=synth.SERVER_IP,
                                                    dst=synth.CLIENT_IP),
                                          proto=6, src=synth.SERVER_IP, dst=synth.CLIENT_IP))
    return decode(Frame(number, 1, frame, len(frame), number * 1000))


def reassemble(packets: list) -> list:
    r = Reassembler()
    for pkt in packets:
        r.add(pkt)
    return r.streams()


def test_in_order_segments() -> None:
    packets = [segment(b"", seq=1000, flags=0x02),
               segment(b"", seq=5000, to_server=False, flags=0x12),
               segment(b"abc", seq=1001), segment(b"def", seq=1004),
               segment(b"xyz", seq=5001, to_server=False)]
    streams = reassemble(packets)
    assert len(streams) == 1
    assert streams[0].client_bytes == b"abcdef"
    assert streams[0].server_bytes == b"xyz"
    assert streams[0].syn_seen and streams[0].client == (synth.CLIENT_IP, CLIENT_PORT)


def test_out_of_order_segments_are_sorted() -> None:
    packets = [segment(b"", seq=1000, flags=0x02),
               segment(b"third", seq=1011), segment(b"first", seq=1001),
               segment(b"secnd", seq=1006)]
    assert reassemble(packets)[0].client_bytes == b"firstsecndthird"


def test_retransmission_is_not_duplicated() -> None:
    packets = [segment(b"", seq=1000, flags=0x02),
               segment(b"hello", seq=1001), segment(b"hello", seq=1001),
               segment(b"world", seq=1006)]
    assert reassemble(packets)[0].client_bytes == b"helloworld"


def test_overlapping_retransmission_keeps_the_new_bytes() -> None:
    # The second segment repeats "lo" (already held) and adds "world".
    packets = [segment(b"", seq=1000, flags=0x02),
               segment(b"hello", seq=1001), segment(b"loworld", seq=1004)]
    assert reassemble(packets)[0].client_bytes == b"helloworld"


def test_gap_stops_the_stream_there() -> None:
    packets = [segment(b"", seq=1000, flags=0x02),
               segment(b"start", seq=1001), segment(b"after the hole", seq=9000)]
    stream = reassemble(packets)[0]
    assert stream.client_bytes == b"start"
    assert stream.client_data.gap


def test_capture_starting_mid_stream() -> None:
    """With no SYN, the first byte seen is the start of what we have."""
    packets = [segment(b"middle", seq=123456), segment(b" of it", seq=123462)]
    stream = reassemble(packets)[0]
    assert stream.client_bytes == b"middle of it" and not stream.syn_seen


def test_sequence_number_wraparound() -> None:
    base = 0xFFFFFFF0
    packets = [segment(b"", seq=base, flags=0x02),
               segment(b"before", seq=(base + 1) & 0xFFFFFFFF),
               segment(b"after", seq=(base + 7) & 0xFFFFFFFF)]
    assert reassemble(packets)[0].client_bytes == b"beforeafter"


def test_port_reuse_starts_a_new_stream() -> None:
    packets = [segment(b"", seq=1000, flags=0x02), segment(b"first", seq=1001),
               segment(b"", seq=7000, flags=0x02), segment(b"second", seq=7001)]
    streams = reassemble(packets)
    assert len(streams) == 2
    assert [s.client_bytes for s in streams] == [b"first", b"second"]


def test_keep_predicate_drops_uninteresting_streams() -> None:
    packets = [segment(b"", seq=1000, flags=0x02), segment(b"\x00\x01binary junk", seq=1001),
               segment(b"", seq=2000, flags=0x02, sport=52001),
               segment(synth.http_request(), seq=2001, sport=52001)]
    r = Reassembler(keep=lambda first: first.startswith(b"GET"))
    for pkt in packets:
        r.add(pkt)
    streams = r.streams()
    assert len(streams) == 1
    assert streams[0].client_bytes.startswith(b"GET")


def test_size_cap_marks_the_stream() -> None:
    packets = [segment(b"", seq=1000, flags=0x02)]
    packets += [segment(b"x" * 100, seq=1001 + i * 100, number=i + 2) for i in range(20)]
    r = Reassembler(max_bytes=512)
    for pkt in packets:
        r.add(pkt)
    stream = r.streams()[0]
    assert len(stream.client_bytes) == 512 and stream.client_data.capped


def test_client_hello_split_across_segments_is_recovered() -> None:
    """The point of reassembly: a ClientHello too big for one segment."""
    hello = synth.tls_record(synth.client_hello("split.example.com"))
    cut = len(hello) // 2
    packets = [segment(b"", seq=1000, flags=0x02, dport=443),
               segment(hello[:cut], seq=1001, dport=443),
               segment(hello[cut:], seq=1001 + cut, dport=443)]
    stream = reassemble(packets)[0]
    messages = tls.parse_handshake_messages(tls.handshake_bytes(stream.client_bytes))
    hello_body = messages[0].body
    assert isinstance(hello_body, tls.ClientHello)
    assert hello_body.server_name == "split.example.com"


def test_quoted_tcp_inside_icmp_is_not_a_stream() -> None:
    quoted = synth.ipv4(synth.tcp(b"", sport=52000, dport=80)[:8], proto=6)
    frame = synth.ethernet(synth.ipv4(synth.icmp_unreachable(quoted), proto=1))
    pkt = decode(Frame(1, 1, frame, len(frame), 0))
    assert reassemble([pkt]) == []
