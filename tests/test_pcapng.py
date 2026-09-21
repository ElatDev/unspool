"""The pcapng block layer: byte order, options, block types, damage."""

from __future__ import annotations

import struct

import pytest

import unspool
from unspool import pcapng as ng
from unspool.errors import FormatError, TruncatedError

from . import synth


def frames_of(data: bytes) -> list:
    with unspool.open(data) as cap:
        return list(cap.frames())


def test_reads_a_minimal_file() -> None:
    data = synth.pcapng([synth.Packet(synth.ethernet(b"hello"), timestamp_us=1_000_000)])
    frames = frames_of(data)
    assert len(frames) == 1
    assert frames[0].number == 1
    assert frames[0].timestamp_ns == 1_000_000_000
    assert frames[0].linktype == 1


@pytest.mark.parametrize("endian", ["<", ">"])
def test_both_byte_orders(endian: str) -> None:
    data = synth.pcapng([synth.Packet(synth.ethernet(b"x"), 5_000_000)], endian=endian)
    with unspool.open(data) as cap:
        blocks = list(cap.blocks())
        assert blocks[0].byte_order == endian  # type: ignore[attr-defined]
        assert [f.timestamp_ns for f in cap.frames()] == [5_000_000_000]


def test_sections_may_differ_in_byte_order() -> None:
    """Byte order is per section, so a file can hold both."""
    little = synth.pcapng([synth.Packet(b"\x00" * 20, 1_000_000)], endian="<")
    big = synth.pcapng([synth.Packet(b"\x11" * 20, 2_000_000)], endian=">")
    frames = frames_of(little + big)
    assert [f.timestamp_ns for f in frames] == [1_000_000_000, 2_000_000_000]
    assert [f.section for f in frames] == [0, 1]
    assert [f.number for f in frames] == [1, 2]


def test_interface_ids_restart_each_section() -> None:
    one = synth.pcapng([synth.Packet(b"\x00" * 16)], linktype=1)
    two = synth.pcapng([synth.Packet(b"\x00" * 16)], linktype=101)
    assert [f.linktype for f in frames_of(one + two)] == [1, 101]


def test_timestamp_resolution_option() -> None:
    """if_tsresol says what a timestamp tick is worth; the default is microseconds."""
    header = synth.shb() + synth.idb(opts=[(9, b"\x09")])          # 10^-9: nanoseconds
    data = header + synth.epb(synth.ethernet(b"x"), timestamp=1_500_000_000)
    assert frames_of(data)[0].timestamp_ns == 1_500_000_000

    header = synth.shb() + synth.idb(opts=[(9, bytes([0x80 | 16]))])  # 2^-16 seconds
    data = header + synth.epb(synth.ethernet(b"x"), timestamp=65536 * 3)
    assert frames_of(data)[0].timestamp_ns == 3_000_000_000


def test_timestamp_offset_option() -> None:
    header = synth.shb() + synth.idb(opts=[(14, struct.pack("<q", 1_000_000))])
    data = header + synth.epb(synth.ethernet(b"x"), timestamp=500_000)
    assert frames_of(data)[0].timestamp_ns == 1_000_000_500_000_000


def test_options_are_decoded_by_name() -> None:
    header = synth.shb(opts=[(1, b"a comment"), (3, b"Linux 6.1"), (4, b"unspool")])
    header += synth.idb(opts=[(2, b"eth0"), (3, b"lab uplink"), (6, bytes.fromhex("02005e100001")),
                              (8, struct.pack("<Q", 1_000_000_000)), (9, b"\x06"),
                              (11, b"\x00tcp port 443")])
    data = header + synth.epb(synth.ethernet(b"x"), opts=[(1, b"frame note"),
                                                          (2, struct.pack("<I", 1))])
    with unspool.open(data) as cap:
        shb, idb, epb = list(cap.blocks())
    assert shb.options.get("shb_os") == "Linux 6.1"
    assert shb.options.comments == ["a comment"]
    assert idb.options.get("if_name") == "eth0"
    assert idb.options.get("if_description") == "lab uplink"
    assert idb.options.get("if_MACaddr") == "02:00:5e:10:00:01"
    assert idb.options.get("if_speed") == 1_000_000_000
    assert idb.options.get("if_filter") == "tcp port 443"
    assert epb.options.get("epb_flags") == 1
    assert epb.options.comments == ["frame note"]
    assert frames_of(data)[0].comments == ("frame note",)


def test_unknown_option_keeps_its_bytes() -> None:
    data = synth.shb(opts=[(4242, b"\x01\x02\x03")]) + synth.idb() \
        + synth.epb(synth.ethernet(b"x"))
    with unspool.open(data) as cap:
        shb = next(iter(cap.blocks()))
    assert shb.options[0].name == "opt_4242"
    assert shb.options[0].value == b"\x01\x02\x03"


def test_badly_sized_option_keeps_raw_value() -> None:
    """A known option with the wrong length is kept, not fatal."""
    data = synth.shb() + synth.idb(opts=[(8, b"\x01\x02")]) + synth.epb(synth.ethernet(b"x"))
    with unspool.open(data) as cap:
        idb = list(cap.blocks())[1]
    assert idb.options.get("if_speed") == b"\x01\x02"
    assert idb.tsresol == 1_000_000


def test_option_running_past_the_block_is_an_error() -> None:
    body = struct.pack("<HHI", 1, 0, 262144) + struct.pack("<HH", 2, 400) + b"eth0"
    data = synth.shb() + synth.block(0x00000001, body) + synth.epb(b"\x00" * 16)
    with pytest.raises(FormatError, match="runs past"):
        frames_of(data)


def test_simple_packet_block() -> None:
    data = synth.shb() + synth.idb() + synth.spb(synth.ethernet(b"payload"))
    frames = frames_of(data)
    assert frames[0].timestamp_ns is None
    assert frames[0].original_length == len(synth.ethernet(b"payload"))


def test_obsolete_packet_block() -> None:
    frame = synth.ethernet(b"old")
    body = struct.pack("<HHIIII", 0, 0, 0, 2_000_000, len(frame), len(frame)) + frame
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    data = synth.shb() + synth.idb() + synth.block(0x00000002, body)
    frames = frames_of(data)
    assert len(frames) == 1
    assert frames[0].timestamp_ns == 2_000_000_000


def test_name_resolution_block() -> None:
    records = [(1, synth.ipv4_bytes("192.0.2.10") + b"client.example.com\x00"),
               (2, synth.ipv6_bytes("2001:db8::10") + b"v6.example.com\x00")]
    data = synth.shb() + synth.idb() + synth.nrb(records) + synth.epb(b"\x00" * 16)
    with unspool.open(data) as cap:
        nrb = next(b for b in cap.blocks() if isinstance(b, ng.NameResolutionBlock))
    assert nrb.records[0].address == "192.0.2.10"
    assert nrb.records[0].names == ("client.example.com",)
    assert nrb.records[1].kind == "ipv6"


def test_statistics_and_secrets_blocks() -> None:
    data = (synth.shb() + synth.idb()
            + synth.isb(opts=[(4, struct.pack("<Q", 100)), (5, struct.pack("<Q", 2))])
            + synth.dsb() + synth.epb(b"\x00" * 16))
    with unspool.open(data) as cap:
        blocks = list(cap.blocks())
    isb = next(b for b in blocks if isinstance(b, ng.InterfaceStatisticsBlock))
    dsb = next(b for b in blocks if isinstance(b, ng.DecryptionSecretsBlock))
    assert isb.options.get("isb_ifrecv") == 100
    assert dsb.secrets_name == "TLS key log"
    # The keys are reported but never used: unspool decrypts nothing.
    assert dsb.secrets.startswith(b"CLIENT_RANDOM")


def test_custom_and_unknown_blocks_are_skipped() -> None:
    custom = synth.block(0x00000BAD, struct.pack("<I", 32473) + b"vendor data")
    unknown = synth.block(0x00FFFFFF, b"\x00" * 8)
    data = synth.shb() + synth.idb() + custom + unknown + synth.epb(synth.ethernet(b"x"))
    assert len(frames_of(data)) == 1
    with unspool.open(data) as cap:
        kinds = [type(b).__name__ for b in cap.blocks()]
    assert "CustomBlock" in kinds and "UnknownBlock" in kinds


def test_block_lengths_must_agree() -> None:
    data = bytearray(synth.pcapng([synth.Packet(synth.ethernet(b"x"))]))
    data[-4:] = struct.pack("<I", 999)  # corrupt the trailing copy of the length
    with pytest.raises(FormatError, match="lengths disagree"):
        frames_of(bytes(data))


def test_block_length_must_be_a_multiple_of_four() -> None:
    data = synth.shb() + synth.idb() + struct.pack("<II", 6, 33) + b"\x00" * 21 \
        + struct.pack("<I", 33)
    with pytest.raises(FormatError, match="multiple of 4"):
        frames_of(data)


def test_packet_block_naming_an_undefined_interface() -> None:
    data = synth.shb() + synth.idb() + synth.epb(synth.ethernet(b"x"), interface=3)
    with pytest.raises(FormatError, match="interface 3"):
        frames_of(data)


def test_captured_length_beyond_the_block() -> None:
    body = struct.pack("<IIIII", 0, 0, 0, 5000, 5000) + b"\x00" * 16
    data = synth.shb() + synth.idb() + synth.block(0x00000006, body)
    with pytest.raises(FormatError, match="captured length"):
        frames_of(data)


def test_truncated_file_yields_every_whole_packet_first() -> None:
    """A capture cut off mid-write still gives up everything before the cut."""
    data = synth.pcapng([synth.Packet(synth.ethernet(b"one")),
                         synth.Packet(synth.ethernet(b"two")),
                         synth.Packet(synth.ethernet(b"three"))])
    with unspool.open(data[:-20]) as cap:
        seen = []
        with pytest.raises(TruncatedError):
            for frame in cap.frames():
                seen.append(frame.number)
    assert seen == [1, 2]


def test_file_must_start_with_a_section_header() -> None:
    with pytest.raises(FormatError, match="not a pcap or pcapng"):
        frames_of(synth.idb() + synth.epb(b"\x00" * 16))


def test_bad_byte_order_magic() -> None:
    data = bytearray(synth.pcapng([synth.Packet(b"\x00" * 16)]))
    data[8:12] = b"\xde\xad\xbe\xef"
    with pytest.raises(FormatError, match="byte-order magic"):
        frames_of(bytes(data))


def test_unsupported_version() -> None:
    body = struct.pack("<IHHq", 0x1A2B3C4D, 2, 0, -1)
    data = synth.block(0x0A0D0D0A, body) + synth.idb() + synth.epb(b"\x00" * 16)
    with pytest.raises(FormatError, match=r"version 2\.0"):
        frames_of(data)


def test_reverse_walk_visits_every_block_backwards() -> None:
    data = synth.pcapng([synth.Packet(synth.ethernet(b"a")), synth.Packet(synth.ethernet(b"b")),
                         synth.Packet(synth.ethernet(b"c"))])
    with unspool.open(data) as cap:
        reader = cap.reader
        assert isinstance(reader, ng.PcapngReader)
        forward = [(b.offset, b.type, b.length) for b in cap.blocks()]
        backward = list(reader.reverse_blocks())
    assert backward == list(reversed(forward))


def test_last_frames_reads_backwards() -> None:
    packets = [synth.Packet(synth.ethernet(bytes([i])), i * 1000) for i in range(50)]
    data = synth.pcapng(packets)
    with unspool.open(data) as cap:
        tail = cap.last_frames(3)
    assert [f.data[-1] for f in tail] == [47, 48, 49]
    assert [f.number for f in tail] == [-3, -2, -1]


def test_last_frames_falls_back_when_backwards_is_impossible() -> None:
    """Two sections defeat a backward walk; the answer must still be right."""
    data = synth.pcapng([synth.Packet(synth.ethernet(b"a"))]) \
        + synth.pcapng([synth.Packet(synth.ethernet(b"b")), synth.Packet(synth.ethernet(b"c"))])
    with unspool.open(data) as cap:
        tail = cap.last_frames(2)
    assert [bytes(f.data[-1:]) for f in tail] == [b"b", b"c"]
