"""Opening files: format sniffing, classic pcap, compression, the public API."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import struct

import pytest

import unspool
from unspool.errors import FormatError, TruncatedError
from unspool.layers import TCP, UDP

from . import synth

PACKETS = [synth.Packet(synth.ethernet(synth.ipv4(synth.udp(b"one"))), 1_000_000),
           synth.Packet(synth.ethernet(synth.ipv4(synth.udp(b"two"))), 2_500_000)]


def test_open_accepts_bytes_paths_and_file_objects(tmp_path) -> None:
    data = synth.pcapng(PACKETS)
    path = tmp_path / "capture.pcapng"
    path.write_bytes(data)
    assert len(list(unspool.packets(data))) == 2
    assert len(list(unspool.packets(path))) == 2
    assert len(list(unspool.packets(str(path)))) == 2
    with path.open("rb") as fh, unspool.open(fh) as cap:
        assert len(list(cap.packets())) == 2


def test_capture_is_a_context_manager_and_reiterable() -> None:
    with unspool.open(synth.pcapng(PACKETS)) as cap:
        assert [f.number for f in cap.frames()] == [1, 2]
        assert [f.number for f in cap.frames()] == [1, 2]   # iterating again rewinds
        assert cap.format == "pcapng"
        assert cap.interfaces[0].linktype == 1


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nanosecond", [False, True])
def test_classic_pcap(endian: str, nanosecond: bool) -> None:
    data = synth.pcap(PACKETS, endian=endian, nanosecond=nanosecond)
    with unspool.open(data) as cap:
        assert cap.format == "pcap"
        frames = list(cap.frames())
    assert [f.timestamp_ns for f in frames] == [1_000_000_000, 2_500_000_000]
    assert frames[0].linktype == 1


def test_pcap_fcs_length_in_the_link_type_field() -> None:
    data = bytearray(synth.pcap(PACKETS))
    # libpcap stores an FCS length in the top bits of the link type field.
    data[20:24] = struct.pack("<I", 1 | 0x04000000 | (2 << 28))
    with unspool.open(bytes(data)) as cap:
        assert cap.format == "pcap"
        assert cap.reader.header.fcs_length == 4  # type: ignore[union-attr]
        assert cap.interfaces[0].linktype == 1


def test_modified_pcap_has_longer_record_headers() -> None:
    frame = synth.ethernet(synth.ipv4(synth.udp(b"x")))
    data = b"\x34\xcd\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 262144, 1)
    data += struct.pack("<IIII", 7, 500_000, len(frame), len(frame))
    data += struct.pack("<IIHHI", 3, 1, 0, 0, 0)[:8] + frame   # 8 extra header bytes
    with unspool.open(data) as cap:
        frames = list(cap.frames())
    assert len(frames) == 1 and frames[0].timestamp_ns == 7_500_000_000


def test_truncated_pcap_record() -> None:
    data = synth.pcap(PACKETS)
    with unspool.open(data[:-10]) as cap, pytest.raises(TruncatedError):
        list(cap.frames())


@pytest.mark.parametrize("compress", [gzip.compress, bz2.compress, lzma.compress])
def test_compressed_captures(compress) -> None:
    data = compress(synth.pcapng(PACKETS))
    with unspool.open(data) as cap:
        assert len(list(cap.packets())) == 2
        assert cap.compression in ("gzip", "bzip2", "xz")


def test_corrupt_gzip_raises_an_unspool_error() -> None:
    broken = bytearray(gzip.compress(synth.pcapng(PACKETS)))
    broken[30:40] = b"\x00" * 10
    with pytest.raises(unspool.UnspoolError), unspool.open(bytes(broken)) as cap:
        list(cap.packets())


def test_empty_and_foreign_files() -> None:
    with pytest.raises(FormatError, match="empty"):
        unspool.open(b"")
    with pytest.raises(FormatError, match="not a pcap or pcapng"):
        unspool.open(b"just some text, not a capture at all")
    with pytest.raises(FormatError, match="Network Monitor"):
        unspool.open(b"GMBU" + b"\x00" * 100)


def test_blocks_are_pcapng_only() -> None:
    with unspool.open(synth.pcap(PACKETS)) as cap, pytest.raises(unspool.UnspoolError):
        list(cap.blocks())


def test_packet_accessors() -> None:
    data = synth.pcapng(synth.dns_exchange())
    packets = list(unspool.packets(data))
    query = packets[0]
    assert query.dns is not None and query.udp is not None
    assert query.src == synth.CLIENT_IP and query.dport == 53
    assert query.protocol_label == "DNS"
    assert "udp" in query and UDP in query
    assert query.get(TCP) is None
    assert [layer.name for layer in query] == ["eth", "ip", "udp", "dns"]


def test_stateless_decode_helper() -> None:
    frame = next(iter(unspool.frames(synth.pcapng(PACKETS))))
    assert unspool.decode(frame).protocols == ("eth", "ip", "udp")


def test_last_frames_on_pcap_walks_forward() -> None:
    with unspool.open(synth.pcap(PACKETS)) as cap:
        tail = cap.last_frames(1)
    assert len(tail) == 1 and tail[0].number == -1


def test_file_object_without_seek() -> None:
    class Pipe(io.RawIOBase):
        def __init__(self, data: bytes) -> None:
            self._data = io.BytesIO(data)

        def readable(self) -> bool:
            return True

        def read(self, size: int = -1) -> bytes:  # type: ignore[override]
            return self._data.read(size)

        def seekable(self) -> bool:
            return False

    stream = io.BufferedReader(Pipe(synth.pcapng(PACKETS)))
    with unspool.open(stream) as cap:
        assert len(list(cap.packets())) == 2
