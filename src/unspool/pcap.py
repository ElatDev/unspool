"""Classic libpcap files.

pcapng is the subject of this library, but most captures in the wild -- and
most of Wireshark's own sample set -- are the older format, so reading both is
table stakes. The format is a 24-byte global header followed by records of a
16-byte header plus packet bytes. There is no trailing length, which is why a
pcap file, unlike pcapng, cannot be read backwards.
"""

from __future__ import annotations

import struct
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO

from .errors import FormatError, TruncatedError
from .frame import Frame

# magic -> (byte order, fractional-second units, record header size)
MAGICS: dict[bytes, tuple[str, int, int]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000, 16),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000, 16),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000, 16),   # nanosecond resolution
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000, 16),
    # Alexey Kuznetsov's patched libpcap: 8 extra bytes per record header.
    b"\x34\xcd\xb2\xa1": ("<", 1_000_000, 24),
    b"\xa1\xb2\xcd\x34": (">", 1_000_000, 24),
}

#: Refuse records larger than this; a corrupt length would otherwise ask for
#: gigabytes. Wireshark's own ceiling is lower still for most link types.
MAX_RECORD_SIZE = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class PcapHeader:
    byte_order: str
    version: tuple[int, int]
    snaplen: int
    linktype: int
    #: Frame check sequence length in bytes, when the header declares one.
    fcs_length: int | None
    nanosecond: bool
    modified: bool


class PcapReader:
    """Reads frames from a classic pcap stream."""

    def __init__(self, fh: BinaryIO, size: int | None = None) -> None:
        self._fh = fh
        self._size = size
        self.header = self._read_header()

    def _read_header(self) -> PcapHeader:
        fh = self._fh
        fh.seek(0)
        raw = fh.read(24)
        if len(raw) < 24:
            raise TruncatedError("file ends inside the pcap global header", 0)
        spec = MAGICS.get(raw[:4])
        if spec is None:
            raise FormatError(f"not a pcap file (magic {raw[:4].hex()})", 0)
        endian, units, record_size = spec
        major, minor, _zone, _sigfigs, snaplen, network = struct.unpack(
            endian + "HHiIII", raw[4:24])
        if major != 2:
            raise FormatError(f"unsupported pcap version {major}.{minor}", 4)
        # Upper bits of the link type field carry the FCS length (libpcap's
        # LT_FCS_LENGTH_PRESENT / LT_FCS_LENGTH).
        fcs = (network >> 28) * 2 if network & 0x04000000 else None
        return PcapHeader(endian, (major, minor), snaplen, network & 0xFFFF, fcs,
                          units == 1_000_000_000, record_size == 24)

    def frames(self) -> Iterator[Frame]:
        header = self.header
        units = 1_000_000_000 if header.nanosecond else 1_000_000
        record_size = 24 if header.modified else 16
        record = struct.Struct(header.byte_order + "IIII")
        scale = 1_000_000_000 // units
        fh = self._fh
        fh.seek(24)
        offset = 24
        number = 0
        while True:
            raw = fh.read(record_size)
            if not raw:
                return
            if len(raw) < record_size:
                raise TruncatedError("file ends inside a record header", offset)
            ts_sec, ts_frac, caplen, origlen = record.unpack_from(raw, 0)
            if caplen > MAX_RECORD_SIZE:
                raise FormatError(f"record claims {caplen} captured bytes", offset)
            if self._size is not None and offset + record_size + caplen > self._size:
                raise TruncatedError("file ends inside a packet", offset)
            data = fh.read(caplen)
            if len(data) < caplen:
                raise TruncatedError("file ends inside a packet", offset)
            number += 1
            yield Frame(number, header.linktype, data, origlen,
                        ts_sec * 1_000_000_000 + ts_frac * scale, 0, 0)
            offset += record_size + caplen

    def last_frames(self, count: int) -> list[Frame]:
        """pcap has no trailing lengths, so the only way to the end is through
        the whole file."""
        tail = deque(self.frames(), maxlen=max(count, 0))
        for i, frame in enumerate(tail):
            frame.number = i - len(tail)
        return list(tail) if count > 0 else []
