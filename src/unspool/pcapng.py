"""The pcapng block layer.

A pcapng file is a sequence of blocks. Every block has the same frame::

    block type       u32
    total length     u32   (whole block, including these 8 bytes and the trailer)
    body             ...   (padded to a multiple of 4)
    total length     u32   (again, so the file can be walked backwards)

Byte order is not fixed by the format. Each section starts with a Section
Header Block whose byte-order magic (0x1A2B3C4D) says how every integer in that
section is stored, so everything below takes the endianness as a parameter.
The SHB's own type code, 0x0A0D0D0A, is a palindrome precisely so it can be
recognised before the byte order is known.

Reference: the IETF pcapng draft (draft-ietf-opsawg-pcapng).
"""

from __future__ import annotations

import ipaddress
import struct
from collections import Counter, deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import BinaryIO

from ._cursor import Cursor
from .errors import DecodeError, FormatError, TruncatedError
from .frame import Frame

SHB = 0x0A0D0D0A
IDB = 0x00000001
PB = 0x00000002  # obsolete Packet Block, still written by old tools
SPB = 0x00000003
NRB = 0x00000004
ISB = 0x00000005
EPB = 0x00000006
DSB = 0x0000000A
CB_COPY = 0x00000BAD
CB_NOCOPY = 0x40000BAD

BYTE_ORDER_MAGIC = 0x1A2B3C4D
_SHB_BYTES = b"\x0a\x0d\x0d\x0a"
_BOM_LE = b"\x4d\x3c\x2b\x1a"
_BOM_BE = b"\x1a\x2b\x3c\x4d"

#: Refuse blocks larger than this. Real captures never come close; a corrupt
#: length field would otherwise ask for gigabytes.
MAX_BLOCK_SIZE = 256 * 1024 * 1024

BLOCK_NAMES = {
    SHB: "SHB",
    IDB: "IDB",
    PB: "PB",
    SPB: "SPB",
    NRB: "NRB",
    ISB: "ISB",
    EPB: "EPB",
    0x00000007: "IRIG",
    0x00000008: "ARINC-429",
    0x00000009: "Journal",
    DSB: "DSB",
    CB_COPY: "CB",
    CB_NOCOPY: "CB",
}

_MIN_LENGTH = {SHB: 28, IDB: 20, PB: 32, SPB: 16, NRB: 16, ISB: 24, EPB: 32, DSB: 20,
               CB_COPY: 16, CB_NOCOPY: 16}

#: Decryption Secrets Block secret types.
SECRETS_TYPES = {
    0x544C534B: "TLS key log",
    0x57474B4C: "WireGuard key log",
    0x5A4E574B: "ZigBee NWK key",
    0x5A415053: "ZigBee APS key",
    0x6F706373: "OPC UA key log",
}


def block_name(block_type: int) -> str:
    """Short name for a block type, e.g. ``"EPB"``, or its hex code if unknown."""
    return BLOCK_NAMES.get(block_type, f"0x{block_type:08x}")


# --------------------------------------------------------------------------
# Options
# --------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Option:
    """One TLV option. ``value`` is decoded when the option is known and well
    formed; otherwise it is the raw bytes."""

    code: int
    name: str
    value: object
    raw: bytes = field(repr=False)


class Options(tuple[Option, ...]):
    """The options attached to a block, in file order."""

    __slots__ = ()

    def get(self, key: str | int, default: object = None) -> object:
        """First value for an option name (``"if_name"``) or code (``2``)."""
        for opt in self:
            if opt.name == key or opt.code == key:
                return opt.value
        return default

    def get_all(self, key: str | int) -> list[object]:
        return [opt.value for opt in self if opt.name == key or opt.code == key]

    @property
    def comments(self) -> list[str]:
        return [opt.value for opt in self if opt.code == 1 and isinstance(opt.value, str)]


OptionDecoder = Callable[[bytes, str], object]


def _utf8(raw: bytes, endian: str) -> str:
    # The spec says strings are not NUL-terminated; some writers add one anyway.
    return raw.rstrip(b"\x00").decode("utf-8", "replace")


def _fixed(size: int, code: str) -> OptionDecoder:
    def decode(raw: bytes, endian: str) -> object:
        if len(raw) != size:
            raise DecodeError(f"expected {size} bytes, got {len(raw)}")
        return struct.unpack(endian + code, raw)[0]
    return decode


def _ipv4_netmask(raw: bytes, endian: str) -> str:
    if len(raw) != 8:
        raise DecodeError("expected address + netmask")
    iface = ipaddress.IPv4Interface((raw[:4], str(ipaddress.IPv4Address(raw[4:]))))
    return str(iface)


def _ipv6_prefix(raw: bytes, endian: str) -> str:
    if len(raw) != 17 or raw[16] > 128:
        raise DecodeError("expected address + prefix length")
    return f"{ipaddress.IPv6Address(raw[:16])}/{raw[16]}"


def _ipv4(raw: bytes, endian: str) -> str:
    if len(raw) != 4:
        raise DecodeError("expected 4 bytes")
    return str(ipaddress.IPv4Address(raw))


def _ipv6(raw: bytes, endian: str) -> str:
    if len(raw) != 16:
        raise DecodeError("expected 16 bytes")
    return str(ipaddress.IPv6Address(raw))


def _hwaddr(size: int) -> OptionDecoder:
    def decode(raw: bytes, endian: str) -> str:
        if len(raw) != size:
            raise DecodeError(f"expected {size} bytes")
        return ":".join(f"{b:02x}" for b in raw)
    return decode


def _timestamp_pair(raw: bytes, endian: str) -> int:
    # 64-bit timestamps in options are stored high word first, like the EPB.
    if len(raw) != 8:
        raise DecodeError("expected 8 bytes")
    high, low = struct.unpack(endian + "II", raw)
    return int((high << 32) | low)


def _filter(raw: bytes, endian: str) -> object:
    if not raw:
        raise DecodeError("empty filter")
    if raw[0] == 0:
        return raw[1:].rstrip(b"\x00").decode("utf-8", "replace")
    return (raw[0], raw[1:])


_HASH_ALGORITHMS = {0: "2s-complement", 1: "XOR", 2: "CRC32", 3: "MD5", 4: "SHA-1",
                    5: "Toeplitz"}


def _hash(raw: bytes, endian: str) -> tuple[str, str]:
    if not raw:
        raise DecodeError("empty hash")
    return (_HASH_ALGORITHMS.get(raw[0], str(raw[0])), raw[1:].hex())


def _verdict(raw: bytes, endian: str) -> tuple[str, bytes]:
    if not raw:
        raise DecodeError("empty verdict")
    kind = {0: "hardware", 1: "linux-ebpf-tc", 2: "linux-ebpf-xdp"}.get(raw[0], str(raw[0]))
    return (kind, raw[1:])


def _pid_tid(raw: bytes, endian: str) -> tuple[int, int]:
    if len(raw) != 8:
        raise DecodeError("expected 8 bytes")
    pid, tid = struct.unpack(endian + "II", raw)
    return (int(pid), int(tid))


def _custom(text: bool) -> OptionDecoder:
    def decode(raw: bytes, endian: str) -> tuple[int, object]:
        if len(raw) < 4:
            raise DecodeError("custom option shorter than its enterprise number")
        pen = struct.unpack(endian + "I", raw[:4])[0]
        body = raw[4:]
        return (int(pen), body.decode("utf-8", "replace") if text else body)
    return decode


_COMMON: dict[int, tuple[str, OptionDecoder]] = {
    1: ("comment", _utf8),
    2988: ("custom", _custom(True)),
    2989: ("custom", _custom(False)),
    19372: ("custom", _custom(True)),
    19373: ("custom", _custom(False)),
}

_OPTION_TABLES: dict[int, dict[int, tuple[str, OptionDecoder]]] = {
    SHB: {
        2: ("shb_hardware", _utf8),
        3: ("shb_os", _utf8),
        4: ("shb_userappl", _utf8),
    },
    IDB: {
        2: ("if_name", _utf8),
        3: ("if_description", _utf8),
        4: ("if_IPv4addr", _ipv4_netmask),
        5: ("if_IPv6addr", _ipv6_prefix),
        6: ("if_MACaddr", _hwaddr(6)),
        7: ("if_EUIaddr", _hwaddr(8)),
        8: ("if_speed", _fixed(8, "Q")),
        9: ("if_tsresol", _fixed(1, "B")),
        10: ("if_tzone", _fixed(4, "i")),
        11: ("if_filter", _filter),
        12: ("if_os", _utf8),
        13: ("if_fcslen", _fixed(1, "B")),
        14: ("if_tsoffset", _fixed(8, "q")),
        15: ("if_hardware", _utf8),
        16: ("if_txspeed", _fixed(8, "Q")),
        17: ("if_rxspeed", _fixed(8, "Q")),
        18: ("if_iana_tzname", _utf8),
    },
    EPB: {
        2: ("epb_flags", _fixed(4, "I")),
        3: ("epb_hash", _hash),
        4: ("epb_dropcount", _fixed(8, "Q")),
        5: ("epb_packetid", _fixed(8, "Q")),
        6: ("epb_queue", _fixed(4, "I")),
        7: ("epb_verdict", _verdict),
        8: ("epb_processid_threadid", _pid_tid),
    },
    PB: {
        2: ("pack_flags", _fixed(4, "I")),
        3: ("pack_hash", _hash),
    },
    NRB: {
        2: ("ns_dnsname", _utf8),
        3: ("ns_dnsIP4addr", _ipv4),
        4: ("ns_dnsIP6addr", _ipv6),
    },
    ISB: {
        2: ("isb_starttime", _timestamp_pair),
        3: ("isb_endtime", _timestamp_pair),
        4: ("isb_ifrecv", _fixed(8, "Q")),
        5: ("isb_ifdrop", _fixed(8, "Q")),
        6: ("isb_filteraccept", _fixed(8, "Q")),
        7: ("isb_osdrop", _fixed(8, "Q")),
        8: ("isb_usrdeliv", _fixed(8, "Q")),
    },
}


def parse_options(data: bytes, pos: int, block_type: int, endian: str,
                  offset: int = 0) -> Options:
    """Parse the TLV option list in ``data[pos:]``.

    Each option is code (u16), length (u16), value, padded to 4 bytes. The list
    ends at ``opt_endofopt`` (code 0) or at the end of the block; writers are
    allowed to omit the terminator. A value that would run past the block is a
    format error, which is also how Wireshark treats it.
    """
    table = _OPTION_TABLES.get(block_type, {})
    items: list[Option] = []
    header = struct.Struct(endian + "HH")
    end = len(data)
    while end - pos >= 4:
        code, length = header.unpack_from(data, pos)
        pos += 4
        if code == 0:
            break
        padded = (length + 3) & ~3
        if pos + length > end:
            raise FormatError(
                f"{block_name(block_type)} option {code} length {length} runs past "
                "the end of the block", offset + pos,
            )
        raw = data[pos:pos + length]
        pos += padded
        name, decoder = table.get(code) or _COMMON.get(code) or (f"opt_{code}", None)
        value: object = raw
        if decoder is not None:
            try:
                value = decoder(raw, endian)
            except (DecodeError, ValueError, struct.error):
                value = raw
        items.append(Option(code, name, value, raw))
    return Options(items)


# --------------------------------------------------------------------------
# Blocks
# --------------------------------------------------------------------------

@dataclass(eq=False)
class Block:
    """Common header of every block. ``offset`` is where the block starts."""

    type: int
    offset: int
    length: int
    options: Options

    @property
    def name(self) -> str:
        return block_name(self.type)


@dataclass(eq=False)
class SectionHeaderBlock(Block):
    byte_order: str          # "<" little-endian or ">" big-endian
    major: int
    minor: int
    section_length: int      # -1 means "not specified"

    @property
    def endianness(self) -> str:
        return "little-endian" if self.byte_order == "<" else "big-endian"


@dataclass(eq=False)
class InterfaceDescriptionBlock(Block):
    interface_id: int
    linktype: int
    snaplen: int
    #: Timestamp units per second, from ``if_tsresol`` (default 10**6).
    tsresol: int
    #: Seconds added to every timestamp, from ``if_tsoffset`` (default 0).
    tsoffset: int

    @property
    def if_name(self) -> str | None:
        value = self.options.get("if_name")
        return value if isinstance(value, str) else None


@dataclass(eq=False)
class EnhancedPacketBlock(Block):
    interface_id: int
    timestamp: int           # raw, in the interface's tsresol units
    captured_length: int
    original_length: int
    data: bytes = field(repr=False)


@dataclass(eq=False)
class ObsoletePacketBlock(Block):
    interface_id: int
    drops_count: int
    timestamp: int
    captured_length: int
    original_length: int
    data: bytes = field(repr=False)


@dataclass(eq=False)
class SimplePacketBlock(Block):
    original_length: int
    data: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class NameRecord:
    kind: str                # "ipv4", "ipv6", "eui48", "eui64" or "type N"
    address: str
    names: tuple[str, ...]


@dataclass(eq=False)
class NameResolutionBlock(Block):
    records: list[NameRecord]


@dataclass(eq=False)
class InterfaceStatisticsBlock(Block):
    interface_id: int
    timestamp: int


@dataclass(eq=False)
class DecryptionSecretsBlock(Block):
    """Key material some tools embed. unspool reports it exists and never uses it."""

    secrets_type: int
    secrets: bytes = field(repr=False)

    @property
    def secrets_name(self) -> str:
        return SECRETS_TYPES.get(self.secrets_type, f"0x{self.secrets_type:08x}")


@dataclass(eq=False)
class CustomBlock(Block):
    pen: int                 # IANA Private Enterprise Number of the vendor
    copyable: bool
    data: bytes = field(repr=False)


@dataclass(eq=False)
class UnknownBlock(Block):
    body: bytes = field(repr=False)


PACKET_BLOCK_TYPES = frozenset({EPB, SPB, PB})


def _tsresol(options: Options) -> int:
    value = options.get("if_tsresol")
    if not isinstance(value, int):
        return 1_000_000
    exponent = value & 0x7F
    return int(2 ** exponent if value & 0x80 else 10 ** exponent)


# --------------------------------------------------------------------------
# Reader
# --------------------------------------------------------------------------

@dataclass
class _Section:
    index: int
    byte_order: str
    interfaces: list[InterfaceDescriptionBlock] = field(default_factory=list)


class _Window:
    """A sliding read buffer for walking a file backwards.

    The backward walk reads 4 bytes here and 12 bytes there, one pair per
    block. Doing that with seeks costs two system calls per block, which on a
    file with a million blocks is slower than reading the whole thing forwards.
    Buffering a window around each read makes it cheap again.
    """

    __slots__ = ("_chunk", "_data", "_fh", "_size", "_start")

    def __init__(self, fh: BinaryIO, size: int, chunk: int = 1 << 18) -> None:
        self._fh = fh
        self._size = size
        self._chunk = chunk
        self._data = b""
        self._start = size

    def at(self, offset: int, length: int) -> bytes:
        end = offset + length
        if not (self._start <= offset and end <= self._start + len(self._data)):
            start = max(0, end - self._chunk)
            self._fh.seek(start)
            self._data = self._fh.read(min(self._chunk, self._size - start))
            self._start = start
            if end > start + len(self._data):     # a block larger than the window
                self._fh.seek(offset)
                return self._fh.read(length)
        begin = offset - self._start
        return self._data[begin:begin + length]


class PcapngReader:
    """Reads blocks and frames from a seekable pcapng stream.

    ``size`` is the stream length if known; it lets the reader reject a block
    whose declared length runs past the end of the file before allocating
    anything for it.
    """

    def __init__(self, fh: BinaryIO, size: int | None = None) -> None:
        self._fh = fh
        self._size = size
        self.sections: list[SectionHeaderBlock] = []
        #: Every IDB read so far, across all sections.
        self.interfaces: list[InterfaceDescriptionBlock] = []
        #: How many blocks of each kind (by short name) have been read.
        self.block_counts: Counter[str] = Counter()

    # -- forward reading ---------------------------------------------------

    def blocks(self) -> Iterator[Block]:
        """Yield every block in file order, fully decoded."""
        fh = self._fh
        fh.seek(0)
        self.sections = []
        self.interfaces = []
        self.block_counts = Counter()
        section: _Section | None = None
        offset = 0
        while True:
            block, section = self._read_block(offset, section)
            if block is None:
                return
            self.block_counts[block.name] += 1
            yield block
            offset += block.length

    def frames(self) -> Iterator[Frame]:
        """Yield a :class:`Frame` for every packet block, numbered from 1."""
        interfaces: list[InterfaceDescriptionBlock] = []
        section_index = -1
        number = 0
        for block in self.blocks():
            if isinstance(block, SectionHeaderBlock):
                interfaces = []
                section_index += 1
            elif isinstance(block, InterfaceDescriptionBlock):
                interfaces.append(block)
            elif isinstance(block, (EnhancedPacketBlock, SimplePacketBlock,
                                    ObsoletePacketBlock)):
                number += 1
                yield _to_frame(block, number, interfaces, section_index)

    # -- backward reading --------------------------------------------------

    def reverse_blocks(self) -> Iterator[tuple[int, int, int]]:
        """Walk the block chain from the end: yield ``(offset, type, length)``.

        This is what the trailing length copy is for. Only the 4-byte trailer
        and the 8-byte header of each block are read, so walking back over a
        multi-gigabyte capture touches a few bytes per block. The byte order
        used is the first section's; blocks whose leading and trailing lengths
        disagree raise :class:`FormatError`.
        """
        if self._size is None:
            raise FormatError("reading backwards needs a seekable file of known size")
        byte_order = self._first_byte_order()
        window = _Window(self._fh, self._size)
        pos = self._size
        while pos > 0:
            if pos < 12:
                raise FormatError("stray bytes before the first block", 0)
            (length,) = struct.unpack(byte_order + "I", window.at(pos - 4, 4))
            start = pos - length
            if length < 12 or length % 4 or start < 0:
                raise FormatError(f"trailing block length {length} is invalid", pos - 4)
            head = window.at(start, 12)
            if head[:4] == _SHB_BYTES:
                block_type = SHB
                order = "<" if head[8:12] == _BOM_LE else ">" if head[8:12] == _BOM_BE else None
                if order != byte_order:
                    raise FormatError("section byte order changes mid-file", start)
                (leading,) = struct.unpack(byte_order + "I", head[4:8])
            else:
                block_type, leading = struct.unpack(byte_order + "II", head[:8])
            if leading != length:
                raise FormatError(
                    f"block lengths disagree: {leading} at the start, {length} at the end",
                    start,
                )
            yield (start, block_type, length)
            pos = start

    def last_frames(self, count: int) -> list[Frame]:
        """Return the final ``count`` frames by reading the file backwards.

        Frame numbers are negative, counted from the end (``-1`` is the last
        packet), because the absolute position is unknown without reading
        everything before it. Files this cannot handle backwards (several
        sections, mixed byte order, no known size) fall back to a forward pass.
        """
        if count <= 0:
            return []
        try:
            return self._last_frames_backward(count)
        except FormatError:
            tail = deque(self.frames(), maxlen=count)
            for i, frame in enumerate(tail):
                frame.number = i - len(tail)
            return list(tail)

    def _last_frames_backward(self, count: int) -> list[Frame]:
        packet_offsets: list[int] = []
        idb_offsets: list[int] = []
        shb_offset: int | None = None
        for start, block_type, _length in self.reverse_blocks():
            if block_type == SHB:
                shb_offset = start
                break
            if block_type in PACKET_BLOCK_TYPES and len(packet_offsets) < count:
                packet_offsets.append(start)
            elif block_type == IDB:
                idb_offsets.append(start)
        if shb_offset is None:
            raise FormatError("no section header found walking backwards")
        if shb_offset != 0:
            raise FormatError("more than one section")  # triggers the forward fallback

        shb, section = self._read_block(shb_offset, None)
        assert shb is not None and section is not None
        for offset in reversed(idb_offsets):
            self._read_block(offset, section)
        frames = []
        packet_offsets.reverse()
        for i, offset in enumerate(packet_offsets):
            block, _ = self._read_block(offset, section)
            assert block is not None
            frames.append(_to_frame(block, i - len(packet_offsets), section.interfaces, 0))
        return frames

    def _first_byte_order(self) -> str:
        fh = self._fh
        fh.seek(0)
        head = fh.read(12)
        if head[:4] != _SHB_BYTES or len(head) < 12:
            raise FormatError("file does not start with a Section Header Block", 0)
        if head[8:12] == _BOM_LE:
            return "<"
        if head[8:12] == _BOM_BE:
            return ">"
        raise FormatError("bad byte-order magic in Section Header Block", 8)

    # -- one block ---------------------------------------------------------

    def _read_block(
        self, offset: int, section: _Section | None
    ) -> tuple[Block | None, _Section | None]:
        """Read the block at ``offset``. Returns ``(None, section)`` at clean EOF."""
        fh = self._fh
        fh.seek(offset)
        head = fh.read(8)
        if not head:
            return None, section
        if len(head) < 8:
            raise TruncatedError("file ends inside a block header", offset)

        if head[:4] == _SHB_BYTES:
            bom = fh.read(4)
            if len(bom) < 4:
                raise TruncatedError("file ends inside a Section Header Block", offset)
            if bom == _BOM_LE:
                endian = "<"
            elif bom == _BOM_BE:
                endian = ">"
            else:
                raise FormatError("bad byte-order magic in Section Header Block", offset + 8)
            block_type = SHB
            (length,) = struct.unpack(endian + "I", head[4:8])
            prefix = bom
        else:
            if section is None:
                raise FormatError("file does not start with a Section Header Block", offset)
            endian = section.byte_order
            block_type, length = struct.unpack(endian + "II", head)
            prefix = b""

        self._check_length(block_type, length, offset)
        body = prefix + fh.read(length - 12 - len(prefix))
        trailer = fh.read(4)
        if len(body) < length - 12 or len(trailer) < 4:
            raise TruncatedError(
                f"file ends inside a {block_name(block_type)} block", offset
            )
        (trailing,) = struct.unpack(endian + "I", trailer)
        if trailing != length:
            raise FormatError(
                f"{block_name(block_type)} block lengths disagree: {length} at the start, "
                f"{trailing} at the end", offset,
            )

        if block_type == SHB:
            shb = self._parse_shb(body, offset, length, endian)
            self.sections.append(shb)
            section = _Section(len(self.sections) - 1, endian)
            return shb, section
        assert section is not None
        return self._parse_block(block_type, body, offset, length, section), section

    def _check_length(self, block_type: int, length: int, offset: int) -> None:
        minimum = _MIN_LENGTH.get(block_type, 12)
        if length < minimum:
            raise FormatError(
                f"{block_name(block_type)} block length {length} is below the minimum "
                f"of {minimum}", offset,
            )
        if length % 4:
            raise FormatError(
                f"{block_name(block_type)} block length {length} is not a multiple of 4",
                offset,
            )
        if length > MAX_BLOCK_SIZE:
            raise FormatError(f"block length {length} is implausibly large", offset)
        if self._size is not None and offset + length > self._size:
            raise TruncatedError(
                f"{block_name(block_type)} block of {length} bytes runs past the end "
                "of the file", offset,
            )

    @staticmethod
    def _parse_shb(body: bytes, offset: int, length: int, endian: str) -> SectionHeaderBlock:
        _, major, minor, section_length = struct.unpack_from(endian + "IHHq", body, 0)
        if major != 1:
            raise FormatError(f"unsupported pcapng version {major}.{minor}", offset + 12)
        options = parse_options(body, 16, SHB, endian, offset + 8)
        return SectionHeaderBlock(SHB, offset, length, options, endian, major, minor,
                                  section_length)

    def _parse_block(self, block_type: int, body: bytes, offset: int, length: int,
                     section: _Section) -> Block:
        endian = section.byte_order
        base = offset + 8  # file offset of body[0], for error messages
        try:
            if block_type == IDB:
                linktype, _, snaplen = struct.unpack_from(endian + "HHI", body, 0)
                options = parse_options(body, 8, IDB, endian, base)
                offset_opt = options.get("if_tsoffset")
                idb = InterfaceDescriptionBlock(
                    IDB, offset, length, options, len(section.interfaces), linktype,
                    snaplen, _tsresol(options),
                    offset_opt if isinstance(offset_opt, int) else 0,
                )
                section.interfaces.append(idb)
                self.interfaces.append(idb)
                return idb

            if block_type in (EPB, PB):
                if block_type == EPB:
                    iface, ts_hi, ts_lo, caplen, origlen = struct.unpack_from(
                        endian + "IIIII", body, 0)
                    drops = 0
                else:
                    iface, drops, ts_hi, ts_lo, caplen, origlen = struct.unpack_from(
                        endian + "HHIIII", body, 0)
                self._check_interface(iface, section, block_type, offset)
                if caplen > len(body) - 20:
                    raise FormatError(
                        f"{block_name(block_type)} captured length {caplen} exceeds the "
                        f"{len(body) - 20} bytes in the block", offset,
                    )
                data = body[20:20 + caplen]
                options = parse_options(body, 20 + ((caplen + 3) & ~3), block_type,
                                        endian, base)
                timestamp = (ts_hi << 32) | ts_lo
                if block_type == EPB:
                    return EnhancedPacketBlock(EPB, offset, length, options, iface,
                                               timestamp, caplen, origlen, data)
                return ObsoletePacketBlock(PB, offset, length, options, iface, drops,
                                           timestamp, caplen, origlen, data)

            if block_type == SPB:
                self._check_interface(0, section, block_type, offset)
                (origlen,) = struct.unpack_from(endian + "I", body, 0)
                caplen = min(origlen, len(body) - 4)
                snaplen = section.interfaces[0].snaplen
                if snaplen:
                    caplen = min(caplen, snaplen)
                return SimplePacketBlock(SPB, offset, length, Options(), origlen,
                                         body[4:4 + caplen])

            if block_type == NRB:
                records, pos = _parse_name_records(body, endian, base)
                options = parse_options(body, pos, NRB, endian, base)
                return NameResolutionBlock(NRB, offset, length, options, records)

            if block_type == ISB:
                iface, ts_hi, ts_lo = struct.unpack_from(endian + "III", body, 0)
                options = parse_options(body, 12, ISB, endian, base)
                return InterfaceStatisticsBlock(ISB, offset, length, options, iface,
                                                (ts_hi << 32) | ts_lo)

            if block_type == DSB:
                secrets_type, secrets_len = struct.unpack_from(endian + "II", body, 0)
                if secrets_len > len(body) - 8:
                    raise FormatError("DSB secrets length runs past the block", offset)
                secrets = body[8:8 + secrets_len]
                options = parse_options(body, 8 + ((secrets_len + 3) & ~3), DSB, endian,
                                        base)
                return DecryptionSecretsBlock(DSB, offset, length, options, secrets_type,
                                              secrets)

            if block_type in (CB_COPY, CB_NOCOPY):
                (pen,) = struct.unpack_from(endian + "I", body, 0)
                # Custom block payloads are vendor-defined and their options can't be
                # located without knowing the vendor's format, so keep the rest raw.
                return CustomBlock(block_type, offset, length, Options(), pen,
                                   block_type == CB_COPY, body[4:])
        except struct.error as exc:
            raise FormatError(f"{block_name(block_type)} body too short: {exc}",
                              offset) from None

        return UnknownBlock(block_type, offset, length, Options(), body)

    @staticmethod
    def _check_interface(iface: int, section: _Section, block_type: int,
                         offset: int) -> None:
        if iface >= len(section.interfaces):
            raise FormatError(
                f"{block_name(block_type)} refers to interface {iface}, but the section "
                f"has defined {len(section.interfaces)}", offset,
            )


def _parse_name_records(body: bytes, endian: str, base: int) -> tuple[list[NameRecord], int]:
    """Parse NRB records up to ``nrb_record_end``; return them and where options start."""
    records: list[NameRecord] = []
    cur = Cursor(body, 0, endian=endian)
    try:
        while cur.remaining >= 4:
            kind = cur.u16("record type")
            length = cur.u16("record length")
            if kind == 0:
                return records, cur.pos
            value = cur.take(length, "record value")
            cur.skip((4 - length % 4) % 4, "record padding")
            records.append(_name_record(kind, value))
    except DecodeError as exc:
        raise FormatError(f"NRB records malformed: {exc}", base + cur.pos) from None
    return records, len(body)  # no end-of-records marker; tolerate it


def _name_record(kind: int, value: bytes) -> NameRecord:
    sizes = {1: ("ipv4", 4), 2: ("ipv6", 16), 3: ("eui48", 6), 4: ("eui64", 8)}
    if kind in sizes and len(value) >= sizes[kind][1]:
        label, size = sizes[kind]
        raw = value[:size]
        if kind == 1:
            address = str(ipaddress.IPv4Address(raw))
        elif kind == 2:
            address = str(ipaddress.IPv6Address(raw))
        else:
            address = ":".join(f"{b:02x}" for b in raw)
        names = tuple(
            part.decode("utf-8", "replace") for part in value[size:].split(b"\x00") if part
        )
        return NameRecord(label, address, names)
    return NameRecord(f"type {kind}", value.hex(), ())


def _to_frame(block: Block, number: int, interfaces: list[InterfaceDescriptionBlock],
              section: int) -> Frame:
    comments = tuple(block.options.comments)
    if isinstance(block, (EnhancedPacketBlock, ObsoletePacketBlock)):
        idb = interfaces[block.interface_id]
        ts_ns = block.timestamp * 1_000_000_000 // idb.tsresol + idb.tsoffset * 1_000_000_000
        return Frame(number, idb.linktype, block.data, block.original_length, ts_ns,
                     block.interface_id, section, comments)
    assert isinstance(block, SimplePacketBlock)
    return Frame(number, interfaces[0].linktype, block.data, block.original_length, None,
                 0, section, comments)
