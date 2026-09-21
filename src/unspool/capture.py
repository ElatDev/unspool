"""Opening capture files: format detection, decompression, and the Capture object."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, BinaryIO, cast

from . import pcap, pcapng
from .errors import FormatError, TruncatedError, UnspoolError
from .frame import Frame
from .packet import Decoder, Packet

_GZIP = b"\x1f\x8b"
_BZIP2 = b"BZh"
_XZ = b"\xfd7zXZ\x00"
_ZSTD = b"\x28\xb5\x2f\xfd"

# Formats that are captures but not ones this library reads, for a better error.
_OTHER_FORMATS = {
    b"GMBU": "Microsoft Network Monitor",
    b"snoo": "Solaris snoop",
    b"XCP\x00": "NetXray / Sniffer",
    b"\x00\x00\x00\x00\x00\x00\x00\x00": "unrecognised (starts with zeros)",
}


@dataclass(frozen=True, slots=True)
class Interface:
    """A capture interface: one per IDB in pcapng, one per file in pcap."""

    linktype: int
    snaplen: int
    name: str | None = None
    description: str | None = None
    #: Timestamp units per second.
    tsresol: int = 1_000_000


class _SafeStream:
    """Wraps a decompressor so corrupt compressed data raises UnspoolError."""

    def __init__(self, raw: Any, kind: str) -> None:
        self._raw = raw
        self.kind = kind

    def _guard(self, call: object, *args: int) -> object:
        try:
            return call(*args)  # type: ignore[operator]
        except EOFError:
            raise TruncatedError(f"{self.kind} stream ends early") from None
        except (OSError, zlib.error, lzma.LZMAError, ValueError) as exc:
            raise FormatError(f"corrupt {self.kind} data: {exc}") from None

    def read(self, size: int = -1) -> bytes:
        return cast(bytes, self._guard(self._raw.read, size))

    def seek(self, offset: int, whence: int = 0) -> int:
        return cast(int, self._guard(self._raw.seek, offset, whence))

    def tell(self) -> int:
        return int(self._raw.tell())

    def close(self) -> None:
        self._raw.close()


class Capture:
    """An open capture file.

    Iterate it for decoded :class:`Packet` objects, or use :meth:`frames` for
    raw frames and :meth:`blocks` for the pcapng block structure. Use as a
    context manager so the file is closed.
    """

    def __init__(self, fh: BinaryIO, *, name: str = "<stream>", size: int | None = None,
                 compression: str | None = None, owns: bool = False) -> None:
        self.name = name
        self.compression = compression
        self._fh = fh
        self._owns = owns
        head = fh.read(4)
        fh.seek(0)
        if head == b"\x0a\x0d\x0d\x0a":
            self.format = "pcapng"
            self._reader: pcapng.PcapngReader | pcap.PcapReader = pcapng.PcapngReader(fh, size)
        elif head in pcap.MAGICS:
            self.format = "pcap"
            self._reader = pcap.PcapReader(fh, size)
        elif not head:
            raise FormatError(f"{name}: file is empty")
        else:
            kind = _OTHER_FORMATS.get(head) or _OTHER_FORMATS.get(head + fh.read(8)[4:8])
            fh.seek(0)
            hint = f" (looks like {kind})" if kind else ""
            raise FormatError(f"{name}: not a pcap or pcapng file{hint}", 0)

    # -- iteration -----------------------------------------------------------

    def frames(self) -> Iterator[Frame]:
        """Yield raw frames in file order."""
        return self._reader.frames()

    def packets(self) -> Iterator[Packet]:
        """Yield decoded packets in file order."""
        decoder = Decoder()
        for frame in self.frames():
            yield decoder.decode(frame)

    __iter__ = packets

    def blocks(self) -> Iterator[pcapng.Block]:
        """Yield pcapng blocks (pcapng files only)."""
        if not isinstance(self._reader, pcapng.PcapngReader):
            raise UnspoolError(f"{self.name} is a {self.format} file; it has no blocks")
        return self._reader.blocks()

    def last_frames(self, count: int) -> list[Frame]:
        """The final ``count`` frames. pcapng files are read backwards; see
        :meth:`unspool.pcapng.PcapngReader.last_frames`."""
        return self._reader.last_frames(count)

    # -- metadata ------------------------------------------------------------

    @property
    def interfaces(self) -> list[Interface]:
        """Interfaces seen so far (for pcapng, populated as blocks are read)."""
        reader = self._reader
        if isinstance(reader, pcap.PcapReader):
            return [Interface(reader.header.linktype, reader.header.snaplen)]
        out = []
        for idb in reader.interfaces:
            desc = idb.options.get("if_description")
            out.append(Interface(idb.linktype, idb.snaplen, idb.if_name,
                                 desc if isinstance(desc, str) else None, idb.tsresol))
        return out

    @property
    def sections(self) -> list[pcapng.SectionHeaderBlock]:
        reader = self._reader
        return reader.sections if isinstance(reader, pcapng.PcapngReader) else []

    @property
    def reader(self) -> pcapng.PcapngReader | pcap.PcapReader:
        return self._reader

    # -- lifetime ------------------------------------------------------------

    def close(self) -> None:
        if self._owns:
            self._fh.close()

    def __enter__(self) -> Capture:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.close()

    def __repr__(self) -> str:
        comp = f" ({self.compression})" if self.compression else ""
        return f"<Capture {self.name!r} {self.format}{comp}>"


def open(source: str | os.PathLike[str] | bytes | BinaryIO) -> Capture:
    """Open a pcap or pcapng capture, optionally gzip/bzip2/xz-compressed.

    ``source`` may be a path, the file's bytes, or a binary file object.
    """
    raw: BinaryIO
    size: int | None
    if isinstance(source, (bytes, bytearray, memoryview)):
        raw = io.BytesIO(bytes(source))
        name, size, owns = "<bytes>", len(source), True
    elif isinstance(source, (str, os.PathLike)):
        name = os.fspath(source)
        # Opened without a context manager on purpose: the Capture owns the
        # handle from here on and closes it in Capture.close().
        raw = Path(name).open("rb")
        size, owns = os.fstat(raw.fileno()).st_size, True
    else:
        raw, name, owns = source, getattr(source, "name", "<stream>"), False
        try:
            size = raw.seek(0, io.SEEK_END)
            raw.seek(0)
        except (OSError, AttributeError, ValueError):
            # Not seekable (a pipe): read it into memory so blocks can be found.
            raw = io.BytesIO(raw.read())
            size = len(raw.getvalue())
    try:
        head = raw.read(6)
        raw.seek(0)
        compression: str | None = None
        fh: BinaryIO = raw
        if head.startswith(_GZIP):
            compression, fh = "gzip", cast(BinaryIO, _SafeStream(gzip.GzipFile(fileobj=raw),
                                                                 "gzip"))
        elif head.startswith(_BZIP2):
            compression, fh = "bzip2", cast(BinaryIO, _SafeStream(bz2.BZ2File(raw), "bzip2"))
        elif head.startswith(_XZ):
            compression, fh = "xz", cast(BinaryIO, _SafeStream(lzma.LZMAFile(raw), "xz"))
        elif head.startswith(_ZSTD):
            fh, compression = _zstd(raw), "zstd"
        if compression:
            size = None
        return Capture(fh, name=name, size=size, compression=compression, owns=owns)
    except BaseException:
        if owns:
            raw.close()
        raise


def _zstd(raw: BinaryIO) -> BinaryIO:
    try:
        from compression import zstd  # type: ignore[import-not-found]  # Python 3.14+
    except ImportError:
        raise FormatError("zstd-compressed capture: needs Python 3.14 or later") from None
    return cast(BinaryIO, _SafeStream(zstd.ZstdFile(raw), "zstd"))


def packets(source: str | os.PathLike[str] | bytes | BinaryIO) -> Iterator[Packet]:
    """Open ``source`` and yield its decoded packets, closing it afterwards."""
    with open(source) as cap:
        yield from cap.packets()


def frames(source: str | os.PathLike[str] | bytes | BinaryIO) -> Iterator[Frame]:
    """Open ``source`` and yield its raw frames, closing it afterwards."""
    with open(source) as cap:
        yield from cap.frames()
