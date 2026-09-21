"""Exceptions raised by unspool.

Everything unspool raises on purpose derives from :class:`UnspoolError`, so a
caller can wrap a whole capture in one ``except`` and be sure nothing else
leaks out. The fuzzer enforces that promise: any other exception type escaping
the library counts as a bug.
"""

from __future__ import annotations


class UnspoolError(Exception):
    """Base class for every error unspool raises deliberately."""


class FormatError(UnspoolError):
    """The file is not a capture, or its container structure is invalid.

    ``offset`` is the byte position in the (decompressed) file where the
    problem was found, when known.
    """

    def __init__(self, message: str, offset: int | None = None) -> None:
        self.offset = offset
        if offset is not None:
            message = f"{message} (at offset {offset:#x})"
        super().__init__(message)


class TruncatedError(FormatError):
    """The file ends in the middle of a block or record.

    Captures cut off mid-write are common (a killed capture process, a full
    disk). Every packet before the cut is still delivered; this is raised
    only once the reader reaches the damaged tail.
    """


class DecodeError(UnspoolError):
    """A protocol header does not fit in the bytes available.

    Protocol decoders raise this; the packet decoder catches it and records
    the message in :attr:`unspool.Packet.malformed` instead of failing the
    whole capture, the way Wireshark marks a frame "Malformed Packet".
    """
