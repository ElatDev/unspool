"""A bounds-checked reader over a bytes buffer.

Every protocol decoder reads through a :class:`Cursor`, so there is exactly one
place that checks lengths. Running past the end raises :class:`DecodeError`
instead of ``IndexError``/``struct.error``, which is what lets the decoders
treat hostile input as data rather than as a crash.
"""

from __future__ import annotations

import struct

from .errors import DecodeError

_STRUCTS = {
    (endian, code): struct.Struct(endian + code)
    for endian in "<>"
    for code in "BHIQbhiq"
}


class Cursor:
    """Sequential reader over ``data[pos:end]``. Big-endian unless told otherwise."""

    __slots__ = ("_u16", "_u32", "_u64", "data", "end", "endian", "pos")

    def __init__(
        self, data: bytes, pos: int = 0, end: int | None = None, endian: str = ">"
    ) -> None:
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else min(end, len(data))
        self.endian = endian
        self._u16 = _STRUCTS[(endian, "H")]
        self._u32 = _STRUCTS[(endian, "I")]
        self._u64 = _STRUCTS[(endian, "Q")]

    @property
    def remaining(self) -> int:
        return self.end - self.pos

    def need(self, n: int, what: str = "field") -> None:
        if n < 0 or self.pos + n > self.end:
            raise DecodeError(
                f"{what} needs {n} bytes at offset {self.pos}, only {self.remaining} left"
            )

    def u8(self, what: str = "u8") -> int:
        self.need(1, what)
        value = self.data[self.pos]
        self.pos += 1
        return value

    def u16(self, what: str = "u16") -> int:
        self.need(2, what)
        (value,) = self._u16.unpack_from(self.data, self.pos)
        self.pos += 2
        return int(value)

    def u24(self, what: str = "u24") -> int:
        self.need(3, what)
        b = self.data[self.pos:self.pos + 3]
        self.pos += 3
        if self.endian == ">":
            return (b[0] << 16) | (b[1] << 8) | b[2]
        return (b[2] << 16) | (b[1] << 8) | b[0]

    def u32(self, what: str = "u32") -> int:
        self.need(4, what)
        (value,) = self._u32.unpack_from(self.data, self.pos)
        self.pos += 4
        return int(value)

    def u64(self, what: str = "u64") -> int:
        self.need(8, what)
        (value,) = self._u64.unpack_from(self.data, self.pos)
        self.pos += 8
        return int(value)

    def take(self, n: int, what: str = "bytes") -> bytes:
        self.need(n, what)
        value = self.data[self.pos:self.pos + n]
        self.pos += n
        return value

    def skip(self, n: int, what: str = "bytes") -> None:
        self.need(n, what)
        self.pos += n

    def rest(self) -> bytes:
        value = self.data[self.pos:self.end]
        self.pos = self.end
        return value

    def sub(self, n: int, what: str = "block") -> Cursor:
        """Return a cursor over the next ``n`` bytes and advance past them."""
        self.need(n, what)
        child = Cursor(self.data, self.pos, self.pos + n, self.endian)
        self.pos += n
        return child

    def vector(self, length_bytes: int, what: str = "vector") -> bytes:
        """Read a TLS-style vector: a big-endian length prefix, then that many bytes."""
        if length_bytes == 1:
            n = self.u8(what)
        elif length_bytes == 2:
            n = self.u16(what)
        else:
            n = self.u24(what)
        return self.take(n, what)
