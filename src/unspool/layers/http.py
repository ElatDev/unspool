"""HTTP/1.x messages (RFC 9112): start line, headers, and body framing.

The body rules are the part people get wrong: a response to HEAD, a 1xx, 204
or 304 has no body whatever its headers say; ``Transfer-Encoding: chunked``
wins over ``Content-Length``; and a response with neither runs until the
server closes the connection. Chunked bodies are decoded, extensions and
trailers included.

One TCP segment rarely holds a whole message, so there are two entry points:
:func:`parse_http` looks at a single segment (what ``unspool packets``
shows), and :func:`parse_stream` walks a reassembled TCP byte stream (what
``unspool http`` and the summary use).
"""

from __future__ import annotations

import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import ClassVar

from ..errors import DecodeError
from .base import Layer, MalformedLayerError

#: The characters a method may be made of (RFC 9110's ``token``).
TOKEN_CHARACTERS = frozenset(
    "!#$%&'*+-.^_`|~0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

MAX_HEADER_BYTES = 64 * 1024
MAX_HEADERS = 256
#: Ceiling for Content-Encoding decompression, so a gzip bomb can't eat memory.
MAX_DECODED_BODY = 32 * 1024 * 1024


class Headers:
    """Header fields in wire order, with case-insensitive lookup."""

    __slots__ = ("_items",)

    def __init__(self, items: list[tuple[str, str]] | None = None) -> None:
        self._items = items or []

    def get(self, name: str, default: str | None = None) -> str | None:
        lower = name.lower()
        for key, value in self._items:
            if key.lower() == lower:
                return value
        return default

    def get_all(self, name: str) -> list[str]:
        lower = name.lower()
        return [value for key, value in self._items if key.lower() == lower]

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and self.get(name) is not None

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"Headers({self._items!r})"


@dataclass(slots=True)
class HTTPMessage:
    is_request: bool
    version: str
    method: str | None = None
    target: str | None = None
    status: int | None = None
    reason: str | None = None
    headers: Headers = field(default_factory=Headers)
    #: The body with transfer coding (chunking) removed. Content coding such
    #: as gzip is left alone; see :meth:`decoded_body`.
    body: bytes = field(default=b"", repr=False)
    #: False when the bytes ran out before the message did.
    complete: bool = True
    chunked: bool = False
    chunks: int = 0
    trailers: Headers = field(default_factory=Headers)
    #: Bytes the message occupied on the wire (start line to end of body).
    wire_length: int = 0

    @property
    def host(self) -> str | None:
        return self.headers.get("host")

    @property
    def content_type(self) -> str | None:
        return self.headers.get("content-type")

    @property
    def url(self) -> str | None:
        """Absolute URL for a request, built from the Host header when needed."""
        if not self.is_request or self.target is None:
            return None
        if "://" in self.target:
            return self.target
        host = self.host
        return f"http://{host}{self.target}" if host else self.target

    @property
    def start_line(self) -> str:
        if self.is_request:
            return f"{self.method} {self.target} {self.version}"
        return f"{self.version} {self.status} {self.reason}".rstrip()

    def decoded_body(self) -> bytes:
        """The body with gzip/deflate content coding undone (capped in size)."""
        coding = (self.headers.get("content-encoding") or "").strip().lower()
        if coding in ("gzip", "x-gzip"):
            wbits = 16 + zlib.MAX_WBITS
        elif coding == "deflate":
            wbits = zlib.MAX_WBITS
        else:
            return self.body
        try:
            inflater = zlib.decompressobj(wbits)
            out = inflater.decompress(self.body, MAX_DECODED_BODY)
        except zlib.error:
            if coding != "deflate":
                raise DecodeError(f"{coding} body does not decompress") from None
            try:  # some servers send raw deflate without the zlib wrapper
                out = zlib.decompressobj(-zlib.MAX_WBITS).decompress(self.body,
                                                                     MAX_DECODED_BODY)
            except zlib.error:
                raise DecodeError("deflate body does not decompress") from None
        return out

    def summary(self) -> str:
        if self.is_request:
            return self.start_line
        ctype = self.content_type
        return f"{self.start_line} ({ctype})" if ctype else self.start_line


class NeedMoreDataError(DecodeError):
    """The buffer ends before the message head does."""


def _is_number(text: str) -> bool:
    """Plain ASCII digits only.

    ``str.isdigit()`` is true for characters like "²" and "٣" that ``int()``
    then refuses, so trusting it turns a crafted status line into a ValueError.
    """
    return text.isascii() and text.isdigit()


def looks_like_http(data: bytes) -> bool:
    """True if ``data`` starts with an HTTP/1.x request line or status line.

    This is Wireshark's own test: the first complete line must either start
    with ``HTTP/1.`` (a status line) or end with it (a request line). The
    version token is what matters, because RTSP and SIP borrow HTTP's grammar
    and even its method names — ``OPTIONS rtsp://... RTSP/1.0`` is not HTTP.
    """
    ends = [i for i in (data.find(b"\r"), data.find(b"\n")) if i != -1]
    if not ends:
        return False
    line = data[:min(ends)].lower()
    if len(line) == 8:          # a bare "HTTP/1.1" line says nothing
        return False
    return line.startswith(b"http/1.") or line[-8:].startswith(b"http/1.")


def parse_head(data: bytes, pos: int = 0) -> tuple[HTTPMessage, int]:
    """Parse a start line and header block at ``pos``.

    Returns the message (body not yet read) and the offset of the body.
    Raises :class:`NeedMoreDataError` if the blank line ending the head isn't there.
    """
    end = data.find(b"\r\n\r\n", pos, pos + MAX_HEADER_BYTES)
    sep = 4
    lf_end = data.find(b"\n\n", pos, pos + MAX_HEADER_BYTES)
    if lf_end != -1 and (end == -1 or lf_end < end):
        end, sep = lf_end, 2  # tolerate bare-LF line endings
    if end == -1:
        if len(data) - pos >= MAX_HEADER_BYTES:
            raise DecodeError(f"HTTP header block exceeds {MAX_HEADER_BYTES} bytes")
        raise NeedMoreDataError("HTTP header block is incomplete")
    lines = data[pos:end].decode("latin-1").replace("\r\n", "\n").split("\n")
    msg = _start_line(lines[0])
    items: list[tuple[str, str]] = []
    for line in lines[1:]:
        if line[:1] in (" ", "\t") and items:  # obsolete line folding
            key, value = items[-1]
            items[-1] = (key, f"{value} {line.strip()}")
            continue
        key, colon, value = line.partition(":")
        if not colon or not key or key != key.strip():
            raise DecodeError(f"malformed HTTP header line {line[:40]!r}")
        items.append((key, value.strip()))
        if len(items) > MAX_HEADERS:
            raise DecodeError(f"more than {MAX_HEADERS} HTTP headers")
    msg.headers = Headers(items)
    return msg, end + sep


def _start_line(line: str) -> HTTPMessage:
    if line.startswith("HTTP/"):
        version, _, rest = line.partition(" ")
        code, _, reason = rest.partition(" ")
        if not (len(code) == 3 and _is_number(code)):
            raise DecodeError(f"bad HTTP status line {line[:40]!r}")
        return HTTPMessage(False, version, status=int(code), reason=reason)
    parts = line.split(" ")
    # Any token is a valid method (RFC 9110 §9), not just the registered ones.
    if len(parts) != 3 or not parts[2].startswith("HTTP/") or not parts[0] \
            or not set(parts[0]) <= TOKEN_CHARACTERS:
        raise DecodeError(f"bad HTTP request line {line[:40]!r}")
    return HTTPMessage(True, parts[2], method=parts[0], target=parts[1])


def has_body(msg: HTTPMessage, request_method: str | None = None) -> bool:
    if msg.is_request:
        return "transfer-encoding" in msg.headers or "content-length" in msg.headers
    if request_method == "HEAD" or msg.status is None:
        return False
    if request_method == "CONNECT" and 200 <= msg.status < 300:
        return False  # what follows a successful CONNECT is the tunnel, not a body
    return not (100 <= msg.status < 200 or msg.status in (204, 304))


def read_body(msg: HTTPMessage, data: bytes, pos: int, *, request_method: str | None = None,
              at_eof: bool = True) -> int:
    """Fill ``msg.body`` from ``data[pos:]``; return the offset after the body.

    ``at_eof`` says whether ``data`` is everything there will ever be, which
    decides whether a close-delimited response is complete.
    """
    if not has_body(msg, request_method):
        return pos
    # Several Transfer-Encoding lines are one comma-separated list (RFC 9112 §6.1).
    coding = ", ".join(msg.headers.get_all("transfer-encoding")).lower()
    if coding:
        if coding.split(",")[-1].strip() != "chunked":
            msg.body, msg.complete = data[pos:], at_eof  # read until close
            return len(data)
        msg.chunked = True
        return _read_chunked(msg, data, pos)
    lengths = msg.headers.get_all("content-length")
    if lengths:
        values = {v.strip() for v in ",".join(lengths).split(",")}
        value = next(iter(values))
        # Length-capped as well as digit-checked: CPython refuses int() on a
        # string of more than 4300 digits, and that would escape as a ValueError.
        if len(values) != 1 or not _is_number(value) or len(value) > 19:
            raise DecodeError(f"invalid Content-Length {lengths!r}")
        length = int(value)
        msg.body = data[pos:pos + length]
        msg.complete = len(msg.body) == length
        return pos + len(msg.body)
    if msg.is_request:
        return pos
    msg.body, msg.complete = data[pos:], at_eof
    return len(data)


def _read_chunked(msg: HTTPMessage, data: bytes, pos: int) -> int:
    parts = []
    while True:
        line_end = data.find(b"\n", pos, pos + 1024)
        if line_end == -1:
            msg.complete = False
            break
        size_field = data[pos:line_end].rstrip(b"\r").split(b";", 1)[0].strip()
        if not size_field or len(size_field) > 16 or \
                any(c not in b"0123456789abcdefABCDEF" for c in size_field):
            raise DecodeError(f"bad chunk size {size_field[:20]!r}")
        size = int(size_field, 16)
        pos = line_end + 1
        if size == 0:
            trailers, pos, done = _read_trailers(data, pos)
            msg.trailers = trailers
            msg.complete = done
            break
        chunk = data[pos:pos + size]
        parts.append(chunk)
        msg.chunks += 1
        pos += len(chunk)
        if len(chunk) < size:
            msg.complete = False
            break
        if data[pos:pos + 2] == b"\r\n":
            pos += 2
        elif data[pos:pos + 1] == b"\n":
            pos += 1
        elif pos >= len(data) - 1:
            msg.complete = False
            break
        else:
            raise DecodeError("chunk data not followed by CRLF")
    msg.body = b"".join(parts)
    return pos


def _read_trailers(data: bytes, pos: int) -> tuple[Headers, int, bool]:
    items: list[tuple[str, str]] = []
    while True:
        line_end = data.find(b"\n", pos, pos + 8192)
        if line_end == -1:
            return Headers(items), len(data), False
        line = data[pos:line_end].rstrip(b"\r").decode("latin-1")
        pos = line_end + 1
        if not line:
            return Headers(items), pos, True
        key, _, value = line.partition(":")
        items.append((key.strip(), value.strip()))
        if len(items) > MAX_HEADERS:
            raise DecodeError("too many chunked trailers")


def parse_message(data: bytes, pos: int = 0, *, request_method: str | None = None,
                  at_eof: bool = True) -> tuple[HTTPMessage, int]:
    """Parse one complete-or-partial message at ``pos``; return it and where it ends."""
    msg, body_start = parse_head(data, pos)
    end = read_body(msg, data, body_start, request_method=request_method, at_eof=at_eof)
    msg.wire_length = end - pos
    return msg, end


def parse_stream(data: bytes, *, requests: list[HTTPMessage] | None = None) -> list[HTTPMessage]:
    """Parse every message in one direction of a reassembled TCP stream.

    For the client side, call with no ``requests``. For the server side, pass
    the client's parsed requests so a response to HEAD is known to have no
    body; interim 1xx responses don't use up a request.
    """
    server_side = requests is not None
    methods = [r.method for r in requests or []]
    messages: list[HTTPMessage] = []
    final_responses = 0
    pos = 0
    while pos < len(data):
        method = None
        if server_side:
            if not data.startswith(b"HTTP/1.", pos):
                break
            method = methods[final_responses] if final_responses < len(methods) else None
        try:
            msg, end = parse_message(data, pos, request_method=method)
        except NeedMoreDataError:
            break
        messages.append(msg)
        if msg.status is not None and msg.status >= 200:
            final_responses += 1
        if end <= pos or not msg.complete:
            break
        pos = end
    return messages


@dataclass(slots=True)
class HTTP(Layer):
    """HTTP in one TCP segment. ``message`` is None for continuation segments
    that carry the middle of a body."""

    name: ClassVar[str] = "http"
    message: HTTPMessage | None = None

    def summary(self) -> str:
        return self.message.summary() if self.message else "Continuation"


def parse_http(data: bytes) -> HTTP:
    """Decode the message starting at the beginning of a single segment."""
    if not looks_like_http(data):
        return HTTP()
    try:
        try:
            msg, _ = parse_message(data, at_eof=False)
        except NeedMoreDataError:
            msg = _partial_head(data)
    except DecodeError as exc:
        raise MalformedLayerError(HTTP(), str(exc)) from None
    return HTTP(msg)


def _partial_head(data: bytes) -> HTTPMessage:
    """Best effort for a head split across segments: parse the start line."""
    line_end = data.find(b"\n")
    first = data[:line_end if line_end != -1 else len(data)].rstrip(b"\r")
    msg = _start_line(first.decode("latin-1"))
    msg.complete = False
    return msg
