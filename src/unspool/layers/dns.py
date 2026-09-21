"""DNS (RFC 1035), also used for mDNS (RFC 6762) and LLMNR (RFC 4795).

The interesting part is name compression. A name is a run of length-prefixed
labels, and any suffix can be replaced by a two-byte pointer (top bits ``11``)
to an earlier occurrence. Nothing in the wire format stops a pointer from
pointing at itself, or two pointers from pointing at each other, so a decoder
that follows pointers blindly can be made to spin forever by a 14-byte packet.

This decoder caps pointer-following three ways: a hard limit on jumps per
name, a set of already-visited targets (a revisit is a loop by definition),
and the RFC's 255-byte limit on a name's total length. It also memoizes
decoded names by offset, so a message that points thousands of records at
the same long chain costs linear time rather than quadratic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from .._cursor import Cursor
from ..errors import DecodeError
from .base import Layer, MalformedLayerError, ipv4_text, ipv6_text

MAX_POINTER_JUMPS = 32
MAX_NAME_LENGTH = 255

TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT",
    17: "RP", 18: "AFSDB", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC", 33: "SRV",
    35: "NAPTR", 36: "KX", 37: "CERT", 39: "DNAME", 41: "OPT", 43: "DS", 44: "SSHFP",
    46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA",
    53: "SMIMEA", 59: "CDS", 60: "CDNSKEY", 61: "OPENPGPKEY", 64: "SVCB", 65: "HTTPS",
    99: "SPF", 108: "EUI48", 109: "EUI64", 249: "TKEY", 250: "TSIG", 251: "IXFR",
    252: "AXFR", 255: "ANY", 256: "URI", 257: "CAA",
}
CLASSES = {1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}
OPCODES = {0: "Standard query", 1: "Inverse query", 2: "Server status request",
           4: "Zone change notification", 5: "Dynamic update"}
RCODES = {0: "No error", 1: "Format error", 2: "Server failure", 3: "No such name",
          4: "Not implemented", 5: "Refused", 6: "Name exists", 7: "RRset exists",
          8: "RRset does not exist", 9: "Not authoritative", 10: "Name out of zone"}
SVC_PARAM_KEYS = {0: "mandatory", 1: "alpn", 2: "no-default-alpn", 3: "port",
                  4: "ipv4hint", 5: "ech", 6: "ipv6hint"}

# Types whose RDATA is exactly one domain name (compression allowed per RFC 3597).
_NAME_RDATA = frozenset({2, 3, 4, 5, 7, 8, 9, 12, 39})


def type_name(rtype: int) -> str:
    return TYPES.get(rtype, f"TYPE{rtype}")


# --------------------------------------------------------------------------
# Names
# --------------------------------------------------------------------------

_PLAIN = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_*")


def _label_text(raw: bytes) -> str:
    if all(b in _PLAIN for b in raw):
        return raw.decode("ascii")
    out = []
    for b in raw:
        if b in (0x2E, 0x5C):          # '.' and '\' are escaped, as dig does
            out.append("\\" + chr(b))
        elif 0x21 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(f"\\{b:03d}")
    return "".join(out)


class NameReader:
    """Decodes names out of one DNS message, memoizing by offset."""

    __slots__ = ("_cache", "msg")

    def __init__(self, msg: bytes) -> None:
        self.msg = msg
        # offset -> (dotted name, wire length incl. the root byte, offset just past it)
        self._cache: dict[int, tuple[str, int, int]] = {}

    def read(self, pos: int) -> tuple[str, int]:
        """Decode the name at ``pos``; return it and the offset just past it.

        The root name is returned as ``"<Root>"``, as Wireshark displays it.
        """
        msg = self.msg
        labels: list[str] = []
        wire = 0
        visited: set[int] = set()
        # Every offset we pass through starts a valid name (a suffix of this one),
        # so each gets cached: (offset, labels before it, wire bytes before it,
        # index of the contiguous segment it lies in).
        starts: list[tuple[int, int, int, int]] = []
        segment_ends: list[int] = []
        cursor = pos
        while True:
            if cursor >= len(msg):
                raise DecodeError(f"name at offset {pos} runs past the end of the message")
            cached = self._cache.get(cursor)
            if cached is not None:
                suffix, suffix_wire, suffix_end = cached
                if suffix != "<Root>":
                    labels.append(suffix)
                wire += suffix_wire
                segment_ends.append(suffix_end)
                break
            starts.append((cursor, len(labels), wire, len(segment_ends)))
            length = msg[cursor]
            if length == 0:
                wire += 1
                segment_ends.append(cursor + 1)
                break
            kind = length & 0xC0
            if kind == 0xC0:
                if cursor + 1 >= len(msg):
                    raise DecodeError("compression pointer cut off at the end of the message")
                target = ((length & 0x3F) << 8) | msg[cursor + 1]
                segment_ends.append(cursor + 2)
                if target in visited:
                    raise DecodeError(f"compression pointer loop at offset {target}")
                visited.add(target)
                if len(visited) > MAX_POINTER_JUMPS:
                    raise DecodeError(f"more than {MAX_POINTER_JUMPS} compression pointers")
                cursor = target
                continue
            if kind:
                raise DecodeError(f"unsupported label type 0x{kind:02x} at offset {cursor}")
            wire += length + 1
            if wire + 1 > MAX_NAME_LENGTH:
                raise DecodeError(f"name at offset {pos} is longer than {MAX_NAME_LENGTH} bytes")
            label = msg[cursor + 1:cursor + 1 + length]
            if len(label) < length:
                raise DecodeError("label runs past the end of the message")
            labels.append(_label_text(label))
            cursor += 1 + length
        if wire > MAX_NAME_LENGTH:
            raise DecodeError(f"name at offset {pos} is longer than {MAX_NAME_LENGTH} bytes")

        for offset, index, wire_before, segment in starts:
            suffix = ".".join(labels[index:]) or "<Root>"
            self._cache[offset] = (suffix, wire - wire_before, segment_ends[segment])
        return ".".join(labels) or "<Root>", segment_ends[0]

    def read_at(self, cur: Cursor) -> str:
        name, cur.pos = self.read(cur.pos)
        if cur.pos > cur.end:
            raise DecodeError("name runs past the end of its record")
        return name


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------

@dataclass(slots=True)
class Question:
    name: str
    type: int
    cls: int
    #: mDNS "QU" bit (top bit of the class field).
    unicast_response: bool = False

    @property
    def type_name(self) -> str:
        return type_name(self.type)


@dataclass(slots=True)
class SOA:
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int

    def __str__(self) -> str:
        return f"{self.mname} {self.rname} {self.serial}"


@dataclass(slots=True)
class EDNS:
    udp_size: int
    extended_rcode: int
    version: int
    dnssec_ok: bool
    options: list[tuple[int, bytes]] = field(default_factory=list)


@dataclass(slots=True)
class ResourceRecord:
    name: str
    type: int
    cls: int
    ttl: int
    #: Decoded RDATA: an address or name string, a tuple for MX/SRV/TXT,
    #: an SOA/EDNS object, or a hex string for types that aren't decoded.
    data: object
    raw: bytes = field(repr=False, default=b"")
    #: mDNS cache-flush bit (top bit of the class field).
    cache_flush: bool = False

    @property
    def type_name(self) -> str:
        return type_name(self.type)

    def value_text(self) -> str:
        d = self.data
        if isinstance(d, tuple):
            return " ".join(str(part) for part in d)
        return str(d)


@dataclass(slots=True)
class DNS(Layer):
    name: ClassVar[str] = "dns"
    id: int
    flags: int
    questions: list[Question] = field(default_factory=list)
    answers: list[ResourceRecord] = field(default_factory=list)
    authorities: list[ResourceRecord] = field(default_factory=list)
    additionals: list[ResourceRecord] = field(default_factory=list)
    #: Counts from the header, which may exceed what was actually decoded.
    counts: tuple[int, int, int, int] = (0, 0, 0, 0)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0x0F

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    @property
    def rcode_name(self) -> str:
        return RCODES.get(self.rcode, f"rcode {self.rcode}")

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)

    @property
    def recursion_desired(self) -> bool:
        return bool(self.flags & 0x0100)

    @property
    def authoritative(self) -> bool:
        return bool(self.flags & 0x0400)

    @property
    def edns(self) -> EDNS | None:
        for rr in self.additionals:
            if isinstance(rr.data, EDNS):
                return rr.data
        return None

    def summary(self) -> str:
        kind = OPCODES.get(self.opcode, f"Opcode {self.opcode}")
        parts = [f"{kind}{' response' if self.is_response else ''} 0x{self.id:04x}"]
        if self.is_response and self.rcode:
            parts.append(self.rcode_name)
        parts.extend(f"{q.type_name} {q.name}" for q in self.questions)
        parts.extend(f"{rr.type_name} {rr.value_text()}" for rr in self.answers
                     if rr.type != 41)
        return " ".join(parts)


@dataclass(slots=True)
class MDNS(DNS):
    name: ClassVar[str] = "mdns"


@dataclass(slots=True)
class LLMNR(DNS):
    name: ClassVar[str] = "llmnr"


_KINDS: dict[str, type[DNS]] = {"dns": DNS, "mdns": MDNS, "llmnr": LLMNR}


def parse_dns(data: bytes, *, protocol: str = "dns", tcp: bool = False) -> DNS:
    """Decode one DNS message. With ``tcp=True``, expect the 2-byte length prefix."""
    if tcp:
        if len(data) < 2:
            raise DecodeError("DNS-over-TCP length prefix missing")
        length = (data[0] << 8) | data[1]
        data = data[2:2 + length]
    if len(data) < 12:
        raise DecodeError(f"DNS header needs 12 bytes, have {len(data)}")
    cur = Cursor(data)
    msg_id, flags = cur.u16(), cur.u16()
    counts = (cur.u16(), cur.u16(), cur.u16(), cur.u16())
    msg = _KINDS[protocol](msg_id, flags, counts=counts)
    names = NameReader(data)
    mdns = protocol == "mdns"
    try:
        for _ in range(counts[0]):
            qname = names.read_at(cur)
            qtype, qclass = cur.u16("question type"), cur.u16("question class")
            unicast = mdns and bool(qclass & 0x8000)
            msg.questions.append(Question(qname, qtype, qclass & 0x7FFF if mdns else qclass,
                                          unicast))
        for section, count in ((msg.answers, counts[1]), (msg.authorities, counts[2]),
                               (msg.additionals, counts[3])):
            for _ in range(count):
                section.append(_read_record(cur, names, mdns))
    except DecodeError as exc:
        raise MalformedLayerError(msg, str(exc)) from None
    return msg


def _read_record(cur: Cursor, names: NameReader, mdns: bool) -> ResourceRecord:
    rname = names.read_at(cur)
    rtype, rclass = cur.u16("record type"), cur.u16("record class")
    ttl, rdlen = cur.u32("record TTL"), cur.u16("record length")
    start = cur.pos
    rdata = cur.take(rdlen, "record data")
    if rtype == 41:  # OPT: the class and TTL fields are repurposed
        value: object = _edns(rclass, ttl, rdata)
        return ResourceRecord(rname, rtype, rclass, ttl, value, rdata)
    try:
        value = _rdata(names, rtype, rdata, start)
    except DecodeError:
        value = rdata.hex()
    flush = mdns and bool(rclass & 0x8000)
    return ResourceRecord(rname, rtype, rclass & 0x7FFF if mdns else rclass, ttl, value,
                          rdata, flush)


def _rdata(names: NameReader, rtype: int, rdata: bytes, start: int) -> object:
    # Names inside RDATA may point anywhere in the message, so they are read
    # against the whole message with a cursor bounded to this record.
    cur = Cursor(names.msg, start, start + len(rdata))
    if rtype == 1:
        if len(rdata) != 4:
            raise DecodeError("A record must be 4 bytes")
        return ipv4_text(rdata)
    if rtype == 28:
        if len(rdata) != 16:
            raise DecodeError("AAAA record must be 16 bytes")
        return ipv6_text(rdata)
    if rtype in _NAME_RDATA:
        return names.read_at(cur)
    if rtype == 15:
        return (cur.u16("MX preference"), names.read_at(cur))
    if rtype == 6:
        return SOA(names.read_at(cur), names.read_at(cur), cur.u32(), cur.u32(), cur.u32(),
                   cur.u32(), cur.u32())
    if rtype == 33:
        return (cur.u16(), cur.u16(), cur.u16(), names.read_at(cur))
    if rtype in (16, 99, 13):
        strings = []
        while cur.remaining:
            strings.append(cur.vector(1, "character-string").decode("utf-8", "replace"))
        return tuple(strings)
    if rtype in (64, 65):
        return _svcb(cur, names)
    if rtype == 257:
        flags = cur.u8("CAA flags")
        tag = cur.vector(1, "CAA tag").decode("ascii", "replace")
        return (flags, tag, cur.rest().decode("utf-8", "replace"))
    return rdata.hex()


def _svcb(cur: Cursor, names: NameReader) -> tuple[object, ...]:
    priority = cur.u16("SvcPriority")
    target = names.read_at(cur)
    params: list[str] = []
    while cur.remaining:
        key, value = cur.u16("SvcParamKey"), cur.vector(2, "SvcParamValue")
        label = SVC_PARAM_KEYS.get(key, f"key{key}")
        if key == 1:
            ids, pos = [], 0
            while pos < len(value):
                n = value[pos]
                ids.append(value[pos + 1:pos + 1 + n].decode("ascii", "replace"))
                pos += 1 + n
            params.append(f"alpn={','.join(ids)}")
        elif key == 3 and len(value) == 2:
            params.append(f"port={int.from_bytes(value, 'big')}")
        elif key == 4 and len(value) % 4 == 0:
            hints = [ipv4_text(value[i:i + 4]) for i in range(0, len(value), 4)]
            params.append(f"ipv4hint={','.join(hints)}")
        elif key == 6 and len(value) % 16 == 0:
            hints = [ipv6_text(value[i:i + 16]) for i in range(0, len(value), 16)]
            params.append(f"ipv6hint={','.join(hints)}")
        else:
            params.append(f"{label}=<{len(value)} bytes>")
    return (priority, target, *params)


def _edns(rclass: int, ttl: int, rdata: bytes) -> EDNS:
    edns = EDNS(rclass, ttl >> 24, (ttl >> 16) & 0xFF, bool(ttl & 0x8000))
    cur = Cursor(rdata)
    try:
        while cur.remaining >= 4:
            code = cur.u16()
            edns.options.append((code, cur.vector(2, "EDNS option")))
    except DecodeError:
        pass  # keep the options that parsed
    return edns
