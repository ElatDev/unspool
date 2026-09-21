"""TLS record layer and handshake messages (RFC 5246, RFC 8446). Handshake only.

What can be read from a TLS connection without keys is the unencrypted start
of the handshake: the ClientHello (server name, offered versions, cipher
suites, extensions) and the ServerHello (the choices the server made). In TLS
1.2 the server's certificate chain is also in the clear; in TLS 1.3 it is not.
Nothing here decrypts anything, and nothing reads Decryption Secrets Blocks.

The ClientHello also yields JA3 and JA4 fingerprints, which summarise a TLS
client's configuration and are computed by Wireshark too -- which makes them a
handy cross-check that every field was parsed exactly right.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import ClassVar

from .._cursor import Cursor
from ..errors import DecodeError
from .base import Layer

CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, APPLICATION_DATA, HEARTBEAT = 20, 21, 22, 23, 24
CONTENT_TYPES = {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake",
                 23: "Application Data", 24: "Heartbeat"}

CLIENT_HELLO, SERVER_HELLO, CERTIFICATE = 1, 2, 11
HANDSHAKE_TYPES = {
    0: "Hello Request", 1: "Client Hello", 2: "Server Hello", 3: "Hello Verify Request",
    4: "New Session Ticket", 5: "End of Early Data", 6: "Hello Retry Request",
    8: "Encrypted Extensions", 11: "Certificate", 12: "Server Key Exchange",
    13: "Certificate Request", 14: "Server Hello Done", 15: "Certificate Verify",
    16: "Client Key Exchange", 20: "Finished", 22: "Certificate Status", 24: "Key Update",
}

VERSIONS = {0x0002: "SSL 2.0", 0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
            0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

EXTENSIONS = {
    0: "server_name", 1: "max_fragment_length", 5: "status_request",
    10: "supported_groups", 11: "ec_point_formats", 13: "signature_algorithms",
    14: "use_srtp", 15: "heartbeat", 16: "application_layer_protocol_negotiation",
    17: "status_request_v2", 18: "signed_certificate_timestamp", 21: "padding",
    22: "encrypt_then_mac", 23: "extended_master_secret", 27: "compress_certificate",
    28: "record_size_limit", 34: "delegated_credentials", 35: "session_ticket",
    41: "pre_shared_key", 42: "early_data", 43: "supported_versions", 44: "cookie",
    45: "psk_key_exchange_modes", 47: "certificate_authorities", 48: "oid_filters",
    49: "post_handshake_auth", 50: "signature_algorithms_cert", 51: "key_share",
    57: "quic_transport_parameters", 17513: "application_settings",
    17613: "application_settings", 65037: "encrypted_client_hello",
    65281: "renegotiation_info",
}

GROUPS = {
    23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448",
    256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096", 259: "ffdhe6144",
    260: "ffdhe8192", 4587: "SecP256r1MLKEM768", 4588: "X25519MLKEM768",
    4589: "SecP384r1MLKEM1024", 25497: "X25519Kyber768Draft00",
}

CIPHER_SUITES = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0x5600: "TLS_FALLBACK_SCSV",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

ALERT_DESCRIPTIONS = {
    0: "Close Notify", 10: "Unexpected Message", 20: "Bad Record MAC",
    40: "Handshake Failure", 42: "Bad Certificate", 43: "Unsupported Certificate",
    44: "Certificate Revoked", 45: "Certificate Expired", 46: "Certificate Unknown",
    47: "Illegal Parameter", 48: "Unknown CA", 49: "Access Denied", 50: "Decode Error",
    51: "Decrypt Error", 70: "Protocol Version", 71: "Insufficient Security",
    80: "Internal Error", 86: "Inappropriate Fallback", 90: "User Canceled",
    109: "Missing Extension", 110: "Unsupported Extension", 112: "Unrecognized Name",
    116: "Certificate Required", 120: "No Application Protocol",
}

#: The ServerHello random value that marks a HelloRetryRequest (RFC 8446 4.1.3).
HELLO_RETRY_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

MAX_RECORD_LENGTH = 16384 + 2048


def is_grease(value: int) -> bool:
    """GREASE values (RFC 8701) are 0x?A?A with both bytes equal."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def version_name(version: int) -> str:
    if version in VERSIONS:
        return VERSIONS[version]
    if version >> 8 == 0x7F:
        return f"TLS 1.3 (draft {version & 0xFF})"
    return f"0x{version:04x}"


def cipher_suite_name(suite: int) -> str:
    if is_grease(suite):
        return "GREASE"
    return CIPHER_SUITES.get(suite, f"0x{suite:04x}")


# --------------------------------------------------------------------------
# Hellos
# --------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Extension:
    type: int
    data: bytes = field(repr=False)

    @property
    def name(self) -> str:
        if is_grease(self.type):
            return "GREASE"
        return EXTENSIONS.get(self.type, f"unknown_{self.type}")


@dataclass(slots=True)
class ClientHello:
    legacy_version: int
    random: bytes = field(repr=False)
    session_id: bytes = field(repr=False)
    cipher_suites: tuple[int, ...]
    compression_methods: bytes
    extensions: tuple[Extension, ...] = ()
    server_name: str | None = None
    alpn: tuple[str, ...] = ()
    supported_versions: tuple[int, ...] = ()
    supported_groups: tuple[int, ...] = ()
    ec_point_formats: tuple[int, ...] = ()
    signature_algorithms: tuple[int, ...] = ()
    key_share_groups: tuple[int, ...] = ()

    @property
    def version(self) -> int:
        """Highest version offered: from supported_versions if present."""
        offered = [v for v in self.supported_versions if not is_grease(v)]
        return max(offered) if offered else self.legacy_version

    @property
    def extension_types(self) -> tuple[int, ...]:
        return tuple(ext.type for ext in self.extensions)

    def ja3_string(self) -> str:
        """``version,ciphers,extensions,groups,point_formats`` with GREASE removed."""
        def join(values: tuple[int, ...]) -> str:
            return "-".join(str(v) for v in values if not is_grease(v))
        return ",".join((str(self.legacy_version), join(self.cipher_suites),
                         join(self.extension_types), join(self.supported_groups),
                         join(self.ec_point_formats)))

    def ja3(self) -> str:
        """The JA3 fingerprint: MD5 of :meth:`ja3_string`."""
        return hashlib.md5(self.ja3_string().encode(), usedforsecurity=False).hexdigest()

    def ja4(self, transport: str = "t") -> str:
        """The JA4 TLS client fingerprint (FoxIO's JA4, BSD-3-Clause spec).

        ``transport`` is ``"t"`` for TCP, ``"q"`` for QUIC, ``"d"`` for DTLS.
        """
        ciphers = [c for c in self.cipher_suites if not is_grease(c)]
        exts = [e for e in self.extension_types if not is_grease(e)]
        version = _JA4_VERSIONS.get(self.version, "00")
        sni = "d" if 0 in exts else "i"
        if self.alpn and self.alpn[0]:
            first = self.alpn[0]
            if first[0].isascii() and first[0].isalnum() and first[-1].isascii() \
                    and first[-1].isalnum():
                alpn = first[0] + first[-1]
            else:
                hexed = first.encode("latin-1", "replace").hex()
                alpn = hexed[0] + hexed[-1]
        else:
            alpn = "00"
        part_a = f"{transport}{version}{sni}{min(len(ciphers), 99):02d}" \
                 f"{min(len(exts), 99):02d}{alpn}"
        part_b = _ja4_hash(",".join(f"{c:04x}" for c in sorted(ciphers))) if ciphers \
            else "000000000000"
        # Server name and ALPN are already in part a, so they are left out here.
        # With nothing left to hash, the field is zeros rather than the hash of
        # an empty string.
        listed = sorted(e for e in exts if e not in (0x0000, 0x0010))
        sigs = ",".join(f"{s:04x}" for s in self.signature_algorithms if not is_grease(s))
        if not listed:
            part_c = "000000000000"
        else:
            joined = ",".join(f"{e:04x}" for e in listed)
            part_c = _ja4_hash(f"{joined}_{sigs}" if sigs else joined)
        return f"{part_a}_{part_b}_{part_c}"


_JA4_VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
                 0x0002: "s2", 0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3"}


def _ja4_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


@dataclass(slots=True)
class ServerHello:
    legacy_version: int
    random: bytes = field(repr=False)
    session_id: bytes = field(repr=False)
    cipher_suite: int
    compression_method: int
    extensions: tuple[Extension, ...] = ()
    selected_version: int | None = None
    alpn: str | None = None
    key_share_group: int | None = None

    @property
    def version(self) -> int:
        return self.selected_version or self.legacy_version

    @property
    def is_hello_retry_request(self) -> bool:
        return self.random == HELLO_RETRY_RANDOM

    def ja3s_string(self) -> str:
        exts = "-".join(str(e.type) for e in self.extensions)
        return f"{self.legacy_version},{self.cipher_suite},{exts}"

    def ja3s(self) -> str:
        return hashlib.md5(self.ja3s_string().encode(), usedforsecurity=False).hexdigest()


@dataclass(slots=True)
class Certificate:
    """A TLS 1.2 Certificate message: the chain's DER blobs, leaf first."""

    certificates: tuple[bytes, ...] = field(repr=False)

    @property
    def lengths(self) -> tuple[int, ...]:
        return tuple(len(c) for c in self.certificates)


@dataclass(slots=True)
class HandshakeMessage:
    type: int
    length: int
    #: Parsed body for Client Hello, Server Hello and Certificate; else None.
    body: ClientHello | ServerHello | Certificate | None = None
    #: False when the message continues beyond the bytes available.
    complete: bool = True

    @property
    def type_name(self) -> str:
        return HANDSHAKE_TYPES.get(self.type, f"Handshake type {self.type}")


def parse_client_hello(body: bytes) -> ClientHello:
    cur = Cursor(body)
    hello = ClientHello(
        legacy_version=cur.u16("legacy_version"),
        random=cur.take(32, "random"),
        session_id=cur.vector(1, "session_id"),
        cipher_suites=(),
        compression_methods=b"",
    )
    suites = cur.vector(2, "cipher_suites")
    hello.cipher_suites = tuple(int.from_bytes(suites[i:i + 2], "big")
                                for i in range(0, len(suites) - 1, 2))
    hello.compression_methods = cur.vector(1, "compression_methods")
    if cur.remaining:
        hello.extensions = _extensions(cur)
    for ext in hello.extensions:
        _client_extension(hello, ext)
    return hello


def parse_server_hello(body: bytes) -> ServerHello:
    cur = Cursor(body)
    hello = ServerHello(
        legacy_version=cur.u16("legacy_version"),
        random=cur.take(32, "random"),
        session_id=cur.vector(1, "session_id"),
        cipher_suite=cur.u16("cipher_suite"),
        compression_method=cur.u8("compression_method"),
    )
    if cur.remaining:
        hello.extensions = _extensions(cur)
    for ext in hello.extensions:
        data = ext.data
        if ext.type == 43 and len(data) == 2:
            hello.selected_version = int.from_bytes(data, "big")
        elif ext.type == 16 and len(data) > 3:
            hello.alpn = data[3:3 + data[2]].decode("ascii", "replace")
        elif ext.type == 51 and len(data) >= 2:
            hello.key_share_group = int.from_bytes(data[:2], "big")
    return hello


def parse_certificate(body: bytes) -> Certificate:
    cur = Cursor(body)
    chain = cur.sub(cur.u24("certificate_list length"), "certificate_list")
    certs = []
    while chain.remaining:
        certs.append(chain.vector(3, "certificate"))
    return Certificate(tuple(certs))


def _extensions(cur: Cursor) -> tuple[Extension, ...]:
    block = cur.sub(cur.u16("extensions length"), "extensions")
    exts = []
    while block.remaining:
        ext_type = block.u16("extension type")
        exts.append(Extension(ext_type, block.vector(2, "extension data")))
    return tuple(exts)


def _u16_list(data: bytes) -> tuple[int, ...]:
    return tuple(int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data) - 1, 2))


def _client_extension(hello: ClientHello, ext: Extension) -> None:
    """Decode the ClientHello extensions worth decoding. Bad ones stay raw."""
    cur = Cursor(ext.data)
    try:
        if ext.type == 0:
            names = cur.sub(cur.u16("server_name_list"), "server_name_list")
            while names.remaining:
                kind, value = names.u8("name type"), names.vector(2, "host name")
                if kind == 0:
                    hello.server_name = value.decode("utf-8", "replace")
                    break
        elif ext.type == 16:
            protocols = cur.sub(cur.u16("ALPN list"), "ALPN list")
            found = []
            while protocols.remaining:
                found.append(protocols.vector(1, "ALPN protocol").decode("latin-1"))
            hello.alpn = tuple(found)
        elif ext.type == 43:
            hello.supported_versions = _u16_list(cur.vector(1, "supported_versions"))
        elif ext.type == 10:
            hello.supported_groups = _u16_list(cur.vector(2, "supported_groups"))
        elif ext.type == 11:
            hello.ec_point_formats = tuple(cur.vector(1, "ec_point_formats"))
        elif ext.type == 13:
            hello.signature_algorithms = _u16_list(cur.vector(2, "signature_algorithms"))
        elif ext.type == 51:
            shares = cur.sub(cur.u16("key_share list"), "key_share list")
            groups = []
            while shares.remaining:
                groups.append(shares.u16("key_share group"))
                shares.vector(2, "key_exchange")
            hello.key_share_groups = tuple(groups)
    except DecodeError:
        pass


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------

@dataclass(slots=True)
class TLSRecord:
    content_type: int
    version: int
    length: int
    fragment: bytes = field(repr=False)

    @property
    def complete(self) -> bool:
        return len(self.fragment) == self.length

    @property
    def type_name(self) -> str:
        return CONTENT_TYPES.get(self.content_type, f"content type {self.content_type}")


def looks_like_record(data: bytes) -> bool:
    """A plausible TLS record header: known content type, version 3.x, sane length."""
    return (len(data) >= 5 and 20 <= data[0] <= 24 and data[1] == 3 and data[2] <= 4
            and ((data[3] << 8) | data[4]) <= MAX_RECORD_LENGTH)


def looks_like_hello(data: bytes) -> bool:
    """A handshake record opening with a ClientHello or ServerHello."""
    return (looks_like_record(data) and data[0] == HANDSHAKE and len(data) >= 6
            and data[5] in (CLIENT_HELLO, SERVER_HELLO))


#: Record-layer versions the heuristic accepts. TLS 1.3 is excluded because it
#: is never written in a record header (it says 0x0303 for compatibility);
#: 0x0101 is TLCP, the Chinese variant.
HEURISTIC_VERSIONS = frozenset({0x0300, 0x0301, 0x0302, 0x0303, 0x0101})


def looks_like_records(data: bytes) -> bool:
    """True if a TCP payload starts with something that must be a TLS record.

    This is the test for spotting TLS on a port nobody registered it on, and
    it is deliberately Wireshark's own test (``is_sslv3_or_tls``): a handshake
    or application-data record, a record-layer version it knows, and a length
    that is neither zero nor beyond what a record may hold.
    """
    if len(data) < 5 or data[0] not in (HANDSHAKE, APPLICATION_DATA):
        return False
    if ((data[1] << 8) | data[2]) not in HEURISTIC_VERSIONS:
        return False
    return 0 < ((data[3] << 8) | data[4]) < MAX_RECORD_LENGTH


def iter_records(data: bytes) -> Iterator[TLSRecord]:
    """Yield the records in ``data``; the last one may be cut short."""
    pos = 0
    while pos + 5 <= len(data) and looks_like_record(data[pos:pos + 5]):
        length = (data[pos + 3] << 8) | data[pos + 4]
        yield TLSRecord(data[pos], (data[pos + 1] << 8) | data[pos + 2], length,
                        data[pos + 5:pos + 5 + length])
        pos += 5 + length


def parse_handshake_messages(data: bytes) -> list[HandshakeMessage]:
    """Split concatenated handshake bytes into messages, decoding the hellos.

    A message that runs past the end of ``data`` is returned with
    ``complete=False``. Anything that doesn't look like a handshake header --
    typically an encrypted Finished message after Change Cipher Spec -- stops
    the walk.
    """
    messages = []
    pos = 0
    while pos + 4 <= len(data):
        hs_type = data[pos]
        length = int.from_bytes(data[pos + 1:pos + 4], "big")
        if hs_type not in HANDSHAKE_TYPES:
            break
        body = data[pos + 4:pos + 4 + length]
        msg = HandshakeMessage(hs_type, length, complete=len(body) == length)
        if msg.complete:
            try:
                if hs_type == CLIENT_HELLO:
                    msg.body = parse_client_hello(body)
                elif hs_type == SERVER_HELLO:
                    msg.body = parse_server_hello(body)
                elif hs_type == CERTIFICATE:
                    msg.body = parse_certificate(body)
            except DecodeError:
                msg.body = None
        messages.append(msg)
        pos += 4 + length
    return messages


@dataclass(slots=True)
class TLS(Layer):
    """The TLS records found in one TCP segment.

    Without reassembly a segment may start mid-record; such a segment is
    marked ``continuation`` with no records, the same way Wireshark shows
    "Continuation Data".
    """

    name: ClassVar[str] = "tls"
    records: list[TLSRecord] = field(default_factory=list)
    handshakes: list[HandshakeMessage] = field(default_factory=list)
    alerts: list[tuple[int, int]] = field(default_factory=list)

    @property
    def continuation(self) -> bool:
        return not self.records

    @property
    def client_hello(self) -> ClientHello | None:
        for msg in self.handshakes:
            if isinstance(msg.body, ClientHello):
                return msg.body
        return None

    @property
    def server_hello(self) -> ServerHello | None:
        for msg in self.handshakes:
            if isinstance(msg.body, ServerHello):
                return msg.body
        return None

    def summary(self) -> str:
        if not self.records:
            return "Continuation Data"
        parts: list[str] = []
        listed = encrypted = False
        for record in self.records:
            if record.content_type == HANDSHAKE and not encrypted and self.handshakes:
                if not listed:
                    parts.extend(_describe(msg) for msg in self.handshakes)
                    listed = True
            elif record.content_type == HANDSHAKE:
                parts.append("Encrypted Handshake Message")
            elif record.content_type == ALERT and len(record.fragment) == 2 and not encrypted:
                level = "Fatal" if record.fragment[0] == 2 else "Warning"
                desc = ALERT_DESCRIPTIONS.get(record.fragment[1], str(record.fragment[1]))
                parts.append(f"Alert ({level}, {desc})")
            elif record.content_type == ALERT:
                parts.append("Encrypted Alert")
            else:
                parts.append(record.type_name)
                if record.content_type in (CHANGE_CIPHER_SPEC, APPLICATION_DATA):
                    encrypted = True
        return ", ".join(dict.fromkeys(parts))


def _describe(msg: HandshakeMessage) -> str:
    body = msg.body
    if isinstance(body, ClientHello) and body.server_name:
        return f"Client Hello (SNI={body.server_name})"
    if isinstance(body, ServerHello) and body.is_hello_retry_request:
        return "Hello Retry Request"
    return msg.type_name


def parse_tls(data: bytes) -> TLS:
    """Decode the TLS records at the start of a TCP payload."""
    tls = TLS(records=list(iter_records(data)))
    plaintext = _plaintext_handshake(tls.records)
    if plaintext:
        tls.handshakes = parse_handshake_messages(plaintext)
    for record in tls.records:
        if record.content_type in (CHANGE_CIPHER_SPEC, APPLICATION_DATA):
            break
        if record.content_type == ALERT and len(record.fragment) == 2:
            tls.alerts.append((record.fragment[0], record.fragment[1]))
    return tls


def _plaintext_handshake(records: Iterable[TLSRecord]) -> bytes:
    # Past Change Cipher Spec or Application Data, handshake records are encrypted.
    parts = []
    for record in records:
        if record.content_type == HANDSHAKE:
            parts.append(record.fragment)
        elif record.content_type in (CHANGE_CIPHER_SPEC, APPLICATION_DATA):
            break
    return b"".join(parts)


def handshake_bytes(stream: bytes) -> bytes:
    """Concatenate the plaintext handshake bytes from one direction of a stream."""
    return _plaintext_handshake(iter_records(stream))
