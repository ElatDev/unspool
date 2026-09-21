"""TLS handshake decoding and fingerprints.

The ClientHello test that matters most is the last one: rather than checking
our own builder's output against our own parser, it makes Python's ssl module
produce a real ClientHello and parses that.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import struct
import threading

import pytest

from unspool.layers import tls

from . import synth


def test_client_hello_fields() -> None:
    hello = tls.parse_handshake_messages(synth.client_hello())[0].body
    assert isinstance(hello, tls.ClientHello)
    assert hello.server_name == synth.SERVER_NAME
    assert hello.alpn == ("h2", "http/1.1")
    assert hello.version == 0x0304                      # from supported_versions
    assert hello.legacy_version == 0x0303
    assert 0x1301 in hello.cipher_suites
    assert hello.supported_groups == (29, 23, 24)
    assert hello.key_share_groups == (29,)
    assert 0x0403 in hello.signature_algorithms


def test_server_hello_fields() -> None:
    reply = tls.parse_handshake_messages(synth.server_hello())[0].body
    assert isinstance(reply, tls.ServerHello)
    assert reply.version == 0x0304 and reply.cipher_suite == 0x1301
    assert not reply.is_hello_retry_request
    assert tls.version_name(reply.version) == "TLS 1.3"


def test_hello_retry_request_is_recognised() -> None:
    body = (struct.pack(">H", 0x0303) + tls.HELLO_RETRY_RANDOM + b"\x00"
            + struct.pack(">HB", 0x1301, 0) + struct.pack(">H", 0))
    message = tls.parse_handshake_messages(b"\x02" + struct.pack(">I", len(body))[1:] + body)[0]
    assert isinstance(message.body, tls.ServerHello)
    assert message.body.is_hello_retry_request


def test_grease_values_are_ignored_in_fingerprints() -> None:
    with_grease = tls.parse_handshake_messages(synth.client_hello(grease=True))[0].body
    without = tls.parse_handshake_messages(synth.client_hello(grease=False))[0].body
    assert isinstance(with_grease, tls.ClientHello) and isinstance(without, tls.ClientHello)
    assert with_grease.ja3_string() == without.ja3_string()
    assert with_grease.ja4() == without.ja4()
    assert tls.is_grease(0x0A0A) and tls.is_grease(0xFAFA) and not tls.is_grease(0x1301)


def test_ja3_is_the_documented_string_hashed() -> None:
    hello = tls.parse_handshake_messages(synth.client_hello())[0].body
    assert isinstance(hello, tls.ClientHello)
    fields = hello.ja3_string().split(",")
    assert fields[0] == "771"                       # 0x0303, the legacy version
    assert fields[1].startswith("4865-4866-4867")   # cipher suites, GREASE removed
    assert fields[3] == "29-23-24"                  # supported groups
    assert hello.ja3() == hashlib.md5(hello.ja3_string().encode()).hexdigest()


def test_ja4_shape() -> None:
    hello = tls.parse_handshake_messages(synth.client_hello())[0].body
    assert isinstance(hello, tls.ClientHello)
    ja4 = hello.ja4()
    part_a, part_b, part_c = ja4.split("_")
    assert part_a.startswith("t13d")        # TCP, TLS 1.3, SNI present
    assert part_a.endswith("h2")            # first ALPN is h2
    assert len(part_b) == len(part_c) == 12
    # No SNI means "i" for IP, and no ALPN means "00".
    bare = tls.parse_handshake_messages(synth.client_hello(None, alpn=()))[0].body
    assert isinstance(bare, tls.ClientHello)
    assert bare.ja4().startswith("t13i") and bare.ja4().split("_")[0].endswith("00")


def test_records_in_one_segment() -> None:
    segment = (synth.tls_record(synth.client_hello())
               + synth.tls_record(b"\x01", content_type=20))
    layer = tls.parse_tls(segment)
    assert [r.content_type for r in layer.records] == [22, 20]
    assert layer.client_hello is not None
    assert "Client Hello" in layer.summary() and "Change Cipher Spec" in layer.summary()


def test_handshake_split_across_two_records() -> None:
    """One handshake message may be fragmented over several records."""
    hello = synth.client_hello()
    cut = len(hello) // 2
    segment = synth.tls_record(hello[:cut]) + synth.tls_record(hello[cut:])
    layer = tls.parse_tls(segment)
    assert layer.client_hello is not None
    assert layer.client_hello.server_name == synth.SERVER_NAME


def test_partial_record_is_marked_incomplete() -> None:
    segment = synth.tls_record(synth.client_hello())[:100]
    layer = tls.parse_tls(segment)
    assert layer.records and not layer.records[0].complete
    assert layer.client_hello is None


def test_encrypted_handshake_after_change_cipher_spec() -> None:
    segment = (synth.tls_record(b"\x01", content_type=20)
               + synth.tls_record(b"\x9f" * 40, content_type=22))
    layer = tls.parse_tls(segment)
    assert layer.handshakes == []
    assert layer.summary() == "Change Cipher Spec, Encrypted Handshake Message"


def test_alert_record() -> None:
    layer = tls.parse_tls(synth.tls_record(b"\x02\x28", content_type=21))
    assert layer.alerts == [(2, 40)]
    assert "Handshake Failure" in layer.summary()


def test_looks_like_records_rejects_noise() -> None:
    assert tls.looks_like_records(synth.tls_record(synth.client_hello()))
    assert not tls.looks_like_records(b"GET / HTTP/1.1\r\n\r\n")
    assert not tls.looks_like_records(b"\x16\x03\x01\x00\x00")       # empty record
    assert not tls.looks_like_records(b"\x16\x03\x01\xff\xff" + b"\x00" * 10)


def test_certificate_message() -> None:
    cert = b"\x30\x82\x01\x02" + b"\xaa" * 100
    chain = b"".join(struct.pack(">I", len(c))[1:] + c for c in (cert, cert))
    body = struct.pack(">I", len(chain))[1:] + chain
    message = tls.parse_handshake_messages(b"\x0b" + struct.pack(">I", len(body))[1:] + body)[0]
    assert isinstance(message.body, tls.Certificate)
    assert message.body.lengths == (104, 104)


def _real_client_hello(hostname: str) -> bytes:
    """Let Python's own TLS stack produce a ClientHello and keep the bytes."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    grabbed: dict[str, bytes] = {}

    def accept() -> None:
        conn, _ = server.accept()
        grabbed["bytes"] = conn.recv(16384)
        conn.close()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(server.getsockname(), timeout=5) as sock, \
                context.wrap_socket(sock, server_hostname=hostname):
            pass
    except (OSError, ssl.SSLError):
        pass  # nothing is speaking TLS back at us, which is fine
    thread.join(timeout=5)
    server.close()
    return grabbed.get("bytes", b"")


def test_parses_a_hello_from_pythons_ssl_module() -> None:
    hostname = "test.example.com"
    raw = _real_client_hello(hostname)
    if len(raw) < 100:
        pytest.skip("could not capture a local TLS ClientHello")
    layer = tls.parse_tls(raw)
    hello = layer.client_hello
    assert hello is not None
    assert hello.server_name == hostname
    assert hello.cipher_suites and hello.supported_groups
    assert hello.version in (0x0303, 0x0304)
    assert len(hello.ja3()) == 32 and hello.ja4().startswith("t1")
