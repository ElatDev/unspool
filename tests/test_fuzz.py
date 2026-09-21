"""Malformed input must produce errors, never crashes or hangs."""

from __future__ import annotations

import contextlib
import random
import struct

import pytest

import unspool
from unspool.layers import dns, http, tls
from unspool.layers.network import parse_ipv4, parse_ipv6
from unspool.layers.transport import parse_tcp, parse_udp

from . import fuzzing


def test_mutated_captures_only_raise_unspool_errors() -> None:
    result = fuzzing.run(3000, seed=1)
    assert not result.crashes, f"{len(result.crashes)} crashes, first: {result.crashes[0][1]!r}"
    assert not result.slow, f"slow input: {result.slow[0][1]:.1f}s"
    # The corpus should still be recognisable often enough to be a real test.
    assert result.parsed > 100 and result.rejected > 100


def test_random_bytes_into_every_decoder() -> None:
    """Protocol decoders take arbitrary bytes without raising anything odd."""
    rng = random.Random(9)
    decoders = [
        lambda b: dns.parse_dns(b),
        lambda b: dns.parse_dns(b, tcp=True),
        lambda b: tls.parse_tls(b),
        lambda b: tls.parse_handshake_messages(b),
        lambda b: http.parse_http(b),
        lambda b: http.parse_stream(b),
        parse_ipv4, parse_ipv6, parse_tcp, parse_udp,
    ]
    for _ in range(4000):
        payload = bytes(rng.randrange(256) for _ in range(rng.randint(0, 200)))
        for decoder in decoders:
            with contextlib.suppress(unspool.UnspoolError):
                decoder(payload)


def test_deeply_nested_and_absurd_lengths() -> None:
    absurd = [
        b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 0xFFFFFFFF) + b"\x4d\x3c\x2b\x1a",
        b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 12) + b"\x4d\x3c\x2b\x1a",
        b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + b"\x4d\x3c\x2b\x1a" + b"\x00" * 100,
        b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 0xFFFFFFFF, 1)
        + struct.pack("<IIII", 0, 0, 0xFFFFFFF0, 0xFFFFFFF0),
    ]
    for data in absurd:
        with pytest.raises(unspool.UnspoolError), unspool.open(data) as cap:
            list(cap.packets())


def test_a_file_of_zeros() -> None:
    with pytest.raises(unspool.UnspoolError):
        unspool.open(b"\x00" * 4096)


def test_every_single_byte_truncation_of_a_valid_capture() -> None:
    """Cut a good capture at every possible length; nothing may crash."""
    from . import synth
    data = synth.pcapng(synth.dns_exchange() + synth.http_exchange())
    for length in range(len(data)):
        try:
            with unspool.open(data[:length]) as cap:
                list(cap.packets())
        except unspool.UnspoolError:
            pass
