"""Corpus and mutations for fuzzing, shared by the test suite and tools/fuzz.py.

The promise being tested is narrow and absolute: for *any* input, unspool
either parses it or raises an :class:`unspool.UnspoolError`. It must not raise
``struct.error``, ``IndexError``, ``UnicodeDecodeError``, ``MemoryError`` or
``RecursionError``, and it must not hang.
"""

from __future__ import annotations

import random
import struct
import time
from collections.abc import Iterator
from dataclasses import dataclass

import unspool

from . import synth


def corpus() -> list[bytes]:
    """Valid captures covering every block type and decoder, as fuzzing seeds."""
    dns = synth.dns_exchange()
    tls = synth.tls_exchange(split=True)
    http = synth.http_exchange()
    mixed = dns + tls + http
    extras = (synth.nrb([(1, synth.ipv4_bytes(synth.CLIENT_IP) + b"host.example.com\x00")])
              + synth.isb(opts=[(4, struct.pack("<Q", 12))]) + synth.dsb()
              + synth.block(0x00000BAD, struct.pack("<I", 32473) + b"vendor"))
    v6 = synth.Packet(synth.ethernet(
        synth.ipv6(synth.udp(synth.dns_query(), v6=True, src=synth.CLIENT_IP6,
                             dst=synth.SERVER_IP6), next_header=17), ethertype=0x86dd))
    icmp = synth.Packet(synth.ethernet(synth.ipv4(
        synth.icmp_unreachable(synth.ipv4(synth.udp(synth.dns_query()), proto=17)), proto=1)))
    arp = synth.Packet(synth.ethernet(synth.arp(), ethertype=0x0806))
    vlan = synth.Packet(synth.ethernet(synth.vlan(synth.ipv4(synth.udp(b"x"))),
                                       ethertype=0x8100))
    return [
        synth.pcapng(mixed),
        synth.pcapng(mixed, endian=">"),
        synth.pcapng([v6, icmp, arp, vlan], extra_blocks=extras),
        synth.pcapng([synth.Packet(synth.ethernet(b"x"))],
                     interfaces=[1, 101, 113], shb_options=[(1, b"comment")]),
        synth.pcap(mixed),
        synth.pcap(mixed, endian=">", nanosecond=True),
        synth.shb() + synth.idb() + synth.spb(synth.ethernet(synth.ipv4(synth.udp(b"x")))),
        synth.pcapng(dns) + synth.pcapng(tls, endian=">"),   # two sections, both byte orders
    ]


def mutate(data: bytes, rng: random.Random) -> bytes:
    """Damage a capture the way a disk, a network or an attacker would."""
    out = bytearray(data)
    choice = rng.randrange(9)
    if choice == 0:                                   # flip a few bits
        for _ in range(rng.randint(1, 8)):
            pos = rng.randrange(len(out))
            out[pos] ^= 1 << rng.randrange(8)
    elif choice == 1:                                 # cut the file short
        del out[rng.randrange(1, len(out)):]
    elif choice == 2:                                 # corrupt a 32-bit field
        pos = rng.randrange(0, max(len(out) - 4, 1)) & ~3
        out[pos:pos + 4] = struct.pack("<I", rng.choice(
            [0, 1, 7, 12, 0xFFFFFFFF, 0x7FFFFFFF, rng.randrange(1 << 32)]))
    elif choice == 3:                                 # splice in random bytes
        pos = rng.randrange(len(out))
        out[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
    elif choice == 4:                                 # zero a region
        pos = rng.randrange(len(out))
        out[pos:pos + rng.randint(1, 128)] = b"\x00" * min(rng.randint(1, 128), len(out) - pos)
    elif choice == 5:                                 # duplicate a slice
        pos = rng.randrange(len(out))
        end = min(pos + rng.randint(4, 256), len(out))
        out[pos:pos] = out[pos:end]
    elif choice == 6:                                 # random bytes, keeping the magic
        head = out[:4]
        out = bytearray(head + bytes(rng.randrange(256) for _ in range(rng.randint(8, 512))))
    elif choice == 7:                                 # truncate to a header-sized stub
        del out[rng.randint(1, 40):]
    else:                                             # pure noise
        out = bytearray(rng.randrange(256) for _ in range(rng.randint(0, 256)))
    return bytes(out)


@dataclass
class Case:
    data: bytes
    seed: int


def cases(count: int, seed: int = 0) -> Iterator[Case]:
    rng = random.Random(seed)
    seeds = corpus()
    for i in range(count):
        base = seeds[rng.randrange(len(seeds))]
        yield Case(mutate(base, rng), seed * 1_000_000 + i)


@dataclass
class Result:
    parsed: int = 0
    rejected: int = 0
    packets: int = 0
    crashes: list[tuple[Case, BaseException]] = None  # type: ignore[assignment]
    slow: list[tuple[Case, float]] = None             # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.crashes = self.crashes or []
        self.slow = self.slow or []


def run_case(case: Case, result: Result, slow_seconds: float = 2.0) -> None:
    """Parse one mutated input, recording anything that is not an UnspoolError."""
    started = time.monotonic()
    try:
        with unspool.open(case.data) as cap:
            for pkt in cap.packets():
                result.packets += 1
                # exercise the formatting paths too
                assert pkt.summary() is not None and pkt.protocols is not None
        result.parsed += 1
    except unspool.UnspoolError:
        result.rejected += 1
    except Exception as exc:
        result.crashes.append((case, exc))
    elapsed = time.monotonic() - started
    if elapsed > slow_seconds:
        result.slow.append((case, elapsed))


def run(count: int, seed: int = 0) -> Result:
    result = Result()
    for case in cases(count, seed):
        run_case(case, result)
    return result
