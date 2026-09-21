# unspool

**A pcapng parser and protocol decoder in pure Python. It reads capture files.
It never captures.**

[![CI](https://github.com/ElatDev/unspool/actions/workflows/ci.yml/badge.svg)](https://github.com/ElatDev/unspool/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![No dependencies](https://img.shields.io/badge/dependencies-none-lightgrey)](pyproject.toml)

![unspool summary of a capture file](docs/screenshot.svg)

```console
$ pip install git+https://github.com/ElatDev/unspool
$ unspool summary capture.pcapng
```

## Why it exists

I wrote a packet inspector for myself and the interesting half was never the
UI — it was the parser underneath: pcapng's block structure, and decoders for
DNS, TLS and HTTP written from the specifications. This is that parser, taken
out and made to stand on its own.

Dropping the capture half was the point. Capturing packets needs a driver and
administrator rights, and it is what ties such a tool to one operating system.
Parsing needs neither, so unspool installs anywhere Python runs, has no
dependencies, cannot touch your network, and cannot produce a file containing
anybody's traffic.

## What it does

- **pcapng, properly.** Section Header, Interface Description, Enhanced Packet,
  Simple Packet, the obsolete Packet Block, Name Resolution, Interface
  Statistics, Decryption Secrets and Custom blocks, with their options parsed
  and named per block type; both byte orders; several sections in one file;
  timestamp resolution taken from `if_tsresol` instead of assumed. The
  specification's appendix blocks (systemd journal, IRIG, ARINC-429) are
  recognised by name and skipped.
- **Classic pcap too**, including the big-endian, nanosecond and
  Kuznetsov-patched variants, plus transparent gzip, bzip2 and xz.
- **Link, network and transport layers:** Ethernet (with 802.1Q and QinQ
  stacks, 802.3/LLC/SNAP), Linux cooked capture v1 and v2, BSD and OpenBSD
  loopback, raw IP, PPP and PPPoE, ARP/RARP, IPv4 with options and fragments,
  IPv6 with extension headers and fragments, GRE and IP-in-IP tunnels, ICMP and
  ICMPv6 including the original datagram quoted inside an error, TCP with its
  options, and UDP.
- **Application decoders:** DNS (also mDNS and LLMNR, over UDP and TCP, with
  EDNS and the record types worth decoding), TLS handshakes (ClientHello,
  ServerHello, versions, cipher suites, ALPN, SNI, and JA3/JA4 fingerprints),
  and HTTP/1.x (request and status lines, headers, chunked bodies with
  extensions and trailers, gzip/deflate content decoding).
- **TCP stream reassembly**, because a modern ClientHello does not fit in one
  segment and an HTTP body never does. Out-of-order arrival, overlapping
  retransmissions, sequence wraparound, captures that start mid-connection and
  port reuse are all handled.
- **A CLI** that summarises a capture, lists packets, walks the block
  structure, and prints the DNS, TLS and HTTP it found.

## The claim you can check

Two numbers, both reproducible from this repository.

### It agrees with tshark

`tools/compare_tshark.py` downloads the public [Wireshark sample
captures](https://wiki.wireshark.org/SampleCaptures) and compares unspool
against `tshark` frame by frame: the packet count, the set of protocols in
every frame (restricted to those unspool decodes), and the JA3 and JA4
fingerprint of every TLS ClientHello.

> **562 captures — every pcap or pcapng file on the page. 1,290,282 packets.
> unspool agrees with tshark on the packet count in 558 of them, and on which
> protocols are in each frame for 886,786 of 887,640 frames — 99.90%. JA3 and
> JA4 fingerprints match on 29 of 36 ClientHellos. No input made unspool raise
> anything but an `UnspoolError`.**

Every one of the 26 files that differ is accounted for in the report, and
almost all of them are things unspool does not attempt: a tunnel it does not
unwrap (ISL, 6LoWPAN, Teredo, JXTA, netlink, L2TP), a capture whose embedded
TLS keys tshark decrypts with and unspool refuses to, or a TCP retransmission
that tshark deliberately does not hand to a subdissector. The seven
fingerprints it misses are handshakes wrapped inside JXTA and EAP-TLS.

The full report, including every disagreement and why it happens, is in
[compat/README.md](compat/README.md). Reproduce it with:

```console
$ python tools/compare_tshark.py --download
```

### It does not crash on malformed input

`tools/fuzz.py` mutates valid captures — flipped bits, truncations, corrupt
length fields, spliced noise — and checks a single promise: for any input,
unspool either parses it or raises an `UnspoolError`. Never a `struct.error`,
an `IndexError`, a `RecursionError`, or a hang.

> **1,000,000 malformed inputs, 3.4 million packets decoded out of them, zero
> unhandled exceptions and zero inputs that took longer than two seconds.**

```console
$ python tools/fuzz.py --cases 1000000 --jobs 8
1,000,000 malformed inputs in 34.8s (28,776/s, 3,405,652 packets decoded)
  parsed without error: 154,686
  refused with an UnspoolError: 845,314
  unhandled exceptions: 0
  inputs slower than 2.0s: 0
```

The run that produced those numbers found one real bug, which is the point of
fuzzing: a crafted status line of `"²00"` passed Python's `str.isdigit()` and
then made `int()` raise. It is fixed, and there is a test for it.

## Install

```console
$ pip install git+https://github.com/ElatDev/unspool
```

Python 3.10 or newer, any operating system. No dependencies, now or ever:
everything is standard library. (A PyPI release will follow; until then the
line above installs the same thing.)

## The command line

```console
$ unspool summary capture.pcapng      # protocols, talkers, DNS, TLS SNI, HTTP
$ unspool packets capture.pcapng -c 20
$ unspool packets capture.pcapng --last 5      # reads the file backwards
$ unspool blocks capture.pcapng                # the pcapng structure itself
$ unspool dns capture.pcapng
$ unspool tls capture.pcapng                   # SNI, versions, ciphers, JA3/JA4
$ unspool http capture.pcapng --bodies
```

`--json` on `summary`, `packets` and `tls` gives machine-readable output.

`unspool blocks` is the one worth seeing if you care about the format:

```console
$ unspool blocks examples/demo.pcapng -c 4
  0x00000000  SHB      168 B  little-endian, version 1.0, section length unspecified
                                shb_os: Linux 6.11 (synthetic)
                                shb_userappl: unspool tools/make_demo.py
                                comment: Synthetic demo capture: documentation addresses only, no real traffic.
  0x000000a8  IDB       64 B  interface 0: Ethernet, snaplen 262144, 1,000,000 ticks/s
                                if_name: wlan0
                                if_description: laptop wireless
                                if_tsresol: 6 (10^-6)
  0x000000e8  IDB       64 B  interface 1: Ethernet, snaplen 262144, 1,000,000 ticks/s
                                if_name: wlan0.video
                                if_description: media stream
                                if_tsresol: 6 (10^-6)
  0x00000128  NRB      100 B  3 record(s): 198.51.100.23=www.example.com, 198.51.100.77=api.example.net, 2001:db8:2::23=www.example.com
```

## The library

```python
import unspool

with unspool.open("capture.pcapng") as cap:
    for pkt in cap:
        if pkt.dns and not pkt.dns.is_response:
            print(pkt.number, pkt.dns.questions[0].name)
```

Layers are plain dataclasses, reachable by type or by name:

```python
from unspool.layers import IPv4, TCP, TLS

for pkt in unspool.packets("capture.pcapng"):
    tcp = pkt.get(TCP)
    if tcp and tcp.syn:
        print(f"{pkt.src}:{tcp.sport} → {pkt.dst}:{tcp.dport}  mss={tcp.option('MSS')}")

    hello = (pkt.get(TLS) or TLS()).client_hello
    if hello:
        print(hello.server_name, hello.ja4(), [hex(c) for c in hello.cipher_suites])
```

The container is available too, options and all:

```python
with unspool.open("capture.pcapng") as cap:
    for block in cap.blocks():
        print(hex(block.offset), block.name, block.options.get("if_name"))
```

`examples/quickstart.py` is a short tour of the whole API.

## Two details worth a look

**A pcapng file can be read backwards.** Every block ends with a second copy of
its length, so you can walk the chain from the end without reading what comes
before. `unspool packets --last 20` does exactly that: it seeks to the end and
follows the trailing lengths back, reading 12 bytes per block until it has the
packets it needs. On a multi-gigabyte capture that is the difference between
instant and a coffee break. Classic pcap has no such field — which is why the
same command on a `.pcap` file has to read the whole thing.

**DNS name compression is a trap.** A name can be replaced by a pointer to an
earlier name, and nothing in the format stops a pointer from pointing at
itself. Fourteen hostile bytes will hang a naive decoder forever. unspool caps
the number of pointers per name, refuses to visit an offset twice, enforces the
255-byte limit on a name's length, and memoizes decoded names by offset so that
a message aiming thousands of records at one long chain costs linear time
instead of quadratic. There are tests for each of those, including one that
asserts the decoder gives up in under a second.

## Speed

It is pure Python, and it reads about **30,000 packets a second** fully
decoded, or **90,000 a second** if you only want frames and timestamps
(measured on a Ryzen 7 7800X3D with CPython 3.13, on the largest captures in
the Wireshark sample set). That is fast enough for any capture you would open
in Wireshark by hand, and too slow for a pipeline chewing through terabytes —
for that you want something with a C core.

The backward reader is the one place that beats a scan outright, because it
reads twelve bytes per block and never touches a packet's payload: on a 13 MB
capture of 37,448 frames, `--last 5` takes 0.35 s against 0.64 s to read the
same file forwards, and the gap grows with the size of the packets.

## Where it stops

Deliberate omissions, not unfinished work:

- **No packet capture.** No sockets are opened; the library has no code that
  could.
- **No decryption of anything.** A pcapng file may carry TLS keys in a
  Decryption Secrets Block. unspool reports that the block exists and what kind
  of secret it holds, and never reads it. Where `tshark` decrypts such a file
  and reports the HTTP inside, unspool reports TLS and stops — which is one of
  the differences in the compatibility report.
- **No reassembly of IP fragments.** A later fragment is reported as a
  fragment, not silently stitched.
- **No GUI, and no live monitoring.** This is a library and a terminal tool.

## Development

```console
$ git clone https://github.com/ElatDev/unspool && cd unspool
$ pip install -e ".[dev]"
$ pytest                                  # the test suite
$ ruff check . && mypy                    # lint and types
$ python tools/fuzz.py --cases 100000     # malformed input
$ python tools/compare_tshark.py --download   # needs tshark on PATH
$ python tools/make_demo.py               # rebuild examples/demo.pcapng
$ python tools/render_screenshot.py       # rebuild the picture above
```

Every fixture in the test suite is generated by `tests/synth.py`, which builds
captures byte by byte. The addresses in them come from the documentation
ranges (RFC 5737, RFC 3849) and the names from RFC 2606, because a parser
project has no business shipping somebody's real traffic —
see [AUDIT.md](AUDIT.md).

## License

MIT. See [LICENSE](LICENSE).
