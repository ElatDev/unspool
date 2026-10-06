# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-09-20

First release. The parser was extracted from a private packet-inspection tool
and rewritten to stand alone; see [AUDIT.md](AUDIT.md) for what was, and was
not, carried across.

### Added

- **pcapng reader.** Section Header, Interface Description, Enhanced Packet,
  Simple Packet, obsolete Packet, Name Resolution, Interface Statistics,
  Decryption Secrets and Custom blocks. Options are parsed and named per block
  type. Both byte orders, several sections per file, `if_tsresol` and
  `if_tsoffset` honoured, and strict validation of block lengths, interface
  references and captured lengths.
- **Backward reading.** `PcapngReader.reverse_blocks()` and `last_frames()`
  walk a file from the end using each block's trailing length copy, reading
  a few bytes per block; `unspool packets --last N` uses it.
- **Classic pcap reader**, including big-endian, nanosecond and
  Kuznetsov-patched variants and the FCS length in the link-type field.
- **Transparent decompression** of gzip, bzip2 and xz captures (zstd on
  Python 3.14+).
- **Protocol decoders.** Ethernet, 802.1Q/QinQ, 802.2 LLC and SNAP, Linux
  cooked capture v1 and v2, BSD and OpenBSD loopback, raw IP, PPP, PPPoE,
  MPLS label stacks, ARP and RARP, IPv4 (options, fragments), IPv6 (extension
  headers, fragments), GRE and IP-in-IP, ICMP and ICMPv6 with their quoted
  datagrams, TCP (options) and UDP.
- **Application decoders.** DNS, mDNS and LLMNR over UDP and TCP, with EDNS
  and decoded RDATA; TLS handshakes with SNI, versions, cipher suites, ALPN
  and JA3/JA4 fingerprints; HTTP/1.x with chunked bodies, trailers and
  gzip/deflate content decoding.
- **TCP stream reassembly** handling out-of-order segments, overlapping
  retransmissions, sequence wraparound, mid-stream capture and port reuse.
- **Conversation state** in the decoder, so TLS or HTTP recognised by content
  on an unregistered port stays recognised for the rest of that connection.
  The content tests themselves are Wireshark's own, which is what makes the
  frame-by-frame comparison against `tshark` meaningful; a TLS handshake is
  believed on any port, so STARTTLS on SMTP, IMAP, POP3 or LDAP is picked up.
- **CLI:** `summary`, `packets`, `blocks`, `dns`, `tls` and `http`, with
  `--json` where it makes sense and colour that honours `NO_COLOR`.
- **Tooling:** `tools/compare_tshark.py` (frame-by-frame agreement with
  `tshark` over the Wireshark sample set), `tools/fuzz.py` (malformed input),
  `tools/make_demo.py` (the synthetic demo capture) and
  `tools/render_screenshot.py` (the README picture, rendered from a real run).

### Notes

- Parse-only by design: no capture, no sockets, no decryption, no reassembly
  of IP fragments. See "Limitations" in the README.
- No runtime dependencies, and none are planned.

[0.1.0]: https://github.com/ElatDev/unspool/releases/tag/v0.1.0
