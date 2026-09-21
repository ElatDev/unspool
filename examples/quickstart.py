"""A tour of the unspool API in one file.

    python examples/quickstart.py examples/demo.pcapng
"""

from __future__ import annotations

import sys
from collections import Counter

import unspool
from unspool.layers import DNS, TLS, IPv4
from unspool.layers.tls import ClientHello
from unspool.streams import Reassembler


def main(path: str) -> None:
    # 1. Iterate decoded packets.
    with unspool.open(path) as cap:
        print(f"{cap.name}: {cap.format}"
              f"{f' ({cap.compression})' if cap.compression else ''}")
        protocols: Counter[str] = Counter()
        for pkt in cap:
            protocols.update(pkt.protocols)
            if pkt.number <= 3:
                print(f"  #{pkt.number} {pkt.protocol_label:<6} "
                      f"{pkt.src} -> {pkt.dst}  {pkt.summary()}")
        print("  protocols:", dict(protocols.most_common(6)))

    # 2. Reach into a layer by type. Layers are plain dataclasses.
    for pkt in unspool.packets(path):
        ip = pkt.get(IPv4)
        if ip is not None and ip.is_fragment:
            print(f"  fragment: id={ip.identification} offset={ip.fragment_offset}")

    # 3. Application data: DNS questions and answers.
    for pkt in unspool.packets(path):
        dns = pkt.get(DNS)
        if dns is not None and dns.is_response:
            for answer in dns.answers:
                print(f"  {answer.name} {answer.type_name} -> {answer.value_text()}")

    # 4. TLS: what the client offered, without decrypting anything.
    for pkt in unspool.packets(path):
        layer = pkt.get(TLS)
        hello = layer.client_hello if layer else None
        if isinstance(hello, ClientHello):
            print(f"  SNI {hello.server_name}  alpn={','.join(hello.alpn)}  "
                  f"ja4={hello.ja4()}")

    # 5. The pcapng container itself: every block, options included.
    with unspool.open(path) as cap:
        if cap.format == "pcapng":
            for block in cap.blocks():
                if block.options:
                    values = ", ".join(f"{o.name}={o.value!r}" for o in block.options)
                    print(f"  {block.name} at {block.offset:#x}: {values}")
                if block.offset > 0x200:
                    break

    # 6. Reassemble TCP streams (what finds a ClientHello split over segments).
    reassembler = Reassembler()
    for pkt in unspool.packets(path):
        reassembler.add(pkt)
    for stream in reassembler.streams():
        if stream.client_bytes.startswith(b"GET"):
            request_line = stream.client_bytes.split(b"\r\n")[0].decode()
            print(f"  stream {stream.index}: {request_line} "
                  f"({len(stream.server_bytes)} bytes back)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "examples/demo.pcapng")
