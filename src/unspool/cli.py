"""Command-line interface: ``unspool summary|packets|blocks|dns|tls|http FILE``."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Iterator, Sequence
from datetime import datetime, timezone
from typing import TextIO

from . import __version__, linktypes
from . import capture as capture_mod
from . import pcapng as ng
from ._term import Style, human_bytes, human_duration, pad, prepare_stdout, truncate, want_color
from .errors import UnspoolError
from .layers import http, tls
from .packet import Decoder, Packet
from .streams import Reassembler, TCPStream
from .summary import Summary, summarize

_BAR = " ▏▎▍▌▋▊▉█"


class _Out:
    """Writes the report. Columns are declared once and used for both the
    heading and its rows, so they always line up."""

    def __init__(self, stream: TextIO, style: Style) -> None:
        self.stream = stream
        self.s = style

    def line(self, text: str = "") -> None:
        print(text, file=self.stream)

    def row(self, cells: Sequence[tuple[str, int]]) -> None:
        """One row. Each cell is (text, width); a negative width right-aligns."""
        out = []
        for text, width in cells:
            out.append(pad(text, abs(width), "<" if width >= 0 else ">"))
        self.line("  " + "".join(out).rstrip())

    def heading(self, title: str, columns: Sequence[tuple[str, int]] = ()) -> None:
        self.line()
        self.row([(self.s(title.upper(), "bold", "cyan"), columns[0][1] if columns else 0)]
                 + [(self.s(text, "dim"), width) for text, width in columns[1:]])


def _bar(fraction: float, width: int) -> str:
    eighths = round(max(0.0, min(fraction, 1.0)) * width * 8)
    full, part = divmod(eighths, 8)
    text = "█" * full + (_BAR[part] if part else "")
    return text.ljust(width)


def _fmt_time(ns: int | None) -> str:
    if ns is None:
        return "?"
    try:
        stamp = datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return "?"
    return stamp.strftime("%Y-%m-%d %H:%M:%S UTC")


# --------------------------------------------------------------------------
# summary
# --------------------------------------------------------------------------

def render_summary(summary: Summary, out: _Out, top: int = 8) -> None:
    s = out.s
    out.line()
    out.line(f"  {s('unspool', 'bold', 'cyan')} {s('·', 'dim')} {s(summary.name, 'bold')}")
    kinds = sorted({linktypes.name(i.linktype) for i in summary.interfaces})
    facts = [summary.format]
    if summary.compression:
        facts.append(f"{summary.compression}-compressed")
    if summary.format == "pcapng":
        facts.append(f"{summary.sections} section{'s' if summary.sections != 1 else ''}")
    n_if = len(summary.interfaces)
    facts.append(f"{n_if} interface{'s' if n_if != 1 else ''} ({', '.join(kinds) or '?'})")
    if summary.file_size is not None:
        facts.append(human_bytes(summary.file_size))
    out.line(f"  {s(' · '.join(facts), 'dim')}")
    when = [f"{s(f'{summary.packets:,}', 'bold')} packets",
            f"{s(human_bytes(summary.wire_bytes), 'bold')} on the wire"]
    if summary.duration is not None:
        when.append(f"{s(human_duration(summary.duration), 'bold')}")
        when.append(s(f"from {_fmt_time(summary.first_ns)}", "dim"))
    out.line("  " + " · ".join(when))
    if summary.blocks:
        blocks = " · ".join(f"{n} {name}" for name, n in summary.blocks.most_common())
        out.line(s(f"  blocks: {blocks}", "dim"))

    counts = summary.protocol_counts()
    if counts:
        out.heading("Protocols", [("", 34), ("packets", -10), ("share", -8)])
        for name, n in counts:
            share = n / summary.packets if summary.packets else 0
            out.row([(name, 8), (s(_bar(share, 24), "cyan"), 26),
                     (f"{n:,}", -10), (f"{share * 100:.1f}%", -8)])

    talkers = summary.top_talkers(top)
    if talkers:
        out.heading("Top talkers", [("", 34), ("packets", -10), ("bytes", -12)])
        for ep in talkers:
            out.row([(truncate(ep.address, 33), 34), (f"{ep.packets:,}", -10),
                     (human_bytes(ep.bytes), -12)])

    if summary.dns_queries:
        out.heading("DNS queries", [("", 42), ("resolved to", 22), ("count", -6)])
        for (name, qtype), n in summary.dns_queries.most_common(top):
            answers = summary.dns_answers.get((name, qtype))
            value = s(f"→ {truncate(sorted(answers)[0], 19)}", "dim") if answers else ""
            out.row([(s(qtype, "yellow"), 6), (truncate(name, 35), 36), (value, 22),
                     (f"{n:,}", -6)])
        _more(out, len(summary.dns_queries) - top)

    if summary.tls_servers or summary.tls_without_sni:
        out.heading("TLS server names (SNI)", [("", 44), ("version", 10), ("alpn", 10),
                                               ("seen", -5)])
        ranked = sorted(summary.tls_servers.values(),
                        key=lambda t: (-t.handshakes, t.server_name))
        for entry in ranked[:top]:
            version = entry.versions.most_common(1)[0][0] if entry.versions else "?"
            alpn = entry.alpn.most_common(1)[0][0] if entry.alpn else "-"
            out.row([(s(truncate(entry.server_name, 43), "green"), 44), (version, 10),
                     (alpn, 10), (str(entry.handshakes), -5)])
        _more(out, len(ranked) - top)
        if summary.tls_without_sni:
            out.line(s(f"  + {summary.tls_without_sni} handshake(s) without SNI", "dim"))

    if summary.http_requests:
        out.heading("HTTP requests", [("", 52), ("status", 8), ("type", 16)])
        for req in summary.http_requests[:top]:
            status = str(req.status) if req.status is not None else "-"
            colour = "green" if status.startswith("2") else "yellow"
            kind = (req.content_type or "").split(";")[0]
            out.row([(s(req.method, "magenta"), 7), (truncate(req.url, 44), 45),
                     (s(status, colour), 8), (s(truncate(kind, 15), "dim"), 16)])
        _more(out, len(summary.http_requests) - top)

    notes = []
    if summary.malformed:
        notes.append(f"{summary.malformed:,} malformed")
    if summary.truncated_frames:
        notes.append(f"{summary.truncated_frames:,} cut short by snaplen")
    if summary.tcp_streams:
        notes.append(f"{summary.tcp_streams:,} TCP stream(s) reassembled")
    out.line()
    if notes:
        out.line(s(f"  {' · '.join(notes)}", "dim"))
    if summary.error:
        out.line(s(f"  warning: stopped early: {summary.error}", "yellow"))
    out.line()


def _more(out: _Out, extra: int) -> None:
    if extra > 0:
        out.line(out.s(f"  … and {extra:,} more", "dim"))


def cmd_summary(args: argparse.Namespace, out: _Out) -> int:
    summary = summarize(args.file, max_stream_bytes=args.max_stream_bytes)
    if args.json:
        out.line(json.dumps(summary.to_dict(), indent=2))
    else:
        render_summary(summary, out, top=args.top)
    return 1 if summary.error else 0


# --------------------------------------------------------------------------
# packets
# --------------------------------------------------------------------------

def _packet_json(pkt: Packet) -> dict[str, object]:
    return {
        "number": pkt.number, "timestamp_ns": pkt.frame.timestamp_ns, "length": pkt.length,
        "captured": len(pkt.frame.data), "protocols": list(pkt.protocols), "src": pkt.src,
        "dst": pkt.dst, "sport": pkt.sport, "dport": pkt.dport, "info": pkt.summary(),
        "malformed": pkt.malformed,
    }


def cmd_packets(args: argparse.Namespace, out: _Out) -> int:
    s = out.s
    with capture_mod.open(args.file) as cap:
        source: Iterator[Packet]
        if args.last:
            decoder = Decoder()
            source = (decoder.decode(frame) for frame in cap.last_frames(args.last))
        else:
            source = cap.packets()
        if not args.json:
            out.line(s(f"{'No.':>7}  {'Time':>10}  {'Source':<24} {'Destination':<24} "
                       f"{'Proto':<8}{'Length':>6}  Info", "bold"))
        shown = 0
        first: int | None = None
        try:
            for pkt in source:
                if args.proto and args.proto not in pkt.protocols:
                    continue
                if args.json:
                    out.line(json.dumps(_packet_json(pkt)))
                else:
                    ts = pkt.frame.timestamp_ns
                    if first is None and ts is not None:
                        first = ts
                    rel = f"{(ts - first) / 1e9:.6f}" if ts is not None and first is not None \
                        else "-"
                    info = pkt.summary()
                    colour = "red" if pkt.malformed else None
                    line = (f"{pkt.number:>7}  {rel:>10}  {truncate(str(pkt.src), 24):<24} "
                            f"{truncate(str(pkt.dst), 24):<24} "
                            f"{s(f'{pkt.protocol_label:<8}', 'cyan')}{pkt.length:>6}  {info}")
                    out.line(s(line, colour) if colour else line)
                shown += 1
                if args.count and shown >= args.count:
                    break
        except UnspoolError as exc:
            print(f"unspool: {exc}", file=sys.stderr)
            return 1
    return 0


# --------------------------------------------------------------------------
# blocks
# --------------------------------------------------------------------------

def _block_detail(block: ng.Block, interfaces: list[ng.InterfaceDescriptionBlock]) -> str:
    if isinstance(block, ng.SectionHeaderBlock):
        length = "unspecified" if block.section_length == -1 else f"{block.section_length:,} B"
        return f"{block.endianness}, version {block.major}.{block.minor}, section length {length}"
    if isinstance(block, ng.InterfaceDescriptionBlock):
        return (f"interface {block.interface_id}: {linktypes.name(block.linktype)}, "
                f"snaplen {block.snaplen}, {block.tsresol:,} ticks/s")
    if isinstance(block, (ng.EnhancedPacketBlock, ng.ObsoletePacketBlock)):
        text = f"interface {block.interface_id}, {block.captured_length}/{block.original_length} B"
        if block.interface_id < len(interfaces):
            idb = interfaces[block.interface_id]
            ns = block.timestamp * 1_000_000_000 // idb.tsresol + idb.tsoffset * 1_000_000_000
            text += f", {_fmt_time(ns)[:-4]}.{ns % 1_000_000_000:09d}"
        return text
    if isinstance(block, ng.SimplePacketBlock):
        return f"{len(block.data)}/{block.original_length} B, no timestamp"
    if isinstance(block, ng.NameResolutionBlock):
        shown = ", ".join(f"{r.address}={'/'.join(r.names)}" for r in block.records[:3])
        more = f" (+{len(block.records) - 3})" if len(block.records) > 3 else ""
        return f"{len(block.records)} record(s): {shown}{more}"
    if isinstance(block, ng.InterfaceStatisticsBlock):
        return f"interface {block.interface_id}"
    if isinstance(block, ng.DecryptionSecretsBlock):
        return f"{block.secrets_name}, {len(block.secrets)} B (not used by unspool)"
    if isinstance(block, ng.CustomBlock):
        return f"enterprise {block.pen}, {len(block.data)} B"
    return f"{block.length - 12} B body"


def _option_text(opt: ng.Option) -> str:
    value = opt.value
    if isinstance(value, bytes):
        value = value.hex() if len(value) <= 24 else f"{value[:24].hex()}… ({len(value)} B)"
    if opt.name == "if_tsresol" and isinstance(value, int):
        value = f"{value} (10^-{value})" if not value & 0x80 else f"{value} (2^-{value & 0x7F})"
    if opt.name == "epb_flags" and isinstance(value, int):
        direction = ("unknown", "inbound", "outbound", "?")[value & 0x3]
        value = f"0x{value:08x} ({direction})"
    return f"{opt.name}: {value}"


def cmd_blocks(args: argparse.Namespace, out: _Out) -> int:
    s = out.s
    with capture_mod.open(args.file) as cap:
        if cap.format != "pcapng":
            print(f"unspool: {args.file} is a {cap.format} file; blocks exist only in pcapng",
                  file=sys.stderr)
            return 2
        reader = cap.reader
        assert isinstance(reader, ng.PcapngReader)
        shown = 0
        try:
            if args.reverse:
                out.line(s("walking backwards via each block's trailing length", "dim"))
                for offset, block_type, length in reader.reverse_blocks():
                    out.line(f"  {s(f'{offset:#010x}', 'grey')}  "
                             f"{s(f'{ng.block_name(block_type):<4}', 'cyan')} {length:>7,} B")
                    shown += 1
                    if args.count and shown >= args.count:
                        break
                return 0
            interfaces: list[ng.InterfaceDescriptionBlock] = []
            for block in cap.blocks():
                if isinstance(block, ng.SectionHeaderBlock):
                    interfaces = []
                elif isinstance(block, ng.InterfaceDescriptionBlock):
                    interfaces.append(block)
                out.line(f"  {s(f'{block.offset:#010x}', 'grey')}  "
                         f"{s(f'{block.name:<4}', 'cyan')} {block.length:>7,} B  "
                         f"{_block_detail(block, interfaces)}")
                for opt in block.options:
                    out.line(f"  {'':<10}  {'':<4} {'':>9}    {s(_option_text(opt), 'dim')}")
                shown += 1
                if args.count and shown >= args.count:
                    break
        except UnspoolError as exc:
            print(f"unspool: {exc}", file=sys.stderr)
            return 1
    return 0


# --------------------------------------------------------------------------
# dns / tls / http
# --------------------------------------------------------------------------

def cmd_dns(args: argparse.Namespace, out: _Out) -> int:
    s = out.s
    try:
        for pkt in capture_mod.packets(args.file):
            dns = pkt.dns
            icmp = pkt.icmp
            if dns is None or (icmp is not None and icmp.is_error):
                continue
            arrow = s("→", "dim")
            out.line(f"{pkt.number:>7}  {pkt.src} {arrow} {pkt.dst}  "
                     f"{s(dns.name.upper(), 'cyan')}  {dns.summary()}")
    except UnspoolError as exc:
        print(f"unspool: {exc}", file=sys.stderr)
        return 1
    return 0


def _streams(path: str, keep: Callable[[bytes], bool]) -> tuple[list[TCPStream], str | None]:
    reassembler = Reassembler(keep=keep)
    error = None
    try:
        for pkt in capture_mod.packets(path):
            icmp = pkt.icmp
            if icmp is None:
                reassembler.add(pkt)
    except UnspoolError as exc:
        error = str(exc)
    return reassembler.streams(), error


def cmd_tls(args: argparse.Namespace, out: _Out) -> int:
    s = out.s
    streams, error = _streams(args.file, tls.looks_like_record)
    rows = []
    for stream in streams:
        try:
            messages = tls.parse_handshake_messages(tls.handshake_bytes(stream.client_bytes))
            hello = next((m.body for m in messages if isinstance(m.body, tls.ClientHello)), None)
            if hello is None:
                continue
            replies = tls.parse_handshake_messages(tls.handshake_bytes(stream.server_bytes))
            server = next((m.body for m in replies if isinstance(m.body, tls.ServerHello)
                           and not m.body.is_hello_retry_request), None)
        except UnspoolError as exc:
            print(f"unspool: stream {stream.index}: {exc}", file=sys.stderr)
            continue
        rows.append((stream, hello, server))
        if args.json:
            continue
        client = f"{stream.client[0]}:{stream.client[1]}"
        dest = f"{stream.server[0]}:{stream.server[1]}"
        out.line(f"{s(hello.server_name or '(no SNI)', 'bold', 'green')}  "
                 f"{s(f'{client} → {dest}', 'dim')}")
        offered = [tls.version_name(v) for v in hello.supported_versions if not tls.is_grease(v)]
        out.line(f"    client  {tls.version_name(hello.version)} "
                 f"({', '.join(offered) or 'legacy only'}), "
                 f"{len([c for c in hello.cipher_suites if not tls.is_grease(c)])} cipher suites, "
                 f"alpn {','.join(hello.alpn) or '-'}")
        out.line(f"    ja3     {hello.ja3()}")
        out.line(f"    ja4     {hello.ja4()}")
        if server is not None:
            out.line(f"    server  {tls.version_name(server.version)}, "
                     f"{tls.cipher_suite_name(server.cipher_suite)}"
                     f"{', alpn ' + server.alpn if server.alpn else ''}")
        else:
            out.line(s("    server  (no Server Hello captured)", "dim"))
    if args.json:
        out.line(json.dumps([
            {"client": list(st.client), "server": list(st.server), "sni": h.server_name,
             "offered_versions": [tls.version_name(v) for v in h.supported_versions
                                  if not tls.is_grease(v)],
             "cipher_suites": list(h.cipher_suites), "alpn": list(h.alpn),
             "ja3": h.ja3(), "ja3_string": h.ja3_string(), "ja4": h.ja4(),
             "negotiated_version": tls.version_name(sv.version) if sv else None,
             "cipher_suite": tls.cipher_suite_name(sv.cipher_suite) if sv else None}
            for st, h, sv in rows], indent=2))
    if error:
        print(f"unspool: stopped early: {error}", file=sys.stderr)
        return 1
    return 0


def cmd_http(args: argparse.Namespace, out: _Out) -> int:
    s = out.s
    streams, error = _streams(args.file, http.looks_like_http)
    for stream in streams:
        try:
            requests = [m for m in http.parse_stream(stream.client_bytes) if m.is_request]
            if not requests:
                continue
            responses = [m for m in http.parse_stream(stream.server_bytes, requests=requests)
                         if m.status is not None and m.status >= 200]
        except UnspoolError as exc:
            print(f"unspool: stream {stream.index}: {exc}", file=sys.stderr)
            continue
        for i, req in enumerate(requests):
            resp = responses[i] if i < len(responses) else None
            out.line(f"{s(f'{req.method:<7}', 'magenta', 'bold')}{req.url}")
            if resp is None:
                out.line(s("        (no response captured)", "dim"))
                continue
            detail = [resp.content_type or "no content type", human_bytes(len(resp.body))]
            if resp.chunked:
                detail.append(f"chunked x{resp.chunks}")
            if not resp.complete:
                detail.append("incomplete")
            colour = "green" if resp.status and resp.status < 400 else "yellow"
            out.line(f"        {s(f'{resp.status} {resp.reason}', colour)}  "
                     f"{s(', '.join(detail), 'dim')}")
            if args.bodies and resp.body:
                try:
                    body = resp.decoded_body()
                except UnspoolError:
                    body = resp.body
                text = body[:400].decode("utf-8", "replace")
                for line in text.splitlines()[:8]:
                    out.line(s(f"        │ {truncate(line, 100)}", "grey"))
    if error:
        print(f"unspool: stopped early: {error}", file=sys.stderr)
        return 1
    return 0


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unspool",
        description="Parse pcapng and pcap captures: packets, protocols, DNS, TLS, HTTP. "
                    "Read-only: unspool never captures traffic.",
    )
    parser.add_argument("--version", action="version", version=f"unspool {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                        help="colourise output (default: auto)")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser("summary", parents=[common],
                       help="protocol counts, top talkers, DNS, TLS SNI, HTTP")
    p.add_argument("file")
    p.add_argument("--top", type=int, default=8, help="rows per section (default 8)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--max-stream-bytes", type=int, default=4 * 1024 * 1024,
                   help="bytes kept per TCP stream direction for TLS/HTTP parsing")
    p.set_defaults(func=cmd_summary)

    p = sub.add_parser("packets", parents=[common], help="one line per packet, like tshark")
    p.add_argument("file")
    p.add_argument("-c", "--count", type=int, help="stop after N packets")
    p.add_argument("--last", type=int, metavar="N",
                   help="show only the last N packets (pcapng is read backwards)")
    p.add_argument("-p", "--proto", help="only packets containing this protocol, e.g. dns")
    p.add_argument("--json", action="store_true", help="one JSON object per line")
    p.set_defaults(func=cmd_packets)

    p = sub.add_parser("blocks", parents=[common],
                       help="the pcapng block structure, options included")
    p.add_argument("file")
    p.add_argument("-c", "--count", type=int, help="stop after N blocks")
    p.add_argument("--reverse", action="store_true",
                   help="walk the file from the end using trailing block lengths")
    p.set_defaults(func=cmd_blocks)

    p = sub.add_parser("dns", parents=[common], help="every DNS, mDNS and LLMNR message")
    p.add_argument("file")
    p.set_defaults(func=cmd_dns)

    p = sub.add_parser("tls", parents=[common],
                       help="TLS handshakes: SNI, versions, ciphers, JA3/JA4")
    p.add_argument("file")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_tls)

    p = sub.add_parser("http", parents=[common],
                       help="HTTP/1.x requests and responses (chunked decoded)")
    p.add_argument("file")
    p.add_argument("--bodies", action="store_true", help="print the start of each body")
    p.set_defaults(func=cmd_http)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    prepare_stdout()
    out = _Out(sys.stdout, Style(want_color(args.color, sys.stdout)))
    try:
        return int(args.func(args, out))
    except FileNotFoundError as exc:
        print(f"unspool: {exc.filename}: no such file", file=sys.stderr)
        return 2
    except UnspoolError as exc:
        print(f"unspool: {exc}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130
