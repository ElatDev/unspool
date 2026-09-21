"""Check unspool against tshark on Wireshark's public sample captures.

    python tools/compare_tshark.py --download          # fetch the sample set (once)
    python tools/compare_tshark.py                     # compare and write compat/

For every capture in the Wireshark wiki's SampleCaptures page that unspool can
open (pcap or pcapng, optionally compressed), this compares, frame by frame:

* the packet count;
* which protocols each frame contains, for every protocol unspool decodes
  (tshark's ``frame.protocols`` restricted to that set);
* the JA3 and JA4 fingerprints of every TLS ClientHello.

tshark runs with IP defragmentation and TCP/TLS/HTTP reassembly turned off,
because unspool's per-packet decoder looks at one frame at a time. Nothing
else about tshark's configuration is changed.

Results go to ``compat/results.json`` and a readable ``compat/README.md``.
The sample files themselves are cached in ``.cache/wireshark-samples`` and
never committed; ``compat/manifest.tsv`` records the name, size and SHA-256 of
each one so anyone can check they compared the same bytes.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import unspool  # noqa: E402
from unspool import linktypes  # noqa: E402
from unspool.layers.tls import TLS  # noqa: E402

WIKI = "https://wiki.wireshark.org/"
PAGE = WIKI + "SampleCaptures"
CACHE = ROOT / ".cache" / "wireshark-samples"
OUT = ROOT / "compat"

#: Protocols unspool decodes, by Wireshark filter name. Comparison is limited to these.
SCOPE = {
    "eth", "vlan", "llc", "sll", "null", "mpls", "ppp", "pppoes", "arp", "ip", "ipv6",
    "gre", "icmp", "icmpv6", "tcp", "udp", "dns", "mdns", "llmnr", "tls", "http",
}
#: tshark protocol names that unspool reports under another name.
ALIASES = {"ieee8021ad": "vlan"}

TSHARK_PREFS = [
    "ip.defragment:FALSE", "ipv6.defragment:FALSE", "tcp.desegment_tcp_streams:FALSE",
    "tls.desegment_ssl_records:FALSE", "tls.desegment_ssl_application_data:FALSE",
    "http.desegment_headers:FALSE", "http.desegment_body:FALSE",
]

SKIP_EXTENSIONS = (".tgz", ".zip", ".tar.gz", ".7z", ".mp4", ".xml", ".txt", ".xlsx", ".ts",
                   ".png", ".jpg", ".gif", ".pdf")

#: The kinds of difference seen so far, and what each one means. Written by hand;
#: if a file differs for a reason not listed here, it needs investigating.
DIFFERENCE_NOTES = """Every difference recorded so far falls into one of these:

1. **tshark decrypts, unspool does not.** A pcapng file may carry TLS keys in a
   Decryption Secrets Block. tshark uses them and reports the protocols inside
   the tunnel; unspool reports `tls` and stops. This is a deliberate scope
   decision, not a parsing difference.
2. **Tunnels unspool does not decode.** ZEP/802.15.4/6LoWPAN and Teredo carry
   IPv6 inside UDP; tshark unwraps them, unspool reports the outer layers only.
3. **Retransmitted segments.** tshark's `tcp.no_subdissector_on_error` defaults
   to TRUE, so it does not hand a retransmission's payload to a subdissector.
   unspool decodes it, and reports the protocol tshark leaves out.
4. **Event captures in pcapng framing.** A sysdig `.scap` file is pcapng with
   system-call event blocks and no packet blocks: tshark decodes the events,
   unspool reports zero packets.
5. **Encapsulations unspool does not decode.** Cisco ISL, JXTA, netlink,
   L2TP, PIM register tunnels, EAP-TLS and Centrino monitor headers all carry
   something unspool would otherwise recognise. Where TLS is carried inside
   one of them, tshark computes a JA3/JA4 fingerprint that unspool never sees.
6. **Content heuristics on ports unspool knows nothing about.** On a port with
   no registered protocol, unspool falls back to recognising TLS records or an
   HTTP start line by content. Wireshark has a dissector for the port instead
   (LDAP, DOF, IPP...), so it never reaches its own heuristics. Fuzzing suites
   that fire HTTP-shaped bytes at an LDAP port land here.
7. **Invalid files.** Where a file breaks the format — a packet block naming an
   interface that was never described, say — both tools stop, but not
   necessarily at the same point, so their packet counts differ."""


# --------------------------------------------------------------------------
# download
# --------------------------------------------------------------------------

def local_name(link: str) -> str:
    name = re.sub(r"^uploads/(__moin_import__/attachments/SampleCaptures/)?", "", link)
    return name.replace("/", "__")


def sample_links() -> list[str]:
    with urllib.request.urlopen(PAGE, timeout=60) as resp:
        page = resp.read().decode("utf-8", "replace")
    found = re.findall(r'href="/?(uploads/[^"]+)"', page)
    links = sorted({html.unescape(m) for m in found})
    return [link for link in links if not link.lower().endswith(SKIP_EXTENSIONS)]


def download(delay: float, shard: tuple[int, int] = (0, 1)) -> None:
    """Fetch the sample set into the cache, skipping files already there.

    ``shard`` is (index, count): running a few shards at once fetches the set
    faster while each one still waits ``delay`` between its own requests.
    """
    CACHE.mkdir(parents=True, exist_ok=True)
    links = sample_links()
    index, count = shard
    if count > 1:
        links = links[index::count]
    print(f"{len(links)} candidate files on {PAGE}")
    dead = []
    for i, link in enumerate(links, 1):
        target = CACHE / local_name(link)
        if target.exists() and target.stat().st_size:
            continue
        for attempt in range(6):
            try:
                with urllib.request.urlopen(WIKI + link, timeout=120) as resp:
                    body = resp.read()
                # Write via a temporary file so two shards can never leave a
                # half-written capture behind.
                partial = target.with_suffix(target.suffix + f".part{index}")
                partial.write_bytes(body)
                partial.replace(target)
                print(f"[{i}/{len(links)}] {target.name}")
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    dead.append(link)
                    break
                wait = float(exc.headers.get("Retry-After") or 10 * (attempt + 1))
                time.sleep(min(wait, 120))
            except OSError:
                time.sleep(5 * (attempt + 1))
        time.sleep(delay)
    if dead:
        print(f"{len(dead)} dead links on the wiki page (404), skipped")


# --------------------------------------------------------------------------
# compare one file
# --------------------------------------------------------------------------

def run_tshark(tshark: str, path: Path) -> tuple[dict[int, dict[str, str]], str]:
    cmd = [tshark, "-n", "-r", str(path), "-T", "fields", "-E", "separator=\t",
           "-E", "occurrence=f",
           "-e", "frame.number", "-e", "frame.protocols",
           "-e", "tls.handshake.ja3", "-e", "tls.handshake.ja4"]
    for pref in TSHARK_PREFS:
        cmd += ["-o", pref]
    proc = subprocess.run(cmd, capture_output=True, timeout=900)
    frames: dict[int, dict[str, str]] = {}
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split("\t")
        if not parts[0].strip().isdigit():
            continue
        parts += [""] * (4 - len(parts))
        frames[int(parts[0])] = {"protocols": parts[1], "ja3": parts[2], "ja4": parts[3]}
    return frames, proc.stderr.decode("utf-8", "replace").strip()


def tshark_protocols(field: str) -> frozenset[str]:
    names = {ALIASES.get(p, p) for p in field.split(":") if p}
    return frozenset(names & SCOPE)


def compare_file(path: Path, tshark: str) -> dict[str, object]:
    data = path.read_bytes()
    result: dict[str, object] = {
        "file": path.name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
    }
    ours: dict[int, frozenset[str]] = {}
    fingerprints: dict[int, tuple[str, str]] = {}
    decoded_frames: set[int] = set()
    link_counts: Counter[int] = Counter()
    try:
        cap = unspool.open(data)
    except unspool.UnspoolError as exc:
        result["status"] = "unsupported"
        result["reason"] = str(exc)
        return result
    result["format"] = cap.format + (f"+{cap.compression}" if cap.compression else "")
    try:
        for pkt in cap.packets():
            link_counts[pkt.frame.linktype] += 1
            ours[pkt.number] = frozenset(pkt.protocols) & SCOPE
            if pkt.frame.linktype in linktypes.DECODED:
                decoded_frames.add(pkt.number)
            for layer in pkt.layers:
                if isinstance(layer, TLS) and layer.client_hello is not None:
                    hello = layer.client_hello
                    fingerprints[pkt.number] = (hello.ja3(), hello.ja4())
                    break
    except unspool.UnspoolError as exc:
        result["our_error"] = str(exc)
    except Exception as exc:  # a bug: only UnspoolError may escape
        result["crash"] = f"{type(exc).__name__}: {exc}"
    result["linktypes"] = {linktypes.name(k): v for k, v in link_counts.items()}

    theirs, stderr = run_tshark(tshark, path)
    result["packets_unspool"] = len(ours)
    result["packets_tshark"] = len(theirs)
    if stderr:
        result["tshark_stderr"] = stderr.splitlines()[-1][:200]

    mismatches = []
    counts_ours: Counter[str] = Counter()
    counts_theirs: Counter[str] = Counter()
    compared = 0
    unreported = 0
    unreliable = 0
    # Frames are matched by number, so an unequal count means the two tools are
    # not looking at the same frames at all (a sysdig capture, say, where tshark
    # numbers system-call events alongside packets). Comparing those would be
    # comparing frame 5 with frame 500.
    aligned = len(ours) == len(theirs)
    for number in sorted(decoded_frames) if aligned else ():
        if number not in theirs:
            continue
        listed = theirs[number]["protocols"]
        if not listed:
            # tshark lists no protocols at all for a frame whose dissector asked
            # for reassembly while reassembly is off. Nothing to compare against.
            unreported += 1
            continue
        if "mpls" in listed.split(":"):
            # Under MPLS, tshark's frame.protocols leaves out the IP layer that
            # its own detail view shows, so the field is not ground truth here.
            unreliable += 1
            continue
        compared += 1
        mine = ours[number]
        other = tshark_protocols(theirs[number]["protocols"])
        counts_ours.update(mine)
        counts_theirs.update(other)
        if mine != other:
            mismatches.append({"frame": number, "unspool": sorted(mine - other),
                               "tshark_only": sorted(other - mine),
                               "tshark": theirs[number]["protocols"]})
    result["frames_compared"] = compared
    result["frames_tshark_unreported"] = unreported
    result["frames_tshark_unreliable"] = unreliable
    result["frames_aligned"] = aligned
    result["frame_mismatches"] = len(mismatches)
    result["mismatch_examples"] = mismatches[:25]
    result["protocols_unspool"] = dict(counts_ours)
    result["protocols_tshark"] = dict(counts_theirs)

    ja3 = ja4 = ja3_bad = ja4_bad = 0
    ja_examples = []
    for number, info in theirs.items():
        mine_fp = fingerprints.get(number)
        if info["ja3"]:
            ja3 += 1
            if mine_fp is None or mine_fp[0] != info["ja3"]:
                ja3_bad += 1
                ja_examples.append({"frame": number, "kind": "ja3", "tshark": info["ja3"],
                                    "unspool": mine_fp[0] if mine_fp else None})
        if info["ja4"]:
            ja4 += 1
            if mine_fp is None or mine_fp[1] != info["ja4"]:
                ja4_bad += 1
                ja_examples.append({"frame": number, "kind": "ja4", "tshark": info["ja4"],
                                    "unspool": mine_fp[1] if mine_fp else None})
    extra = [n for n in fingerprints if n in theirs and not theirs[n]["ja3"]]
    result.update(ja3_checked=ja3, ja3_mismatches=ja3_bad, ja4_checked=ja4,
                  ja4_mismatches=ja4_bad, ja_examples=ja_examples[:10],
                  client_hellos_tshark_missed=len(extra))
    count_ok = result["packets_unspool"] == result["packets_tshark"]
    result["status"] = "agree" if count_ok and not mismatches and not ja3_bad and not ja4_bad \
        and "crash" not in result else "differ"
    return result


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

def write_report(results: list[dict[str, object]], tshark_version: str) -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    with (OUT / "manifest.tsv").open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("file\tsize\tsha256\n")
        for r in sorted(results, key=lambda r: str(r["file"])):
            fh.write(f"{r['file']}\t{r['size']}\t{r['sha256']}\n")

    readable = [r for r in results if r["status"] != "unsupported"]
    unsupported = [r for r in results if r["status"] == "unsupported"]
    crashes = [r for r in readable if "crash" in r]
    count_agree = [r for r in readable if r["packets_unspool"] == r["packets_tshark"]]
    frames = sum(int(r["frames_compared"]) for r in readable)
    unreported = sum(int(r["frames_tshark_unreported"]) for r in readable)
    unreliable = sum(int(r["frames_tshark_unreliable"]) for r in readable)
    frame_bad = sum(int(r["frame_mismatches"]) for r in readable)
    packets = sum(int(r["packets_tshark"]) for r in readable)
    ja3 = sum(int(r["ja3_checked"]) for r in readable)
    ja3_bad = sum(int(r["ja3_mismatches"]) for r in readable)
    ja4 = sum(int(r["ja4_checked"]) for r in readable)
    ja4_bad = sum(int(r["ja4_mismatches"]) for r in readable)
    totals_ours: Counter[str] = Counter()
    totals_theirs: Counter[str] = Counter()
    for r in readable:
        totals_ours.update(r["protocols_unspool"])  # type: ignore[arg-type]
        totals_theirs.update(r["protocols_tshark"])  # type: ignore[arg-type]
    files_all_frames = [r for r in readable if not r["frame_mismatches"]]

    lines = [
        "# unspool vs tshark",
        "",
        "Generated by `python tools/compare_tshark.py` against "
        f"{tshark_version.rstrip('.')} on the "
        f"[Wireshark sample captures]({PAGE}). Do not edit by hand.",
        "",
        "## How to read this",
        "",
        "Every capture on that page that unspool can open is parsed twice: once",
        "by unspool and once by `tshark -T fields -e frame.protocols`. For each",
        "frame, the set of protocols found is compared, restricted to the ones",
        "unspool claims to decode (" + ", ".join(sorted(SCOPE)) + ").",
        "Frames whose link layer unspool does not decode are counted but not",
        "compared. JA3 and JA4 fingerprints are compared wherever tshark",
        "computes one.",
        "",
        "tshark is run with reassembly off — `" + "`, `".join(TSHARK_PREFS) + "` —",
        "because unspool's per-packet decoder looks at one frame at a time.",
        "Nothing else about tshark's configuration is changed. With reassembly",
        "off, tshark reports no protocols at all for a frame whose dissector",
        "asked for more data; those frames are counted separately and skipped.",
        "",
        "A file listed under *Files that differ* is not necessarily a bug: see",
        "the notes under that table.",
        "",
        "## Totals",
        "",
        "| | |",
        "|---|---|",
        f"| Sample files downloaded | {len(results)} |",
        f"| pcap / pcapng files (what unspool reads) | {len(readable)} |",
        f"| Other formats (snoop, ERF, NetMon, ...), skipped | {len(unsupported)} |",
        f"| Packets in the readable files (per tshark) | {packets:,} |",
        f"| Files where packet counts agree | {len(count_agree)} / {len(readable)} |",
        f"| Frames compared protocol-by-protocol | {frames:,} |",
        f"| Frames tshark listed no protocols for (reassembly off) | {unreported:,} |",
        f"| Frames skipped: tshark's own layer list omits IP under MPLS | {unreliable:,} |",
        f"| Frames whose protocol set matches tshark | {frames - frame_bad:,} / {frames:,} "
        f"({(frames - frame_bad) / frames * 100 if frames else 100:.3f}%) |",
        f"| Files where every frame matches | {len(files_all_frames)} / {len(readable)} |",
        f"| JA3 fingerprints matching tshark | {ja3 - ja3_bad} / {ja3} |",
        f"| JA4 fingerprints matching tshark | {ja4 - ja4_bad} / {ja4} |",
        f"| Unhandled exceptions in unspool | {len(crashes)} |",
        "",
        "## Protocol distribution (frames containing each protocol)",
        "",
        "| protocol | unspool | tshark | difference |",
        "|---|---:|---:|---:|",
    ]
    for proto in sorted(set(totals_ours) | set(totals_theirs),
                        key=lambda p: -totals_theirs.get(p, 0)):
        a, b = totals_ours.get(proto, 0), totals_theirs.get(proto, 0)
        lines.append(f"| {proto} | {a:,} | {b:,} | {a - b:+,} |")
    lines += ["", "## Files that differ", ""]
    differing = [r for r in readable if r["status"] != "agree"]
    if not differing:
        lines.append("None.")
    else:
        lines += ["| file | packets (unspool / tshark) | frames differing | example |",
                  "|---|---|---:|---|"]
        for r in sorted(differing, key=lambda r: -int(r["frame_mismatches"])):
            example = ""
            if r["mismatch_examples"]:
                ex = r["mismatch_examples"][0]  # type: ignore[index]
                example = (f"frame {ex['frame']}: unspool-only {ex['unspool']}, "
                           f"tshark-only {ex['tshark_only']}")
            elif r.get("ja_examples"):
                ex = r["ja_examples"][0]  # type: ignore[index]
                example = f"frame {ex['frame']}: {ex['kind']} differs"
            elif "crash" in r:
                example = f"crash: {r['crash']}"
            lines.append(f"| {r['file']} | {r['packets_unspool']} / {r['packets_tshark']} "
                         f"| {r['frame_mismatches']} | {example} |")
        lines += ["", "### Why files end up in that table", "", DIFFERENCE_NOTES]
    lines += ["", "## Skipped (not pcap/pcapng)", ""]
    lines += [f"- {r['file']}: {r['reason']}" for r in sorted(unsupported,
                                                             key=lambda r: str(r["file"]))]
    (OUT / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def find_tshark(explicit: str | None) -> str:
    candidates = [explicit, os.environ.get("TSHARK"), shutil.which("tshark"),
                  r"C:\Program Files\Wireshark\tshark.exe",
                  "/usr/bin/tshark", "/opt/homebrew/bin/tshark"]
    for c in candidates:
        if c and Path(c).exists():
            return c
    sys.exit("tshark not found: install Wireshark or pass --tshark PATH")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--download", action="store_true", help="fetch the sample set first")
    parser.add_argument("--delay", type=float, default=1.5, help="seconds between downloads")
    parser.add_argument("--shard", default="0/1", metavar="I/N",
                        help="download only every Nth file, offset I (run shards in parallel)")
    parser.add_argument("--tshark", help="path to tshark")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    parser.add_argument("--only", help="compare only files whose name contains this")
    parser.add_argument("--no-compare", action="store_true", help="download only")
    args = parser.parse_args()

    if args.download:
        index, _, count = args.shard.partition("/")
        download(args.delay, (int(index), int(count or 1)))
    if args.no_compare:
        return
    tshark = find_tshark(args.tshark)
    version = subprocess.run([tshark, "--version"], capture_output=True, text=True)
    tshark_version = version.stdout.splitlines()[0].strip() if version.stdout else "tshark"
    files = sorted(p for p in CACHE.iterdir() if p.is_file()) if CACHE.exists() else []
    if args.only:
        files = [p for p in files if args.only in p.name]
    if not files:
        sys.exit(f"no samples in {CACHE}; run with --download")

    results = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(compare_file, p, tshark): p for p in files}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            r = future.result()
            results.append(r)
            mark = {"agree": "ok ", "differ": "DIFF", "unsupported": "skip"}[str(r["status"])]
            print(f"[{i:>3}/{len(files)}] {mark} {r['file']}", flush=True)
    results.sort(key=lambda r: str(r["file"]))
    if not args.only:
        write_report(results, tshark_version)
        print(f"wrote {OUT / 'README.md'}")
    else:
        for r in results:
            print(json.dumps(r, indent=1))


if __name__ == "__main__":
    main()
