"""The summary statistics and the command-line interface."""

from __future__ import annotations

import json

import pytest

from unspool.cli import main
from unspool.summary import summarize

from . import synth


def demo_capture() -> bytes:
    packets = (synth.dns_exchange() + synth.tls_exchange(start_us=100_000, split=True)
               + synth.http_exchange(start_us=300_000))
    packets.append(synth.Packet(synth.ethernet(synth.arp(), ethertype=0x0806), 400_000))
    return synth.pcapng(packets)


@pytest.fixture
def capture_file(tmp_path):
    path = tmp_path / "demo.pcapng"
    path.write_bytes(demo_capture())
    return path


def test_summary_counts(capture_file) -> None:
    summary = summarize(capture_file)
    assert summary.format == "pcapng"
    assert summary.packets == 14
    assert summary.protocols["eth"] == 14
    assert summary.protocols["dns"] == 2
    assert summary.protocols["arp"] == 1
    assert summary.duration == pytest.approx(0.4, abs=0.01)
    assert summary.tcp_streams == 2


def test_summary_finds_names_and_requests(capture_file) -> None:
    summary = summarize(capture_file)
    assert summary.dns_queries[(synth.SERVER_NAME, "A")] == 1
    assert summary.dns_answers[(synth.SERVER_NAME, "A")] == {"198.51.100.23"}
    # The ClientHello was split across two segments: only reassembly finds the SNI.
    assert synth.SERVER_NAME in summary.tls_servers
    assert summary.tls_servers[synth.SERVER_NAME].versions["TLS 1.3"] == 1
    assert summary.http_requests[0].method == "GET"
    assert summary.http_requests[0].url == "http://example.com/index.html"
    assert summary.http_requests[0].status == 200
    assert summary.http_requests[0].chunked


def test_top_talkers(capture_file) -> None:
    summary = summarize(capture_file)
    top = summary.top_talkers(3)
    assert top[0].address == synth.CLIENT_IP
    assert top[0].packets == 13     # everything except the ARP broadcast
    assert top[0].bytes > 0


def test_summary_of_a_damaged_file_still_reports(tmp_path) -> None:
    path = tmp_path / "cut.pcapng"
    path.write_bytes(demo_capture()[:-40])
    summary = summarize(path)
    assert summary.packets >= 10
    assert summary.error is not None


def test_summary_json_round_trip(capture_file) -> None:
    payload = json.dumps(summarize(capture_file).to_dict())
    loaded = json.loads(payload)
    assert loaded["packets"] == 14
    assert loaded["protocols"]["dns"] == 2
    assert loaded["tls_servers"][0]["server_name"] == synth.SERVER_NAME


def test_cli_summary(capture_file, capsys) -> None:
    assert main(["summary", str(capture_file), "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "PROTOCOLS" in out and "TOP TALKERS" in out
    assert synth.SERVER_NAME in out
    assert "14" in out


def test_cli_summary_json(capture_file, capsys) -> None:
    assert main(["summary", str(capture_file), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["packets"] == 14
    assert payload["format"] == "pcapng"


def test_cli_packets(capture_file, capsys) -> None:
    assert main(["packets", str(capture_file), "-c", "3", "--color", "never"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 4               # header plus three packets
    assert "Standard query" in lines[1]


def test_cli_packets_filter_and_json(capture_file, capsys) -> None:
    assert main(["packets", str(capture_file), "-p", "dns", "--json"]) == 0
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(rows) == 2
    assert all("dns" in row["protocols"] for row in rows)


def test_cli_packets_last(capture_file, capsys) -> None:
    assert main(["packets", str(capture_file), "--last", "2", "--color", "never"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 3
    assert lines[1].split()[0] == "-2"


def test_cli_blocks(capture_file, capsys) -> None:
    assert main(["blocks", str(capture_file), "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "SHB" in out and "IDB" in out and "EPB" in out
    assert "little-endian, version 1.0" in out
    assert "if_name: if0" in out


def test_cli_blocks_reverse(capture_file, capsys) -> None:
    assert main(["blocks", str(capture_file), "--reverse", "-c", "3", "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "backwards" in out
    assert out.count("EPB") == 3


def test_cli_dns_tls_http(capture_file, capsys) -> None:
    assert main(["dns", str(capture_file), "--color", "never"]) == 0
    assert synth.SERVER_NAME in capsys.readouterr().out
    assert main(["tls", str(capture_file), "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "ja3" in out and "ja4" in out and "TLS 1.3" in out
    assert main(["http", str(capture_file), "--bodies", "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "200 OK" in out and "unspool demo page" in out


def test_cli_missing_file(capsys) -> None:
    assert main(["summary", "no-such-file.pcapng"]) == 2
    assert "no such file" in capsys.readouterr().err


def test_cli_rejects_a_non_capture(tmp_path, capsys) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("this is not a capture")
    assert main(["summary", str(path)]) == 1
    assert "not a pcap or pcapng" in capsys.readouterr().err


def test_cli_blocks_on_a_pcap_file(tmp_path, capsys) -> None:
    path = tmp_path / "old.pcap"
    path.write_bytes(synth.pcap([synth.Packet(synth.ethernet(b"x"))]))
    assert main(["blocks", str(path)]) == 2
    assert "only in pcapng" in capsys.readouterr().err
