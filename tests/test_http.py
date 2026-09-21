"""HTTP/1.x message parsing: start lines, headers, and body framing."""

from __future__ import annotations

import gzip

import pytest

from unspool.errors import DecodeError
from unspool.layers import http

from . import synth


def parse(data: bytes, **kwargs: object) -> http.HTTPMessage:
    message, _ = http.parse_message(data, **kwargs)  # type: ignore[arg-type]
    return message


def test_request_line_and_headers() -> None:
    message = parse(synth.http_request("GET", "/index.html?q=1", host="example.com"))
    assert message.is_request and message.method == "GET"
    assert message.target == "/index.html?q=1" and message.version == "HTTP/1.1"
    assert message.host == "example.com"
    assert message.url == "http://example.com/index.html?q=1"
    assert message.headers.get("USER-agent") == "unspool-demo/0.1"   # case-insensitive


def test_response_with_content_length() -> None:
    message = parse(synth.http_response(body=b"hello world"))
    assert not message.is_request and message.status == 200 and message.reason == "OK"
    assert message.body == b"hello world" and message.complete


def test_chunked_body_is_decoded() -> None:
    body = bytes(range(256)) * 4
    message = parse(synth.http_response(body=body, chunked=True, chunk_size=100))
    assert message.chunked and message.body == body
    assert message.chunks == 11 and message.complete


def test_chunk_extensions_and_trailers() -> None:
    raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"5;name=value\r\nhello\r\n"
           b"0\r\nX-Checksum: abc123\r\n\r\n")
    message = parse(raw)
    assert message.body == b"hello"
    assert message.trailers.get("X-Checksum") == "abc123"
    assert message.complete


def test_incomplete_chunked_body() -> None:
    raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nonly-part"
    message = parse(raw)
    assert not message.complete and message.body == b"only-part"


def test_bad_chunk_size() -> None:
    raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZZZ\r\ndata\r\n"
    with pytest.raises(DecodeError, match="chunk size"):
        parse(raw)


def test_no_body_for_head_204_and_304() -> None:
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n"
    assert parse(raw, request_method="HEAD").body == b""
    assert parse(b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n").body == b""
    assert parse(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n").body == b""


def test_response_without_framing_runs_to_the_end_of_the_stream() -> None:
    raw = b"HTTP/1.0 200 OK\r\nServer: old\r\n\r\nthe rest of the connection"
    message = parse(raw)
    assert message.body == b"the rest of the connection" and message.complete
    partial = parse(raw, at_eof=False)
    assert not partial.complete


def test_conflicting_content_length_is_refused() -> None:
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 9\r\n\r\nhello"
    with pytest.raises(DecodeError, match="Content-Length"):
        parse(raw)


def test_obsolete_line_folding() -> None:
    raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Long: first\r\n  second\r\n\r\n"
    message = parse(raw)
    assert message.headers.get("x-long") == "first second"


def test_malformed_header_line() -> None:
    with pytest.raises(DecodeError, match="header line"):
        parse(b"GET / HTTP/1.1\r\nnot-a-header\r\n\r\n")


def test_incomplete_head_asks_for_more() -> None:
    with pytest.raises(http.NeedMoreDataError):
        parse(b"GET / HTTP/1.1\r\nHost: exa")


def test_gzip_content_encoding() -> None:
    body = gzip.compress(b"compressed page body")
    raw = (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: "
           + str(len(body)).encode() + b"\r\n\r\n" + body)
    message = parse(raw)
    assert message.body == body
    assert message.decoded_body() == b"compressed page body"


def test_looks_like_http_needs_the_version_token() -> None:
    assert http.looks_like_http(b"GET /x HTTP/1.1\r\n")
    assert http.looks_like_http(b"HTTP/1.1 200 OK\r\n")
    # RTSP and SIP reuse HTTP's method names and must not be mistaken for it.
    assert not http.looks_like_http(b"OPTIONS rtsp://example/ RTSP/1.0\r\n")
    assert not http.looks_like_http(b"\x16\x03\x01\x00\x40")


def test_parse_stream_pairs_requests_and_responses() -> None:
    client = (synth.http_request("GET", "/one") + synth.http_request("HEAD", "/two")
              + synth.http_request("GET", "/three"))
    server = (synth.http_response(body=b"first") +
              b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n" +   # HEAD: no body follows
              synth.http_response(status=404, reason="Not Found", body=b"nope"))
    requests = http.parse_stream(client)
    responses = http.parse_stream(server, requests=requests)
    assert [r.target for r in requests] == ["/one", "/two", "/three"]
    assert [r.status for r in responses] == [200, 200, 404]
    assert responses[1].body == b""          # the HEAD response's body is not there
    assert responses[2].body == b"nope"


def test_interim_1xx_response_does_not_consume_a_request() -> None:
    client = synth.http_request("POST", "/upload", body=b"data")
    server = (b"HTTP/1.1 100 Continue\r\n\r\n" + synth.http_response(body=b"stored"))
    requests = http.parse_stream(client)
    responses = http.parse_stream(server, requests=requests)
    assert [r.status for r in responses] == [100, 200]
    assert responses[1].body == b"stored"


def test_packet_level_continuation() -> None:
    """A segment holding the middle of a body is HTTP with no message."""
    layer = http.parse_http(b"the middle of some body bytes")
    assert layer.message is None and layer.summary() == "Continuation"
    layer = http.parse_http(synth.http_request())
    assert layer.message is not None and layer.message.method == "GET"
