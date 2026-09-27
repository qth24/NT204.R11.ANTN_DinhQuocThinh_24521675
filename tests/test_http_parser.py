"""Unit tests for the HTTP/1.x parser."""

from __future__ import annotations

import json

from parsers.app.http_parser import MAX_BODY_PREVIEW, parse_http


def test_get_request() -> None:
    payload = (
        b"GET /index.html?q=1 HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: curl/8.5.0\r\n"
        b"Accept: */*\r\n\r\n"
    )
    result = parse_http(payload)
    data = result.data

    assert result.error is None
    assert data["type"] == "request"
    assert data["method"] == "GET"
    assert data["uri"] == "/index.html?q=1"
    assert data["version"] == "HTTP/1.1"
    assert data["host"] == "example.com"
    assert data["user_agent"] == "curl/8.5.0"
    assert data["headers"]["Accept"] == "*/*"
    assert data["headers_complete"] is True
    assert data["body"] == ""
    assert data["body_length"] == 0


def test_post_with_body() -> None:
    body = b"username=admin&password=123456"
    payload = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    data = parse_http(payload).data

    assert data["method"] == "POST"
    assert data["content_type"] == "application/x-www-form-urlencoded"
    assert data["content_length"] == len(body)
    assert data["body"] == body.decode()
    assert data["body_length"] == len(body)
    assert data["body_truncated"] is False


def test_response_status_and_headers() -> None:
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx/1.24.0\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: 14\r\n\r\n"
        b"<h1>Hello</h1>"
    )
    result = parse_http(payload)
    data = result.data

    assert result.error is None
    assert data["type"] == "response"
    assert data["version"] == "HTTP/1.1"
    assert data["status_code"] == 200
    assert data["reason"] == "OK"
    assert data["server"] == "nginx/1.24.0"
    assert data["content_type"] == "text/html; charset=utf-8"
    assert data["content_length"] == 14
    assert data["body"] == "<h1>Hello</h1>"


def test_response_without_reason() -> None:
    data = parse_http(b"HTTP/1.1 204\r\n\r\n").data
    assert data["status_code"] == 204
    assert data["reason"] == ""


def test_header_names_case_insensitive_and_repeated() -> None:
    payload = (
        b"HTTP/1.1 200 OK\r\nset-cookie: a=1\r\nSet-Cookie: b=2\r\n"
        b"SERVER: x\r\n\r\n"
    )
    data = parse_http(payload).data
    assert data["headers"]["set-cookie"] == "a=1, b=2"
    assert data["server"] == "x"


def test_body_split_across_segments() -> None:
    payload = b"POST /upload HTTP/1.1\r\nContent-Length: 1000\r\n\r\n" + b"A" * 100
    data = parse_http(payload).data
    assert data["body_length"] == 100
    assert data["body_truncated"] is True


def test_headers_split_across_segments() -> None:
    data = parse_http(b"GET / HTTP/1.1\r\nHost: exam").data
    assert data["method"] == "GET"
    assert data["headers_complete"] is False
    assert data["host"] == "exam"


def test_request_line_without_version() -> None:
    data = parse_http(b"GET /very/long/path").data
    assert data["uri"] == "/very/long/path"
    assert data["version"] is None


def test_bare_lf_line_endings() -> None:
    data = parse_http(b"GET / HTTP/1.0\nHost: a\n\nbody").data
    assert data["host"] == "a"
    assert data["body"] == "body"


def test_continuation_segment() -> None:
    result = parse_http(b'{"more": "json body"}')
    assert result.error is None
    assert result.data["type"] == "continuation"
    assert result.data["body"] == '{"more": "json body"}'


def test_malformed_header_line_is_reported_but_rest_parsed() -> None:
    payload = (
        b"GET / HTTP/1.1\r\nHost: a\r\nthis is not a header\r\nAccept: */*\r\n\r\n"
    )
    result = parse_http(payload)
    assert "Malformed header line" in result.error
    assert result.data["host"] == "a"
    assert result.data["headers"]["Accept"] == "*/*"


def test_invalid_content_length() -> None:
    result = parse_http(b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\nxyz")
    assert "Invalid Content-Length" in result.error
    assert result.data["content_length"] is None
    assert result.data["body"] == "xyz"


def test_malformed_status_line() -> None:
    result = parse_http(b"HTTP/1.1 OK\r\n\r\n")
    assert result.data["type"] == "response"
    assert "Malformed HTTP status line" in result.error


def test_binary_body_is_decoded_with_replacement() -> None:
    payload = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\xff\xfe\x00\x81"
    result = parse_http(payload)
    assert result.error is None
    assert "�" in result.data["body"]
    json.dumps(result.data)  # must stay JSON-serializable


def test_non_ascii_header_bytes_do_not_crash() -> None:
    result = parse_http(b"GET / HTTP/1.1\r\nX-Name: Th\xe1\xbb\x8bnh\r\n\r\n")
    assert result.data["headers"]["X-Name"]  # decoded as ISO-8859-1


def test_body_preview_is_limited() -> None:
    payload = b"POST / HTTP/1.1\r\n\r\n" + b"B" * (MAX_BODY_PREVIEW * 3)
    data = parse_http(payload).data
    assert len(data["body"]) == MAX_BODY_PREVIEW
    assert data["body_length"] == MAX_BODY_PREVIEW * 3


def test_empty_payload() -> None:
    result = parse_http(b"")
    assert result.data["type"] == "continuation"
    assert result.data["body_length"] == 0
