"""Unit tests for decoder.decode_event (Decoder stage on whole events)."""

from __future__ import annotations

import base64
import json

from config import DecoderConfig
from decoder import decode_event

CFG = DecoderConfig()


def _http_request(uri: str, **app_data) -> dict:
    return {
        "app_protocol": "HTTP",
        "app_data": {"type": "request", "method": "GET", "uri": uri, **app_data},
    }


def test_http_uri_decoded_and_raw_kept() -> None:
    event = decode_event(_http_request("/a%20b?q=%3Cx%3E"), CFG)
    assert event["app_data"]["uri"] == "/a%20b?q=%3Cx%3E"  # raw untouched
    assert event["decoded"]["uri"] == "/a b?q=<x>"
    assert event["decoded"]["query_params"] == {"q": ["<x>"]}
    assert event["decode_status"] == "ok"
    assert event["decode_errors"] == []


def test_http_form_body_from_payload() -> None:
    payload = (
        b"POST /login HTTP/1.1\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        b"user=admin%27%20OR%201%3D1--&note=%26lt%3Bb%26gt%3B"
    )
    event = _http_request(
        "/login", method="POST", content_type="application/x-www-form-urlencoded"
    )
    decoded = decode_event(event, CFG, payload)["decoded"]
    assert decoded["form_params"] == {"user": ["admin' OR 1=1--"], "note": ["<b>"]}
    assert decoded["body_text"].startswith("user=admin%27")


def test_http_response_html_entities() -> None:
    event = {
        "app_protocol": "HTTP",
        "app_data": {
            "type": "response",
            "content_type": "text/html",
            "body": "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>",
        },
    }
    decoded = decode_event(event, CFG)["decoded"]
    assert decoded["body_text"] == "<p><script>alert(1)</script></p>"
    assert decoded["uri"] is None


def test_binary_body_is_not_decoded() -> None:
    payload = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\x89PNG\xff\x00"
    event = {
        "app_protocol": "HTTP",
        "app_data": {"type": "response", "content_type": "image/png"},
    }
    event = decode_event(event, CFG, payload)
    assert event["decoded"]["body_text"] is None
    assert event["decode_status"] == "not_applicable"


def test_invalid_utf8_body_is_partial() -> None:
    payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok \xff\xfe"
    event = {
        "app_protocol": "HTTP",
        "app_data": {"type": "response", "content_type": "text/plain"},
    }
    event = decode_event(event, CFG, payload)
    assert event["decode_status"] == "partial"
    assert event["decoded"]["body_text"] == "ok ��"
    assert "invalid UTF-8" in event["decode_errors"][0]


def test_body_size_limit() -> None:
    payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + b"x" * 100
    event = {
        "app_protocol": "HTTP",
        "app_data": {"type": "response", "content_type": "text/plain"},
    }
    event = decode_event(event, DecoderConfig(max_body_bytes=10), payload)
    assert event["decoded"]["body_text"] == "x" * 10
    assert event["decode_status"] == "partial"
    assert "truncated_for_decode" in event["decode_errors"]


def test_smtp_data_base64() -> None:
    body = base64.b64encode("Xin chào".encode())
    payload = (
        b"Subject: hi\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n" + body + b"\r\n.\r\n"
    )
    event = {"app_protocol": "SMTP", "app_data": {"type": "data"}}
    event = decode_event(event, CFG, payload)
    assert event["decoded"]["body_text"] == "Xin chào"
    assert event["decoded"]["mime_parts"][0]["transfer_encoding"] == "base64"
    assert event["decode_status"] == "ok"


def test_not_applicable_protocols() -> None:
    for event in (
        {"app_protocol": "DNS", "app_data": {"type": "query"}},
        {"app_protocol": "SMTP", "app_data": {"type": "command"}},
        {"app_protocol": None, "app_data": {}},
        {},
    ):
        result = decode_event(event, CFG)
        assert result["decoded"] == {}
        assert result["decode_status"] == "not_applicable"
        assert result["decode_errors"] == []


def test_disabled_decoder() -> None:
    event = decode_event(_http_request("/a%20b"), DecoderConfig(enabled=False))
    assert event["decoded"] == {} and event["decode_status"] == "not_applicable"


def test_wrong_types_do_not_crash() -> None:
    event = {"app_protocol": "HTTP", "app_data": {"type": "request", "uri": 123}}
    result = decode_event(event, CFG)
    json.dumps(result)
    assert result["decoded"]["uri"] is None


def test_lowercase_app_protocol_is_decoded() -> None:
    event = {"app_protocol": "http", "app_data": {"type": "request", "uri": "/a%20b"}}
    assert decode_event(event, CFG)["decoded"]["uri"] == "/a b"
    smtp = {
        "app_protocol": "Smtp",
        "app_data": {"type": "data", "preview": "Subject: x\r\n\r\nhi"},
    }
    assert decode_event(smtp, CFG)["decoded"]["mime_parts"][0]["body"] == "hi"
