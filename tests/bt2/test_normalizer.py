"""Unit tests for preprocess.normalizer."""

from __future__ import annotations

import pytest

from preprocess.normalizer import (
    normalize_domain,
    normalize_event,
    normalize_headers,
    normalize_ip,
    normalize_path,
    to_iso,
)


def test_protocol_and_app_protocol_uppercase() -> None:
    normalized, _ = normalize_event(
        {"protocol": " tcp", "app_protocol": "http", "app_data": {}}
    )
    assert normalized["protocol"] == "TCP"
    assert normalized["app_protocol"] == "HTTP"


@pytest.mark.parametrize(
    "value, expected",
    [
        ("Example.COM.", "example.com"),
        ("example.com:8080", "example.com"),
        ("[::1]:8080", "::1"),
        ("  WWW.UIT.edu.vn ", "www.uit.edu.vn"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("xn--bcher-kva.de", "xn--bcher-kva.de"),
        ("", None),
        (".", None),
        (None, None),
    ],
)
def test_normalize_domain(value: str | None, expected: str | None) -> None:
    assert normalize_domain(value) == (expected, None)


def test_idna_error_keeps_value_and_reason() -> None:
    bad = "a" * 70 + "ü.com"  # label longer than 63 characters
    domain, reason = normalize_domain(bad)
    assert domain == bad
    assert reason == f"idna_error:{bad}"


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/a//b///c", "/a/b/c"),
        ("/a/./b/../c", "/a/c"),
        ("/../../etc/passwd", "/etc/passwd"),
        ("/a/b/", "/a/b/"),
        ("/a/b/..", "/a/"),
        ("/", "/"),
        ("//", "/"),
        ("/..", "/"),
        ("*", "*"),
    ],
)
def test_normalize_path(path: str, expected: str) -> None:
    assert normalize_path(path) == expected


def test_headers_lowercase_and_trimmed() -> None:
    headers = {" Content-Type ": " text/html ", "HOST": "a", "host": "b"}
    assert normalize_headers(headers) == {"content-type": "text/html", "host": "a, b"}
    assert normalize_headers("not a dict") is None


def test_ip_and_timestamp() -> None:
    assert normalize_ip(" 10.0.0.1 ") == "10.0.0.1"
    assert normalize_ip("2001:DB8::0001") == "2001:db8::1"
    assert normalize_ip("10.0.0.256") is None
    assert normalize_ip(None) is None
    assert to_iso(1759000000.5) == "2025-09-27T19:06:40.500000+00:00"
    assert to_iso(-1) is None
    assert to_iso("x") is None


def test_http_event() -> None:
    event = {
        "protocol": "TCP",
        "app_protocol": "HTTP",
        "src_ip": "192.168.1.10",
        "dst_ip": "93.184.216.34",
        "timestamp": 1759000000.0,
        "app_data": {
            "type": "request",
            "uri": "/a/%2E%2E/admin//panel?x=1",
            "host": "Example.com:80",
            "headers": {"Host": "Example.com:80", "User-Agent": "curl"},
        },
        "decoded": {"uri": "/a/../admin//panel?x=1"},
    }
    normalized, reasons = normalize_event(event)
    assert reasons == []
    assert normalized["domain"] == "example.com"
    assert normalized["uri_path"] == "/admin/panel"
    assert normalized["http_headers"] == {
        "host": "Example.com:80",
        "user-agent": "curl",
    }
    assert normalized["timestamp_iso"] == "2025-09-27T19:06:40.000000+00:00"
    assert event["app_data"]["uri"] == "/a/%2E%2E/admin//panel?x=1"  # not mutated


def test_dns_event() -> None:
    event = {
        "protocol": "UDP",
        "app_protocol": "DNS",
        "app_data": {"questions": [{"name": "WWW.UIT.EDU.VN.", "type": "A"}]},
    }
    normalized, _ = normalize_event(event)
    assert normalized["domain"] == "www.uit.edu.vn"
    assert normalized["http_headers"] is None
    assert normalized["uri_path"] is None


def test_empty_event_gives_consistent_nulls() -> None:
    normalized, reasons = normalize_event({})
    assert reasons == []
    assert normalized == {
        "protocol": None,
        "app_protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "domain": None,
        "http_headers": None,
        "uri_path": None,
        "timestamp": None,
        "timestamp_iso": None,
    }
