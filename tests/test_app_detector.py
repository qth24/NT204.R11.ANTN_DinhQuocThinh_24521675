"""Unit tests for the application protocol detector."""

from __future__ import annotations

import struct

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR

from parsers.app_detector import AppDetection, detect_app_protocol

DNS_QUERY = bytes(DNS(id=1, rd=1, qd=DNSQR(qname="example.com")))
DNS_RESPONSE = bytes(
    DNS(
        id=1,
        qr=1,
        qd=DNSQR(qname="example.com"),
        an=DNSRR(rrname="example.com", rdata="93.184.216.34"),
    )
)


@pytest.mark.parametrize(
    "method", [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS"]
)
def test_http_methods_on_port_80(method: bytes) -> None:
    payload = method + b" /index.html HTTP/1.1\r\nHost: a\r\n\r\n"
    assert detect_app_protocol("TCP", 51000, 80, payload) == AppDetection(
        "HTTP", "payload"
    )


def test_http_on_non_standard_port_detected_by_payload() -> None:
    payload = b"GET / HTTP/1.0\r\n\r\n"
    assert detect_app_protocol("TCP", 51000, 12345, payload) == AppDetection(
        "HTTP", "payload"
    )


def test_http_response() -> None:
    payload = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    assert detect_app_protocol("TCP", 80, 51000, payload).app_protocol == "HTTP"


def test_http_request_line_split_across_segments() -> None:
    assert detect_app_protocol("TCP", 1, 9000, b"GET /very/long/path").app_protocol == (
        "HTTP"
    )


def test_http_lookalikes_are_not_http() -> None:
    for payload in (b"GETTING started", b"POST office", b"GET  / HTTP/1.1\r\n"):
        assert detect_app_protocol("TCP", 1, 9000, payload).app_protocol is None


def test_http_body_continuation_uses_port_fallback() -> None:
    body = b'{"user": "alice", "items": [1, 2, 3]}'
    assert detect_app_protocol("TCP", 51000, 8080, body) == AppDetection("HTTP", "port")


def test_smtp_strong_commands_any_port() -> None:
    for payload in (
        b"EHLO client.example.com\r\n",
        b"HELO client\r\n",
        b"MAIL FROM:<a@example.com>\r\n",
        b"rcpt to:<b@example.com>\r\n",
    ):
        assert detect_app_protocol("TCP", 51000, 2500, payload) == AppDetection(
            "SMTP", "payload"
        )


def test_smtp_replies_need_smtp_port() -> None:
    reply = b"250 OK\r\n"
    assert detect_app_protocol("TCP", 25, 51000, reply) == AppDetection(
        "SMTP", "payload"
    )
    # Same reply format is used by FTP -> not SMTP on port 21
    assert detect_app_protocol("TCP", 21, 51000, reply).app_protocol is None


def test_smtp_greeting_naming_esmtp() -> None:
    greeting = b"220 mail.example.com ESMTP Postfix\r\n"
    assert detect_app_protocol("TCP", 2525, 51000, greeting).app_protocol == "SMTP"
    assert detect_app_protocol("TCP", 10025, 51000, greeting).app_protocol == "SMTP"


def test_smtp_multiline_reply_and_data_command() -> None:
    assert detect_app_protocol("TCP", 587, 5000, b"250-SIZE 1000\r\n").app_protocol
    assert detect_app_protocol("TCP", 5000, 25, b"DATA\r\n").app_protocol == "SMTP"


def test_dns_query_and_response_on_port_53() -> None:
    assert detect_app_protocol("UDP", 5000, 53, DNS_QUERY).app_protocol == "DNS"
    assert detect_app_protocol("UDP", 53, 5000, DNS_RESPONSE).app_protocol == "DNS"


def test_dns_on_non_standard_port_detected_by_payload() -> None:
    assert detect_app_protocol("UDP", 5000, 5300, DNS_QUERY) == AppDetection(
        "DNS", "payload"
    )


def test_dns_over_tcp() -> None:
    payload = struct.pack("!H", len(DNS_QUERY)) + DNS_QUERY
    assert detect_app_protocol("TCP", 5000, 53, payload).app_protocol == "DNS"


def test_garbage_on_dns_port_is_not_dns() -> None:
    assert detect_app_protocol("UDP", 5000, 53, b"\x00\x01").app_protocol is None
    assert detect_app_protocol("UDP", 5000, 53, b"\xff" * 12).app_protocol is None


def test_random_udp_is_not_dns() -> None:
    payload = bytes(range(40))
    assert detect_app_protocol("UDP", 5000, 6000, payload).app_protocol is None


def test_empty_payload_and_unknown_protocols() -> None:
    assert detect_app_protocol("TCP", 51000, 80, b"") == AppDetection()
    assert detect_app_protocol("UNKNOWN", None, None, b"data") == AppDetection()
    ssh = b"SSH-2.0-OpenSSH_9.6\r\n"
    assert detect_app_protocol("TCP", 51000, 22, ssh) == AppDetection()


def test_binary_payload_does_not_crash() -> None:
    payload = bytes(range(256)) * 4
    for proto in ("TCP", "UDP"):
        for port in (25, 53, 80, 9999):
            detect_app_protocol(proto, 1, port, payload)


def test_malformed_dns_on_dns_port_is_still_dns() -> None:
    # Header announces 50 answers but carries none: the parser must see it
    # (and report the error) instead of it becoming an unknown payload.
    header = struct.pack("!HHHHHH", 1, 0x8180, 1, 50, 0, 0)
    payload = header + b"\x03uit\x03edu\x02vn\x00\x00\x01\x00\x01"
    assert detect_app_protocol("UDP", 53, 5000, payload).app_protocol == "DNS"
    # Same bytes on a random port: strict check rejects it
    assert detect_app_protocol("UDP", 6000, 5000, payload).app_protocol is None
