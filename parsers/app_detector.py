"""Application protocol detector: decide whether a payload is HTTP, DNS or SMTP.

Input: transport protocol ("TCP"/"UDP"), ports and payload
(from ``parsers.transport``).
Output: ``AppDetection`` with the protocol name (or None) and how it was
recognised ("payload" signature or "port" fallback).

Detection order:
1. Payload signatures (independent of the port): HTTP request/status line,
   SMTP commands, DNS header structure.
2. Port fallback, only for payloads that match no signature (e.g. the middle
   of an HTTP body, lines of an e-mail after DATA).
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

HTTP = "HTTP"
DNS = "DNS"
SMTP = "SMTP"

HTTP_PORTS = frozenset({80, 8000, 8008, 8080, 8888})
SMTP_PORTS = frozenset({25, 587, 2525})  # 465 is SMTP over implicit TLS: unreadable
DNS_PORTS = frozenset({53, 5353})

HTTP_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH")

# "GET /index.html HTTP/1.1" - the version may be missing if the request line
# is split across TCP segments, so only method + space + target is required.
_HTTP_REQUEST_RE = re.compile(
    rb"^(?:" + b"|".join(HTTP_METHODS) + rb") (?:/|\*|https?://)\S*"
    rb"(?: HTTP/1\.[01])?(?:\r?\n|$)"
)
# "HTTP/1.1 200 OK"
_HTTP_RESPONSE_RE = re.compile(rb"^HTTP/1\.[01] \d{3}(?: |\r?\n|$)")

# Commands that only exist in SMTP -> safe to trust on any port.
_SMTP_STRONG_RE = re.compile(rb"^(?:HELO|EHLO) \S|^MAIL FROM:|^RCPT TO:", re.IGNORECASE)
# Commands / replies shared with other protocols (FTP, POP3...) -> port needed.
_SMTP_WEAK_RE = re.compile(
    rb"^(?:DATA|QUIT|RSET|NOOP|VRFY|EXPN|HELP|AUTH|STARTTLS|BDAT)\b"
    rb"|^[2-5]\d\d[ -]",
    re.IGNORECASE,
)
# A 220 greeting that names the protocol is SMTP on any port.
_SMTP_GREETING_RE = re.compile(rb"^220[ -].*\bE?SMTP\b", re.IGNORECASE)

_DNS_HEADER = struct.Struct("!HHHHHH")
_DNS_VALID_OPCODES = frozenset({0, 1, 2, 4, 5})  # QUERY, IQUERY, STATUS, NOTIFY, UPDATE
_DNS_VALID_QCLASSES = frozenset({1, 3, 4, 254, 255})


@dataclass(frozen=True)
class AppDetection:
    """Result of application protocol detection.

    Fields:
        app_protocol: "HTTP", "DNS", "SMTP" or None if not recognised.
        detected_by: "payload" (signature match) or "port" (fallback), or None.
    """

    app_protocol: str | None = None
    detected_by: str | None = None


def detect_app_protocol(
    transport: str,
    src_port: int | None,
    dst_port: int | None,
    payload: bytes,
) -> AppDetection:
    """Recognise the application protocol of a TCP/UDP payload.

    Input: transport protocol name, source/destination ports, payload bytes.
    Output: AppDetection. Empty payloads (e.g. TCP handshake) and unknown
    protocols give ``AppDetection()`` (app_protocol None). Never raises.
    """
    if not payload or transport not in ("TCP", "UDP"):
        return AppDetection()
    ports = {p for p in (src_port, dst_port) if p is not None}
    try:
        if transport == "TCP":
            return _detect_tcp(payload, ports)
        return _detect_udp(payload, ports)
    except Exception:  # noqa: BLE001 - detection must never break the pipeline
        return AppDetection()


def _detect_tcp(payload: bytes, ports: set[int]) -> AppDetection:
    # 1. Payload signatures
    if _HTTP_REQUEST_RE.match(payload) or _HTTP_RESPONSE_RE.match(payload):
        return AppDetection(HTTP, "payload")
    if _SMTP_STRONG_RE.match(payload) or _SMTP_GREETING_RE.match(payload):
        return AppDetection(SMTP, "payload")
    if ports & SMTP_PORTS and _SMTP_WEAK_RE.match(payload):
        return AppDetection(SMTP, "payload")
    if ports & DNS_PORTS and _looks_like_dns_over_tcp(payload):
        return AppDetection(DNS, "payload")

    # 2. Port fallback (continuation segments without a signature)
    if ports & HTTP_PORTS:
        return AppDetection(HTTP, "port")
    if ports & SMTP_PORTS:
        return AppDetection(SMTP, "port")
    return AppDetection()


def _detect_udp(payload: bytes, ports: set[int]) -> AppDetection:
    # DNS is binary, so the "signature" is a plausible header. On a DNS port a
    # loose check is enough; elsewhere the first question must also decode.
    if ports & DNS_PORTS:
        if _looks_like_dns(payload, strict=False):
            return AppDetection(DNS, "port")
    elif _looks_like_dns(payload, strict=True):
        return AppDetection(DNS, "payload")
    return AppDetection()


def _looks_like_dns_over_tcp(payload: bytes) -> bool:
    """DNS over TCP prefixes each message with a 2-byte length (RFC 1035 4.2.2)."""
    if len(payload) < 2:
        return False
    length = struct.unpack_from("!H", payload)[0]
    return length == len(payload) - 2 and _looks_like_dns(payload[2:], strict=False)


def _looks_like_dns(msg: bytes, strict: bool) -> bool:
    """Check that ``msg`` has a plausible DNS header (RFC 1035 4.1.1).

    Loose check (DNS port): 12-byte header, valid opcode, at least one record.
    A header whose counts do not match the message is still accepted, so the
    DNS parser can report it as malformed instead of it silently becoming an
    unknown payload.
    Strict check (any other port): the record counts must also fit in the
    message (a question is >= 5 bytes, a resource record >= 11 bytes) and
    exactly one question must decode (name, type, class).
    """
    if len(msg) < _DNS_HEADER.size:
        return False
    _id, flags, qd, an, ns, ar = _DNS_HEADER.unpack_from(msg)
    opcode = (flags >> 11) & 0x0F
    if opcode not in _DNS_VALID_OPCODES:
        return False
    if qd + an + ns + ar == 0:
        return False
    if not strict:
        return True
    if _DNS_HEADER.size + qd * 5 + (an + ns + ar) * 11 > len(msg):
        return False
    return qd == 1 and _first_question_ok(msg)


def _first_question_ok(msg: bytes) -> bool:
    """Walk the labels of the first question name, then check QTYPE/QCLASS."""
    offset = _DNS_HEADER.size
    name_len = 0
    while True:
        if offset >= len(msg):
            return False
        length = msg[offset]
        offset += 1
        if length == 0:
            break
        # The first name cannot use a compression pointer (nothing before it).
        if length > 63:
            return False
        name_len += length + 1
        if name_len > 255 or offset + length > len(msg):
            return False
        offset += length
    if name_len == 0 or offset + 4 > len(msg):
        return False
    _qtype, qclass = struct.unpack_from("!HH", msg, offset)
    return (qclass & 0x7FFF) in _DNS_VALID_QCLASSES  # top bit = mDNS unicast flag
