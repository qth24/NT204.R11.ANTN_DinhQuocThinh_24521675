"""HTTP/1.x parser (RFC 9112): request line / status line, headers and body.

Input: TCP payload already classified as HTTP by ``parsers.app_detector``.
Output: ``AppResult`` whose ``data`` is one of:

* request:  {"type": "request", "method", "uri", "version", "headers",
             "host", "user_agent", "content_type", "content_length",
             "headers_complete", "body", "body_length", "body_truncated"}
* response: {"type": "response", "version", "status_code", "reason",
             "headers", "content_type", "content_length", "server",
             "headers_complete", "body", "body_length", "body_truncated"}
* continuation: {"type": "continuation", "body", "body_length"} for a TCP
  segment in the middle of a message (no start line).
"""

from __future__ import annotations

import re
from typing import Any

from parsers.app import AppResult

# Only the first N characters of the body are kept in the log.
MAX_BODY_PREVIEW = 1024

_REQUEST_LINE_RE = re.compile(
    r"^(?P<method>[A-Z]+) (?P<uri>\S+)(?: (?P<version>HTTP/\d\.\d))?$"
)
_STATUS_LINE_RE = re.compile(
    r"^(?P<version>HTTP/\d\.\d) (?P<status>\d{3})(?: (?P<reason>.*))?$"
)


def parse_http(payload: bytes) -> AppResult:
    """Parse one HTTP/1.x message (or the part of it inside this segment).

    Never raises: problems are reported in ``AppResult.error`` together with
    whatever fields could be extracted.
    """
    try:
        return _parse(payload)
    except Exception as exc:  # noqa: BLE001 - a parser bug must not stop the IDS
        return AppResult(
            data={"type": "unknown", "body_length": len(payload)},
            error=f"HTTP parse error: {exc}",
        )


def _parse(payload: bytes) -> AppResult:
    head, body, headers_complete = _split_head_body(payload)
    # Header bytes are ISO-8859-1 by spec: every byte maps to a character,
    # so decoding can never fail.
    lines = head.decode("iso-8859-1").splitlines()
    start_line = lines[0] if lines else ""
    errors: list[str] = []

    if match := _REQUEST_LINE_RE.match(start_line):
        data: dict[str, Any] = {
            "type": "request",
            "method": match["method"],
            "uri": match["uri"],
            "version": match["version"],
        }
    elif match := _STATUS_LINE_RE.match(start_line):
        data = {
            "type": "response",
            "version": match["version"],
            "status_code": int(match["status"]),
            "reason": match["reason"] or "",
        }
    elif start_line.startswith("HTTP/"):
        # Looks like a status line but the format is wrong.
        return AppResult(
            data={"type": "response", **_body_fields(payload, None)},
            error=f"Malformed HTTP status line: {start_line[:100]!r}",
        )
    else:
        # Middle of a message split across segments (e.g. rest of a POST body).
        return AppResult(data={"type": "continuation", **_body_fields(payload, None)})

    headers = _parse_headers(lines[1:], errors)
    content_length = _content_length(headers, errors)
    data["headers"] = headers
    data["content_type"] = _header(headers, "Content-Type")
    data["content_length"] = content_length
    if data["type"] == "request":
        data["host"] = _header(headers, "Host")
        data["user_agent"] = _header(headers, "User-Agent")
    else:
        data["server"] = _header(headers, "Server")
    data["headers_complete"] = headers_complete
    data.update(_body_fields(body, content_length))

    return AppResult(data=data, error="; ".join(errors) or None)


def _split_head_body(payload: bytes) -> tuple[bytes, bytes, bool]:
    """Split at the blank line ending the headers (CRLF CRLF, or bare LF LF)."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = payload.find(sep)
        if idx != -1:
            return payload[:idx], payload[idx + len(sep) :], True
    # Headers continue in the next TCP segment.
    return payload, b"", False


def _parse_headers(lines: list[str], errors: list[str]) -> dict[str, str]:
    """ "Name: value" lines -> dict. Repeated names are joined with ", "."""
    headers: dict[str, str] = {}
    canonical: dict[str, str] = {}  # lower-case name -> first spelling seen
    for line in lines:
        if not line:
            continue
        name, sep, value = line.partition(":")
        name = name.strip()
        if not sep or not name or " " in name:
            errors.append(f"Malformed header line: {line[:100]!r}")
            continue
        key = canonical.setdefault(name.lower(), name)
        value = value.strip()
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
    return headers


def _header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup (Host == host == HOST)."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _content_length(headers: dict[str, str], errors: list[str]) -> int | None:
    raw = _header(headers, "Content-Length")
    if raw is None:
        return None
    try:
        value = int(raw)
        if value < 0:
            raise ValueError
        return value
    except ValueError:
        errors.append(f"Invalid Content-Length: {raw[:50]!r}")
        return None


def _body_fields(body: bytes, content_length: int | None) -> dict[str, Any]:
    """Body preview decoded as UTF-8 (undecodable bytes become U+FFFD)."""
    return {
        "body": body[:MAX_BODY_PREVIEW].decode("utf-8", errors="replace"),
        "body_length": len(body),
        # True when the rest of the body is in later TCP segments
        "body_truncated": content_length is not None and len(body) < content_length,
    }
