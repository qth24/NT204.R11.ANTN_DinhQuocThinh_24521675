"""Event normalization: one canonical representation for detection rules.

Input:  event dict (BT1 fields + decoder fields).
Output: (``normalized`` dict, reasons). Original fields are never modified.

    "normalized": {
        "protocol":      "TCP" / "UDP" / ...   (UPPERCASE)
        "app_protocol":  "HTTP" / "DNS" / ... or None (UPPERCASE)
        "src_ip", "dst_ip": canonical text form (ipaddress), None if invalid
        "domain":        DNS qname or HTTP Host: lowercase, no trailing dot,
                         no port, IDNA (punycode) for non-ASCII names
        "http_headers":  {lowercase name: value} (HTTP only, else None)
        "uri_path":      decoded path, "//" collapsed, "." / ".." resolved
                         without going above "/"; the query is kept apart
        "timestamp":     float epoch (unchanged)
        "timestamp_iso": UTC ISO-8601
    }
"""

from __future__ import annotations

import ipaddress
import math
import re
from datetime import datetime, timezone
from typing import Any

_MULTI_SLASH = re.compile(r"/{2,}")


def normalize_event(event: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Build the ``normalized`` dict of one event. Never raises."""
    reasons: list[str] = []
    app = event.get("app_data")
    app_data = app if isinstance(app, dict) else {}
    app_protocol = _upper(event.get("app_protocol"))

    domain_source = None
    if app_protocol == "DNS":
        questions = app_data.get("questions")
        if isinstance(questions, list) and questions and isinstance(questions[0], dict):
            domain_source = questions[0].get("name")
    elif app_protocol == "HTTP":
        domain_source = app_data.get("host")
    domain, reason = normalize_domain(domain_source)
    if reason:
        reasons.append(reason)

    timestamp = event.get("timestamp")
    return {
        "protocol": _upper(event.get("protocol")),
        "app_protocol": app_protocol,
        "src_ip": normalize_ip(event.get("src_ip")),
        "dst_ip": normalize_ip(event.get("dst_ip")),
        "domain": domain,
        "http_headers": (
            normalize_headers(app_data.get("headers"))
            if app_protocol == "HTTP"
            else None
        ),
        "uri_path": _uri_path(event, app_data) if app_protocol == "HTTP" else None,
        "timestamp": timestamp if _is_number(timestamp) else None,
        "timestamp_iso": to_iso(timestamp),
    }, reasons


def normalize_ip(value: Any) -> str | None:
    """'010.000.000.001' is rejected by ipaddress; '10.0.0.1 ' -> '10.0.0.1'."""
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def normalize_domain(value: Any) -> tuple[str | None, str | None]:
    """Return (domain, reason). Reason is set when IDNA encoding fails."""
    if not isinstance(value, str):
        return None, None
    host = value.strip().lower()
    if host.startswith("["):  # IPv6 literal in a Host header: "[::1]:8080"
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:  # "example.com:8080" -> drop the port
        host = host.split(":", 1)[0]
    host = host.rstrip(".")
    if not host:
        return None, None
    if host.isascii():
        return host, None
    try:
        return host.encode("idna").decode("ascii"), None
    except UnicodeError:
        return host, f"idna_error:{host}"


def normalize_headers(headers: Any) -> dict[str, str] | None:
    """Header names lowercased and trimmed; values trimmed."""
    if not isinstance(headers, dict):
        return None
    result: dict[str, str] = {}
    for name, value in headers.items():
        key = str(name).strip().lower()
        text = str(value).strip()
        result[key] = f"{result[key]}, {text}" if key in result else text
    return result


def normalize_path(path: str) -> str:
    """Collapse "//" and resolve "." / ".." without going above the root."""
    if not path.startswith("/"):
        return path  # "*" or other non-path targets are kept as they are
    segments: list[str] = []
    parts = _MULTI_SLASH.sub("/", path).split("/")[1:]
    for segment in parts:
        if segment == "..":
            if segments:
                segments.pop()  # never above "/": extra ".." are ignored
        elif segment not in (".", ""):
            segments.append(segment)
    trailing = parts[-1] in ("", ".", "..") and bool(segments)
    return "/" + "/".join(segments) + ("/" if trailing else "")


def to_iso(timestamp: Any) -> str | None:
    """Epoch seconds -> '2025-09-27T19:06:40.500000+00:00' (UTC)."""
    if not _is_number(timestamp) or timestamp < 0:
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(
            timespec="microseconds"
        )
    except (OverflowError, OSError, ValueError):
        return None


def _uri_path(event: dict[str, Any], app_data: dict[str, Any]) -> str | None:
    decoded = event.get("decoded")
    uri = decoded.get("uri") if isinstance(decoded, dict) else None
    if not isinstance(uri, str):
        uri = app_data.get("uri")  # decoder disabled: raw path is the best we have
    if not isinstance(uri, str):
        return None
    return normalize_path(uri.split("?", 1)[0])


def _upper(value: Any) -> str | None:
    return value.strip().upper() if isinstance(value, str) and value.strip() else None


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )
