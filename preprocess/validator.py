"""Event validation: decide whether an event is valid, partial or invalid.

Input:  event dict (BT1 fields + decoder fields).
Output: ``ValidationResult(status, reasons, unsupported)``.

* invalid  - a core field is missing or unusable:
             packet_id, timestamp, src_ip, dst_ip, protocol;
             IP that does not parse; timestamp not a finite number >= 0;
             protocol outside the supported set (TCP, UDP)
* partial  - a secondary problem: TCP/UDP port missing or outside 0-65535,
             bad tcp_flags, a BT1 parse error, decoding partial/failed
* valid    - everything else

Reasons are short machine-readable strings, e.g. "missing_field:dst_port",
"invalid_port:70000", "unsupported_protocol:UNKNOWN".
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field
from typing import Any

CORE_FIELDS = ("packet_id", "timestamp", "src_ip", "dst_ip", "protocol")
SUPPORTED_PROTOCOLS = frozenset({"TCP", "UDP"})


@dataclass
class ValidationResult:
    """status: "valid" | "partial" | "invalid"; unsupported: protocol not handled."""

    status: str
    reasons: list[str] = field(default_factory=list)
    unsupported: bool = False


def validate_event(event: dict[str, Any]) -> ValidationResult:
    """Check required fields and value ranges of one event. Never raises."""
    invalid: list[str] = []
    partial: list[str] = []
    unsupported = False

    # --- core fields -> invalid -------------------------------------------
    for name in CORE_FIELDS:
        if event.get(name) is None:
            invalid.append(f"missing_field:{name}")

    packet_id = event.get("packet_id")
    if packet_id is not None and (
        isinstance(packet_id, bool) or not isinstance(packet_id, int)
    ):
        invalid.append(f"invalid_packet_id:{packet_id!r}")

    timestamp = event.get("timestamp")
    if timestamp is not None and not _valid_timestamp(timestamp):
        invalid.append(f"invalid_timestamp:{timestamp!r}")

    for name in ("src_ip", "dst_ip"):
        value = event.get(name)
        if value is not None and not _valid_ip(value):
            invalid.append(f"invalid_ip:{value!r}")

    protocol = event.get("protocol")
    supported = (
        isinstance(protocol, str) and protocol.strip().upper() in SUPPORTED_PROTOCOLS
    )
    if protocol is not None and not supported:
        invalid.append(f"unsupported_protocol:{protocol}")
        unsupported = True

    # --- secondary fields -> partial --------------------------------------
    if supported:
        for name in ("src_port", "dst_port"):
            port = event.get(name)
            if port is None:
                partial.append(f"missing_field:{name}")
            elif (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 0 <= port <= 65535
            ):
                partial.append(f"invalid_port:{port}")
        flags = event.get("tcp_flags")
        if flags is not None and not isinstance(flags, list):
            partial.append("invalid_field:tcp_flags")

    if event.get("error"):
        partial.append("parse_error")
    decode_status = event.get("decode_status")
    if decode_status in ("partial", "failed"):
        partial.append(f"decode_{decode_status}")

    if invalid:
        return ValidationResult("invalid", invalid + partial, unsupported)
    if partial:
        return ValidationResult("partial", partial, unsupported)
    return ValidationResult("valid", [], unsupported)


def _valid_timestamp(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value) and value >= 0


def _valid_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True
