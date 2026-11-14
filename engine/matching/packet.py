"""Packet matcher: TCP ``flags`` and payload ``dsize``.

flags semantics (Snort), with E = flags of the event, R = flags of the rule,
M = mask (flags to ignore, removed from both E and R before comparing):

    (none)  exact : E == R       ("S" matches a pure SYN, not SYN+ACK)
    +       all   : R subset of E (extra flags allowed; "+SA" matches SYN+ACK+PSH)
    *       any   : R and E share at least one flag
    !       none  : R and E share no flag

A rule with ``flags`` never matches a UDP (non-TCP) packet.

dsize compares the payload length of the transport layer (``payload_length``
of the event, so truncation of the stored payload does not matter). A pure
ACK has dsize 0. ``N<>M`` is inclusive by default (Snort docs: ``dsize:min<>max``
matches min <= size <= max); config ``engine.dsize_range_inclusive`` can make
it exclusive.
"""

from __future__ import annotations

from typing import Any

from engine.rule_model import DsizeOption, FlagsOption, Rule

# BT1 tcp_flags names -> Snort letters (NS has no Snort letter and is ignored)
_FLAG_LETTER = {
    "FIN": "F",
    "SYN": "S",
    "RST": "R",
    "PSH": "P",
    "ACK": "A",
    "URG": "U",
    "CWR": "C",
    "ECE": "E",
}


def match_packet(
    rule: Rule, event: dict[str, Any], dsize_inclusive: bool = True
) -> str | None:
    """Return None when flags and dsize match, else the reason."""
    if rule.flags is not None:
        if _protocol(event) != "TCP":
            return "flags:not_tcp"
        if not match_flags(rule.flags, event_flag_letters(event)):
            return "flags"
    if rule.dsize is not None:
        size = event_dsize(event)
        if size is None:
            return "dsize:missing"
        if not match_dsize(rule.dsize, size, dsize_inclusive):
            return "dsize"
    return None


def event_flag_letters(event: dict[str, Any]) -> frozenset[str]:
    flags = event.get("tcp_flags")
    if not isinstance(flags, list):
        return frozenset()
    return frozenset(
        _FLAG_LETTER[f.upper()]
        for f in flags
        if isinstance(f, str) and f.upper() in _FLAG_LETTER
    )


def match_flags(option: FlagsOption, present: frozenset[str]) -> bool:
    wanted = option.flags - option.mask
    seen = present - option.mask
    if option.modifier == "+":
        return wanted <= seen
    if option.modifier == "*":
        return bool(wanted & seen)
    if option.modifier == "!":
        return not (wanted & seen)
    return wanted == seen


def event_dsize(event: dict[str, Any]) -> int | None:
    length = event.get("payload_length")
    if isinstance(length, int) and not isinstance(length, bool):
        return length
    payload = event.get("payload")
    return len(payload) if isinstance(payload, bytes) else None


def match_dsize(option: DsizeOption, size: int, inclusive: bool = True) -> bool:
    if option.op == "eq":
        return size == option.value
    if option.op == "lt":
        return size < option.value
    if option.op == "gt":
        return size > option.value
    assert option.high is not None
    if inclusive:
        return option.value <= size <= option.high
    return option.value < size < option.high


def _protocol(event: dict[str, Any]) -> str:
    normalized = event.get("normalized")
    if isinstance(normalized, dict) and normalized.get("protocol"):
        return str(normalized["protocol"]).upper()
    return str(event.get("protocol") or "").upper()
