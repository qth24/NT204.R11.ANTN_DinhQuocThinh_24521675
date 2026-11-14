"""Detection Event: the output of the engine, input of Alert/Logging/Response.

The field names below are a contract for later assignments - do not rename.
This module only builds objects/dicts; writing ``detections.jsonl`` is done
by the output stage in ``main.py``. Time comes from the packet timestamp.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from engine.matching import MatchResult
from engine.rule_index import RuleRepository


@dataclass
class DetectionEvent:
    timestamp: float
    timestamp_iso: str
    sid: int
    rev: int
    msg: str
    classtype: str | None
    priority: int | None
    action: str
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    application_protocol: str | None
    flow_id: str | None
    direction: str | None
    packet_id: int | None
    match_info: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DetectionEventGenerator:
    """Turn ``MatchResult`` objects of one event into ``DetectionEvent`` objects."""

    def __init__(self, repository: RuleRepository, default_priority: int = 0) -> None:
        self.repository = repository
        self.default_priority = default_priority  # 0 = leave priority null

    def generate(
        self, event: dict[str, Any], results: Iterable[MatchResult]
    ) -> list[DetectionEvent]:
        out: list[DetectionEvent] = []
        for result in results:
            rule = self.repository.get(result.sid)
            if not result.matched or rule is None:
                continue
            normalized = event.get("normalized")
            normalized = normalized if isinstance(normalized, dict) else {}
            app = normalized.get("app_protocol") or event.get("app_protocol")
            timestamp = event.get("timestamp")
            out.append(
                DetectionEvent(
                    timestamp=timestamp,
                    timestamp_iso=normalized.get("timestamp_iso") or _iso(timestamp),
                    sid=rule.sid,
                    rev=rule.rev,
                    msg=rule.msg,
                    classtype=rule.classtype,
                    priority=rule.priority or self.default_priority or None,
                    action=rule.action,
                    src_ip=event.get("src_ip"),
                    src_port=event.get("src_port"),
                    dst_ip=event.get("dst_ip"),
                    dst_port=event.get("dst_port"),
                    protocol=normalized.get("protocol") or event.get("protocol"),
                    application_protocol=str(app).upper() if app else None,
                    flow_id=event.get("flow_id"),
                    direction=event.get("direction"),
                    packet_id=event.get("packet_id"),
                    match_info=_match_info(result),
                )
            )
        return out


def display_pattern(pattern: bytes) -> str:
    """Printable ASCII as text, anything else as Snort-style ``|de ad|`` hex."""
    if all(32 <= b < 127 and b not in (0x7C,) for b in pattern):
        return pattern.decode("ascii")
    return "|" + pattern.hex(" ") + "|"


def _match_info(result: MatchResult) -> dict[str, Any]:
    details = result.details
    return {
        "contents": [
            {**c, "pattern": display_pattern(c["pattern"])}
            for c in details.get("contents", [])
        ],
        "flow": details.get("flow"),
        "flags": details.get("flags"),
        "dsize": details.get("dsize"),
    }


def _iso(timestamp: Any) -> str | None:
    try:
        return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None
