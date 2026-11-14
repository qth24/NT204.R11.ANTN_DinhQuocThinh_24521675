"""Rule matching engine: ``RuleMatcher.match(rule, event, flow_ctx) -> MatchResult``.

Checks run from cheap to expensive so a rule is rejected as early as
possible:  header -> flow -> packet (flags, dsize) -> content.

``match`` is a pure function of its arguments: it prints nothing, writes
nothing and never changes the event or the rule.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from engine.matching.content import match_contents
from engine.matching.flow import match_flow
from engine.matching.header import match_header
from engine.matching.packet import event_dsize, match_packet
from engine.rule_model import Rule

ContentFn = Callable[..., "list[dict[str, Any]] | None"]


@dataclass(frozen=True)
class MatchResult:
    """Outcome of one rule against one event.

    ``reason_no_match`` is the failed stage (``"protocol"``, ``"direction"``,
    ``"flow:established"``, ``"flags"``, ``"dsize"``, ``"content"``...), None
    when matched. ``details`` (matched only) feeds ``match_info`` of the
    Detection Event: ``contents``, ``flow``, ``flags``, ``dsize``.
    """

    matched: bool
    sid: int
    rev: int
    details: dict[str, Any] = field(default_factory=dict)
    reason_no_match: str | None = None


class RuleMatcher:
    """Stateless matcher (only configuration is stored)."""

    def __init__(
        self,
        dsize_inclusive: bool = True,
        max_content_backtrack: int = 1000,
        content_matcher: ContentFn = match_contents,
    ) -> None:
        self.dsize_inclusive = dsize_inclusive
        self.max_content_backtrack = max_content_backtrack
        # Injectable so tests can prove content matching is skipped.
        self.content_matcher = content_matcher

    def match(
        self, rule: Rule, event: dict[str, Any], flow_ctx: dict[str, Any] | None
    ) -> MatchResult:
        def miss(reason: str) -> MatchResult:
            return MatchResult(False, rule.sid, rule.rev, {}, reason)

        reason = match_header(rule, event)
        if reason:
            return miss(reason)
        reason = match_flow(rule, flow_ctx)
        if reason:
            return miss(reason)
        reason = match_packet(rule, event, self.dsize_inclusive)
        if reason:
            return miss(reason)

        contents: list[dict[str, Any]] = []
        if rule.contents:
            found = self.content_matcher(
                rule.contents, _payload(event), self.max_content_backtrack
            )
            if found is None:
                return miss("content")
            contents = found

        details = {
            "contents": contents,
            "flow": _flow_info(rule, flow_ctx),
            "flags": (
                sorted(event.get("tcp_flags") or []) if rule.flags is not None else None
            ),
            "dsize": _dsize_info(rule, event),
        }
        return MatchResult(True, rule.sid, rule.rev, details, None)


def _payload(event: dict[str, Any]) -> bytes | None:
    """Raw transport payload; an event known to be empty counts as b""."""
    payload = event.get("payload")
    if isinstance(payload, bytes):
        return payload
    return b"" if event.get("payload_length") == 0 else None


def _flow_info(rule: Rule, ctx: dict[str, Any] | None) -> dict[str, Any] | None:
    if rule.flow is None or not ctx:
        return None
    return {
        "direction": ctx.get("direction"),
        "state": ctx.get("state"),
        "flow": rule.flow.direction,
        "established": rule.flow.state,
    }


def _dsize_info(rule: Rule, event: dict[str, Any]) -> int | None:
    if rule.dsize is None:
        return None
    return event_dsize(event)


__all__ = ["MatchResult", "RuleMatcher"]
