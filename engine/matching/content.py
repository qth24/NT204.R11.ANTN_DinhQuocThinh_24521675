"""Content matcher: ``content`` with ``nocase``, ``offset`` and ``depth``.

The buffer is the raw transport payload (bytes). No regex: patterns are plain
bytes, so ``bytes.find(pattern, start, end)`` does the search - it finds the
pattern only if it lies COMPLETELY inside ``[start, end)``.

Search window of one content (absolute, i.e. not relative):
    start = offset            (default 0)
    end   = start + depth     (default: end of payload)
``depth`` therefore counts from the offset, not from the payload start.
Example: ``offset:4; depth:3`` searches bytes [4, 7) only.

nocase: ASCII-only. ``bytes.lower()`` touches only A-Z, so non-ASCII bytes are
never altered; both payload and pattern are lowered, positions stay identical.

Relative content (``distance`` / ``within``): the window starts at the end of
the previous match plus ``distance`` (may be negative) and is ``within`` bytes
long; the previous content is retried at all its positions (backtracking).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from engine.rule_model import ContentOption


def match_contents(
    contents: tuple[ContentOption, ...],
    payload: bytes | None,
    max_backtrack: int = 1000,
) -> list[dict[str, Any]] | None:
    """All contents must match (AND), in order. Returns details or None.

    Each detail: ``{"pattern", "index", "offset", "length", "nocase"}`` where
    ``offset`` is the position found in the payload.

    Relative contents (distance/within) depend on where the PREVIOUS content
    matched. The previous content may occur several times, and only some
    positions may let the next content fit, so we backtrack: try every
    position of content i, recurse into content i+1, and go back to the next
    position of i if the rest fails. ``max_backtrack`` caps the total number
    of positions tried per rule/event (worst case is exponential); when it is
    exhausted the rule is treated as not matching.
    """
    if not contents:
        return []
    if payload is None:
        return None
    lowered = payload.lower()  # ASCII-only lowering, same length as payload
    budget = [max_backtrack]

    def search(index: int, previous_end: int) -> list[dict[str, Any]] | None:
        if index == len(contents):
            return []
        content = contents[index]
        haystack = lowered if content.nocase else payload
        pattern = content.pattern.lower() if content.nocase else content.pattern
        start, end = _window(content, previous_end, len(payload))
        for found in positions(haystack, pattern, start, end):
            if budget[0] <= 0:
                return None
            budget[0] -= 1
            rest = search(index + 1, found + len(pattern))
            if rest is not None:
                return [_detail(content, index, found), *rest]
        return None

    return search(0, 0)


def _window(content: ContentOption, previous_end: int, size: int) -> tuple[int, int]:
    """Search window ``[start, end)`` for one content.

    absolute : start = offset (0), end = start + depth (or payload end)
    relative : start = previous_end + distance (distance defaults to 0, may be
               negative, never below 0), end = start + within (or payload end).
               The first content has previous_end = 0 (relative to the start).
    """
    if content.relative:
        start = max(0, previous_end + (content.distance or 0))
        width = content.within if content.within is not None else content.depth
    else:
        start = content.offset or 0
        width = content.depth
    end = size if width is None else min(size, start + width)
    return start, end


def _detail(content: ContentOption, index: int, found: int) -> dict[str, Any]:
    return {
        "pattern": content.pattern,
        "index": index,
        "offset": found,
        "length": len(content.pattern),
        "nocase": content.nocase,
    }


def positions(haystack: bytes, pattern: bytes, start: int, end: int) -> Iterator[int]:
    """Every position where ``pattern`` lies fully inside ``[start, end)``."""
    found = haystack.find(pattern, start, end)
    while found >= 0:
        yield found
        found = haystack.find(pattern, found + 1, end)
