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
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from engine.rule_model import ContentOption


def match_contents(
    contents: tuple[ContentOption, ...], payload: bytes | None
) -> list[dict[str, Any]] | None:
    """All contents must match (AND). Returns match details or None.

    Each detail: ``{"pattern", "index", "offset", "length", "nocase"}`` where
    ``offset`` is the position found in the payload.
    """
    if not contents:
        return []
    if payload is None:
        return None
    lowered: bytes | None = None
    details: list[dict[str, Any]] = []
    for index, content in enumerate(contents):
        haystack = payload
        pattern = content.pattern
        if content.nocase:
            lowered = lowered if lowered is not None else payload.lower()
            haystack, pattern = lowered, pattern.lower()
        window_start, window_end = _window(content, len(payload))
        found = haystack.find(pattern, window_start, window_end)
        if found < 0:
            return None
        details.append(_detail(content, index, found))
    return details


def _window(content: ContentOption, size: int) -> tuple[int, int]:
    start = content.offset or 0
    end = size if content.depth is None else min(size, start + content.depth)
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
