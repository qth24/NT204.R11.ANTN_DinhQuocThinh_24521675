"""Write IDS events as JSON Lines (one JSON object per line)."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from types import TracebackType
from typing import IO, Any

from core.event import IDSEvent


class JsonLinesWriter:
    """Context manager writing ``IDSEvent`` objects to a .jsonl file.

    Input: output path ("-" = stdout), append mode flag.
    Output: one line per event, flushed immediately so a live capture can be
    followed with ``tail -f`` and nothing is lost on Ctrl+C.

    Usage::

        with JsonLinesWriter("output.jsonl") as writer:
            writer.write(event)
    """

    def __init__(self, path: str, append: bool = False) -> None:
        self.path = path
        self.append = append
        self.count = 0
        self._file: IO[str] | None = None

    def __enter__(self) -> JsonLinesWriter:  # noqa: PYI034 - Self needs 3.11
        if self.path == "-":
            self._file = sys.stdout
        else:
            self._file = open(self.path, "a" if self.append else "w", encoding="utf-8")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._file is not None and self._file is not sys.stdout:
            self._file.close()
        self._file = None

    def write(self, event: IDSEvent | dict[str, Any]) -> None:
        """Serialize one event (dataclass or dict) and write it as a single line."""
        if self._file is None:
            raise RuntimeError("JsonLinesWriter used outside of a 'with' block")
        record = event.to_dict() if isinstance(event, IDSEvent) else event
        line = json.dumps(record, ensure_ascii=False, default=_fallback)
        self._file.write(line + "\n")
        self._file.flush()
        self.count += 1


def read_jsonl(path: str) -> Iterator[dict[str, Any]]:
    """Yield the events of a JSON Lines file (input of ``--events``).

    Never raises on bad content: a line that is not a JSON object becomes an
    event with only an ``error`` field, which the Preprocessor then reports
    as invalid. Blank lines are skipped.
    """
    with open(path, encoding="utf-8", errors="replace") as file:
        for number, line in enumerate(file, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                yield {"error": f"input line {number}: invalid JSON ({exc.msg})"}
                continue
            if isinstance(value, dict):
                yield value
            else:
                yield {"error": f"input line {number}: not a JSON object"}


def _fallback(value: Any) -> Any:
    """Last-resort conversion for values json cannot handle (e.g. bytes)."""
    if isinstance(value, bytes):
        return value.hex()
    return str(value)
