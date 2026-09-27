"""Application layer parsers (HTTP, DNS, SMTP) and their common result type."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AppResult:
    """Output of every application parser.

    Fields:
        data: JSON-serializable dict that becomes ``app_data`` in the event.
        error: description of a parse problem, None if the payload was clean.
    """

    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
