"""bytes -> str with an explicit status, never raising.

Order (spec):
1. UTF-8 strict                      -> status "ok"
2. charset declared by the protocol  -> status "partial" (input was not UTF-8)
   (e.g. ``Content-Type: text/html; charset=iso-8859-1``)
3. UTF-8 with errors="replace"       -> status "partial" (bad bytes become U+FFFD)

Every fallback also returns an ``error`` message for ``decode_errors``.
"""

from __future__ import annotations

import codecs
import re
from dataclasses import dataclass

_CHARSET_RE = re.compile(r"""charset\s*=\s*["']?([\w.:-]+)""", re.IGNORECASE)


@dataclass(frozen=True)
class CharsetResult:
    """Output of ``decode_bytes``.

    Fields:
        text: decoded string (always present).
        status: "ok" (clean UTF-8) or "partial" (fallback was needed).
        charset: codec actually used, e.g. "utf-8", "iso8859-1".
        error: why a fallback was needed, None when status is "ok".
    """

    text: str
    status: str
    charset: str
    error: str | None = None


def charset_from_content_type(content_type: str | None) -> str | None:
    """Extract ``charset=`` from a Content-Type header value, if any."""
    if not content_type:
        return None
    match = _CHARSET_RE.search(content_type)
    return match.group(1) if match else None


def decode_bytes(data: bytes, declared: str | None = None) -> CharsetResult:
    """Decode ``data`` following the UTF-8 -> declared charset -> replace order."""
    try:
        return CharsetResult(data.decode("utf-8"), "ok", "utf-8")
    except UnicodeDecodeError as exc:
        utf8_error = f"invalid UTF-8 at byte {exc.start}"

    codec = _lookup(declared)
    if codec is not None and codec != "utf-8":
        try:
            text = data.decode(codec)
            return CharsetResult(
                text, "partial", codec, f"{utf8_error}; decoded as declared {codec}"
            )
        except UnicodeDecodeError:
            utf8_error += f"; invalid for declared {codec}"
    elif declared and codec is None:
        utf8_error += f"; unknown declared charset {declared!r}"

    text = data.decode("utf-8", errors="replace")
    return CharsetResult(
        text, "partial", "utf-8", f"{utf8_error}; undecodable bytes replaced"
    )


def _lookup(name: str | None) -> str | None:
    """Canonical codec name, or None for a missing/unknown charset."""
    if not name:
        return None
    try:
        return codecs.lookup(name).name
    except LookupError:
        return None
