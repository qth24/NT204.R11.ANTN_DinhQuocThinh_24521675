"""HTML entity decoding ("&lt;script&gt;" -> "<script>") with ``html.unescape``.

Only applied to text content (``should_unescape``): text/html, text/plain,
application/x-www-form-urlencoded (and XHTML). Binary bodies (images,
application/octet-stream...) are never touched.

Like URL decoding it is a single pass: "&amp;lt;" becomes "&lt;" and is
flagged ``double_encoded`` instead of being decoded a second time.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

TEXT_CONTENT_TYPES = (
    "text/html",
    "text/plain",
    "application/x-www-form-urlencoded",
    "application/xhtml+xml",
)
# Named (&lt;), decimal (&#60;) or hex (&#x3c;) character references
_ENTITY_RE = re.compile(
    r"&(?:[a-zA-Z][a-zA-Z0-9]{1,31}|#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6});"
)


@dataclass(frozen=True)
class HtmlDecodeResult:
    """Output of ``unescape_html``.

    Fields:
        text: text with entities replaced once.
        changed: True if at least one entity was decoded.
        double_encoded: True if entities are still present after decoding.
    """

    text: str
    changed: bool
    double_encoded: bool


def should_unescape(content_type: str | None) -> bool:
    """True for the text content types listed in TEXT_CONTENT_TYPES."""
    if not content_type:
        return False
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type in TEXT_CONTENT_TYPES


def unescape_html(text: str) -> HtmlDecodeResult:
    """Decode HTML character references exactly once."""
    decoded = html.unescape(text)
    return HtmlDecodeResult(
        text=decoded,
        changed=decoded != text,
        double_encoded=decoded != text and bool(_ENTITY_RE.search(decoded)),
    )


def unescape_params(
    params: dict[str, list[str]],
) -> tuple[dict[str, list[str]], bool]:
    """Apply ``unescape_html`` to every name/value; returns (params, double)."""
    result: dict[str, list[str]] = {}
    double = False
    for name, values in params.items():
        key = unescape_html(name)
        decoded_values = [unescape_html(value) for value in values]
        double = (
            double
            or key.double_encoded
            or any(v.double_encoded for v in decoded_values)
        )
        result.setdefault(key.text, []).extend(v.text for v in decoded_values)
    return result, double
