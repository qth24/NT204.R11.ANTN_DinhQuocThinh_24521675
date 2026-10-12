"""Percent-decoding of HTTP URIs and application/x-www-form-urlencoded bodies.

Rules (RFC 3986 / HTML form encoding):
* path : ``unquote``  -> "%2F" becomes "/", but "+" stays "+" (not a space)
* query and form body : ``parse_qs`` / ``unquote_plus`` -> "+" means space

Each layer is decoded exactly ONCE. If the result still contains ``%XX``
the input was double-encoded (``%2527`` -> ``%27``): we only flag it with
``double_encoded=True`` and never decode again, so the meaning of the data is
not changed by the IDS.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, unquote_plus, urlsplit

_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")


@dataclass
class UriDecodeResult:
    """Output of ``decode_uri``.

    Fields:
        uri: decoded path + "?" + decoded query (raw URI is never modified).
        path: decoded path only.
        query_params: {name: [values]} from the query string, None if no query.
        double_encoded: True if "%XX" is still present after one decoding pass.
        status: "ok" or "partial" (invalid UTF-8 inside the percent-encoding).
        errors: problems found while decoding.
    """

    uri: str
    path: str
    query_params: dict[str, list[str]] | None
    double_encoded: bool
    status: str = "ok"
    errors: list[str] = field(default_factory=list)


@dataclass
class FormDecodeResult:
    """Output of ``decode_form``: params of an urlencoded body."""

    params: dict[str, list[str]]
    double_encoded: bool
    status: str = "ok"
    errors: list[str] = field(default_factory=list)


def decode_uri(raw_uri: str) -> UriDecodeResult:
    """Percent-decode a request target ("/a%20b?q=1+2", "http://h/x", "*")."""
    path, query = _split_target(raw_uri)
    errors: list[str] = []

    decoded_path = _unquote(path, unquote, "path", errors)
    if query is None:
        return UriDecodeResult(
            uri=decoded_path,
            path=decoded_path,
            query_params=None,
            double_encoded=bool(_PERCENT_RE.search(decoded_path)),
            status="partial" if errors else "ok",
            errors=errors,
        )

    decoded_query = _unquote(query, unquote_plus, "query", errors)
    params = _parse_qs(query, "query", errors)
    return UriDecodeResult(
        uri=f"{decoded_path}?{decoded_query}",
        path=decoded_path,
        query_params=params,
        double_encoded=bool(
            _PERCENT_RE.search(decoded_path) or _PERCENT_RE.search(decoded_query)
        ),
        status="partial" if errors else "ok",
        errors=errors,
    )


def decode_form(body: str) -> FormDecodeResult:
    """Decode an application/x-www-form-urlencoded body ("a=1&b=%27+OR+1%3D1")."""
    errors: list[str] = []
    params = _parse_qs(body.strip(), "form", errors)
    double = any(
        _PERCENT_RE.search(text)
        for name, values in params.items()
        for text in (name, *values)
    )
    return FormDecodeResult(
        params=params,
        double_encoded=double,
        status="partial" if errors else "ok",
        errors=errors,
    )


def _split_target(raw: str) -> tuple[str, str | None]:
    """Split a request target into (path, query). The fragment is dropped."""
    if raw.lower().startswith(("http://", "https://")):
        parts = urlsplit(raw)  # absolute-form, e.g. requests sent to a proxy
        path = parts.path or "/"
        return path, parts.query if "?" in raw else None
    # origin-form: split by hand so a path like "//x" is not read as a host
    target = raw.split("#", 1)[0]
    path, sep, query = target.partition("?")
    return path, query if sep else None


def _unquote(text: str, func, where: str, errors: list[str]) -> str:
    """One decoding pass; invalid UTF-8 behind %XX is replaced, not fatal."""
    try:
        return func(text, errors="strict")
    except UnicodeDecodeError:
        errors.append(f"invalid UTF-8 in percent-encoded {where}")
        return func(text, errors="replace")


def _parse_qs(text: str, where: str, errors: list[str]) -> dict[str, list[str]]:
    try:
        return parse_qs(text, keep_blank_values=True, errors="strict")
    except UnicodeDecodeError:
        errors.append(f"invalid UTF-8 in percent-encoded {where} parameters")
        return parse_qs(text, keep_blank_values=True, errors="replace")
