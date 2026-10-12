"""Unit tests for decoder.charset."""

from __future__ import annotations

from decoder.charset import charset_from_content_type, decode_bytes


def test_valid_utf8_is_ok() -> None:
    result = decode_bytes("Xin chào ✓".encode())
    assert (result.text, result.status, result.charset) == ("Xin chào ✓", "ok", "utf-8")
    assert result.error is None


def test_declared_charset_fallback_is_partial() -> None:
    result = decode_bytes("café".encode("latin-1"), "ISO-8859-1")
    assert result.text == "café"
    assert result.status == "partial"
    assert result.charset == "iso8859-1"
    assert "invalid UTF-8 at byte 3" in result.error


def test_replace_fallback() -> None:
    result = decode_bytes(b"ab\xff\xfecd")
    assert result.text == "ab��cd"
    assert result.status == "partial"
    assert "replaced" in result.error


def test_unknown_declared_charset() -> None:
    result = decode_bytes(b"\xff", "no-such-charset")
    assert result.text == "�"
    assert "unknown declared charset" in result.error


def test_declared_charset_that_also_fails() -> None:
    result = decode_bytes(b"\xff\xfe", "ascii")
    assert result.status == "partial"
    assert "invalid for declared ascii" in result.error


def test_empty_bytes() -> None:
    assert decode_bytes(b"").status == "ok"


def test_charset_from_content_type() -> None:
    assert charset_from_content_type("text/html; charset=UTF-8") == "UTF-8"
    assert charset_from_content_type('text/plain; charset="iso-8859-1"') == "iso-8859-1"
    assert charset_from_content_type("application/json") is None
    assert charset_from_content_type(None) is None
