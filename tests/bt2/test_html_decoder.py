"""Unit tests for decoder.html_decoder."""

from __future__ import annotations

import pytest

from decoder.html_decoder import should_unescape, unescape_html, unescape_params


def test_named_decimal_and_hex_entities() -> None:
    result = unescape_html("&lt;script&gt;alert(&#39;x&#x27;)&lt;/script&gt;")
    assert result.text == "<script>alert('x')</script>"
    assert result.changed is True
    assert result.double_encoded is False


def test_double_encoded_entities_decoded_once() -> None:
    result = unescape_html("&amp;lt;img src=x&amp;gt;")
    assert result.text == "&lt;img src=x&gt;"
    assert result.double_encoded is True


def test_plain_text_unchanged() -> None:
    result = unescape_html("a & b < c")  # bare "&" is not an entity
    assert result.text == "a & b < c"
    assert result.changed is False
    assert result.double_encoded is False


def test_unknown_and_malformed_entities_do_not_crash() -> None:
    assert unescape_html("&notanentity; &#99999999; &#xZZ;").text  # no exception


@pytest.mark.parametrize(
    "content_type, expected",
    [
        ("text/html; charset=utf-8", True),
        ("TEXT/PLAIN", True),
        ("application/x-www-form-urlencoded", True),
        ("application/json", False),
        ("image/png", False),
        ("application/octet-stream", False),
        (None, False),
    ],
)
def test_should_unescape(content_type: str | None, expected: bool) -> None:
    assert should_unescape(content_type) is expected


def test_unescape_params() -> None:
    params, double = unescape_params({"q": ["&lt;b&gt;", "x"], "a&amp;b": ["1"]})
    assert params == {"q": ["<b>", "x"], "a&b": ["1"]}
    assert double is False
    assert unescape_params({"x": ["&amp;quot;"]})[1] is True
