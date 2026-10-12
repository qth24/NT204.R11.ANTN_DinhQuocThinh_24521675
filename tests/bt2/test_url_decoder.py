"""Unit tests for decoder.url_decoder."""

from __future__ import annotations

from decoder.url_decoder import decode_form, decode_uri


def test_path_and_query_decoding() -> None:
    result = decode_uri("/search%20page/a+b?q=%3Cscript%3E&lang=vi+VN&empty=")
    assert result.path == "/search page/a+b"  # "+" in path is NOT a space
    assert result.uri == "/search page/a+b?q=<script>&lang=vi VN&empty="
    assert result.query_params == {"q": ["<script>"], "lang": ["vi VN"], "empty": [""]}
    assert result.double_encoded is False
    assert result.status == "ok"


def test_sql_injection_payload() -> None:
    result = decode_uri("/item?id=1%27%20OR%201%3D1--")
    assert result.query_params == {"id": ["1' OR 1=1--"]}


def test_repeated_parameters_kept_in_order() -> None:
    assert decode_uri("/?a=1&a=2&b=3").query_params == {"a": ["1", "2"], "b": ["3"]}


def test_no_query() -> None:
    result = decode_uri("/a%2Fb")
    assert result.uri == "/a/b"
    assert result.query_params is None


def test_double_encoding_decoded_once_and_flagged() -> None:
    result = decode_uri("/%252e%252e/etc/passwd?x=%2527")
    assert result.path == "/%2e%2e/etc/passwd"  # only ONE layer removed
    assert result.query_params == {"x": ["%27"]}
    assert result.double_encoded is True


def test_absolute_form_and_fragment() -> None:
    assert decode_uri("http://example.com/a%20b?x=1").uri == "/a b?x=1"
    assert decode_uri("/page#frag%20x").uri == "/page"
    assert decode_uri("*").uri == "*"


def test_double_slash_path_is_not_a_host() -> None:
    assert decode_uri("//evil.com/x").path == "//evil.com/x"


def test_invalid_utf8_is_partial() -> None:
    result = decode_uri("/caf%E9?n=%FF")
    assert result.path == "/caf�"
    assert result.query_params == {"n": ["�"]}
    assert result.status == "partial"
    assert len(result.errors) == 3  # path, query string, query parameters


def test_form_body() -> None:
    result = decode_form("username=admin%27--&password=a+b%26c&remember=")
    assert result.params == {
        "username": ["admin'--"],
        "password": ["a b&c"],
        "remember": [""],
    }
    assert result.status == "ok"
    assert result.double_encoded is False


def test_form_double_encoded_and_invalid() -> None:
    assert decode_form("x=%2541").double_encoded is True
    bad = decode_form("x=%C3%28")
    assert bad.status == "partial"
    assert bad.params == {"x": ["�("]}


def test_empty_inputs() -> None:
    assert decode_uri("").uri == ""
    assert decode_form("").params == {}
