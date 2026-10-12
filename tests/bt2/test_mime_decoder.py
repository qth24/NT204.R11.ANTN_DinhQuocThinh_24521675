"""Unit tests for decoder.mime_decoder."""

from __future__ import annotations

import base64

from decoder.mime_decoder import (
    decode_base64,
    decode_mime_message,
    smtp_data_to_message,
)

LIMIT = 65536


def _single(cte: str, body: bytes, ctype: str = "text/plain; charset=utf-8") -> bytes:
    return (
        b"Subject: test\r\n"
        b"Content-Type: " + ctype.encode() + b"\r\n"
        b"Content-Transfer-Encoding: " + cte.encode() + b"\r\n\r\n" + body
    )


def test_base64_part() -> None:
    body = base64.b64encode("Xin chào thầy".encode())
    parts, errors = decode_mime_message(_single("base64", body), LIMIT)
    assert errors == []
    assert parts == [
        {
            "content_type": "text/plain",
            "transfer_encoding": "base64",
            "body": "Xin chào thầy",
            "decode_status": "ok",
            "size": len("Xin chào thầy".encode()),
        }
    ]


def test_base64_missing_padding_and_line_breaks() -> None:
    encoded = base64.b64encode(b"hello world!!").rstrip(b"=")  # "aGVsbG8gd29ybGQhIQ"
    wrapped = encoded[:8] + b"\r\n" + encoded[8:]
    data, error = decode_base64(wrapped)
    assert (data, error) == (b"hello world!!", None)


def test_invalid_base64_is_failed_but_kept() -> None:
    parts, errors = decode_mime_message(_single("base64", b"!!!not base64!!!"), LIMIT)
    assert parts[0]["decode_status"] == "failed"
    assert parts[0]["body"] == "!!!not base64!!!"
    assert "invalid base64" in errors[0]


def test_quoted_printable_part() -> None:
    qp = b"Caf=C3=A9 =3D 3 =E2=82=AC, d=C3=B2ng d=C3=A0i=\r\n ti=E1=BA=BFp"
    parts, _ = decode_mime_message(_single("quoted-printable", qp), LIMIT)
    assert parts[0]["body"] == "Café = 3 €, dòng dài tiếp"
    assert parts[0]["decode_status"] == "ok"


def test_7bit_is_not_applicable() -> None:
    parts, errors = decode_mime_message(b"Subject: x\r\n\r\nplain body\r\n", LIMIT)
    assert parts[0]["transfer_encoding"] == "7bit"
    assert parts[0]["decode_status"] == "not_applicable"
    assert parts[0]["body"] == "plain body\r\n"
    assert errors == []


def test_multipart_mixed() -> None:
    raw = (
        b"Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n"
        b"--XYZ\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\nB=C3=A0i t=E1=BA=ADp 2\r\n"
        b"--XYZ\r\nContent-Type: application/pdf\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n"
        b"--XYZ--\r\n"
    )
    parts, errors = decode_mime_message(raw, LIMIT)
    assert [p["content_type"] for p in parts] == ["text/plain", "application/pdf"]
    assert parts[0]["body"].startswith("Bài tập 2")
    assert parts[1]["body"] is None  # binary part is not turned into text
    assert parts[1]["size"] == 9  # "%PDF-1.4\n"
    assert errors == []


def test_invalid_charset_bytes_are_partial() -> None:
    body = base64.b64encode(b"caf\xe9")  # latin-1 bytes, declared utf-8
    parts, errors = decode_mime_message(_single("base64", body), LIMIT)
    assert parts[0]["decode_status"] == "partial"
    assert parts[0]["body"] == "caf�"
    assert "invalid UTF-8" in errors[0]


def test_declared_latin1_charset() -> None:
    body = base64.b64encode(b"caf\xe9")
    parts, _ = decode_mime_message(
        _single("base64", body, "text/plain; charset=iso-8859-1"), LIMIT
    )
    assert parts[0]["body"] == "café"


def test_size_limit_truncates() -> None:
    body = base64.b64encode(b"A" * 100)
    parts, errors = decode_mime_message(_single("base64", body), 10)
    assert parts[0]["body"] == "A" * 10
    assert parts[0]["decode_status"] == "partial"
    assert "truncated_for_decode" in errors[0]


def test_smtp_data_framing() -> None:
    data = b"Subject: x\r\n\r\n..leading dot\r\nline\r\n.\r\n"
    assert smtp_data_to_message(data) == b"Subject: x\r\n\r\n.leading dot\r\nline\r\n"


def test_8bit_body_keeps_original_bytes() -> None:
    raw = b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\ncaf\xe9"
    parts, _ = decode_mime_message(raw, LIMIT)
    assert parts[0]["body"] == "caf\u00e9"  # declared charset fallback
    assert parts[0]["decode_status"] == "partial"


def test_garbage_does_not_crash() -> None:
    parts, _ = decode_mime_message(b"\xff\xfe\x00garbage", LIMIT)
    assert len(parts) == 1
    assert parts[0]["body"] == "\ufffd\ufffd\x00garbage"
    assert parts[0]["decode_status"] == "partial"
