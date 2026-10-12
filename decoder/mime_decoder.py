"""SMTP message (DATA) -> MIME parts with Base64 / Quoted-Printable decoded.

Input:  raw bytes of the message sent after the SMTP ``DATA`` command.
Output: list of parts ``{"content_type", "transfer_encoding", "body",
        "decode_status", "size"}`` + list of errors.

Per part, decoding follows its ``Content-Transfer-Encoding`` header:
* base64           -> ``base64.b64decode`` (missing "=" padding is restored)
* quoted-printable -> ``quopri.decodestring``
* anything else (7bit, 8bit, binary, missing) -> "not_applicable", body as is
Text parts are then turned into str with ``decoder.charset`` (declared
``charset=`` of the part as fallback). Non-text parts keep body=None.
"""

from __future__ import annotations

import base64
import binascii
import email
import email.policy
import quopri
import re
from typing import Any

from decoder.charset import decode_bytes

_B64_WHITESPACE = re.compile(rb"\s+")


def smtp_data_to_message(data: bytes) -> bytes:
    """Undo SMTP DATA framing: drop the final "." line and dot-stuffing.

    RFC 5321 4.5.2: a line starting with "." is sent as ".." by the client.
    """
    lines = data.split(b"\r\n")
    if len(lines) >= 2 and lines[-1] == b"" and lines[-2] == b".":
        lines = lines[:-2] + [b""]  # "<CRLF>.<CRLF>" terminator
    elif lines and lines[-1] == b".":
        lines = lines[:-1]
    return b"\r\n".join(line[1:] if line.startswith(b"..") else line for line in lines)


def decode_mime_message(
    raw: bytes, max_body_bytes: int
) -> tuple[list[dict[str, Any]], list[str]]:
    """Split a message into leaf MIME parts and decode each of them."""
    message = email.message_from_bytes(raw, policy=email.policy.compat32)
    parts: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, part in enumerate(p for p in message.walk() if not p.is_multipart()):
        decoded, part_errors = _decode_part(part, max_body_bytes)
        parts.append(decoded)
        errors.extend(f"mime part {index}: {e}" for e in part_errors)
    return parts, errors


def decode_base64(data: bytes) -> tuple[bytes, str | None]:
    """Decode Base64, tolerating line breaks and missing padding.

    Returns (decoded, error); error is set when the data is not Base64.
    """
    compact = _B64_WHITESPACE.sub(b"", data)
    compact += b"=" * (-len(compact) % 4)  # restore missing padding
    try:
        return base64.b64decode(compact, validate=True), None
    except (binascii.Error, ValueError) as exc:
        return b"", f"invalid base64: {exc}"


def _decode_part(
    part: email.message.Message, max_body_bytes: int
) -> tuple[dict, list[str]]:
    content_type = part.get_content_type()
    encoding = str(part.get("Content-Transfer-Encoding", "7bit")).strip().lower()
    errors: list[str] = []

    if encoding in ("base64", "quoted-printable"):
        # Encoded content is pure ASCII, so the undecoded str is exact; we
        # decode it ourselves to control padding and report errors.
        raw = str(part.get_payload(decode=False)).encode("ascii", "replace")
    else:
        # For 7bit/8bit/binary, decode=True returns the original bytes
        # (decode=False would replace 8-bit bytes with U+FFFD).
        payload = part.get_payload(decode=True)
        raw = payload if isinstance(payload, bytes) else b""

    if encoding == "base64":
        data, error = decode_base64(raw)
        status = "failed" if error else "ok"
        if error:
            errors.append(error)
            data = raw  # keep the original text so analysts still see it
    elif encoding == "quoted-printable":
        data, status = quopri.decodestring(raw), "ok"
    else:
        data, status = raw, "not_applicable"

    if len(data) > max_body_bytes:
        data = data[:max_body_bytes]
        errors.append("truncated_for_decode")
        status = "partial" if status != "failed" else status

    body: str | None = None
    if part.get_content_maintype() == "text" or status == "failed":
        text = decode_bytes(data, part.get_content_charset())
        body = text.text
        if text.error:
            errors.append(text.error)
            if status in ("ok", "not_applicable"):
                status = "partial"

    return {
        "content_type": content_type,
        "transfer_encoding": encoding,
        "body": body,
        "decode_status": status,
        "size": len(data),
    }, errors
