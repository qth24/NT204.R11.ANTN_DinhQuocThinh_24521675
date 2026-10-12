"""Decoder stage (BT2): turn encoded fields of an IDS event into plain text.

Input:  event dict produced by BT1 (+ optional raw application payload bytes,
        which the pipeline passes along; JSONL input has none).
Output: the same dict with three new keys (original fields are never changed):

    "decoded":       HTTP -> {"uri", "query_params", "form_params", "body_text",
                              "double_encoded"}
                     SMTP message data -> {"mime_parts", "body_text"}
                     anything else -> {}
    "decode_status": "ok" | "partial" | "failed" | "not_applicable"
    "decode_errors": [str]
"""

from __future__ import annotations

from typing import Any

from config import DecoderConfig
from decoder.charset import charset_from_content_type, decode_bytes
from decoder.html_decoder import should_unescape, unescape_html, unescape_params
from decoder.mime_decoder import decode_mime_message, smtp_data_to_message
from decoder.url_decoder import decode_form, decode_uri

FORM_TYPE = "application/x-www-form-urlencoded"
# Media types decoded to body_text in addition to text/*
_TEXT_LIKE = (
    "application/json",
    "application/xml",
    "application/javascript",
    FORM_TYPE,
)


def decode_event(
    event: dict[str, Any], cfg: DecoderConfig, payload: bytes | None = None
) -> dict[str, Any]:
    """Add decoded / decode_status / decode_errors to ``event`` and return it.

    Never raises: an internal error gives decode_status "failed".
    """
    event["decoded"] = {}
    event["decode_status"] = "not_applicable"
    event["decode_errors"] = []
    if not cfg.enabled:
        return event

    statuses: list[str] = []
    errors: list[str] = []
    try:
        app = event.get("app_protocol")
        data = event.get("app_data") or {}
        if app == "HTTP":
            event["decoded"] = _decode_http(data, payload, cfg, statuses, errors)
        elif app == "SMTP" and data.get("type") == "data":
            event["decoded"] = _decode_smtp(data, payload, cfg, statuses, errors)
    except Exception as exc:  # noqa: BLE001 - a decoder bug must not stop the pipeline
        statuses.append("failed")
        errors.append(f"decoder internal error: {exc}")

    event["decode_status"] = _overall_status(statuses, errors)
    event["decode_errors"] = errors
    return event


# --- HTTP -------------------------------------------------------------------


def _decode_http(
    data: dict[str, Any],
    payload: bytes | None,
    cfg: DecoderConfig,
    statuses: list[str],
    errors: list[str],
) -> dict[str, Any]:
    decoded: dict[str, Any] = {
        "uri": None,
        "query_params": None,
        "form_params": None,
        "body_text": None,
        "double_encoded": False,
    }

    # 1. Request target: percent-decoding (raw app_data["uri"] is kept as is)
    raw_uri = data.get("uri")
    if data.get("type") == "request" and isinstance(raw_uri, str):
        uri = decode_uri(raw_uri)
        decoded["uri"] = uri.uri
        decoded["query_params"] = uri.query_params
        decoded["double_encoded"] = uri.double_encoded
        statuses.append(uri.status)
        errors.extend(uri.errors)

    # 2. Body: charset -> (form decoding) -> HTML entities
    if data.get("type") not in ("request", "response"):
        return decoded  # continuation segment: no headers, content type unknown
    body = _http_body_bytes(data, payload, errors)
    content_type = data.get("content_type")
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if not body or not (media_type.startswith("text/") or media_type in _TEXT_LIKE):
        return decoded  # no body, or binary content: never decoded as text

    if len(body) > cfg.max_body_bytes:
        body = body[: cfg.max_body_bytes]
        errors.append("truncated_for_decode")
        statuses.append("partial")

    text = decode_bytes(body, charset_from_content_type(content_type))
    statuses.append(text.status)
    if text.error:
        errors.append(f"body: {text.error}")

    if media_type == FORM_TYPE:
        form = decode_form(text.text)
        params, html_double = unescape_params(form.params)
        decoded["form_params"] = params
        decoded["double_encoded"] |= form.double_encoded or html_double
        statuses.append(form.status)
        errors.extend(form.errors)

    if should_unescape(content_type):
        html = unescape_html(text.text)
        decoded["body_text"] = html.text
        decoded["double_encoded"] |= html.double_encoded
    else:
        decoded["body_text"] = text.text
    return decoded


def _http_body_bytes(
    data: dict[str, Any], payload: bytes | None, errors: list[str]
) -> bytes:
    """Body bytes: from the real payload when available, else from BT1 text."""
    if payload:
        for sep in (b"\r\n\r\n", b"\n\n"):
            idx = payload.find(sep)
            if idx != -1:
                return payload[idx + len(sep) :]
        return b""
    body = data.get("body")
    if not isinstance(body, str):
        return b""
    if "�" in body:
        errors.append(
            "body: original bytes unavailable, parser already replaced invalid bytes"
        )
    return body.encode("utf-8")


# --- SMTP -------------------------------------------------------------------


def _decode_smtp(
    data: dict[str, Any],
    payload: bytes | None,
    cfg: DecoderConfig,
    statuses: list[str],
    errors: list[str],
) -> dict[str, Any]:
    if payload:
        raw = payload
    else:
        preview = data.get("preview")
        raw = preview.encode("utf-8") if isinstance(preview, str) else b""
        length = data.get("length")
        if isinstance(length, int) and length > len(raw):
            errors.append("only the parser preview is available, message cut")
            statuses.append("partial")

    parts, part_errors = decode_mime_message(
        smtp_data_to_message(raw), cfg.max_body_bytes
    )
    errors.extend(part_errors)
    statuses.extend(part["decode_status"] for part in parts)
    text_parts = [
        p["body"]
        for p in parts
        if p["body"] is not None and p["content_type"].startswith("text/")
    ]
    return {
        "mime_parts": parts,
        "body_text": text_parts[0] if text_parts else None,
    }


# --- status -----------------------------------------------------------------


def _overall_status(statuses: list[str], errors: list[str]) -> str:
    """Combine per-step statuses into one decode_status.

    * nothing decodable                       -> not_applicable
    * every decodable step failed            -> failed
    * at least one partial/failed or an error -> partial
    * otherwise                               -> ok
    """
    relevant = [s for s in statuses if s != "not_applicable"]
    if not relevant:
        return "partial" if errors else "not_applicable"
    if all(s == "failed" for s in relevant):
        return "failed"
    if errors or any(s in ("partial", "failed") for s in relevant):
        return "partial"
    return "ok"
