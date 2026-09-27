"""SMTP parser (RFC 5321): client commands, server replies and message data.

Input: TCP payload classified as SMTP by ``parsers.app_detector``.
Output: ``AppResult`` whose ``data`` is one of:

* command:  {"type": "command", "commands": [{"command", "argument"}],
             "helo", "mail_from", "rcpt_to", "auth_mechanism"}
* response: {"type": "response", "status_code", "status_class",
             "enhanced_status", "message",
             "replies": [{"code", "lines", "enhanced_status"}]}
* data:     {"type": "data", "subject", "from", "to", "length",
             "end_of_data", "preview"}  (e-mail content sent after DATA)

One TCP segment may hold several commands (PIPELINING, RFC 2920) or a
multi-line reply ("250-..." lines followed by "250 ..."), so every line is
parsed.
"""

from __future__ import annotations

import re
from typing import Any

from parsers.app import AppResult

MAX_DATA_PREVIEW = 512

KNOWN_COMMANDS = frozenset(
    {
        "HELO",
        "EHLO",
        "MAIL",
        "RCPT",
        "DATA",
        "BDAT",
        "RSET",
        "VRFY",
        "EXPN",
        "HELP",
        "NOOP",
        "QUIT",
        "AUTH",
        "STARTTLS",
    }
)

STATUS_CLASSES = {
    "2": "positive_completion",
    "3": "positive_intermediate",  # e.g. 354 start mail input
    "4": "transient_negative",  # try again later
    "5": "permanent_negative",  # rejected
}

_REPLY_LINE_RE = re.compile(r"^(?P<code>\d{3})(?P<sep>[ -]|$)(?P<text>.*)$")
_ENHANCED_STATUS_RE = re.compile(r"^([245]\.\d{1,3}\.\d{1,3})\b")
# "FROM:<a@b.c> SIZE=100" / "TO: <a@b.c>" - address may be empty (<>)
_PATH_RE = re.compile(
    r"^(?P<kw>FROM|TO):\s*<(?P<addr>[^>]*)>(?P<params>.*)$", re.IGNORECASE
)
_HEADER_RE = re.compile(r"^(Subject|From|To):\s*(.*)$", re.IGNORECASE)


def parse_smtp(payload: bytes) -> AppResult:
    """Parse an SMTP segment (command(s), reply or message data).

    Never raises: problems go to ``AppResult.error`` together with the
    fields that could be extracted.
    """
    try:
        return _parse(payload)
    except Exception as exc:  # noqa: BLE001 - a parser bug must not stop the IDS
        return AppResult(error=f"SMTP parse error: {exc}")


def _parse(payload: bytes) -> AppResult:
    # SMTP is 7-bit ASCII (UTF-8 with SMTPUTF8); never fail on bad bytes.
    text = payload.decode("utf-8", errors="replace")
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return AppResult(data={"type": "empty"}, error="Empty SMTP payload")

    if _REPLY_LINE_RE.match(lines[0]):
        return _parse_replies(lines)
    first_word = lines[0].split(" ", 1)[0].upper()
    if first_word in KNOWN_COMMANDS:
        return _parse_commands(lines)
    return _parse_data(text, len(payload))


def _parse_commands(lines: list[str]) -> AppResult:
    data: dict[str, Any] = {
        "type": "command",
        "commands": [],
        "helo": None,
        "mail_from": None,
        "rcpt_to": [],
        "auth_mechanism": None,
    }
    errors: list[str] = []

    for line in lines:
        verb, _, argument = line.strip().partition(" ")
        verb = verb.upper()
        argument = argument.strip()
        if verb not in KNOWN_COMMANDS:
            errors.append(f"Unknown SMTP command: {line[:50]!r}")
            continue

        if verb in ("HELO", "EHLO"):
            data["helo"] = argument or None
            if not argument:
                errors.append(f"{verb} without domain")
        elif verb in ("MAIL", "RCPT"):
            keyword = "FROM" if verb == "MAIL" else "TO"
            match = _PATH_RE.match(argument)
            if not match or match["kw"].upper() != keyword:
                errors.append(f"Malformed {verb} {keyword}: {argument[:80]!r}")
            elif verb == "MAIL":
                data["mail_from"] = match["addr"]  # "" = null sender (bounces)
                params = match["params"].strip()
                if params:
                    data["mail_params"] = params
            else:
                data["rcpt_to"].append(match["addr"])
        elif verb == "AUTH":
            mechanism, _, initial = argument.partition(" ")
            data["auth_mechanism"] = mechanism.upper() or None
            if initial:
                # AUTH PLAIN <base64> carries the password: never log it.
                argument = f"{mechanism} [redacted]"

        data["commands"].append({"command": verb, "argument": argument or None})

    return AppResult(data=data, error="; ".join(errors) or None)


def _parse_replies(lines: list[str]) -> AppResult:
    """Group reply lines: "250-x" continues a reply, "250 y" ends it."""
    replies: list[dict[str, Any]] = []
    errors: list[str] = []
    current: dict[str, Any] | None = None

    for line in lines:
        match = _REPLY_LINE_RE.match(line)
        if not match:
            errors.append(f"Malformed SMTP reply line: {line[:50]!r}")
            continue
        code = int(match["code"])
        if current is None or current["code"] != code:
            current = {"code": code, "lines": []}
            replies.append(current)
        current["lines"].append(match["text"].strip())
        if match["sep"] != "-":
            current = None  # last line of this reply

    for reply in replies:
        enhanced = _ENHANCED_STATUS_RE.match(reply["lines"][0])
        reply["enhanced_status"] = enhanced.group(1) if enhanced else None
        if str(reply["code"])[0] not in STATUS_CLASSES:
            errors.append(f"Invalid SMTP reply code {reply['code']}")

    if not replies:
        return AppResult(data={"type": "response"}, error="; ".join(errors))

    first = replies[0]
    data = {
        "type": "response",
        "status_code": first["code"],
        "status_class": STATUS_CLASSES.get(str(first["code"])[0], "invalid"),
        "enhanced_status": first["enhanced_status"],
        "message": " ".join(first["lines"]),
        "replies": replies,
    }
    return AppResult(data=data, error="; ".join(errors) or None)


def _parse_data(text: str, length: int) -> AppResult:
    """E-mail content sent between DATA and the terminating "." line."""
    data: dict[str, Any] = {
        "type": "data",
        "subject": None,
        "from": None,
        "to": None,
        "length": length,
        # "<CRLF>.<CRLF>" marks the end of the message
        "end_of_data": text.endswith("\r\n.\r\n") or text.strip() == ".",
        "preview": text[:MAX_DATA_PREVIEW],
    }
    # Only the message headers (before the first blank line) are scanned.
    for line in text.split("\r\n\r\n", 1)[0].splitlines():
        match = _HEADER_RE.match(line)
        if match and data[match.group(1).lower()] is None:
            data[match.group(1).lower()] = match.group(2).strip()
    return AppResult(data=data)
