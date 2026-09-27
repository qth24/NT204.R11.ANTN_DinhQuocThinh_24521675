"""Unit tests for the SMTP parser."""

from __future__ import annotations

import json

from parsers.app.smtp_parser import parse_smtp


def test_ehlo() -> None:
    result = parse_smtp(b"EHLO client.example.com\r\n")
    assert result.error is None
    assert result.data["type"] == "command"
    assert result.data["helo"] == "client.example.com"
    assert result.data["commands"] == [
        {"command": "EHLO", "argument": "client.example.com"}
    ]


def test_mail_from_and_rcpt_to() -> None:
    mail = parse_smtp(b"MAIL FROM:<alice@example.com> SIZE=1024\r\n")
    assert mail.error is None
    assert mail.data["mail_from"] == "alice@example.com"
    assert mail.data["mail_params"] == "SIZE=1024"

    rcpt = parse_smtp(b"rcpt to: <bob@example.org>\r\n")
    assert rcpt.error is None
    assert rcpt.data["rcpt_to"] == ["bob@example.org"]
    assert rcpt.data["commands"][0]["command"] == "RCPT"


def test_null_sender() -> None:
    assert parse_smtp(b"MAIL FROM:<>\r\n").data["mail_from"] == ""


def test_pipelined_commands() -> None:
    payload = (
        b"MAIL FROM:<a@x.com>\r\n"
        b"RCPT TO:<b@y.com>\r\n"
        b"RCPT TO:<c@z.com>\r\n"
        b"DATA\r\n"
    )
    data = parse_smtp(payload).data
    assert [c["command"] for c in data["commands"]] == ["MAIL", "RCPT", "RCPT", "DATA"]
    assert data["rcpt_to"] == ["b@y.com", "c@z.com"]


def test_auth_credentials_are_redacted() -> None:
    result = parse_smtp(b"AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n")
    assert result.data["auth_mechanism"] == "PLAIN"
    assert result.data["commands"][0]["argument"] == "PLAIN [redacted]"
    assert "AGFsaWNl" not in json.dumps(result.data)


def test_malformed_commands_reported() -> None:
    result = parse_smtp(b"MAIL alice@example.com\r\nHELO\r\n")
    assert "Malformed MAIL FROM" in result.error
    assert "HELO without domain" in result.error
    # Malformed commands are still recorded (useful for the IDS), just flagged
    assert [c["command"] for c in result.data["commands"]] == ["MAIL", "HELO"]
    assert result.data["mail_from"] is None


def test_unknown_command_in_command_segment() -> None:
    result = parse_smtp(b"NOOP\r\nXYZZY now\r\n")
    assert result.data["commands"] == [{"command": "NOOP", "argument": None}]
    assert "Unknown SMTP command" in result.error


def test_single_line_reply() -> None:
    result = parse_smtp(b"250 2.1.0 Sender OK\r\n")
    data = result.data
    assert result.error is None
    assert data["type"] == "response"
    assert data["status_code"] == 250
    assert data["status_class"] == "positive_completion"
    assert data["enhanced_status"] == "2.1.0"
    assert data["message"] == "2.1.0 Sender OK"


def test_greeting_and_error_classes() -> None:
    assert parse_smtp(b"220 mail.example.com ESMTP\r\n").data["status_code"] == 220
    assert parse_smtp(b"354 End data with <CR><LF>.<CR><LF>\r\n").data[
        "status_class"
    ] == ("positive_intermediate")
    assert parse_smtp(b"421 Try later\r\n").data["status_class"] == (
        "transient_negative"
    )
    rejected = parse_smtp(b"550 5.1.1 User unknown\r\n").data
    assert rejected["status_class"] == "permanent_negative"
    assert rejected["enhanced_status"] == "5.1.1"


def test_multiline_ehlo_reply() -> None:
    payload = (
        b"250-mail.example.com Hello\r\n"
        b"250-SIZE 35882577\r\n"
        b"250-PIPELINING\r\n"
        b"250 STARTTLS\r\n"
    )
    data = parse_smtp(payload).data
    assert data["status_code"] == 250
    assert len(data["replies"]) == 1
    assert data["replies"][0]["lines"] == [
        "mail.example.com Hello",
        "SIZE 35882577",
        "PIPELINING",
        "STARTTLS",
    ]


def test_pipelined_replies() -> None:
    data = parse_smtp(b"250 OK\r\n250 OK\r\n354 Go ahead\r\n").data
    assert [r["code"] for r in data["replies"]] == [250, 250, 354]
    assert data["status_code"] == 250


def test_invalid_reply_code() -> None:
    result = parse_smtp(b"999 what\r\n")
    assert result.data["status_code"] == 999
    assert result.data["status_class"] == "invalid"
    assert "Invalid SMTP reply code" in result.error


def test_message_data() -> None:
    payload = (
        b"From: Alice <alice@example.com>\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: Hello\r\n"
        b"\r\n"
        b"Hi Bob,\r\nSubject: not a header\r\n.\r\n"
    )
    data = parse_smtp(payload).data
    assert data["type"] == "data"
    assert data["subject"] == "Hello"
    assert data["from"] == "Alice <alice@example.com>"
    assert data["to"] == "bob@example.org"
    assert data["end_of_data"] is True
    assert data["length"] == len(payload)


def test_empty_and_binary_payload() -> None:
    assert parse_smtp(b"").error == "Empty SMTP payload"
    assert parse_smtp(b"\r\n\r\n").data["type"] == "empty"
    result = parse_smtp(b"\xff\xfe\x00garbage\x81")
    assert result.data["type"] == "data"
    json.dumps(result.data)
