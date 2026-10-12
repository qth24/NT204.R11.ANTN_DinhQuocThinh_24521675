"""T03 - SMTP Base64/QP: decoded body correct + decode_status."""

from __future__ import annotations

from tests.bt2.conftest import committed, run_case


def test_t03_smtp_mime() -> None:
    events, flows = run_case("T03")
    assert [e["app_protocol"] for e in events] == ["SMTP"] * 5
    parts = [e["decoded"]["mime_parts"] for e in events]

    # 1. base64 (split over two lines) -> UTF-8 text
    assert parts[0][0]["transfer_encoding"] == "base64"
    assert parts[0][0]["body"] == "Chào thầy, em gửi bài tập 2 IDS."
    assert events[0]["decoded"]["body_text"] == "Chào thầy, em gửi bài tập 2 IDS."
    # 2. quoted-printable with =3D and a soft line break
    assert parts[1][0]["body"] == "Chào thầy, 1 + 1 = 2 và dòng này rất dài.\r\n"
    # 3. multipart: QP text + base64 PDF whose "=" padding was removed
    assert [(p["content_type"], p["transfer_encoding"]) for p in parts[2]] == [
        ("text/plain", "quoted-printable"),
        ("application/pdf", "base64"),
    ]
    assert parts[2][0]["body"] == "Bài nộp kèm file."
    assert (parts[2][1]["body"], parts[2][1]["size"]) == (None, 20)
    # 4. invalid base64 -> failed, original text kept
    assert parts[3][0]["decode_status"] == "failed"
    assert parts[3][0]["body"] == "!!!this is not base64!!!\r\n"
    assert "invalid base64" in events[3]["decode_errors"][0]
    # 5. no Content-Transfer-Encoding (7bit) -> not_applicable
    assert parts[4][0]["transfer_encoding"] == "7bit"

    assert [e["decode_status"] for e in events] == [
        "ok",
        "ok",
        "ok",
        "failed",
        "not_applicable",
    ]
    assert events == committed("T03", "events.jsonl")
    assert flows == committed("T03", "flows.jsonl")
