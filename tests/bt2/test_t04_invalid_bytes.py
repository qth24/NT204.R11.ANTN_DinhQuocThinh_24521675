"""T04 - Invalid bytes: non UTF-8 payload -> partial + error, processing goes on."""

from __future__ import annotations

from tests.bt2.conftest import committed, run_case


def test_t04_invalid_bytes() -> None:
    events, flows = run_case("T04")
    by_id = {e["packet_id"]: e for e in events}

    assert [by_id[i]["decode_status"] for i in range(1, 8)] == ["partial"] * 6 + ["ok"]

    # 1. no charset: invalid bytes replaced by U+FFFD
    assert by_id[1]["decoded"]["body_text"] == "Gi� tr�� kh�ng hợp l�"
    assert by_id[1]["decode_errors"] == [
        "body: invalid UTF-8 at byte 2; undecodable bytes replaced"
    ]
    # 2. declared charset used as fallback -> no information lost
    assert by_id[2]["decoded"]["body_text"] == "<p>Café crème</p>"
    assert "decoded as declared iso8859-1" in by_id[2]["decode_errors"][0]
    # 3. %E9 / %FF are not valid UTF-8 after percent-decoding
    assert by_id[3]["decoded"]["uri"] == "/caf�?name=��"
    assert by_id[3]["app_data"]["uri"] == "/caf%E9?name=%FF%FE"
    # 4. raw invalid bytes inside a form body
    assert by_id[4]["decoded"]["form_params"] == {"name": ["Thịnh"], "city": ["��HCM"]}
    # 5. unknown declared charset
    assert "unknown declared charset 'no-such-charset'" in by_id[5]["decode_errors"][0]
    # 6. SMTP base64 part declared utf-8 but holding latin-1 bytes
    assert by_id[6]["decoded"]["mime_parts"][0]["body"] == "caf�"
    # partial decoding is reported by the preprocessor too
    assert all(by_id[i]["reason"] == ["decode_partial"] for i in range(1, 7))
    assert by_id[7]["preprocess_status"] == "valid"

    assert events == committed("T04", "events.jsonl")
    assert flows == committed("T04", "flows.jsonl")
