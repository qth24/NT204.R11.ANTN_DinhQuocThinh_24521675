"""T01 - HTTP URL decode: decoded URI correct, raw URI kept unchanged."""

from __future__ import annotations

from conftest import committed, run_case


def test_t01_http_url_decode() -> None:
    events, flows = run_case("T01")
    by_id = {e["packet_id"]: e for e in events}

    first = by_id[1]
    assert first["app_data"]["uri"] == (
        "/search%20page/a+b?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&lang=vi+VN&empty="
    )  # raw URI untouched
    assert first["decoded"]["uri"] == (
        "/search page/a+b?q=<script>alert(1)</script>&lang=vi VN&empty="
    )
    assert first["decoded"]["query_params"] == {
        "q": ["<script>alert(1)</script>"],
        "lang": ["vi VN"],  # "+" is a space in the query...
        "empty": [""],
    }
    assert (
        first["normalized"]["uri_path"] == "/search page/a+b"
    )  # ...but not in the path

    assert by_id[2]["decoded"]["query_params"]["id"] == ["1' OR 1=1--"]

    double = by_id[3]
    assert (
        double["decoded"]["uri"] == "/%2e%2e/%2e%2e/etc/passwd?f=%27"
    )  # one layer only
    assert double["decoded"]["double_encoded"] is True

    assert by_id[4]["decoded"]["uri"] == "/files/report+final v2.pdf"
    assert by_id[5]["decoded"]["uri"] == "/a b?x=1"  # absolute-form target
    assert by_id[6]["decoded"]["form_params"] == {
        "username": ["admin'--"],
        "password": ["P@ss word!"],
    }
    assert all(e["decode_status"] == "ok" for e in events)
    assert all(e["preprocess_status"] == "valid" for e in events)

    assert events == committed("T01", "events.jsonl")
    assert flows == committed("T01", "flows.jsonl")
