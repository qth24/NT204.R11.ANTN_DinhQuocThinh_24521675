"""T02 - HTML entity: &lt;...&gt; decoded correctly, no crash."""

from __future__ import annotations

from tests.bt2.conftest import committed, run_case


def test_t02_html_entity() -> None:
    events, flows = run_case("T02")
    body = {e["packet_id"]: e["decoded"]["body_text"] for e in events}

    assert body[1] == "<p>Comment: <script>alert('XSS')</script></p>"
    assert body[2] == "Tom & Jerry © 2025 😀 €"
    # double-encoded: decoded once, flagged
    assert body[3] == "&lt;script&gt;double&lt;/script&gt;"
    assert events[2]["decoded"]["double_encoded"] is True
    # malformed / unknown references: HTML5 rules, no exception
    assert body[4] == "broken: ¬anentity; � &#xZZ; & alone"
    # not text/html, text/plain or form: entities are left alone
    assert body[5] == '{"msg": "&lt;b&gt; stays encoded in JSON"}'
    # binary content is never decoded
    assert body[6] is None
    assert events[5]["decode_status"] == "not_applicable"
    # form: URL decoding then HTML entity decoding of the parameters
    assert events[6]["decoded"]["form_params"] == {
        "comment": ["<img src=x onerror=alert(1)>"],
        "name": ["Thịnh"],
    }
    assert [e["decode_status"] for e in events] == ["ok"] * 5 + ["not_applicable", "ok"]

    assert events == committed("T02", "events.jsonl")
    assert flows == committed("T02", "flows.jsonl")
