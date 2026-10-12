"""T06 - Missing field: optional fields missing -> null / [] / {} consistently."""

from __future__ import annotations

from tests.bt2.conftest import committed, run_case


def test_t06_missing_field() -> None:
    events, flows = run_case("T06")

    # Every event ends up with exactly the same set of keys
    assert len({tuple(sorted(e)) for e in events}) == 1
    first, tcp_no_ports, http_no_uri, http_null_data = events[:4]

    # missing scalar -> None, missing list -> [], missing dict -> {}
    assert (first["src_port"], first["app_protocol"], first["error"]) == (
        None,
        None,
        None,
    )
    assert first["tcp_flags"] == []
    assert first["app_data"] == {}
    assert first["decoded"] == {} and first["decode_errors"] == []
    assert http_null_data["app_data"] == {}  # null dict -> {}

    # TCP/UDP without ports: partial, reasons listed, no flow (portless = skip)
    for event in (first, tcp_no_ports):
        assert event["preprocess_status"] == "partial"
        assert event["reason"] == ["missing_field:src_port", "missing_field:dst_port"]
        assert (event["flow_id"], event["direction"]) == (None, None)

    # HTTP without uri/headers: decoded keys exist with null, headers -> {}
    assert http_no_uri["decoded"] == {
        "uri": None,
        "query_params": None,
        "form_params": None,
        "body_text": None,
        "double_encoded": False,
    }
    assert http_no_uri["normalized"]["http_headers"] == {}
    assert http_no_uri["normalized"]["uri_path"] is None
    assert http_no_uri["preprocess_status"] == "valid"

    # DNS without questions / SMTP data without preview: no exception
    assert events[4]["normalized"]["domain"] is None
    assert events[5]["decoded"]["body_text"] == ""
    assert [e["processing_action"] for e in events] == ["mark", "mark"] + ["pass"] * 5
    assert len(flows) == 5

    assert events == committed("T06", "events.jsonl")
    assert flows == committed("T06", "flows.jsonl")
