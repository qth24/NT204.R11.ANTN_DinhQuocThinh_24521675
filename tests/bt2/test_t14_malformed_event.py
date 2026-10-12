"""T14 - Malformed event: invalid/unsupported events never crash and get a
fitting status/reason; with the "drop" policy they never reach the tracker."""

from __future__ import annotations

from tests.bt2.conftest import committed, run_case

DROP = ["preprocess.on_invalid=drop", "preprocess.on_unsupported=drop"]


def test_t14_malformed_event_mark() -> None:
    events, flows = run_case("T14")
    assert len(events) == 15
    status = [e["preprocess_status"] for e in events]
    assert status == ["invalid"] * 9 + [
        "partial",
        "invalid",
        "invalid",
        "partial",
        "invalid",
        "valid",
    ]
    reasons = [e["reason"] for e in events]

    # broken input lines -> event with only an error, every core field missing
    assert "invalid JSON" in events[0]["error"]
    assert "not a JSON object" in events[1]["error"]
    assert reasons[0][:5] == [
        "missing_field:packet_id",
        "missing_field:timestamp",
        "missing_field:src_ip",
        "missing_field:dst_ip",
        "missing_field:protocol",
    ]
    assert reasons[4] == ["invalid_ip:'999.10.10.10'"]
    assert reasons[5] == ["invalid_ip:12345"]
    assert reasons[6] == ["invalid_timestamp:-5"]
    assert reasons[7] == ["invalid_timestamp:'yesterday'"]
    assert reasons[8] == ["invalid_timestamp:nan"]
    assert reasons[9] == ["invalid_port:70000", "invalid_port:-1"]
    assert reasons[10] == ["unsupported_protocol:ICMP"]
    assert reasons[11] == [
        "missing_field:src_ip",
        "missing_field:dst_ip",
        "unsupported_protocol:UNKNOWN",
    ]
    assert reasons[12] == ["invalid_field:tcp_flags", "decode_failed"]
    assert events[12]["decode_errors"] == ["app_data is not an object (list)"]
    assert reasons[13] == ["invalid_packet_id:'fourteen'"]

    # policy "mark": everything kept and flagged
    assert [e["processing_action"] for e in events] == ["mark"] * 14 + ["pass"]
    # events whose time or endpoints are unusable never join a flow
    with_flow = [e["packet_id"] for e in events if e["flow_id"]]
    assert with_flow == [13, "fourteen", 15]
    assert len(flows) == 3

    assert events == committed("T14", "events.jsonl")
    assert flows == committed("T14", "flows.jsonl")


def test_t14_malformed_event_drop_policy() -> None:
    events, flows = run_case("T14", DROP)
    actions = [e["processing_action"] for e in events]
    assert actions.count("drop") == 12  # every invalid event (log_dropped = true)
    assert all(e["flow_id"] is None for e in events if e["processing_action"] == "drop")
    assert [e["packet_id"] for e in events if e["processing_action"] != "drop"] == [
        10,
        13,
        15,
    ]
    assert len(flows) == 2  # only events 13 and 15 have usable endpoints

    assert events == committed("T14", "events_drop.jsonl")
    assert flows == committed("T14", "flows_drop.jsonl")
