"""T08 - Bidirectional: A->B and B->A share one flow_id, direction is correct."""

from __future__ import annotations

from tests.bt2.conftest import committed, run_case

CLIENT = ("192.168.1.10", 51300)


def test_t08_bidirectional() -> None:
    events, flows = run_case("T08")
    assert len(events) == 7
    assert len({e["flow_id"] for e in events}) == 1
    for event in events:
        from_client = (event["src_ip"], event["src_port"]) == CLIENT
        assert event["direction"] == ("forward" if from_client else "backward")
    assert [e["direction"] for e in events] == [
        "forward",
        "backward",
        "forward",
        "forward",
        "backward",
        "backward",
        "forward",
    ]

    (flow,) = flows
    assert flow["flow_id"] == events[0]["flow_id"]
    assert flow["application_protocol"] == "HTTP"
    fwd = [e["ip_total_length"] for e in events if e["direction"] == "forward"]
    bwd = [e["ip_total_length"] for e in events if e["direction"] == "backward"]
    assert (
        (flow["fwd_packet_count"], flow["fwd_byte_count"]) == (4, sum(fwd)) == (4, 207)
    )
    assert (
        (flow["bwd_packet_count"], flow["bwd_byte_count"]) == (3, sum(bwd)) == (3, 202)
    )
    assert flow["byte_count"] == 409

    assert events == committed("T08", "events.jsonl")
    assert flows == committed("T08", "flows.jsonl")
