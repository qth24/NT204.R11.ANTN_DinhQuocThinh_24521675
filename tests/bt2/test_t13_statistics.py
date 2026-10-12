"""T13 - Statistics: packet/byte/flag counters and duration are exact."""

from __future__ import annotations

from tests.bt2.conftest import committed, run_case


def test_t13_statistics() -> None:
    events, flows = run_case("T13")
    (flow,) = flows

    # Expected values computed independently from the per-packet events
    fwd = [e for e in events if e["direction"] == "forward"]
    bwd = [e for e in events if e["direction"] == "backward"]
    assert flow["packet_count"] == len(events) == 11
    assert flow["byte_count"] == sum(e["ip_total_length"] for e in events) == 1040
    assert (
        (flow["fwd_packet_count"], flow["fwd_byte_count"])
        == (len(fwd), 580)
        == (7, 580)
    )
    assert (
        (flow["bwd_packet_count"], flow["bwd_byte_count"])
        == (len(bwd), 460)
        == (4, 460)
    )
    assert sum(e["ip_total_length"] for e in fwd) == 580
    for flag, key in (
        ("SYN", "syn_count"),
        ("ACK", "ack_count"),
        ("FIN", "fin_count"),
        ("RST", "rst_count"),
    ):
        assert flow[key] == sum(flag in e["tcp_flags"] for e in events)
    assert (
        flow["syn_count"],
        flow["ack_count"],
        flow["fin_count"],
        flow["rst_count"],
    ) == (2, 10, 2, 0)

    # 140 = 20 IP + 20 TCP + 100 bytes of payload
    assert [e["ip_total_length"] for e in events][3:7] == [140, 240, 40, 340]
    assert flow["start_time"] == events[0]["timestamp"]
    assert flow["last_seen"] == events[-1]["timestamp"]
    assert flow["duration"] == 2.5
    assert (flow["state"], flow["end_reason"]) == ("CLOSED", "fin")

    assert events == committed("T13", "events.jsonl")
    assert flows == committed("T13", "flows.jsonl")
