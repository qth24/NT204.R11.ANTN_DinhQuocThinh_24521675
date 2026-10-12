"""Unit tests for flow.flow (Flow statistics)."""

from __future__ import annotations

from flow.flow import BACKWARD, FORWARD, Endpoint, Flow
from flow.flow_key import make_flow_id, make_flow_key


def _flow() -> Flow:
    key = make_flow_key("TCP", "10.0.0.1", 40000, "10.0.0.2", 80)
    return Flow(
        flow_id=make_flow_id(key, 1),
        key=key,
        endpoint_a=Endpoint("10.0.0.1", 40000),
        endpoint_b=Endpoint("10.0.0.2", 80),
        start_time=100.0,
        last_seen=100.0,
        state="NEW",
    )


def test_direction() -> None:
    flow = _flow()
    assert flow.direction_of("10.0.0.1", 40000) == FORWARD
    assert flow.direction_of("10.0.0.2", 80) == BACKWARD


def test_counters_and_duration() -> None:
    flow = _flow()
    flow.add_packet(FORWARD, 60, ["SYN"], 100.0, None)
    flow.add_packet(BACKWARD, 60, ["SYN", "ACK"], 100.1, None)
    flow.add_packet(FORWARD, 52, ["ACK"], 100.2, None)  # pure ACK still counted
    flow.add_packet(FORWARD, 152, ["PSH", "ACK"], 100.5, "HTTP")
    flow.add_packet(BACKWARD, 40, ["RST"], 101.25, "SMTP")

    record = flow.to_record()
    assert record["packet_count"] == 5
    assert record["byte_count"] == 364
    assert (record["fwd_packet_count"], record["fwd_byte_count"]) == (3, 264)
    assert (record["bwd_packet_count"], record["bwd_byte_count"]) == (2, 100)
    assert (record["syn_count"], record["ack_count"]) == (2, 3)
    assert (record["fin_count"], record["rst_count"]) == (0, 1)
    assert record["duration"] == 1.25
    assert record["application_protocol"] == "HTTP"  # first one wins


def test_out_of_order_timestamps() -> None:
    flow = _flow()
    flow.add_packet(FORWARD, 40, [], 105.0, None)
    flow.add_packet(FORWARD, 40, [], 99.0, None)
    assert (flow.start_time, flow.last_seen, flow.duration) == (99.0, 105.0, 6.0)


def test_record_fields() -> None:
    record = _flow().to_record()
    assert set(record) == {
        "flow_id", "protocol", "application_protocol", "endpoint_a", "endpoint_b",
        "start_time", "last_seen", "duration", "packet_count", "byte_count",
        "fwd_packet_count", "fwd_byte_count", "bwd_packet_count", "bwd_byte_count",
        "syn_count", "ack_count", "fin_count", "rst_count", "state", "end_reason",
        "notes",
    }  # fmt: skip
    assert record["endpoint_a"] == {"ip": "10.0.0.1", "port": 40000}
    assert record["protocol"] == "TCP"
    assert record["notes"] == []
