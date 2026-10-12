"""Unit tests for flow.tracker.FlowTracker (event dicts in, flows out)."""

from __future__ import annotations

from config import FlowConfig
from flow.tracker import FlowTracker

A, B = ("192.168.1.10", 51000), ("192.168.1.20", 80)


def _tcp(
    ts: float, src, dst, flags: list[str], size: int = 40, payload: int = 0
) -> dict:
    return {
        "timestamp": ts,
        "protocol": "TCP",
        "src_ip": src[0],
        "src_port": src[1],
        "dst_ip": dst[0],
        "dst_port": dst[1],
        "tcp_flags": flags,
        "ip_total_length": size,
        "payload_length": payload,
        "app_protocol": None,
    }


def _udp(ts: float, src, dst, size: int = 60) -> dict:
    event = _tcp(ts, src, dst, [], size)
    event["protocol"] = "UDP"
    return event


def _feed(tracker: FlowTracker, events: list[dict]) -> list[dict]:
    exported: list[dict] = []
    for event in events:
        exported += tracker.process(event)
    return exported


def test_handshake_one_flow_established() -> None:
    tracker = FlowTracker(FlowConfig())
    events = [
        _tcp(1.0, A, B, ["SYN"]),
        _tcp(1.1, B, A, ["SYN", "ACK"]),
        _tcp(1.2, A, B, ["ACK"]),
    ]
    assert _feed(tracker, events) == []
    assert len({e["flow_id"] for e in events}) == 1
    assert [e["direction"] for e in events] == ["forward", "backward", "forward"]
    (record,) = tracker.flush()
    assert record["state"] == "ESTABLISHED"
    assert record["endpoint_a"] == {"ip": A[0], "port": A[1]}
    assert record["end_reason"] == "end_of_capture"
    assert tracker.active_count == 0


def test_fin_close_exported_after_linger() -> None:
    tracker = FlowTracker(FlowConfig(closed_linger=5))
    events = [
        _tcp(1.0, A, B, ["SYN"]),
        _tcp(1.1, B, A, ["SYN", "ACK"]),
        _tcp(1.2, A, B, ["ACK"]),
        _tcp(2.0, A, B, ["FIN", "ACK"]),
        _tcp(2.1, B, A, ["FIN", "ACK"]),
        _tcp(2.2, A, B, ["ACK"]),
    ]
    assert _feed(tracker, events) == []
    assert tracker.active_count == 1  # still lingering
    exported = tracker.process(_udp(10.0, ("10.9.9.9", 1), ("10.9.9.8", 2)))
    assert [r["end_reason"] for r in exported] == ["fin"]
    assert exported[0]["state"] == "CLOSED"
    assert exported[0]["packet_count"] == 6  # final ACK counted
    assert exported[0]["fin_count"] == 2


def test_rst() -> None:
    tracker = FlowTracker(FlowConfig())
    _feed(tracker, [_tcp(1.0, A, B, ["SYN"]), _tcp(1.1, B, A, ["RST", "ACK"])])
    (record,) = tracker.flush()
    assert (record["state"], record["end_reason"], record["rst_count"]) == (
        "RESET",
        "rst",
        1,
    )


def test_new_syn_after_close_creates_new_session() -> None:
    tracker = FlowTracker(FlowConfig(closed_linger=60))
    first = [_tcp(1.0, A, B, ["SYN"]), _tcp(1.1, B, A, ["RST"])]
    _feed(tracker, first)
    again = _tcp(2.0, A, B, ["SYN"])
    exported = tracker.process(again)
    assert exported[0]["flow_id"] == first[0]["flow_id"]
    assert first[0]["flow_id"].endswith("-1")
    assert again["flow_id"] == first[0]["flow_id"][:-1] + "2"


def test_midstream_note() -> None:
    tracker = FlowTracker(FlowConfig())
    event = _tcp(1.0, B, A, ["PSH", "ACK"], payload=10)
    tracker.process(event)
    (record,) = tracker.flush()
    assert record["state"] == "ESTABLISHED"
    assert record["notes"] == ["midstream"]
    assert record["endpoint_a"]["port"] == 80  # first talker


def test_idle_timeout_exports_and_removes() -> None:
    tracker = FlowTracker(FlowConfig(udp_idle_timeout=60, tcp_idle_timeout=300))
    dns = _udp(100.0, ("10.0.0.5", 5353), ("8.8.8.8", 53))
    tcp = _tcp(100.0, A, B, ["SYN"])
    _feed(tracker, [dns, tcp])
    assert tracker.active_count == 2

    exported = tracker.process(_udp(161.0, ("10.0.0.7", 1), ("10.0.0.8", 2)))
    assert [r["flow_id"] for r in exported] == [dns["flow_id"]]
    assert exported[0]["state"] == "EXPIRED"
    assert exported[0]["end_reason"] == "idle_timeout"
    assert dns["flow_id"] not in tracker.active_flow_ids()
    assert tcp["flow_id"] in tracker.active_flow_ids()  # TCP timeout is 300s


def test_same_tuple_after_timeout_gets_new_id() -> None:
    tracker = FlowTracker(FlowConfig(udp_idle_timeout=10, sweep_interval=1000))
    first = _udp(0.0, ("10.0.0.5", 5353), ("8.8.8.8", 53))
    second = _udp(50.0, ("10.0.0.5", 5353), ("8.8.8.8", 53))
    tracker.process(first)
    exported = tracker.process(second)  # sweep skipped, explicit check expires it
    assert exported[0]["end_reason"] == "idle_timeout"
    assert second["flow_id"].endswith("-2")


def test_eviction_when_table_full() -> None:
    tracker = FlowTracker(FlowConfig(max_active_flows=2))
    events = [
        _udp(float(i), ("10.0.0.1", 1000 + i), ("10.0.0.2", 53)) for i in range(3)
    ]
    exported = _feed(tracker, events)
    assert [r["end_reason"] for r in exported] == ["evicted"]
    assert exported[0]["flow_id"] == events[0]["flow_id"]
    assert tracker.active_count == 2


def test_portless_skip_and_zero() -> None:
    icmp = {"timestamp": 1.0, "protocol": "UNKNOWN", "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2", "ip_protocol": 1, "src_port": None, "dst_port": None}  # fmt: skip
    tracker = FlowTracker(FlowConfig(portless="skip"))
    assert tracker.process(dict(icmp)) == [] and tracker.active_count == 0

    tracker = FlowTracker(FlowConfig(portless="zero"))
    event = dict(icmp)
    tracker.process(event)
    assert event["flow_id"].startswith("ICMP-")
    (record,) = tracker.flush()
    assert record["endpoint_a"] == {"ip": "10.0.0.1", "port": 0}


def test_bad_events_get_no_flow() -> None:
    tracker = FlowTracker(FlowConfig())
    for event in (
        {},
        {"timestamp": "x", "protocol": "TCP"},
        {"timestamp": 1.0, "protocol": "TCP", "src_ip": "bad", "dst_ip": "10.0.0.1",
         "src_port": 1, "dst_port": 2},
        {"timestamp": 1.0, "protocol": "TCP", "src_ip": "10.0.0.1",
         "dst_ip": "10.0.0.2", "src_port": 70000, "dst_port": 2},
    ):  # fmt: skip
        assert tracker.process(event) == []
        assert event["flow_id"] is None and event["direction"] is None
    assert tracker.active_count == 0
