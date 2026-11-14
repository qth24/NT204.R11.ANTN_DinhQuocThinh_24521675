"""BT3 prerequisite: per-packet flow context from the tracker."""

from config import FlowConfig
from flow.tracker import FlowTracker


def _pkt(ts, src, sport, dst, dport, flags, proto="TCP"):
    return {
        "timestamp": ts, "protocol": proto, "src_ip": src, "src_port": sport,
        "dst_ip": dst, "dst_port": dport, "tcp_flags": flags, "payload_length": 0,
        "ip_total_length": 40,
    }  # fmt: skip


def test_context_follows_handshake():
    tracker = FlowTracker(FlowConfig())
    steps = [
        (_pkt(1, "1.1.1.1", 5000, "2.2.2.2", 80, ["SYN"]), "NEW", "forward"),
        (_pkt(2, "2.2.2.2", 80, "1.1.1.1", 5000, ["SYN", "ACK"]), "HANDSHAKE", "backward"),
        (_pkt(3, "1.1.1.1", 5000, "2.2.2.2", 80, ["ACK"]), "ESTABLISHED", "forward"),
    ]  # fmt: skip
    for event, state, direction in steps:
        tracker.process(event, with_context=True)
        ctx = event["flow_context"]
        assert (ctx["state"], ctx["direction"]) == (state, direction)
        assert ctx["flow_id"] == event["flow_id"]
    assert (ctx["fwd_packet_count"], ctx["bwd_packet_count"]) == (2, 1)
    assert ctx["protocol"] == "TCP" and ctx["notes"] == []


def test_context_none_without_flow_and_off_by_default():
    tracker = FlowTracker(FlowConfig())
    event = {"timestamp": float("nan"), "protocol": "TCP"}
    tracker.process(event, with_context=True)
    assert event["flow_context"] is None
    event = _pkt(1, "1.1.1.1", 1, "2.2.2.2", 2, [], proto="UDP")
    tracker.process(event)
    assert "flow_context" not in event
