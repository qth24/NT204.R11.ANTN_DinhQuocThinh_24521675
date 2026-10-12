"""T10 - UDP query/response: DNS both ways -> 1 UDP flow, packet/byte counts right."""

from __future__ import annotations

from tests.bt2.conftest import committed, run_case


def test_t10_udp_dns() -> None:
    events, flows = run_case("T10")
    query, response = events
    assert (query["app_data"]["type"], response["app_data"]["type"]) == (
        "query",
        "response",
    )
    assert query["flow_id"] == response["flow_id"]
    assert (query["direction"], response["direction"]) == ("forward", "backward")

    (flow,) = flows
    assert flow["protocol"] == "UDP"
    assert flow["application_protocol"] == "DNS"
    assert flow["state"] == "ACTIVE"  # UDP flows have no TCP state
    assert flow["endpoint_a"] == {"ip": "192.168.1.10", "port": 53530}
    # 56 = 20 IP + 8 UDP + 28 DNS (12 header + 12 "uit.edu.vn" + 4 type/class)
    assert query["ip_total_length"] == 56
    assert response["ip_total_length"] == 82
    assert flow["packet_count"] == 2
    assert flow["byte_count"] == 138
    assert (flow["fwd_packet_count"], flow["fwd_byte_count"]) == (1, 56)
    assert (flow["bwd_packet_count"], flow["bwd_byte_count"]) == (1, 82)
    assert (
        flow["syn_count"]
        == flow["ack_count"]
        == flow["fin_count"]
        == flow["rst_count"]
        == 0
    )
    assert flow["duration"] == 0.025

    assert events == committed("T10", "events.jsonl")
    assert flows == committed("T10", "flows.jsonl")
