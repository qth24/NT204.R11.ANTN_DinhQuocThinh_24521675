"""T07 - TCP handshake: SYN -> SYN/ACK -> ACK gives 1 flow in state ESTABLISHED."""

from __future__ import annotations

from capture.pcap_reader import read_pcap
from core.pipeline import Pipeline
from tests.bt2.conftest import case_dir, committed, run_case


def test_t07_tcp_handshake() -> None:
    events, flows = run_case("T07")
    assert [e["tcp_flags"] for e in events] == [["SYN"], ["SYN", "ACK"], ["ACK"]]
    assert len({e["flow_id"] for e in events}) == 1
    (flow,) = flows
    assert flow["state"] == "ESTABLISHED"
    assert flow["endpoint_a"] == {"ip": "192.168.1.10", "port": 51234}  # SYN sender
    assert flow["endpoint_b"] == {"ip": "192.168.1.20", "port": 80}
    assert (flow["packet_count"], flow["syn_count"], flow["ack_count"]) == (3, 2, 2)
    assert flow["notes"] == []  # handshake seen: not a mid-stream pickup

    assert events == committed("T07", "events.jsonl")
    assert flows == committed("T07", "flows.jsonl")


def test_t07_state_after_each_packet() -> None:
    packets = list(read_pcap(str(case_dir("T07") / "input.pcap")))
    states = []
    for count in (1, 2, 3):
        flows: list[dict] = []
        Pipeline().run_bt2(packets[:count], lambda e: None, flows.append)
        states.append(flows[0]["state"])
    assert states == ["NEW", "HANDSHAKE", "ESTABLISHED"]
