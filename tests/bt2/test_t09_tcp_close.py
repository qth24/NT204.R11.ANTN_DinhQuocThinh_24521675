"""T09 - TCP close: FIN/ACK -> CLOSED, RST -> RESET; new SYN -> new flow."""

from __future__ import annotations

from tests.bt2.conftest import committed, run_case


def test_t09_tcp_close() -> None:
    events, flows = run_case("T09")
    fin_flow, rst_flow, reopened = flows

    # Connection 1: FIN from both sides (+ last ACK) -> CLOSED / "fin"
    assert (fin_flow["state"], fin_flow["end_reason"]) == ("CLOSED", "fin")
    assert (fin_flow["packet_count"], fin_flow["fin_count"]) == (9, 2)
    # Connection 2: refused with RST -> RESET / "rst"
    assert (rst_flow["state"], rst_flow["end_reason"]) == ("RESET", "rst")
    assert (rst_flow["packet_count"], rst_flow["rst_count"]) == (2, 1)

    # Connection 3 reuses the 5-tuple of connection 1 with a new SYN:
    # the closed flow is exported and a new session starts (seq 2)
    prefix = fin_flow["flow_id"].rsplit("-", 1)[0]
    assert fin_flow["flow_id"] == f"{prefix}-1"
    assert reopened["flow_id"] == f"{prefix}-2"
    assert reopened["state"] == "ESTABLISHED"
    assert [e["flow_id"] for e in events[11:]] == [reopened["flow_id"]] * 3
    assert {e["flow_id"] for e in events[:9]} == {fin_flow["flow_id"]}

    assert events == committed("T09", "events.jsonl")
    assert flows == committed("T09", "flows.jsonl")
