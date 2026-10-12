"""T12 - Idle timeout: a flow idle longer than the timeout is exported and
removed from the active table (packet timestamps, no real sleep)."""

from __future__ import annotations

from capture.pcap_reader import read_pcap
from core.pipeline import Pipeline
from tests.bt2.conftest import case_dir, committed, run_case


def test_t12_idle_timeout() -> None:
    events, flows = run_case("T12")
    udp1, tcp, other1, udp2, other2 = flows

    assert (udp1["end_reason"], udp1["state"]) == ("idle_timeout", "EXPIRED")
    assert (tcp["end_reason"], tcp["state"]) == ("idle_timeout", "ESTABLISHED")
    assert other1["end_reason"] == udp2["end_reason"] == "idle_timeout"
    assert other2["end_reason"] == "end_of_capture"
    # Same 5-tuple after expiry -> new session number
    assert udp2["flow_id"] == udp1["flow_id"][:-1] + "2"
    assert other2["flow_id"] == other1["flow_id"][:-1] + "2"
    assert events[6]["flow_id"] == udp2["flow_id"]

    assert events == committed("T12", "events.jsonl")
    assert flows == committed("T12", "flows.jsonl")


def test_t12_active_table_after_each_packet() -> None:
    """Default timeouts: UDP 60 s, TCP 300 s."""
    pipeline = Pipeline()
    exported: list[str] = []
    snapshot = []
    for raw in read_pcap(str(case_dir("T12") / "input.pcap")):
        pipeline.process_bt2(raw, lambda record: exported.append(record["flow_id"]))
        snapshot.append((len(exported), pipeline.tracker.active_count))

    # (flows exported so far, flows still active) after packets 1..8
    assert snapshot == [
        (0, 1),  # t=0    UDP flow
        (0, 2),  # t=0    TCP flow
        (0, 2),
        (0, 2),
        (0, 3),  # t=30   other TCP flow, nothing idle > timeout yet
        (1, 2),  # t=61   UDP idle 61 s > 60 s -> exported + removed
        (1, 3),  # t=90   same UDP 5-tuple -> NEW flow
        (4, 1),  # t=400  TCP (idle 399.8 s), other (339 s), UDP#2 (310 s) exported
    ]
    udp_first = exported[0]
    assert udp_first.startswith("UDP-") and udp_first.endswith("-1")
    assert udp_first not in pipeline.tracker.active_flow_ids()
