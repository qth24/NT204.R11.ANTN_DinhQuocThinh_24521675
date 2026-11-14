"""Case 08 - `flow:` follows the Flow Tracker (end-to-end through a PCAP)."""

import pytest

from engine.matching.flow import is_established, match_flow

from .conftest import (
    assert_matches_committed,
    bundle_for,
    rule_line,
    run_case,
    sids_by_packet,
)


def test_states_seen_by_the_engine(tmp_path):
    run = run_case("08", tmp_path)
    got = [
        (e["packet_id"], e["direction"], e["flow_context"]["state"]) for e in run.events
    ]
    assert got == [
        (1, "forward", "NEW"),
        (2, "backward", "HANDSHAKE"),
        (3, "forward", "ESTABLISHED"),  # the ACK itself already counts
        (4, "forward", "ESTABLISHED"),
        (5, "backward", "ESTABLISHED"),
        (6, "forward", "ESTABLISHED"),
    ]


def test_detections_per_packet(tmp_path):
    run = run_case("08", tmp_path)
    assert sids_by_packet(run.detections) == {
        1: [802],  # SYN: to_server but NOT established yet
        # 2: SYN/ACK goes to the client while still in HANDSHAKE -> nothing
        3: [801],  # ACK completing the handshake -> established
        4: [801, 804],  # request: established + content GET
        5: [803],  # response (also contains "GET") only to_client rule
        6: [801],
    }
    assert_matches_committed(run)


def test_server_to_client_packet_never_matches_to_server_rules(tmp_path):
    run = run_case("08", tmp_path)
    for detection in run.detections:
        if detection["packet_id"] in (2, 5):
            assert detection["sid"] == 803 and detection["direction"] == "backward"


def test_handshake_packets_are_not_established():
    rules = {r.sid: r for r in bundle_for("08").load.rules}
    ctx = {"flow_id": "x", "direction": "forward", "protocol": "TCP"}
    for state, expected in [
        ("NEW", False),
        ("HANDSHAKE", False),
        ("ESTABLISHED", True),
        ("CLOSING", True),  # half-closed: data can still flow
        ("CLOSED", False),
        ("RESET", False),
    ]:
        assert is_established({**ctx, "state": state}) is expected, state
    to_server_est = rules[801]
    assert match_flow(to_server_est, {**ctx, "state": "NEW"}) == "flow:established"
    assert match_flow(to_server_est, {**ctx, "state": "ESTABLISHED"}) is None


def test_missing_flow_context_never_matches_a_flow_rule():
    rule = rule_line(
        'alert tcp any any -> any 80 (msg:"f"; flow:to_server; sid:1;)'
    ).rule
    assert match_flow(rule, None) == "flow:no_context"
    assert match_flow(rule, {"flow_id": None}) == "flow:no_context"


@pytest.mark.parametrize("bwd, expected", [(0, False), (1, True), (5, True)])
def test_udp_established_means_a_reply_was_seen(bwd, expected):
    ctx = {
        "flow_id": "u",
        "protocol": "UDP",
        "state": "ACTIVE",
        "bwd_packet_count": bwd,
    }
    assert is_established(ctx) is expected
