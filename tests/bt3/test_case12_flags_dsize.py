"""Case 12 - TCP `flags` (exact / + / * / ! / mask) and `dsize`."""

import pytest

from engine.matching.packet import match_dsize, match_flags, match_packet
from engine.rule_parser import parse_dsize, parse_flags

from .conftest import (
    assert_matches_committed,
    bundle_for,
    case_dir,
    read_jsonl,
    rule_line,
    run_case,
    sids_by_packet,
)

EXPECTED = {
    1: [1201, 1207],  # SYN
    2: [1202, 1207],  # SYN/ACK
    3: [1204, 1205, 1207, 1210],  # pure ACK, dsize 0
    4: [1204, 1205, 1208],  # PSH/ACK, 12 bytes
    5: [1203, 1204, 1207],  # FIN/ACK
    6: [1204, 1206, 1207],  # no flags
    # 7: UDP -> no TCP rule matches
    8: [1204, 1205, 1209],  # PSH/ACK, 8 bytes
}


def test_end_to_end(tmp_path):
    run = run_case("12", tmp_path)
    assert sids_by_packet(run.detections) == EXPECTED
    assert_matches_committed(run)


def test_pure_ack_has_dsize_zero():
    events = read_jsonl(case_dir("12") / "input_events.jsonl")
    pure_ack = events[2]
    assert pure_ack["tcp_flags"] == ["ACK"] and pure_ack["payload_length"] == 0
    rules = {r.sid: r for r in bundle_for("12").load.rules}
    assert match_packet(rules[1210], pure_ack) is None  # flags:A; dsize:0
    assert match_packet(rules[1207], events[3]) == "dsize"  # data packet != 0


@pytest.mark.parametrize(
    "flags, present, expected",
    [
        ("S", "S", True),
        ("S", "SA", False),  # exact: SYN/ACK is not SYN
        ("+SA", "SAP", True),  # all listed, extra allowed
        ("+SA", "S", False),
        ("*FR", "FA", True),  # any of F, R
        ("*FR", "A", False),
        ("!S", "A", True),  # none of S
        ("!S", "SA", False),
        ("A,P", "PA", True),  # mask: PSH ignored
        ("A,P", "FA", False),
        ("0", "", True),
        ("0", "A", False),
    ],
)
def test_flag_semantics(flags, present, expected):
    assert match_flags(parse_flags(flags), frozenset(present)) is expected


@pytest.mark.parametrize(
    "text, size, expected",
    [
        ("0", 0, True),
        ("0", 1, False),
        ("<5", 4, True),
        ("<5", 5, False),
        (">5", 5, False),
        (">5", 6, True),
        ("5<>8", 5, True),  # inclusive lower bound
        ("5<>8", 8, True),  # inclusive upper bound
        ("5<>8", 4, False),
        ("5<>8", 9, False),
    ],
)
def test_dsize_semantics(text, size, expected):
    assert match_dsize(parse_dsize(text), size) is expected


def test_dsize_range_can_be_exclusive():
    option = parse_dsize("5<>8")
    assert match_dsize(option, 5, inclusive=False) is False
    assert match_dsize(option, 6, inclusive=False) is True


def test_flags_never_match_udp_and_missing_dsize_does_not_match():
    flags_rule = rule_line(
        'alert tcp any any -> any 80 (msg:"m"; flags:S; sid:1;)'
    ).rule
    udp = {"protocol": "UDP", "tcp_flags": [], "payload_length": 0}
    assert match_packet(flags_rule, udp) == "flags:not_tcp"
    dsize_rule = rule_line(
        'alert tcp any any -> any 80 (msg:"m"; dsize:0; sid:2;)'
    ).rule
    assert match_packet(dsize_rule, {"protocol": "TCP"}) == "dsize:missing"
