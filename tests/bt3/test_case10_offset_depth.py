"""Case 10 - `offset` / `depth`: match only inside the window, edges included."""

import pytest

from engine.matching.content import match_contents

from .conftest import assert_matches_committed, rule_line, run_case, sids_by_packet

PAYLOAD = b"ABCDEFGHIJ"  # A=0 ... J=9


def found(options):
    rule = rule_line(f'alert tcp any any -> any 80 (msg:"m"; {options} sid:1;)').rule
    result = match_contents(rule.contents, PAYLOAD)
    return None if result is None else result[0]["offset"]


@pytest.mark.parametrize(
    "options, expected",
    [
        ('content:"EF"; offset:4; depth:2;', 4),  # window [4,6) fits exactly
        ('content:"EF"; offset:5; depth:5;', None),  # starts one byte too late
        ('content:"EF"; offset:3; depth:3;', 4),  # window [3,6): ends on the pattern
        ('content:"EF"; offset:3; depth:2;', None),  # window [3,5): one byte short
        ('content:"IJ"; offset:8;', 8),  # pattern touches the payload end
        ('content:"IJ"; offset:9;', None),  # only one byte left
        ('content:"AB"; depth:2;', 0),  # depth alone: window [0,2)
        ('content:"BC"; depth:2;', None),  # BC needs [1,3)
        ('content:"BC"; depth:3;', 1),
        ('content:"ZZ"; offset:50;', None),  # offset beyond the payload: no crash
    ],
)
def test_window_edges(options, expected):
    assert found(options) == expected


def test_depth_counts_from_offset_not_from_payload_start():
    # depth:3 from offset 3 reaches byte 5; if depth counted from 0 it would stop at 2
    assert found('content:"DEF"; offset:3; depth:3;') == 3
    assert found('content:"EF"; offset:3; depth:3;') == 4


def test_end_to_end(tmp_path):
    run = run_case("10", tmp_path)
    assert sids_by_packet(run.detections) == {1: [1001, 1003, 1005, 1007, 1009]}
    # match_info reports where the content was found
    offsets = {
        d["sid"]: d["match_info"]["contents"][0]["offset"] for d in run.detections
    }
    assert offsets == {1001: 4, 1003: 4, 1005: 8, 1007: 0, 1009: 1}
    assert_matches_committed(run)
