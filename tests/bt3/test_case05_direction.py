"""Case 05 - direction `->` (one way) and `<>` (both ways)."""

from engine.matching.header import match_header

from .conftest import (
    assert_matches_committed,
    bundle_for,
    read_jsonl,
    case_dir,
    run_case,
    sids_by_packet,
)


def test_one_way_and_both_ways_on_the_three_packets():
    rules = {r.sid: r for r in bundle_for("05").load.rules}
    events = read_jsonl(case_dir("05") / "input_events.jsonl")
    forward, reverse, other = events
    # forward 10.0.0.1:4000 -> 10.0.0.2:80 matches both rules
    assert match_header(rules[501], forward) is None
    assert match_header(rules[502], forward) is None
    # reversed 10.0.0.2:80 -> 10.0.0.1:4000: "->" rejects it, "<>" accepts it
    assert match_header(rules[501], reverse) == "direction"
    assert match_header(rules[502], reverse) is None
    # other destination: neither matches
    assert match_header(rules[501], other) is not None
    assert match_header(rules[502], other) is not None


def test_end_to_end(tmp_path):
    run = run_case("05", tmp_path)
    assert sids_by_packet(run.detections) == {1: [501, 502], 2: [502]}
    assert_matches_committed(run)
