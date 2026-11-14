"""Case 13 - one event matches several rules: all are reported, in rule order."""

import base64

from config import load_config
from engine.factory import build_engine

from .conftest import (
    assert_matches_committed,
    case_dir,
    read_jsonl,
    run_case,
    sids_by_packet,
)


def test_all_matching_rules_in_file_order(tmp_path):
    run = run_case("13", tmp_path)
    # a_web.rules: 1301, 1307 (1305 POST does not match), then b_attack.rules:
    # 1303, 1304. File order, NOT sorted by sid (1307 comes before 1303).
    assert sids_by_packet(run.detections) == {4: [1301, 1307, 1303, 1304]}
    assert_matches_committed(run)


def test_earlier_packets_match_nothing(tmp_path):
    run = run_case("13", tmp_path)
    # SYN / SYN-ACK / ACK carry no payload: not even "any tcp payload" (dsize>0)
    assert {d["packet_id"] for d in run.detections} == {4}


def test_every_detection_describes_its_own_rule(tmp_path):
    run = run_case("13", tmp_path)
    by_sid = {d["sid"]: d for d in run.detections}
    assert by_sid[1301]["msg"] == "GET request"
    assert by_sid[1307]["match_info"]["contents"][0]["offset"] == 7  # "../"
    union = by_sid[1303]["match_info"]["contents"]
    assert [(c["pattern"], c["offset"]) for c in union] == [
        ("union", 16),
        ("select", 22),
    ]
    assert by_sid[1304]["match_info"]["contents"] == []  # dsize-only rule


def test_order_follows_the_order_the_files_are_given(tmp_path):
    run = run_case("13", tmp_path)
    event = next(e for e in run.events if e["packet_id"] == 4)
    event["payload"] = base64.b64decode(event["payload_b64"])  # as in memory
    folder = case_dir("13")
    cfg = load_config(None, []).engine
    reverse = build_engine(
        cfg, [str(folder / "b_attack.rules"), str(folder / "a_web.rules")]
    )
    got = [r.sid for r in reverse.evaluator.evaluate(event)]
    assert got == [1303, 1304, 1301, 1307]


def test_stop_on_first_match_reports_only_one(tmp_path):
    run = run_case(
        "13",
        tmp_path,
        extra=["--set", "engine.stop_on_first_match=true"],
        name="_stop_on_first",
    )
    assert [d["sid"] for d in run.detections] == [1301]
    assert_matches_committed(run, "detections_stop_on_first.jsonl")
