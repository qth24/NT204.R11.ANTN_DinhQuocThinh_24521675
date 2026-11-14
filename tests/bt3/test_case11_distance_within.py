"""Case 11 - two contents with `distance` / `within` (relative matching)."""

from engine.matching.content import match_contents

from .conftest import assert_matches_committed, bundle_for, run_case, sids_by_packet

USER = b"user=admin&pass=1234"  # u0 s1 e2 r3 =4 a5 d6 m7 i8 n9 &10 p11 ...
REPEAT = b"AB-AB-XY"  # AB at 0 and 3, XY at 6


def rules():
    return {r.sid: r for r in bundle_for("11").load.rules}


def offsets(sid, payload, **kwargs):
    found = match_contents(rules()[sid].contents, payload, **kwargs)
    return None if found is None else [d["offset"] for d in found]


def test_within_limits_the_search_window():
    assert offsets(1101, USER) == [0, 5]  # admin in [5,10)
    assert offsets(1102, USER) is None  # pass is at 11: outside within:5
    assert offsets(1103, USER) == [0, 11]  # within:15 -> window [5,20)


def test_distance_skips_bytes_after_previous_match():
    assert offsets(1104, USER) == [0, 11]  # start = 5 + 6
    assert offsets(1105, USER) is None  # start = 5 + 7 = 12: pass= not there


def test_negative_distance_reaches_back_into_previous_match():
    # admin ends at 10; distance:-2 -> start 8; "in&" is at 8..11
    assert offsets(1106, USER) == [5, 8]


def test_previous_content_with_several_occurrences_is_retried():
    # first AB (0..2): window [3,5) has no XY -> try the second AB (3..5):
    # window [6,8) = "XY"
    assert offsets(1107, REPEAT) == [3, 6]
    # no AB leaves XY inside a 2-byte window with distance 0
    assert offsets(1108, REPEAT) is None


def test_backtrack_limit_stops_the_search():
    assert offsets(1107, REPEAT, max_backtrack=1) is None  # budget used by 1st AB
    assert offsets(1107, REPEAT, max_backtrack=2) == [3, 6]


def test_end_to_end(tmp_path):
    run = run_case("11", tmp_path)
    assert sids_by_packet(run.detections) == {
        1: [1101, 1103, 1104, 1106],
        2: [1107],
    }
    detection = next(d for d in run.detections if d["sid"] == 1107)
    contents = detection["match_info"]["contents"]
    assert [(c["index"], c["pattern"], c["offset"]) for c in contents] == [
        (0, "AB", 3),
        (1, "XY", 6),
    ]
    assert_matches_committed(run)
