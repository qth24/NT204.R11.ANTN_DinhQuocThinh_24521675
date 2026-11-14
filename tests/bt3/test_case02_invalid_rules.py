"""Case 02 - syntactically wrong rules are `invalid` with a reason code."""

import pytest

from .conftest import assert_matches_committed, bundle_for, rule_line, run_case

EXPECTED = {
    1: "invalid:missing_sid",
    3: "invalid:missing_msg",
    4: "invalid:bad_port_range:80:20",
    5: "invalid:bad_direction:<-",
    6: "invalid:distance_without_content",
    7: "invalid:unterminated_string",
    8: "invalid:bad_ip:10.0.0.0/33",
    10: "invalid:duplicate_sid:209",
    11: "invalid:depth_too_small:3<5",
    12: "invalid:bad_hex:G",
    13: "invalid:flow_conflict",
    14: "invalid:bad_port:70000",
    15: "invalid:offset_with_distance",
}


def test_every_bad_rule_has_its_reason():
    problems = bundle_for("02").load.problems
    assert {p.line_no: p.reasons for p in problems} == {
        line: (reason,) for line, reason in EXPECTED.items()
    }
    assert all(p.status == "invalid" and p.rule is None for p in problems)


def test_counts_and_good_rules_survive():
    bundle = bundle_for("02")
    summary = bundle.load.summary
    assert (summary.loaded, summary.valid, summary.invalid) == (15, 2, 13)
    # the first rule with sid 209 is kept, the second one is the duplicate
    assert [r.sid for r in bundle.load.rules] == [202, 209]
    assert bundle.evaluator.repository.get(209).msg == "valid rule"


@pytest.mark.parametrize(
    "text, reason",
    [
        ("alert tcp any any -> any 80", "invalid:missing_options"),
        ('alert tcp any any -> any 80 (msg:"a"; sid:0;)', "invalid:bad_sid:0"),
        ('alert tcp any any -> any 80 (msg:"a"; sid:1; rev:-1;)', "invalid:bad_rev:-1"),
        (
            'alert tcp any any -> any 80 (msg:"a"; sid:1; priority:0;)',
            "invalid:bad_priority:0",
        ),
        (
            'alert tcp any any -> any 80 (msg:"a"; sid:1; dsize:5<>2;)',
            "invalid:bad_dsize_range:5:2",
        ),
        (
            'alert tcp any any -> any 80 (msg:"a"; sid:1; flags:XYZ;)',
            "invalid:bad_flags:XYZ",
        ),
        (
            'alert tcp any any -> any 80 (msg:"a"; sid:1; content:"";)',
            "invalid:empty_content",
        ),
        (
            'alert tcp any any -> any 80 (msg:"a"; sid:1; content:"ab"; within:1;)',
            "invalid:within_too_small:1<2",
        ),
        (
            'alert tcp any any -> any 80 (msg:"a"; sid:1; sid:2;)',
            "invalid:duplicate_option:sid",
        ),
    ],
)
def test_more_reason_codes(text, reason):
    result = rule_line(text)
    assert result.status == "invalid" and result.reasons == (reason,)


def test_valid_neighbours_still_detect(tmp_path):
    run = run_case("02", tmp_path)
    assert [d["sid"] for d in run.detections] == [202, 209]
    assert_matches_committed(run)
