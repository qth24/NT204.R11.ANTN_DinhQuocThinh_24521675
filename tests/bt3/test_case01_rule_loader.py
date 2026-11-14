"""Case 01 - rule loader: only real rule lines reach the parser."""

from engine.rule_loader import load_rules, read_rule_lines
from engine.rule_parser import make_parser

from .conftest import assert_matches_committed, bundle_for, case_dir, run_case

RULES = "case.rules"


def test_only_rule_lines_reach_the_parser():
    seen = []
    real = make_parser()

    def spy(line, source, number):
        seen.append((number, line))
        return real(line, source, number)

    result = load_rules([case_dir("01") / RULES], spy)
    # 4 rules; the 2 comments, 2 blank lines and the '#alert' rule are skipped
    assert [n for n, _ in seen] == [4, 7, 8, 10]  # first physical line of each
    assert all(not line.startswith("#") for _, line in seen)
    # the rule written on two lines arrives as ONE logical line, no backslash
    joined = [line for _, line in seen if "C smtp" in line]
    assert len(joined) == 1 and "\\" not in joined[0]
    summary = result.summary
    assert (summary.loaded, summary.valid, summary.invalid) == (4, 3, 1)
    assert (summary.unsupported, summary.disabled) == (0, 0)


def test_commented_out_rule_is_not_enabled():
    result = load_rules([case_dir("01") / RULES], make_parser())
    assert 102 not in [r.sid for r in result.rules]
    assert [r.sid for r in result.rules] == [101, 103, 104]  # file order


def test_line_numbers_point_to_first_physical_line():
    lines = read_rule_lines(case_dir("01") / RULES)
    assert [line.line_no for line in lines] == [4, 7, 8, 10]
    assert "C smtp" in lines[2].text  # the two-line rule starts at line 8


def test_invalid_rule_reported_with_reason_and_others_still_load():
    bundle = bundle_for("01")
    (problem,) = bundle.load.problems
    assert problem.status == "invalid"
    assert problem.reasons == ("invalid:missing_sid",)
    assert len(bundle.evaluator.repository) == 3


def test_disable_by_sid_and_by_file():
    by_sid = bundle_for("01", **{"engine.disabled_sids": "103"}).load.summary
    assert (by_sid.loaded, by_sid.valid, by_sid.disabled) == (4, 2, 1)
    by_file = bundle_for("01", **{"engine.disabled_rule_files": "case.rules"})
    summary = by_file.load.summary
    assert (summary.loaded, summary.valid, summary.disabled) == (4, 0, 4)


def test_missing_file_is_a_warning_not_a_crash():
    result = load_rules(["/no/such/file.rules", case_dir("01") / RULES], make_parser())
    assert result.summary.valid == 3
    assert any("not found" in w for w in result.summary.warnings)


def test_end_to_end_detection(tmp_path):
    run = run_case("01", tmp_path)
    assert [d["sid"] for d in run.detections] == [101]
    assert_matches_committed(run)
