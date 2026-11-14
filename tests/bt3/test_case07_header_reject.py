"""Case 07 - a header mismatch rejects the rule BEFORE content matching."""

from engine.evaluator import RuleEvaluationEngine
from engine.matching import RuleMatcher
from engine.matching.content import match_contents

from .conftest import (
    assert_matches_committed,
    bundle_for,
    case_dir,
    read_jsonl,
    run_case,
)


def counting_engine(use_index: bool):
    """Engine whose content matcher records which rules reach it."""
    bundle = bundle_for("07")
    called: list[int] = []

    def spy(contents, payload, max_backtrack=1000):
        called.append(len(contents))
        return match_contents(contents, payload, max_backtrack)

    engine = RuleEvaluationEngine(
        bundle.evaluator.repository,
        RuleMatcher(content_matcher=spy),
        use_index=use_index,
    )
    return engine, called


def first_event():
    return read_jsonl(case_dir("07") / "input_events.jsonl")[0]


def test_content_matcher_only_runs_for_the_rule_whose_header_matches():
    engine, called = counting_engine(use_index=True)
    event = first_event()
    event["payload"] = b"GET / HTTP/1.1\r\n\r\n"
    results = engine.evaluate(event, None)
    assert [r.sid for r in results] == [701]
    assert len(called) == 1  # 703 (wrong source ip) never got to content
    # index already dropped 702 (port) and 704 (protocol): only 701, 703 remain
    assert engine.candidates_total == 2
    assert engine.rules_rejected_by_header == 1  # 703


def test_without_index_every_rule_is_checked_but_content_still_skipped():
    engine, called = counting_engine(use_index=False)
    event = first_event()
    event["payload"] = b"GET / HTTP/1.1\r\n\r\n"
    results = engine.evaluate(event, None)
    assert [r.sid for r in results] == [701]
    assert engine.candidates_total == 4  # all rules scanned
    assert engine.rules_rejected_by_header == 3  # 702, 703, 704 by header
    assert len(called) == 1  # content matcher still only for 701


def test_reject_reason_is_reported():
    bundle = bundle_for("07")
    rules = {r.sid: r for r in bundle.load.rules}
    event = first_event()
    event["payload"] = b"GET /"
    matcher = RuleMatcher()
    assert matcher.match(rules[703], event, None).reason_no_match == "direction"
    assert matcher.match(rules[704], event, None).reason_no_match == "protocol"


def test_end_to_end_stats(tmp_path):
    run = run_case("07", tmp_path)
    assert [(d["packet_id"], d["sid"]) for d in run.detections] == [(1, 701)]
    assert_matches_committed(run)
    log = (run.folder / "run.log").read_text()
    assert "rejected_by_header=2" in log  # 703 on each of the two events
