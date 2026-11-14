"""Case 03 - out-of-scope keywords are `unsupported`, never a crash."""

from .conftest import assert_matches_committed, bundle_for, rule_line, run_case

EXPECTED = {
    1: "unsupported:keyword:pcre",
    2: "unsupported:keyword:byte_test",
    3: "unsupported:keyword:http_uri",
    4: "unsupported:action:drop",
    5: "unsupported:protocol:icmp",
    6: "unsupported:ip_syntax:!10.0.0.0/8",
    7: "unsupported:port_syntax:[80,443]",
    8: "unsupported:ip_syntax:$HOME_NET",
    9: "unsupported:keyword:flowbits",
}


def test_each_unsupported_rule_has_its_reason():
    problems = bundle_for("03").load.problems
    assert {p.line_no: p.reasons for p in problems} == {
        line: (reason,) for line, reason in EXPECTED.items()
    }
    assert all(p.status == "unsupported" for p in problems)


def test_counts_and_ignorable_keywords_are_accepted_with_warning():
    bundle = bundle_for("03")
    summary = bundle.load.summary
    assert (summary.loaded, summary.valid, summary.unsupported) == (10, 1, 9)
    assert summary.invalid == 0
    (rule,) = bundle.load.rules
    assert rule.sid == 310 and rule.contents[0].pattern == b"GET"
    warnings = [w for w in summary.warnings if "ignored:keyword" in w]
    assert [w.rsplit(":", 1)[1] for w in warnings] == ["reference", "metadata", "gid"]


def test_ignorable_list_is_configurable():
    # with an empty list the harmless keywords are no longer accepted
    bundle = bundle_for("03", **{"engine.ignorable_keywords": ""})
    assert bundle.load.summary.valid == 0
    last = bundle.load.problems[-1]
    assert last.reasons == (
        "unsupported:keyword:reference",
        "unsupported:keyword:metadata",
        "unsupported:keyword:gid",
    )


def test_invalid_beats_unsupported():
    result = rule_line('alert tcp any any -> any 99999 (msg:"a"; pcre:"/x/"; sid:1;)')
    assert result.status == "invalid"
    assert result.reasons == ("invalid:bad_port:99999",)


def test_several_unsupported_reasons_are_all_listed():
    result = rule_line(
        'alert icmp any any -> any any (msg:"a"; pcre:"/x/"; byte_jump:1,0; sid:1;)'
    )
    assert result.status == "unsupported"
    assert result.reasons == (
        "unsupported:protocol:icmp",
        "unsupported:keyword:pcre",
        "unsupported:keyword:byte_jump",
    )


def test_supported_rule_still_detects(tmp_path):
    run = run_case("03", tmp_path)
    assert [d["sid"] for d in run.detections] == [310]
    assert_matches_committed(run)
