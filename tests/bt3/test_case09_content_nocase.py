"""Case 09 - `content` with and without `nocase` (ASCII only)."""

from engine.matching.content import match_contents

from .conftest import (
    assert_matches_committed,
    bundle_for,
    rule_line,
    run_case,
    sids_by_packet,
)


def contents(text):
    return rule_line(
        f'alert tcp any any -> any 80 (msg:"m"; {text} sid:1;)'
    ).rule.contents


def test_case_sensitive_vs_nocase():
    sensitive = contents('content:"GET /";')
    insensitive = contents('content:"get /"; nocase;')
    assert match_contents(sensitive, b"GET /index") is not None  # positive
    assert match_contents(sensitive, b"get /index") is None  # negative
    assert match_contents(insensitive, b"get /index") is not None
    assert match_contents(insensitive, b"GeT /index") is not None
    assert match_contents(insensitive, b"POST /index") is None


def test_hex_pattern_is_exact_bytes():
    pattern = contents('content:"|47 45 54|";')
    assert pattern[0].pattern == b"GET"
    assert match_contents(pattern, b"xxGETxx")[0]["offset"] == 2
    assert match_contents(pattern, b"xxgetxx") is None


def test_nocase_is_ascii_only():
    rule = contents('content:"gét"; nocase;')
    assert match_contents(rule, "GéT /".encode()) is not None  # G, T folded
    assert match_contents(rule, "GÉT /".encode()) is None  # É is not folded to é


def test_nocase_does_not_change_reported_offset():
    found = match_contents(contents('content:"BC"; nocase;'), b"aabcxx")
    assert found == [
        {"pattern": b"BC", "index": 0, "offset": 2, "length": 2, "nocase": True}
    ]


def test_end_to_end(tmp_path):
    run = run_case("09", tmp_path)
    assert sids_by_packet(run.detections) == {
        1: [901, 902, 903],  # "GET /index.html"
        2: [902],  # "get /index.html": only the nocase rule
        # 3: "GÉT /" nothing
        4: [904],  # "GéT /": nocase rule with a non-ASCII letter
    }
    assert_matches_committed(run)


def test_rules_parse_nocase_flag():
    rules = {r.sid: r for r in bundle_for("09").load.rules}
    assert not rules[901].contents[0].nocase and rules[902].contents[0].nocase
