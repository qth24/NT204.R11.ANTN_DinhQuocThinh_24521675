"""Case 06 - index: right candidate set for TCP, UDP and `any` rules."""

from engine.matching.header import match_header

from .conftest import bundle_for, case_dir, read_jsonl

EXPECTED = {
    1: [601, 602, 603],  # tcp ->80: exact + range + any
    2: [602, 603, 607],  # tcp ->443: range + any + 443 rule
    3: [603, 606],  # tcp ->8080: any + the "<>" 8080 rule
    4: [603, 606],  # tcp 8080->5000: only the "<>" rule can face its port
    5: [604, 605],  # udp ->53
    6: [605],  # udp ->9999: only "udp any"
    7: [603],  # tcp, no ports at all: only rules with any port
}


def setup():
    repo = bundle_for("06").evaluator.repository
    events = read_jsonl(case_dir("06") / "input_events.jsonl")
    return repo, events


def test_candidate_sets():
    repo, events = setup()
    got = {e["packet_id"]: [r.sid for r in repo.candidates(e)] for e in events}
    assert got == EXPECTED


def test_other_protocol_has_no_candidates():
    repo, events = setup()
    assert repo.candidates({**events[0], "protocol": "UNKNOWN"}) == []
    assert repo.candidates({"protocol": "TCP"}) != []  # port-less tcp: any bucket


def test_candidates_are_a_superset_of_real_matches():
    """The index may over-select but must never lose a rule that can match."""
    repo, events = setup()
    for event in events:
        candidates = {r.sid for r in repo.candidates(event)}
        really = {r.sid for r in repo.all() if match_header(r, event) is None}
        assert really <= candidates, event["packet_id"]


def test_index_removes_wrong_protocol_and_wrong_port_rules():
    repo, events = setup()
    tcp80 = {r.sid for r in repo.candidates(events[0])}
    assert {604, 605} & tcp80 == set()  # udp rules never offered for tcp
    assert 607 not in tcp80 and 606 not in tcp80  # other ports excluded
    assert len(repo.candidates(events[0])) < len(repo)


def test_order_is_file_order_and_without_duplicates():
    repo, events = setup()
    for event in events:
        sids = [r.sid for r in repo.candidates(event)]
        assert sids == sorted(sids, key=[r.sid for r in repo.all()].index)
        assert len(sids) == len(set(sids))
