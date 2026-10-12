"""T11 - Concurrent flows: interleaved flows with close endpoints are not merged."""

from __future__ import annotations

from tests.bt2.conftest import committed, run_case


def test_t11_concurrent_flows() -> None:
    events, flows = run_case("T11")
    assert len(flows) == 4
    assert len({f["flow_id"] for f in flows}) == 4

    a, b, c, dns = (f["flow_id"] for f in flows)
    # packet -> flow, as interleaved in the capture
    assert [e["flow_id"] for e in events] == [a, b, c, a, dns, c, b, a, b, c, a, c]

    by_id = {f["flow_id"]: f for f in flows}
    # a and b: same hosts, only the client port differs
    assert by_id[a]["endpoint_a"] == {"ip": "192.168.1.10", "port": 51500}
    assert by_id[b]["endpoint_a"] == {"ip": "192.168.1.10", "port": 51501}
    # c: other client with the same port as a
    assert by_id[c]["endpoint_a"] == {"ip": "192.168.1.11", "port": 51500}
    # dns: same client ip+port as a but UDP -> separate flow
    assert by_id[dns]["protocol"] == "UDP"
    assert by_id[dns]["endpoint_a"] == by_id[a]["endpoint_a"]

    assert [by_id[x]["packet_count"] for x in (a, b, c, dns)] == [4, 3, 4, 1]
    assert [by_id[x]["state"] for x in (a, b, c)] == ["ESTABLISHED"] * 3

    assert events == committed("T11", "events.jsonl")
    assert flows == committed("T11", "flows.jsonl")
