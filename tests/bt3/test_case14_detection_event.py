"""Case 14 - Detection Event: all contract fields, filled from the real event."""

import base64

from engine.detection import DetectionEventGenerator, display_pattern

from .conftest import assert_matches_committed, bundle_for, run_case

FIELDS = [
    "timestamp", "timestamp_iso", "sid", "rev", "msg", "classtype", "priority",
    "action", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "application_protocol", "flow_id", "direction", "packet_id", "match_info",
]  # fmt: skip


def test_http_detection_has_every_field(tmp_path):
    run = run_case("14", tmp_path)
    assert [d["sid"] for d in run.detections] == [1401, 1402]
    http = run.detections[0]
    assert list(http) == FIELDS  # exact names and order: contract for later labs
    assert (http["sid"], http["rev"]) == (1401, 2)
    assert http["msg"] == "WEB traversal in GET"
    assert (http["classtype"], http["priority"]) == ("web-application-attack", 1)
    assert http["action"] == "alert"
    assert (http["src_ip"], http["src_port"]) == ("192.168.1.10", 51200)
    assert (http["dst_ip"], http["dst_port"]) == ("192.168.1.20", 80)
    assert (http["protocol"], http["application_protocol"]) == ("TCP", "HTTP")
    assert http["direction"] == "forward" and http["packet_id"] == 4
    # timestamp comes from the packet, not from the clock
    assert http["timestamp"] == 1759100000.03
    assert http["timestamp_iso"] == "2025-09-28T22:53:20.030000+00:00"
    assert http["match_info"] == {
        "contents": [
            {"pattern": "GET ", "index": 0, "offset": 0, "length": 4, "nocase": False},
            {"pattern": "../", "index": 1, "offset": 7, "length": 3, "nocase": False},
        ],
        "flow": {
            "direction": "forward",
            "state": "ESTABLISHED",
            "flow": "to_server",
            "established": "established",
        },
        "flags": None,
        "dsize": None,
    }


def test_flow_id_links_to_the_flow_record_and_packet_id_to_the_event(tmp_path):
    run = run_case("14", tmp_path)
    flow_ids = {f["flow_id"] for f in run.flows}
    packets = {e["packet_id"]: e for e in run.events}
    for detection in run.detections:
        assert detection["flow_id"] in flow_ids
        event = packets[detection["packet_id"]]
        assert event["flow_id"] == detection["flow_id"]
        assert event["src_ip"] == detection["src_ip"]


def test_dns_detection_udp_null_priority_and_hex_pattern(tmp_path):
    run = run_case("14", tmp_path)
    dns = run.detections[1]
    assert list(dns) == FIELDS
    assert (dns["protocol"], dns["application_protocol"]) == ("UDP", "DNS")
    assert dns["priority"] is None  # the rule has none -> null
    assert dns["flow_id"].startswith("UDP-") and dns["packet_id"] == 5
    (content,) = dns["match_info"]["contents"]
    assert content["pattern"] == "|07 65 78 61 6d 70 6c 65 03 63 6f 6d 00|"
    assert content["offset"] == 12 and content["nocase"] is True
    assert dns["match_info"]["flow"] is None  # rule has no flow option


def test_default_priority_comes_from_config(tmp_path):
    bundle = bundle_for("14")
    run = run_case("14", tmp_path)
    event = next(e for e in run.events if e["packet_id"] == 5)
    event["payload"] = base64.b64decode(event["payload_b64"])
    results = bundle.evaluator.evaluate(event)
    generator = DetectionEventGenerator(bundle.evaluator.repository, default_priority=3)
    (detection,) = generator.generate(event, results)
    assert detection.priority == 3  # rule without priority -> default
    assert detection.to_dict()["sid"] == 1402


def test_display_pattern():
    assert display_pattern(b"GET /") == "GET /"
    assert display_pattern(b"a|b") == "|61 7c 62|"  # '|' is shown as hex too
    assert display_pattern(b"\x00\xff") == "|00 ff|"


def test_matches_committed_output(tmp_path):
    assert_matches_committed(run_case("14", tmp_path))
