"""Unit tests for preprocess.preprocess_event (validation + policy)."""

from __future__ import annotations

from config import PreprocessConfig
from preprocess import preprocess_event


def _event(**overrides) -> dict:
    event = {
        "packet_id": 1,
        "timestamp": 1759000000.0,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": "udp",
        "src_port": 5000,
        "dst_port": 53,
        "app_protocol": "dns",
        "app_data": {"questions": [{"name": "UIT.edu.VN."}]},
        "error": None,
    }
    event.update(overrides)
    return event


def test_valid_event_passes() -> None:
    event = preprocess_event(_event(), PreprocessConfig())
    assert event["preprocess_status"] == "valid"
    assert event["processing_action"] == "pass"
    assert event["reason"] == []
    assert event["normalized"]["protocol"] == "UDP"
    assert event["normalized"]["domain"] == "uit.edu.vn"
    assert event["protocol"] == "udp"  # original field untouched


def test_partial_is_marked() -> None:
    event = preprocess_event(_event(dst_port=70000), PreprocessConfig())
    assert event["preprocess_status"] == "partial"
    assert event["processing_action"] == "mark"
    assert event["reason"] == ["invalid_port:70000"]


def test_invalid_policy_mark_and_drop() -> None:
    bad = {"src_ip": "not-an-ip"}
    marked = preprocess_event(_event(**bad), PreprocessConfig())
    assert (marked["preprocess_status"], marked["processing_action"]) == (
        "invalid",
        "mark",
    )

    dropped = preprocess_event(_event(**bad), PreprocessConfig(on_invalid="drop"))
    assert dropped["processing_action"] == "drop"
    assert dropped["reason"] == ["invalid_ip:'not-an-ip'"]

    silent = PreprocessConfig(on_invalid="drop", log_dropped=False)
    assert preprocess_event(_event(**bad), silent) is None


def test_unsupported_uses_its_own_policy() -> None:
    arp = {"protocol": "UNKNOWN", "src_ip": None, "dst_ip": None, "src_port": None}
    cfg = PreprocessConfig(on_invalid="mark", on_unsupported="drop")
    event = preprocess_event(_event(**arp), cfg)
    assert event["processing_action"] == "drop"
    assert "unsupported_protocol:UNKNOWN" in event["reason"]


def test_idna_error_makes_valid_event_partial() -> None:
    bad_name = "a" * 70 + "ü.com"
    event = _event(app_data={"questions": [{"name": bad_name}]})
    event = preprocess_event(event, PreprocessConfig())
    assert event["preprocess_status"] == "partial"
    assert event["reason"] == [f"idna_error:{bad_name}"]


def test_disabled() -> None:
    event = preprocess_event(_event(src_ip="bad"), PreprocessConfig(enabled=False))
    assert event["processing_action"] == "pass"
    assert event["reason"] == ["preprocess_disabled"]
