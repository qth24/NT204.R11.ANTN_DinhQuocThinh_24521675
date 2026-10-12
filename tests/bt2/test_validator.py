"""Unit tests for preprocess.validator."""

from __future__ import annotations

import pytest

from preprocess.validator import validate_event


def _event(**overrides) -> dict:
    event = {
        "packet_id": 1,
        "timestamp": 1759000000.5,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": "TCP",
        "src_port": 40000,
        "dst_port": 80,
        "tcp_flags": ["SYN"],
        "error": None,
        "decode_status": "not_applicable",
    }
    event.update(overrides)
    return event


def test_valid_event() -> None:
    result = validate_event(_event())
    assert (result.status, result.reasons, result.unsupported) == ("valid", [], False)


@pytest.mark.parametrize(
    "name", ["packet_id", "timestamp", "src_ip", "dst_ip", "protocol"]
)
def test_missing_core_field_is_invalid(name: str) -> None:
    event = _event()
    del event[name]
    result = validate_event(event)
    assert result.status == "invalid"
    assert f"missing_field:{name}" in result.reasons


@pytest.mark.parametrize(
    "overrides, reason",
    [
        ({"src_ip": "999.1.1.1"}, "invalid_ip:'999.1.1.1'"),
        ({"dst_ip": 12345}, "invalid_ip:12345"),
        ({"timestamp": -1}, "invalid_timestamp:-1"),
        ({"timestamp": float("nan")}, "invalid_timestamp:nan"),
        ({"timestamp": "yesterday"}, "invalid_timestamp:'yesterday'"),
        ({"timestamp": True}, "invalid_timestamp:True"),
        ({"packet_id": "7"}, "invalid_packet_id:'7'"),
    ],
)
def test_bad_core_values_are_invalid(overrides: dict, reason: str) -> None:
    result = validate_event(_event(**overrides))
    assert result.status == "invalid"
    assert reason in result.reasons


def test_unsupported_protocol() -> None:
    result = validate_event(_event(protocol="UNKNOWN", src_port=None, dst_port=None))
    assert result.status == "invalid"
    assert result.unsupported is True
    assert result.reasons == ["unsupported_protocol:UNKNOWN"]


def test_lowercase_protocol_is_supported() -> None:
    assert validate_event(_event(protocol="udp")).status == "valid"


@pytest.mark.parametrize(
    "overrides, reason",
    [
        ({"dst_port": None}, "missing_field:dst_port"),
        ({"src_port": 70000}, "invalid_port:70000"),
        ({"src_port": -1}, "invalid_port:-1"),
        ({"dst_port": "80"}, "invalid_port:80"),
        ({"tcp_flags": "SYN"}, "invalid_field:tcp_flags"),
        ({"error": "transport: truncated"}, "parse_error"),
        ({"decode_status": "partial"}, "decode_partial"),
        ({"decode_status": "failed"}, "decode_failed"),
    ],
)
def test_secondary_problems_are_partial(overrides: dict, reason: str) -> None:
    result = validate_event(_event(**overrides))
    assert result.status == "partial"
    assert reason in result.reasons


def test_invalid_keeps_partial_reasons_too() -> None:
    result = validate_event(_event(src_ip=None, dst_port=99999))
    assert result.status == "invalid"
    assert result.reasons == ["missing_field:src_ip", "invalid_port:99999"]


def test_empty_event() -> None:
    result = validate_event({})
    assert result.status == "invalid"
    assert len(result.reasons) == 5
