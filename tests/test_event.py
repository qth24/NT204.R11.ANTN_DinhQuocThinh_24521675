"""Unit tests for the Normalized IDS Event."""

from __future__ import annotations

import json

from core.event import IDSEvent

REQUIRED_FIELDS = {
    "packet_id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "src_port",
    "dst_port",
    "tcp_flags",
    "app_protocol",
    "app_data",
    "error",
}


def test_defaults_describe_unknown_packet() -> None:
    event = IDSEvent(packet_id=1, timestamp=1.5)
    assert event.protocol == "UNKNOWN"
    assert event.app_protocol is None
    assert event.tcp_flags == []
    assert event.app_data == {}
    assert event.error is None


def test_to_dict_has_required_fields_and_is_json_serializable() -> None:
    event = IDSEvent(
        packet_id=3,
        timestamp=1700000000.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol="TCP",
        src_port=40000,
        dst_port=80,
        tcp_flags=["SYN"],
        app_protocol="HTTP",
        app_data={"method": "GET"},
    )
    data = event.to_dict()
    assert REQUIRED_FIELDS <= data.keys()
    assert json.loads(json.dumps(data)) == data


def test_add_error_accumulates_layers() -> None:
    event = IDSEvent(packet_id=1, timestamp=0.0)
    event.add_error("network", None)
    assert event.error is None
    event.add_error("network", "bad checksum")
    event.add_error("http", "bad header")
    assert event.error == "network: bad checksum; http: bad header"


def test_default_lists_are_not_shared() -> None:
    a = IDSEvent(packet_id=1, timestamp=0.0)
    b = IDSEvent(packet_id=2, timestamp=0.0)
    a.tcp_flags.append("SYN")
    a.app_data["x"] = 1
    assert b.tcp_flags == [] and b.app_data == {}
