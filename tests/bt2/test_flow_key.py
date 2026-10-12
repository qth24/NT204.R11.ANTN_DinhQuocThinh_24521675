"""Unit tests for flow.flow_key."""

from __future__ import annotations

import re

import pytest

from flow.flow_key import FlowKey, make_flow_id, make_flow_key


def test_both_directions_give_same_key() -> None:
    forward = make_flow_key("tcp", "192.168.1.10", 51234, "192.168.1.20", 80)
    backward = make_flow_key("TCP", "192.168.1.20", 80, "192.168.1.10", 51234)
    assert forward == backward
    assert forward == FlowKey("TCP", "192.168.1.10", 51234, "192.168.1.20", 80)


def test_ip_compared_numerically_not_as_text() -> None:
    # As text "10.0.0.9" > "10.0.0.10", numerically it is smaller
    key = make_flow_key("UDP", "10.0.0.10", 1, "10.0.0.9", 2)
    assert (key.lo_ip, key.hi_ip) == ("10.0.0.9", "10.0.0.10")


def test_same_ip_ordered_by_port() -> None:
    key = make_flow_key("TCP", "127.0.0.1", 8080, "127.0.0.1", 40000)
    assert (key.lo_port, key.hi_port) == (8080, 40000)


def test_different_ports_or_protocols_are_different_flows() -> None:
    a = make_flow_key("TCP", "10.0.0.1", 1000, "10.0.0.2", 80)
    b = make_flow_key("TCP", "10.0.0.1", 1001, "10.0.0.2", 80)
    c = make_flow_key("UDP", "10.0.0.1", 1000, "10.0.0.2", 80)
    assert len({a, b, c}) == 3


def test_flow_id_format_and_stability() -> None:
    key = make_flow_key("TCP", "192.168.1.10", 51234, "192.168.1.20", 80)
    flow_id = make_flow_id(key, 1)
    assert re.fullmatch(r"TCP-[0-9a-f]{12}-1", flow_id)
    # Stable across runs: the hash only depends on the canonical key
    assert flow_id == make_flow_id(
        make_flow_key("TCP", "192.168.1.20", 80, "192.168.1.10", 51234), 1
    )
    assert make_flow_id(key, 2) == flow_id[:-1] + "2"


def test_invalid_ip_raises() -> None:
    with pytest.raises(ValueError):
        make_flow_key("TCP", "999.0.0.1", 1, "10.0.0.1", 2)
