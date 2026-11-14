"""Case 04 - header parsing: TCP + any / single IP / CIDR + port / range."""

from ipaddress import IPv4Network

from engine.rule_model import (
    ContentOption,
    DsizeOption,
    FlagsOption,
    FlowOption,
    PortRange,
)

from .conftest import bundle_for


def rules():
    return {r.sid: r for r in bundle_for("04").load.rules}


def net(text):
    return (IPv4Network(text),)


def test_any_means_empty_tuples():
    h = rules()[401].header
    assert (h.proto, h.direction) == ("TCP", "->")
    assert h.src_nets == h.dst_nets == () and h.src_ports == h.dst_ports == ()


def test_single_ip_becomes_slash_32_and_single_port_is_a_one_port_range():
    h = rules()[402].header
    assert h.src_nets == net("192.168.1.10/32")
    assert h.dst_nets == net("10.0.0.5/32")
    assert h.src_ports == ()
    assert h.dst_ports == (PortRange(80, 80),)


def test_cidr_and_ranges():
    h = rules()[403].header
    assert h.src_nets == net("10.0.0.0/8") and h.dst_nets == net("192.168.0.0/16")
    assert h.src_ports == (PortRange(1024, 65535),)  # "1024:" = open upper end
    assert h.dst_ports == (PortRange(1, 1024),)


def test_open_lower_range_and_bidirectional():
    h = rules()[404].header
    assert h.direction == "<>"
    assert h.src_ports == (PortRange(0, 1023),)  # ":1023" = open lower end
    assert h.dst_ports == (PortRange(8080, 8080),)


def test_host_bits_in_cidr_are_cleared():
    assert rules()[405].header.src_nets == net("10.0.0.0/8")  # 10.1.2.3/8


def test_every_field_of_a_full_rule():
    rule = rules()[406]
    assert (rule.sid, rule.rev, rule.action) == (406, 3, "alert")
    assert rule.msg == "full rule; with semicolon"  # ';' inside quotes survives
    assert rule.contents == (
        ContentOption(
            pattern=b"a;b: c",  # \; and |3a 20| decoded
            nocase=True,
            offset=2,
            depth=10,
        ),
    )
    assert rule.flow == FlowOption("to_server", "established")
    assert rule.flags == FlagsOption(frozenset("SA"), "+", frozenset("CE"))
    assert rule.dsize == DsizeOption("range", 4, 8)
    assert (rule.classtype, rule.priority) == ("web-attack", 2)
    assert rule.header.dst_ports == (PortRange(80, 80),)
    assert rule.status == "valid" and rule.line_no == 6
    assert rule.source_file.endswith("header.rules")


def test_rev_defaults_to_1_and_missing_options_are_none():
    rule = rules()[401]
    assert rule.rev == 1
    assert rule.flow is rule.flags is rule.dsize is None
    assert rule.classtype is None and rule.priority is None
    assert rule.contents == ()
