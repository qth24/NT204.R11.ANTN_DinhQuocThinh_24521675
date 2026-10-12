"""Integration tests: RawPacket -> Pipeline -> IDSEvent."""

from __future__ import annotations

import json
from unittest import mock

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

from capture.raw_packet import LINKTYPE_ETHERNET, RawPacket
from core.event import IDSEvent
from core.pipeline import Pipeline

CLIENT, SERVER = "192.168.1.10", "192.168.1.20"


def _raw(pkt: Packet | bytes, ts: float = 1.0) -> RawPacket:
    data = pkt if isinstance(pkt, bytes) else bytes(pkt)
    return RawPacket(
        timestamp=ts, data=data, linktype=LINKTYPE_ETHERNET, wire_len=len(data)
    )


def _tcp(sport: int, dport: int, flags: str, payload: bytes = b"") -> Packet:
    pkt = Ether() / IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=dport)
    pkt[TCP].flags = flags
    return pkt / Raw(payload) if payload else pkt


def test_tcp_syn_event() -> None:
    event = Pipeline().process(_raw(_tcp(40000, 80, "S"), ts=12.5))

    assert isinstance(event, IDSEvent)
    assert event.packet_id == 1
    assert event.timestamp == 12.5
    assert (event.src_ip, event.dst_ip) == (CLIENT, SERVER)
    assert event.protocol == "TCP"
    assert (event.src_port, event.dst_port) == (40000, 80)
    assert event.tcp_flags == ["SYN"]
    assert event.ip_total_length == 40  # 20B IP + 20B TCP
    assert event.app_protocol is None
    assert event.error is None
    json.dumps(event.to_dict())


def test_packet_ids_increase() -> None:
    pipeline = Pipeline()
    ids = [pipeline.process(_raw(_tcp(1, 2, "A"))).packet_id for _ in range(3)]
    assert ids == [1, 2, 3]


def test_http_get_event() -> None:
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    event = Pipeline().process(_raw(_tcp(40000, 80, "PA", payload)))
    assert event.app_protocol == "HTTP"
    assert event.detected_by == "payload"
    assert event.app_data["method"] == "GET"
    assert event.app_data["host"] == "example.com"
    assert event.payload_length == len(payload)
    assert event.payload_preview is None  # parsed data lives in app_data


def test_dns_response_event() -> None:
    pkt = (
        Ether()
        / IP(src=SERVER, dst=CLIENT)
        / UDP(sport=53, dport=5000)
        / DNS(
            qr=1,
            qd=DNSQR(qname="example.com"),
            an=DNSRR(rrname="example.com", rdata="1.2.3.4"),
        )
    )
    event = Pipeline().process(_raw(pkt))
    assert event.protocol == "UDP"
    assert event.tcp_flags == []
    assert event.app_protocol == "DNS"
    assert event.app_data["answers"][0]["data"] == "1.2.3.4"


def test_smtp_command_event() -> None:
    event = Pipeline().process(_raw(_tcp(40000, 25, "PA", b"EHLO client.local\r\n")))
    assert event.app_protocol == "SMTP"
    assert event.app_data["helo"] == "client.local"


def test_unknown_protocols_produce_unknown_events() -> None:
    pipeline = Pipeline()
    icmp = pipeline.process(_raw(Ether() / IP(src=CLIENT, dst=SERVER) / ICMP()))
    arp = pipeline.process(_raw(Ether() / ARP()))
    ipv6 = pipeline.process(_raw(Ether() / IPv6() / UDP()))
    tcp_other = pipeline.process(_raw(_tcp(40000, 22, "PA", b"SSH-2.0-x\r\n")))

    assert icmp.protocol == "UNKNOWN"
    assert icmp.src_ip == CLIENT  # network layer fields still filled
    assert icmp.ip_protocol == 1
    assert arp.protocol == "UNKNOWN" and "ARP" in arp.error
    assert ipv6.protocol == "UNKNOWN" and "IPv6" in ipv6.error
    assert tcp_other.protocol == "TCP"
    assert tcp_other.app_protocol is None


def test_skip_unknown() -> None:
    pipeline = Pipeline(skip_unknown=True)
    assert pipeline.process(_raw(Ether() / ARP())) is None
    assert pipeline.process(_raw(_tcp(1, 2, "S"))).packet_id == 2


def test_malformed_packets_do_not_crash() -> None:
    pipeline = Pipeline()
    good = bytes(_tcp(40000, 80, "PA", b"GET / HTTP/1.1\r\n\r\n"))
    samples = [
        b"",
        b"\x00" * 5,
        good[:20],  # Ethernet + 6 bytes of IP
        good[:40],  # IP ok, TCP header truncated
        good[:14] + b"\x45" + b"\xff" * 40,  # IP header with garbage fields
        bytes(Ether() / IP(src=CLIENT, dst=SERVER, ihl=15) / TCP()),  # bad IHL
    ]
    for data in samples:
        event = pipeline.process(_raw(data))
        assert event.error is not None
        json.dumps(event.to_dict())


def test_truncated_capture_is_noted_but_parsed() -> None:
    frame = bytes(_tcp(40000, 80, "PA", b"GET / HTTP/1.1\r\n\r\n"))
    raw = RawPacket(
        timestamp=1.0,
        data=frame[:-5],
        linktype=LINKTYPE_ETHERNET,
        wire_len=len(frame),
        truncated=True,
    )
    event = Pipeline().process(raw)
    assert event.error.startswith("capture: truncated packet")
    assert event.dst_port == 80
    assert event.app_protocol == "HTTP"


def test_parser_crash_is_contained() -> None:
    with mock.patch("core.pipeline.parse_transport", side_effect=RuntimeError("boom")):
        event = Pipeline().process(_raw(_tcp(1, 2, "S")))
    assert event.src_ip == CLIENT
    assert event.protocol == "UNKNOWN"
    assert "transport: internal error: boom" in event.error


def test_run_collects_stats() -> None:
    packets = [
        _raw(_tcp(40000, 80, "S")),
        _raw(_tcp(40000, 80, "PA", b"GET / HTTP/1.1\r\n\r\n")),
        _raw(Ether() / ARP()),
        _raw(b"\x00"),
    ]
    events: list[IDSEvent] = []
    stats = Pipeline(skip_unknown=True).run(packets, events.append)

    assert stats.processed == 4
    assert stats.written == 2
    assert stats.skipped == 2
    assert stats.by_protocol["TCP"] == 2
    assert stats.by_app_protocol["HTTP"] == 1
    assert [e.packet_id for e in events] == [1, 2]


def test_payload_preview_escapes_binary_and_is_limited() -> None:
    payload = b"AB\x00\xff\r\n" + b"x" * 500
    event = Pipeline().process(_raw(_tcp(40000, 9000, "PA", payload)))
    assert event.payload_preview.startswith("AB\\x00\\xff\r\n")
    assert len(event.payload_preview) == 128 + 6  # 2 escapes add 3 chars each
    assert Pipeline().process(_raw(_tcp(1, 2, "S"))).payload_preview is None


def test_smtp_auth_credentials_do_not_leak() -> None:
    payload = b"AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n"
    event = Pipeline().process(_raw(_tcp(40000, 25, "PA", payload)))
    assert event.app_data["auth_mechanism"] == "PLAIN"
    assert "AGFsaWNl" not in json.dumps(event.to_dict())


def test_bt2_stages_and_drop_policy() -> None:
    from config import Config, PreprocessConfig

    packets = [
        _raw(
            _tcp(40000, 80, "PA", b"GET /a%20b HTTP/1.1\r\nHost: Example.COM\r\n\r\n")
        ),
        _raw(Ether() / ARP()),
    ]
    events: list[dict] = []
    stats = Pipeline().run_bt2(packets, events.append)
    assert stats.written == 2 and stats.dropped == 0
    http, arp = events
    assert http["decoded"]["uri"] == "/a b"
    assert http["normalized"]["domain"] == "example.com"
    assert http["preprocess_status"] == "valid"
    assert arp["preprocess_status"] == "invalid"

    cfg = Config(preprocess=PreprocessConfig(on_unsupported="drop", log_dropped=False))
    events.clear()
    stats = Pipeline(config=cfg).run_bt2(packets, events.append)
    assert stats.written == 1 and stats.dropped == 1
    assert [e["packet_id"] for e in events] == [1]


def test_bt2_flow_tracking_end_to_end() -> None:
    packets = [
        _raw(_tcp(40000, 80, "S"), ts=1.0),
        _raw(
            Ether()
            / IP(src=SERVER, dst=CLIENT)
            / TCP(sport=80, dport=40000, flags="SA"),
            ts=1.1,
        ),
        _raw(_tcp(40000, 80, "A"), ts=1.2),
    ]
    events: list[dict] = []
    flows: list[dict] = []
    stats = Pipeline().run_bt2(packets, events.append, flows.append)

    assert len({e["flow_id"] for e in events}) == 1
    assert [e["direction"] for e in events] == ["forward", "backward", "forward"]
    assert stats.flows_exported == 1
    (flow,) = flows
    assert flow["state"] == "ESTABLISHED"
    assert flow["end_reason"] == "end_of_capture"
    assert flow["packet_count"] == 3
    assert flow["byte_count"] == 120  # 3 x (20B IP + 20B TCP)


def test_dropped_events_do_not_reach_tracker() -> None:
    from config import Config, PreprocessConfig

    cfg = Config(preprocess=PreprocessConfig(on_unsupported="drop"))
    icmp = _raw(Ether() / IP(src=CLIENT, dst=SERVER) / ICMP())
    events: list[dict] = []
    Pipeline(config=cfg).run_bt2([icmp], events.append, lambda r: None)
    assert events[0]["processing_action"] == "drop"
    assert events[0]["flow_id"] is None


def test_flows_flushed_when_interrupted() -> None:
    def source():
        yield _raw(_tcp(40000, 80, "S"))
        raise KeyboardInterrupt

    flows: list[dict] = []
    with pytest.raises(KeyboardInterrupt):
        Pipeline().run_bt2(source(), lambda e: None, flows.append)
    assert [f["end_reason"] for f in flows] == ["end_of_capture"]
