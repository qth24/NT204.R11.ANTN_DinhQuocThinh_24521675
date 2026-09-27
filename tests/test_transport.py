"""Unit tests for the TCP/UDP transport parser."""

from __future__ import annotations

from scapy.layers.inet import TCP, UDP
from scapy.packet import Raw

from parsers.transport import IP_PROTO_TCP, IP_PROTO_UDP, parse_transport


def test_tcp_syn() -> None:
    seg = bytes(TCP(sport=40000, dport=80, flags="S", seq=1000, window=64240))
    result = parse_transport(IP_PROTO_TCP, seg)

    assert result.error is None
    assert result.protocol == "TCP"
    assert (result.src_port, result.dst_port) == (40000, 80)
    assert result.tcp_flags == ["SYN"]
    assert result.seq == 1000
    assert result.window == 64240
    assert result.header_length == 20
    assert result.payload == b""


def test_tcp_handshake_flags() -> None:
    syn_ack = bytes(TCP(flags="SA", seq=5000, ack=1001))
    ack = bytes(TCP(flags="A", seq=1001, ack=5001))

    r1 = parse_transport(IP_PROTO_TCP, syn_ack)
    r2 = parse_transport(IP_PROTO_TCP, ack)

    assert r1.tcp_flags == ["SYN", "ACK"]
    assert (r1.seq, r1.ack) == (5000, 1001)
    assert r2.tcp_flags == ["ACK"]


def test_tcp_all_flags() -> None:
    seg = bytearray(bytes(TCP()))
    seg[12] |= 0x01  # NS
    seg[13] = 0xFF
    result = parse_transport(IP_PROTO_TCP, bytes(seg))
    assert result.tcp_flags == [
        "FIN",
        "SYN",
        "RST",
        "PSH",
        "ACK",
        "URG",
        "ECE",
        "CWR",
        "NS",
    ]


def test_tcp_with_payload_and_options() -> None:
    seg = TCP(dport=80, flags="PA", options=[("MSS", 1460), ("NOP", None)]) / Raw(
        b"GET / HTTP/1.1\r\n\r\n"
    )
    result = parse_transport(IP_PROTO_TCP, bytes(seg))
    assert result.error is None
    assert result.header_length == 28
    assert result.tcp_flags == ["PSH", "ACK"]
    assert result.payload == b"GET / HTTP/1.1\r\n\r\n"


def test_udp_with_payload() -> None:
    dgram = bytes(UDP(sport=5353, dport=53) / Raw(b"hello"))
    result = parse_transport(IP_PROTO_UDP, dgram)
    assert result.error is None
    assert result.protocol == "UDP"
    assert (result.src_port, result.dst_port) == (5353, 53)
    assert result.udp_length == 13
    assert result.payload == b"hello"
    assert result.tcp_flags == []


def test_udp_trailing_bytes_are_cut_to_length() -> None:
    dgram = bytes(UDP() / Raw(b"abc")) + b"\x00\x00"
    assert parse_transport(IP_PROTO_UDP, dgram).payload == b"abc"


def test_unsupported_protocol() -> None:
    result = parse_transport(1, b"\x08\x00\x00\x00")  # ICMP
    assert result.protocol == "UNKNOWN"
    assert "Unsupported transport protocol" in result.error


def test_empty_payload() -> None:
    for proto in (IP_PROTO_TCP, IP_PROTO_UDP):
        result = parse_transport(proto, b"")
        assert result.src_port is None
        assert "Truncated" in result.error


def test_truncated_tcp_header() -> None:
    result = parse_transport(IP_PROTO_TCP, bytes(TCP())[:12])
    assert result.protocol == "TCP"
    assert "Truncated TCP header" in result.error


def test_invalid_tcp_data_offset() -> None:
    seg = bytearray(bytes(TCP(dport=443)))
    seg[12] = 0x30  # data offset 3 -> 12 bytes, invalid
    result = parse_transport(IP_PROTO_TCP, bytes(seg))
    assert result.dst_port == 443
    assert "Invalid TCP data offset" in result.error


def test_truncated_tcp_options_keep_ports() -> None:
    seg = bytes(TCP(sport=1234, options=[("MSS", 1460)]))[:22]
    result = parse_transport(IP_PROTO_TCP, seg)
    assert result.src_port == 1234
    assert "Truncated TCP options" in result.error


def test_invalid_and_truncated_udp_length() -> None:
    dgram = bytearray(bytes(UDP() / Raw(b"abcdef")))
    dgram[4:6] = (4).to_bytes(2, "big")
    assert "Invalid UDP length" in parse_transport(IP_PROTO_UDP, bytes(dgram)).error

    dgram[4:6] = (100).to_bytes(2, "big")
    result = parse_transport(IP_PROTO_UDP, bytes(dgram))
    assert "Truncated UDP datagram" in result.error
    assert result.payload == b"abcdef"


def test_non_first_fragment_has_no_header() -> None:
    result = parse_transport(IP_PROTO_TCP, b"middle of data", fragment_offset=1480)
    assert result.protocol == "TCP"
    assert result.src_port is None
    assert result.payload == b"middle of data"
    assert "Non-first IP fragment" in result.error


def test_chained_with_network_parser() -> None:
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether

    from parsers.network import LINKTYPE_ETHERNET, parse_network

    frame = bytes(
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(dport=25)
        / Raw(b"EHLO x\r\n")
    ).ljust(80, b"\x00")
    net = parse_network(frame, LINKTYPE_ETHERNET)
    result = parse_transport(net.protocol, net.payload, net.fragment_offset)

    assert result.error is None
    assert result.dst_port == 25
    assert result.payload == b"EHLO x\r\n"  # Ethernet padding not included
