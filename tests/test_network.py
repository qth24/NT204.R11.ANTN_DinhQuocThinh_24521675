"""Unit tests for the IPv4 network parser."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, CookedLinux, Dot1Q, Ether
from scapy.packet import Raw

from parsers.network import (
    ETHERTYPE_IPV4,
    IP_PROTO_TCP,
    IP_PROTO_UDP,
    LINKTYPE_ETHERNET,
    LINKTYPE_IPV4,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_RAW,
    parse_network,
)

SRC, DST = "192.168.1.10", "93.184.216.34"


def test_ethernet_ipv4_tcp() -> None:
    pkt = Ether() / IP(src=SRC, dst=DST, ttl=64, id=1234) / TCP(dport=80)
    result = parse_network(bytes(pkt), LINKTYPE_ETHERNET)

    assert result.error is None
    assert result.is_ipv4
    assert result.ethertype == ETHERTYPE_IPV4
    assert (result.src_ip, result.dst_ip) == (SRC, DST)
    assert result.protocol == IP_PROTO_TCP
    assert result.protocol_name == "TCP"
    assert result.ttl == 64
    assert result.identification == 1234
    assert result.header_length == 20
    assert result.checksum_valid is True
    assert result.payload == bytes(pkt)[14 + 20 :]  # after Ethernet + IP headers


def test_raw_ip_linktypes() -> None:
    raw = bytes(IP(src=SRC, dst=DST) / UDP(dport=53))
    for linktype in (LINKTYPE_RAW, LINKTYPE_IPV4):
        result = parse_network(raw, linktype)
        assert result.error is None
        assert result.protocol == IP_PROTO_UDP
        assert result.src_ip == SRC


def test_linux_cooked_capture() -> None:
    pkt = CookedLinux(proto=0x0800) / IP(src=SRC, dst=DST) / UDP()
    result = parse_network(bytes(pkt), LINKTYPE_LINUX_SLL)
    assert result.error is None
    assert result.dst_ip == DST


def test_vlan_tag_is_skipped() -> None:
    pkt = Ether() / Dot1Q(vlan=10) / IP(src=SRC, dst=DST) / TCP()
    result = parse_network(bytes(pkt), LINKTYPE_ETHERNET)
    assert result.error is None
    assert result.src_ip == SRC


def test_ethernet_padding_is_removed() -> None:
    # 20B IP + 8B UDP = 28B, Ethernet pads the frame to 60B
    pkt = Ether() / IP(src=SRC, dst=DST) / UDP()
    frame = bytes(pkt).ljust(60, b"\x00")
    result = parse_network(frame, LINKTYPE_ETHERNET)
    assert result.error is None
    assert len(result.payload) == 8


def test_ip_options_and_flags() -> None:
    pkt = IP(src=SRC, dst=DST, flags="MF", frag=10, options=b"\x01\x01\x01\x00") / Raw(
        b"x" * 8
    )
    result = parse_network(bytes(pkt), LINKTYPE_RAW)
    assert result.header_length == 24
    assert result.flags == ["MF"]
    assert result.fragment_offset == 80
    assert result.is_fragment
    assert result.payload == b"x" * 8


def test_bad_checksum_is_reported_not_rejected() -> None:
    raw = bytes(IP(src=SRC, dst=DST, chksum=0x1234) / UDP())
    result = parse_network(raw, LINKTYPE_RAW)
    assert result.error is None
    assert result.checksum_valid is False


def test_unsupported_ipv6() -> None:
    result = parse_network(bytes(Ether() / IPv6() / UDP()), LINKTYPE_ETHERNET)
    assert not result.is_ipv4
    assert "IPv6" in result.error


def test_unsupported_arp() -> None:
    result = parse_network(bytes(Ether() / ARP()), LINKTYPE_ETHERNET)
    assert not result.is_ipv4
    assert "ARP" in result.error


def test_empty_and_short_frames() -> None:
    assert parse_network(b"", LINKTYPE_ETHERNET).error is not None
    assert parse_network(b"\x00" * 10, LINKTYPE_ETHERNET).error is not None
    assert parse_network(b"", LINKTYPE_RAW).error is not None


def test_truncated_ipv4_header() -> None:
    raw = bytes(IP(src=SRC, dst=DST))[:12]
    result = parse_network(raw, LINKTYPE_RAW)
    assert not result.is_ipv4
    assert "Truncated IPv4 header" in result.error


def test_truncated_ipv4_payload_keeps_header_fields() -> None:
    raw = bytes(IP(src=SRC, dst=DST) / Raw(b"A" * 100))[:60]
    result = parse_network(raw, LINKTYPE_RAW)
    assert result.is_ipv4
    assert result.src_ip == SRC
    assert "Truncated IPv4 packet" in result.error
    assert len(result.payload) == 40


def test_invalid_version_and_ihl() -> None:
    raw = bytearray(bytes(IP(src=SRC, dst=DST)))
    raw[0] = 0x55  # version 5, IHL 5
    assert "version" in parse_network(bytes(raw), LINKTYPE_IPV4).error

    raw[0] = 0x43  # version 4, IHL 3 (12 bytes) is invalid
    assert "header length" in parse_network(bytes(raw), LINKTYPE_RAW).error


def test_total_length_smaller_than_header() -> None:
    raw = bytearray(bytes(IP(src=SRC, dst=DST) / UDP()))
    raw[2:4] = (10).to_bytes(2, "big")
    result = parse_network(bytes(raw), LINKTYPE_RAW)
    assert result.is_ipv4
    assert "Invalid IPv4 total length" in result.error


def test_unknown_linktype() -> None:
    result = parse_network(b"\x00" * 40, 9999)
    assert "unsupported linktype" in result.error
