"""Unit tests for the capture layer (PCAP import + live capture)."""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap, wrpcapng

from capture import CaptureError, RawPacket, live_packets, read_pcap
from capture.raw_packet import LINKTYPE_ETHERNET


def _sample_packets() -> list:
    syn = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80, flags="S")
    syn.time = 1700000000.25
    dns = (
        Ether()
        / IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=5353, dport=53)
        / DNS(qd=DNSQR(qname="example.com"))
    )
    dns.time = 1700000001.5
    return [syn, dns]


@pytest.fixture
def pcap_file(tmp_path: Path) -> Path:
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), _sample_packets())
    return path


def test_read_pcap_yields_raw_packets(pcap_file: Path) -> None:
    packets = list(read_pcap(str(pcap_file)))
    expected = _sample_packets()

    assert len(packets) == 2
    for raw, pkt in zip(packets, expected):
        assert isinstance(raw, RawPacket)
        assert raw.data == bytes(pkt)
        assert raw.linktype == LINKTYPE_ETHERNET
        assert raw.wire_len == len(bytes(pkt))
        assert raw.truncated is False
        assert raw.source == "pcap:sample.pcap"
    assert packets[0].timestamp == pytest.approx(1700000000.25)
    assert packets[1].timestamp == pytest.approx(1700000001.5)


def test_read_pcapng_same_result_as_pcap(tmp_path: Path, pcap_file: Path) -> None:
    ng_path = tmp_path / "sample.pcapng"
    wrpcapng(str(ng_path), _sample_packets())

    from_pcap = list(read_pcap(str(pcap_file)))
    from_ng = list(read_pcap(str(ng_path)))

    assert [p.data for p in from_ng] == [p.data for p in from_pcap]
    assert [p.linktype for p in from_ng] == [p.linktype for p in from_pcap]
    assert [p.timestamp for p in from_ng] == pytest.approx(
        [p.timestamp for p in from_pcap]
    )


def test_truncated_pcap_does_not_crash(tmp_path: Path, pcap_file: Path) -> None:
    content = pcap_file.read_bytes()
    cut = tmp_path / "truncated.pcap"
    cut.write_bytes(content[:-10])  # last record loses 10 bytes

    packets = list(read_pcap(str(cut)))

    assert len(packets) == 2
    assert packets[0].truncated is False
    assert packets[1].truncated is True
    assert len(packets[1].data) == packets[1].wire_len - 10


def test_pcap_cut_inside_record_header(tmp_path: Path, pcap_file: Path) -> None:
    content = pcap_file.read_bytes()
    first_record_end = 24 + 16 + len(bytes(_sample_packets()[0]))
    cut = tmp_path / "cut_header.pcap"
    cut.write_bytes(content[: first_record_end + 5])  # half a record header

    packets = list(read_pcap(str(cut)))

    assert len(packets) == 1


def test_missing_file_raises_capture_error(tmp_path: Path) -> None:
    with pytest.raises(CaptureError):
        list(read_pcap(str(tmp_path / "nope.pcap")))


def test_not_a_pcap_raises_capture_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"this is not a pcap file")
    with pytest.raises(CaptureError):
        list(read_pcap(str(bad)))


def test_empty_file_raises_capture_error(tmp_path: Path) -> None:
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    with pytest.raises(CaptureError):
        list(read_pcap(str(empty)))


def test_live_capture_unknown_interface_raises_capture_error() -> None:
    with pytest.raises(CaptureError):
        list(live_packets("no_such_iface0", timeout=1))
