"""End-to-end tests of the CLI on PCAP files."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

import main


@pytest.fixture
def pcap_file(tmp_path: Path) -> Path:
    path = tmp_path / "sample.pcap"
    wrpcap(
        str(path),
        [
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80, flags="S"),
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(dport=80, flags="PA")
            / Raw(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
            Ether() / ARP(),
        ],
    )
    return path


def _read(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_pcap_to_jsonl(tmp_path: Path, pcap_file: Path) -> None:
    out = tmp_path / "out.jsonl"
    assert main.main(["--pcap", str(pcap_file), "--output", str(out)]) == 0

    events = _read(out)
    assert [e["packet_id"] for e in events] == [1, 2, 3]
    assert events[0]["tcp_flags"] == ["SYN"]
    assert events[1]["app_protocol"] == "HTTP"
    assert events[2]["protocol"] == "UNKNOWN"


def test_skip_unknown_flag(tmp_path: Path, pcap_file: Path) -> None:
    out = tmp_path / "out.jsonl"
    main.main(["--pcap", str(pcap_file), "-o", str(out), "--skip-unknown"])
    assert len(_read(out)) == 2


def test_missing_pcap_returns_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "out.jsonl"
    assert main.main(["--pcap", str(tmp_path / "nope.pcap"), "-o", str(out)]) == 1
    assert "not found" in capsys.readouterr().err


def test_truncated_pcap_is_processed(tmp_path: Path, pcap_file: Path) -> None:
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(pcap_file.read_bytes()[:-20])
    out = tmp_path / "out.jsonl"
    assert main.main(["--pcap", str(cut), "-o", str(out)]) == 0
    events = _read(out)
    assert len(events) == 3
    assert events[2]["error"].startswith("capture: truncated packet")


def test_source_is_required() -> None:
    with pytest.raises(SystemExit):
        main.main([])
    with pytest.raises(SystemExit):
        main.main(["--pcap", "a.pcap", "--interface", "eth0"])
