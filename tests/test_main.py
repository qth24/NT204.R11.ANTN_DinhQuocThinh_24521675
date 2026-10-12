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


def test_bt2_fields_by_default_and_bt1_only(tmp_path: Path, pcap_file: Path) -> None:
    out = tmp_path / "out.jsonl"
    main.main(["--pcap", str(pcap_file), "-o", str(out)])
    assert "decode_status" in _read(out)[1]

    main.main(["--pcap", str(pcap_file), "-o", str(out), "--bt1-only"])
    assert "decode_status" not in _read(out)[1]


def test_invalid_config_override_returns_error(
    tmp_path: Path, pcap_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "out.jsonl"
    argv = ["--pcap", str(pcap_file), "-o", str(out), "--set", "flow.nope=1"]
    assert main.main(argv) == 1
    assert "unknown config key" in capsys.readouterr().err


def test_flow_output_file(tmp_path: Path, pcap_file: Path) -> None:
    out, flows = tmp_path / "events.jsonl", tmp_path / "flows.jsonl"
    assert (
        main.main(
            ["--pcap", str(pcap_file), "-o", str(out), "--flow-output", str(flows)]
        )
        == 0
    )
    records = _read(flows)
    # SYN and HTTP GET both use Scapy default sport 20 -> same 5-tuple, one flow
    assert len(records) == 1
    assert records[0]["protocol"] == "TCP"
    assert {e["flow_id"] for e in _read(out) if e["protocol"] == "TCP"} == {
        records[0]["flow_id"]
    }


def test_events_jsonl_input(tmp_path: Path) -> None:
    events_in = tmp_path / "in.jsonl"
    events_in.write_text(
        json.dumps(
            {
                "packet_id": 1,
                "timestamp": 10.0,
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "protocol": "udp",
                "src_port": 5000,
                "dst_port": 53,
                "ip_total_length": 60,
            }
        )
        + "\n{broken json\n[1, 2]\n\n",
        encoding="utf-8",
    )
    out, flows = tmp_path / "out.jsonl", tmp_path / "flows.jsonl"
    argv = ["--events", str(events_in), "-o", str(out), "--flow-output", str(flows)]
    assert main.main(argv) == 0

    events = _read(out)
    assert len(events) == 3
    assert events[0]["preprocess_status"] == "valid"
    assert events[0]["flow_id"].startswith("UDP-")
    assert "invalid JSON" in events[1]["error"]
    assert "not a JSON object" in events[2]["error"]
    assert all(e["preprocess_status"] == "invalid" for e in events[1:])
    assert _read(flows)[0]["byte_count"] == 60


def test_events_with_bt1_only_is_rejected(tmp_path: Path) -> None:
    events_in = tmp_path / "in.jsonl"
    events_in.write_text("{}\n", encoding="utf-8")
    assert main.main(["--events", str(events_in), "--bt1-only", "-o", "-"]) == 1
