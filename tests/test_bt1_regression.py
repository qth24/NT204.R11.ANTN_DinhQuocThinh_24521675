"""BT1 regression: re-parsing every BT1 test PCAP must give the committed output.

Fields added after a case was recorded (e.g. ``ip_total_length``) are ignored;
every field present in the committed ``output.jsonl`` must be unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from capture.pcap_reader import read_pcap
from core.pipeline import Pipeline

TEST_DIR = Path(__file__).resolve().parent.parent / "TEST"
RUNS = [
    (case / "input.pcap", case / "output.jsonl", False)
    for case in sorted(TEST_DIR.glob("case_*"))
] + [
    (
        TEST_DIR / "case_11_unknown_protocol" / "input.pcap",
        TEST_DIR / "case_11_unknown_protocol" / "output_skip_unknown.jsonl",
        True,
    ),
    (
        TEST_DIR / "case_12_malformed_packet" / "input_truncated.pcap",
        TEST_DIR / "case_12_malformed_packet" / "output_truncated.jsonl",
        False,
    ),
]


@pytest.mark.parametrize(
    "pcap, expected, skip_unknown",
    RUNS,
    ids=[str(r[1].relative_to(TEST_DIR)) for r in RUNS],
)
def test_bt1_case_output_unchanged(
    pcap: Path, expected: Path, skip_unknown: bool
) -> None:
    pipeline = Pipeline(skip_unknown=skip_unknown)
    events = [pipeline.process(raw) for raw in read_pcap(str(pcap))]
    actual = [e.to_dict() for e in events if e is not None]
    recorded = [
        json.loads(line) for line in expected.read_text(encoding="utf-8").splitlines()
    ]

    assert len(actual) == len(recorded)
    for new, old in zip(actual, recorded):
        assert {k: new[k] for k in old} == old
