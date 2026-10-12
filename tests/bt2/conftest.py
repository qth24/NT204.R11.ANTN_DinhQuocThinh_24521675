"""Helpers shared by the BT2 test-case tests (tests/bt2/test_tXX_*.py).

Each test runs the full pipeline in memory on the committed input of a
TEST/bt2_TXX_<name>/ folder, asserts concrete values, and checks that the
result is exactly the committed events.jsonl / flows.jsonl.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from capture.pcap_reader import read_pcap
from config import load_config
from core.logger import read_jsonl
from core.pipeline import Pipeline

TEST_DIR = Path(__file__).resolve().parents[2] / "TEST"


def case_dir(case: str) -> Path:
    (folder,) = TEST_DIR.glob(f"bt2_{case}_*")
    return folder


def run_case(
    case: str, overrides: list[str] | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Run the pipeline on the case input; returns (events, flows) as JSON data."""
    folder = case_dir(case)
    pipeline = Pipeline(config=load_config(None, overrides or []))
    events: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    jsonl = folder / "input_events.jsonl"
    if jsonl.exists():
        pipeline.run_events(read_jsonl(str(jsonl)), events.append, flows.append)
    else:
        pipeline.run_bt2(
            read_pcap(str(folder / "input.pcap")), events.append, flows.append
        )
    # Round-trip through JSON so values compare like the files on disk
    return _roundtrip(events), _roundtrip(flows)


def committed(case: str, name: str) -> list[dict[str, Any]]:
    path = case_dir(case) / name
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _roundtrip(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [json.loads(json.dumps(r, ensure_ascii=False)) for r in records]
