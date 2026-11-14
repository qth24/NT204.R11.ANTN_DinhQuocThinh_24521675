"""Helpers shared by the BT3 test-case tests (tests/bt3/test_caseNN_*.py).

``run_case`` runs the real CLI (``main.main``) on the committed input and
rules of a TEST/BT3/case_NN_<name>/ folder, writing into a temp dir, so each
test checks concrete values AND that the committed output files are exactly
what the program produces today.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import main as cli
from config import load_config
from engine.factory import EngineBundle, build_engine
from engine.rule_parser import parse_rule

BT3_DIR = Path(__file__).resolve().parents[2] / "TEST" / "BT3"


def case_dir(case: str) -> Path:
    (folder,) = BT3_DIR.glob(f"case_{case}_*")
    return folder


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line]


def bundle_for(case: str, **overrides: str) -> EngineBundle:
    """Load the rules of a case folder the way the CLI does."""
    cfg = load_config(None, [f"{k}={v}" for k, v in overrides.items()])
    return build_engine(cfg.engine, [str(case_dir(case))])


def rule_line(text: str):
    """Parse one rule given as text (returns the ParseResult)."""
    return parse_rule(text, "<test>", 1)


def sids_by_packet(detections: list[dict[str, Any]]) -> dict[int, list[int]]:
    out: dict[int, list[int]] = {}
    for item in detections:
        out.setdefault(item["packet_id"], []).append(item["sid"])
    return out


@dataclass
class CaseRun:
    events: list[dict[str, Any]]
    flows: list[dict[str, Any]]
    detections: list[dict[str, Any]]
    folder: Path


def run_case(
    case: str, tmp_path: Path, extra: list[str] | None = None, name: str = ""
) -> CaseRun:
    folder = case_dir(case)
    source = (
        ["--events", str(folder / "input_events.jsonl")]
        if (folder / "input_events.jsonl").exists()
        else ["--pcap", str(folder / "input.pcap")]
    )
    out = tmp_path
    code = cli.main(
        [
            *source,
            "--rules",
            str(folder),
            "-o",
            str(out / "events.jsonl"),
            "--flow-output",
            str(out / "flows.jsonl"),
            "--detection-output",
            str(out / f"detections{name}.jsonl"),
            *(extra or []),
        ]
    )
    assert code == 0
    return CaseRun(
        read_jsonl(out / "events.jsonl"),
        read_jsonl(out / "flows.jsonl"),
        read_jsonl(out / f"detections{name}.jsonl"),
        folder,
    )


def assert_matches_committed(run: CaseRun, name: str = "detections.jsonl") -> None:
    """The committed output file equals what the program produces now."""
    committed = read_jsonl(run.folder / name)
    assert committed == run.detections
