"""Write ``report.json`` for a BT3 case: how the rules were loaded and parsed.

For cases that are about the loader / parser / indexer the interesting
output is not a detection but the result of loading the rules: counts, the
reason of every rejected rule, the internal Rule objects and the candidate
rules the index returns for each input event.

Usage: python tests/bt3/report.py TEST/BT3/case_XX_name [out.json]
"""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from config import load_config  # noqa: E402
from engine.factory import build_engine  # noqa: E402


def _default(value):
    if isinstance(value, bytes):
        return value.hex(" ")
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    return str(value)  # IPv4Network ...


def build_report(case: Path) -> dict:
    config = load_config(None, [])
    bundle = build_engine(config.engine, [str(case)])
    load = bundle.load
    summary = load.summary
    report = {
        "summary": {
            "loaded": summary.loaded,
            "valid": summary.valid,
            "invalid": summary.invalid,
            "unsupported": summary.unsupported,
            "disabled": summary.disabled,
        },
        "problems": [
            {
                "file": Path(p.source_file).name,
                "line": p.line_no,
                "status": p.status,
                "reasons": list(p.reasons),
            }
            for p in load.problems
        ],
        "warnings": summary.warnings,
        "rules": [dataclasses.asdict(r) for r in load.rules],
    }
    events = case / "input_events.jsonl"
    if events.exists():
        repo = bundle.evaluator.repository
        report["candidates"] = {
            str(e["packet_id"]): [r.sid for r in repo.candidates(e)]
            for e in map(json.loads, events.read_text().splitlines())
        }
    return report


def main(argv: list[str]) -> int:
    case = Path(argv[0])
    out = Path(argv[1]) if len(argv) > 1 else case / "report.json"
    out.write_text(
        json.dumps(build_report(case), indent=2, default=_default) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
