"""Unit tests for the JSON Lines writer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.event import IDSEvent
from core.logger import JsonLinesWriter


def _event(packet_id: int, **kwargs) -> IDSEvent:
    return IDSEvent(packet_id=packet_id, timestamp=1.0, **kwargs)


def test_writes_one_json_object_per_line(tmp_path: Path) -> None:
    out = tmp_path / "out.jsonl"
    with JsonLinesWriter(str(out)) as writer:
        writer.write(_event(1, protocol="TCP"))
        writer.write(_event(2, app_data={"note": "Thịnh ✓"}))
        assert writer.count == 2

    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["protocol"] == "TCP"
    assert json.loads(lines[1])["app_data"]["note"] == "Thịnh ✓"


def test_overwrite_and_append_modes(tmp_path: Path) -> None:
    out = tmp_path / "out.jsonl"
    for _ in range(2):
        with JsonLinesWriter(str(out)) as writer:
            writer.write(_event(1))
    assert len(out.read_text().splitlines()) == 1

    with JsonLinesWriter(str(out), append=True) as writer:
        writer.write(_event(2))
    assert len(out.read_text().splitlines()) == 2


def test_non_json_values_are_converted(tmp_path: Path) -> None:
    out = tmp_path / "out.jsonl"
    with JsonLinesWriter(str(out)) as writer:
        writer.write(_event(1, app_data={"raw": b"\x01\x02"}))
    assert json.loads(out.read_text())["app_data"]["raw"] == "0102"


def test_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    with JsonLinesWriter("-") as writer:
        writer.write(_event(5))
    assert json.loads(capsys.readouterr().out)["packet_id"] == 5


def test_write_outside_context_raises() -> None:
    with pytest.raises(RuntimeError):
        JsonLinesWriter("unused.jsonl").write(_event(1))
