"""Unit tests for the BT2 config loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from config import Config, ConfigError, load_config

REPO = Path(__file__).resolve().parents[2]


def test_defaults() -> None:
    cfg = load_config()
    assert cfg == Config()
    assert cfg.flow.tcp_idle_timeout == 300.0
    assert cfg.flow.udp_idle_timeout == 60.0
    assert cfg.preprocess.on_invalid == "mark"


def test_shipped_config_json_equals_defaults() -> None:
    assert load_config(str(REPO / "config.json")) == Config()


def test_file_then_cli_override(tmp_path: Path) -> None:
    file = tmp_path / "cfg.json"
    file.write_text(
        json.dumps({"flow": {"tcp_idle_timeout": 30, "portless": "zero"}}),
        encoding="utf-8",
    )
    cfg = load_config(
        str(file), ["flow.tcp_idle_timeout=10", "preprocess.on_invalid=drop"]
    )
    assert cfg.flow.tcp_idle_timeout == 10.0  # CLI wins over file
    assert cfg.flow.portless == "zero"  # from file
    assert cfg.preprocess.on_invalid == "drop"
    assert cfg.flow.udp_idle_timeout == 60.0  # untouched default


def test_bool_and_int_coercion() -> None:
    cfg = load_config(None, ["decoder.enabled=false", "decoder.max_body_bytes=1024"])
    assert cfg.decoder.enabled is False
    assert cfg.decoder.max_body_bytes == 1024


@pytest.mark.parametrize(
    "override",
    [
        "flow.unknown_key=1",
        "nosection.key=1",
        "flow.tcp_idle_timeout=abc",
        "flow.tcp_idle_timeout=0",
        "flow.closed_linger=-1",
        "preprocess.on_invalid=ignore",
        "flow.portless=maybe",
        "decoder.max_body_bytes=1.5",
        "decoder.enabled=perhaps",
        "missing_equals_sign",
    ],
)
def test_invalid_overrides(override: str) -> None:
    with pytest.raises(ConfigError):
        load_config(None, [override])


def test_bad_files(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "missing.json"))
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(str(bad))
    arr = tmp_path / "arr.json"
    arr.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(str(arr))
