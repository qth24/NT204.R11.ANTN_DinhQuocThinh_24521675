"""BT2 settings: default values, config file loading and CLI overrides.

Every threshold of the Decoder, Preprocessor and Flow Tracker lives here so
nothing is hard-coded in the stages.

Input:  optional config file (.json, or .yaml/.yml when PyYAML is installed)
        + "section.key=value" overrides from the CLI (``--set``).
Output: an immutable ``Config`` object.

Priority (lowest -> highest): defaults below < config file < CLI overrides.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path
from typing import Any

POLICIES = ("mark", "drop")
PORTLESS_MODES = ("skip", "zero")


class ConfigError(ValueError):
    """Invalid config file, unknown key or out-of-range value."""


@dataclass(frozen=True)
class DecoderConfig:
    """decoder.*"""

    enabled: bool = True
    # Bodies longer than this are cut before decoding (status "partial").
    max_body_bytes: int = 65536


@dataclass(frozen=True)
class PreprocessConfig:
    """preprocess.*"""

    enabled: bool = True
    # What to do with invalid events / unsupported protocols: "mark" or "drop".
    on_invalid: str = "mark"
    on_unsupported: str = "mark"
    # Still write dropped events to events.jsonl (they never reach the tracker).
    log_dropped: bool = True


@dataclass(frozen=True)
class FlowConfig:
    """flow.*  (all durations in seconds of *packet* time)"""

    enabled: bool = True
    tcp_idle_timeout: float = 300.0
    udp_idle_timeout: float = 60.0
    # Keep CLOSED/RESET flows a little longer to absorb the last ACK.
    closed_linger: float = 5.0
    # Upper bound of the active table; the least recently seen flow is evicted.
    max_active_flows: int = 100000
    # Packets without ports (ICMP, UNKNOWN...): "skip" = no flow, "zero" = port 0.
    portless: str = "skip"
    # Minimum packet-time gap between two expiry sweeps (0 = every packet).
    sweep_interval: float = 1.0


@dataclass(frozen=True)
class Config:
    decoder: DecoderConfig = field(default_factory=DecoderConfig)
    preprocess: PreprocessConfig = field(default_factory=PreprocessConfig)
    flow: FlowConfig = field(default_factory=FlowConfig)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_config(path: str | None = None, overrides: list[str] | None = None) -> Config:
    """Build a Config from defaults, an optional file and CLI overrides.

    ``overrides`` items look like ``"flow.tcp_idle_timeout=30"``.
    Raises ConfigError on any unknown key or invalid value.
    """
    values: dict[str, dict[str, Any]] = {}
    if path:
        values = _read_file(path)
    for item in overrides or []:
        key, sep, raw = item.partition("=")
        section, dot, name = key.strip().partition(".")
        if not sep or not dot:
            raise ConfigError(f"override must look like section.key=value: {item!r}")
        values.setdefault(section, {})[name] = raw.strip()

    config = Config()
    for section, items in values.items():
        current = getattr(config, section, None)
        if current is None or not isinstance(items, dict):
            raise ConfigError(f"unknown config section: {section!r}")
        known = {f.name: f for f in fields(current)}
        changes = {}
        for name, value in items.items():
            if name not in known:
                raise ConfigError(f"unknown config key: {section}.{name}")
            default = getattr(current, name)
            changes[name] = _coerce(f"{section}.{name}", value, type(default))
        config = replace(config, **{section: replace(current, **changes)})

    _validate(config)
    return config


def _read_file(path: str) -> dict[str, dict[str, Any]]:
    file = Path(path)
    if not file.is_file():
        raise ConfigError(f"config file not found: {path}")
    text = file.read_text(encoding="utf-8")
    try:
        if file.suffix.lower() in (".yaml", ".yml"):
            try:
                import yaml  # optional dependency
            except ImportError as exc:
                raise ConfigError(
                    "YAML config needs PyYAML (pip install pyyaml); "
                    "or use a .json config"
                ) from exc
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be an object")
    return data


def _coerce(key: str, value: Any, target: type) -> Any:
    """Convert a value from JSON or the CLI (always str) to the default's type."""
    try:
        if target is bool:
            if isinstance(value, bool):
                return value
            if str(value).lower() in ("1", "true", "yes", "on"):
                return True
            if str(value).lower() in ("0", "false", "no", "off"):
                return False
            raise ValueError
        if target is int:
            if isinstance(value, bool) or float(value) != int(float(value)):
                raise ValueError
            return int(float(value))
        if target is float:
            if isinstance(value, bool):
                raise ValueError
            return float(value)
        return str(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{key}: invalid {target.__name__} value {value!r}") from exc


def _validate(config: Config) -> None:
    pre, flow = config.preprocess, config.flow
    for name in ("on_invalid", "on_unsupported"):
        if getattr(pre, name) not in POLICIES:
            raise ConfigError(f"preprocess.{name} must be one of {POLICIES}")
    if flow.portless not in PORTLESS_MODES:
        raise ConfigError(f"flow.portless must be one of {PORTLESS_MODES}")
    if config.decoder.max_body_bytes <= 0:
        raise ConfigError("decoder.max_body_bytes must be > 0")
    if flow.max_active_flows <= 0:
        raise ConfigError("flow.max_active_flows must be > 0")
    for name in ("tcp_idle_timeout", "udp_idle_timeout"):
        if getattr(flow, name) <= 0:
            raise ConfigError(f"flow.{name} must be > 0")
    for name in ("closed_linger", "sweep_interval"):
        if getattr(flow, name) < 0:
            raise ConfigError(f"flow.{name} must be >= 0")
