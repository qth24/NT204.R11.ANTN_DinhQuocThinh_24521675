"""Internal rule objects produced by the rule parser.

All dataclasses are frozen: a rule is built once at start-up and only read
by the matcher afterwards.

Conventions for "no constraint" (Snort ``any``):
    * an empty ``src_nets`` / ``dst_nets`` tuple means ``any`` IP
    * an empty ``src_ports`` / ``dst_ports`` tuple means ``any`` port
    * ``None`` for flow / flags / dsize / offset / depth ... means "not set"
(the tuples already allow lists such as ``[80,443]`` if added later).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Network
from typing import Literal

RuleStatus = Literal["valid", "invalid", "unsupported"]


@dataclass(frozen=True)
class PortRange:
    """Inclusive port range; a single port has ``low == high``."""

    low: int
    high: int

    def contains(self, port: int) -> bool:
        return self.low <= port <= self.high


@dataclass(frozen=True)
class RuleHeader:
    """``proto src_ip src_port dir dst_ip dst_port`` of a rule."""

    proto: str  # "TCP" | "UDP"
    src_nets: tuple[IPv4Network, ...]  # empty = any
    src_ports: tuple[PortRange, ...]  # empty = any
    direction: str  # "->" | "<>"
    dst_nets: tuple[IPv4Network, ...]
    dst_ports: tuple[PortRange, ...]


@dataclass(frozen=True)
class ContentOption:
    """One ``content`` keyword with the modifiers that follow it."""

    pattern: bytes  # already decoded from |hex| and \-escapes
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None  # distance/within set => relative to prev match
    within: int | None = None

    @property
    def relative(self) -> bool:
        return self.distance is not None or self.within is not None


@dataclass(frozen=True)
class FlowOption:
    direction: str | None = None  # "to_server" | "to_client" | None
    state: str | None = None  # "established" | "not_established" | None


@dataclass(frozen=True)
class FlagsOption:
    """``flags:[!+*]FSRPAU[,mask]``.

    ``flags`` / ``mask`` hold Snort letters (F S R P A U C E).
    ``modifier``: "" exact, "+" all, "*" any, "!" none.
    """

    flags: frozenset[str]
    modifier: str = ""
    mask: frozenset[str] = frozenset()


@dataclass(frozen=True)
class DsizeOption:
    """``dsize`` as ``op`` in eq / lt / gt / range (range uses ``high``)."""

    op: str
    value: int
    high: int | None = None


@dataclass(frozen=True)
class Rule:
    """A valid, supported rule (only these enter the repository)."""

    sid: int
    rev: int
    msg: str
    action: str
    header: RuleHeader
    contents: tuple[ContentOption, ...] = ()
    flow: FlowOption | None = None
    flags: FlagsOption | None = None
    dsize: DsizeOption | None = None
    classtype: str | None = None
    priority: int | None = None
    source_file: str = ""
    line_no: int = 0
    raw: str = ""
    status: RuleStatus = "valid"


@dataclass(frozen=True)
class ParseResult:
    """Outcome of parsing one rule line.

    ``reasons`` hold stable codes such as ``invalid:missing_sid`` or
    ``unsupported:keyword:pcre``; ``warnings`` hold accepted-but-ignored
    keywords (``ignored:keyword:reference``).
    """

    status: RuleStatus
    rule: Rule | None = None
    reasons: tuple[str, ...] = ()
    source_file: str = ""
    line_no: int = 0
    warnings: tuple[str, ...] = field(default=())
