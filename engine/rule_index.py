"""Rule repository and two-level index (protocol -> destination-port bucket).

Why an index: without it every event is compared with every rule
(O(R) per event). With it only rules that *can* match the event's protocol
and ports are returned (usually a handful), and the exact header check is
done on those few.

Structure::

    by_proto["TCP"] = PortBuckets(
        exact  = {80: [rule_idx, ...], 443: [...]},   # single dst port
        ranges = [(PortRange, rule_idx), ...],        # 1:1024, 1024:, :1024
        any    = [rule_idx, ...])                     # dst port "any"
    by_proto["UDP"] = PortBuckets(...)

Contract: ``candidates(event)`` is a SUPERSET of the rules that can match.
    * A rule is filed by the port of its DESTINATION side.
    * A ``->`` rule can only match if event.dst_port is in that port set, so
      only event.dst_port is looked up for it.
    * A ``<>`` rule also matches the reversed direction, where the rule's
      destination ports face event.src_port, so for ``<>`` rules BOTH event
      ports are looked up.
    * An event without ports (None) can only match rules filed under ``any``.
The header matcher still re-checks everything exactly.

Result order: insertion order (= order of the rule files, then lines), each
rule at most once even when it is found through several buckets.
Cost: one dict lookup per event port + one pass over the range bucket, i.e.
O(1 + |ranges| + |matches|) instead of O(R).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engine.rule_model import PortRange, Rule


@dataclass
class PortBuckets:
    exact: dict[int, list[int]] = field(default_factory=dict)
    ranges: list[tuple[PortRange, int]] = field(default_factory=list)
    any: list[int] = field(default_factory=list)


class RuleRepository:
    """Holds the valid rules and answers ``candidates`` queries."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._by_sid: dict[int, Rule] = {}
        self._by_proto: dict[str, PortBuckets] = {}
        self._bidirectional: set[int] = set()  # indexes of "<>" rules

    def __len__(self) -> int:
        return len(self._rules)

    def add(self, rule: Rule) -> None:
        """Insert one rule. Raises ValueError for a duplicate sid."""
        if rule.sid in self._by_sid:
            raise ValueError(f"duplicate sid {rule.sid}")
        index = len(self._rules)
        self._rules.append(rule)
        self._by_sid[rule.sid] = rule
        if rule.header.direction == "<>":
            self._bidirectional.add(index)
        buckets = self._by_proto.setdefault(rule.header.proto, PortBuckets())
        ports = rule.header.dst_ports
        if not ports:
            buckets.any.append(index)
        for port_range in ports:
            if port_range.low == port_range.high:
                buckets.exact.setdefault(port_range.low, []).append(index)
            else:
                buckets.ranges.append((port_range, index))

    def get(self, sid: int) -> Rule | None:
        return self._by_sid.get(sid)

    def all(self) -> list[Rule]:
        """Every rule in insertion order."""
        return list(self._rules)

    def candidates(self, event: dict[str, Any]) -> list[Rule]:
        """Rules that may match ``event`` (see the module docstring)."""
        proto = _protocol(event)
        buckets = self._by_proto.get(proto)
        if buckets is None:
            return []  # other protocol: nothing can match
        found: set[int] = set(buckets.any)
        dst_port, src_port = _port(event, "dst_port"), _port(event, "src_port")
        if dst_port is not None:
            found.update(buckets.exact.get(dst_port, ()))
            found.update(i for r, i in buckets.ranges if r.contains(dst_port))
        if src_port is not None:
            # Only "<>" rules can face their destination ports to the source.
            bidir = self._bidirectional
            found.update(i for i in buckets.exact.get(src_port, ()) if i in bidir)
            found.update(
                i for r, i in buckets.ranges if i in bidir and r.contains(src_port)
            )
        return [self._rules[i] for i in sorted(found)]


def _protocol(event: dict[str, Any]) -> str:
    normalized = event.get("normalized")
    if isinstance(normalized, dict) and normalized.get("protocol"):
        return str(normalized["protocol"]).upper()
    return str(event.get("protocol") or "").upper()


def _port(event: dict[str, Any], name: str) -> int | None:
    port = event.get(name)
    return port if isinstance(port, int) and not isinstance(port, bool) else None
