"""Rule Evaluation Engine: event -> candidate rules -> matcher -> all matches.

    candidates = repository.candidates(event)      # index: protocol + port
    for rule in candidates: matcher.match(rule, event, flow_ctx)

Every rule that matches is returned (default). With
``stop_on_first_match=True`` evaluation stops at the first match in rule
order; this hides the other rules that also fire, so it is off by default.

Events that must not reach the engine (preprocessor ``drop`` / ``invalid``)
are ignored here too, as a second line of defence.

Statistics are instance attributes (no globals); ``summary()`` is printed at
the end of a run, and ``use_index=False`` scans every rule instead, to
compare the cost with and without the index.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from engine.matching import MatchResult, RuleMatcher
from engine.rule_index import RuleRepository

logger = logging.getLogger(__name__)

# Reasons that mean "rejected by the header stage"
_HEADER_REASONS = frozenset({"protocol", "direction", "address_or_port"})


class RuleEvaluationEngine:
    def __init__(
        self,
        repository: RuleRepository,
        matcher: RuleMatcher | None = None,
        stop_on_first_match: bool = False,
        use_index: bool = True,
    ) -> None:
        self.repository = repository
        self.matcher = matcher or RuleMatcher()
        self.stop_on_first_match = stop_on_first_match
        self.use_index = use_index
        self.events_evaluated = 0
        self.events_skipped = 0
        self.candidates_total = 0
        self.rules_rejected_by_header = 0
        self.rules_matched = 0
        self.rule_errors = 0
        self.rejections: Counter[str] = Counter()
        self.hits: Counter[int] = Counter()

    def evaluate(
        self, event: dict[str, Any], flow_ctx: dict[str, Any] | None = None
    ) -> list[MatchResult]:
        """Return the matching rules for ``event`` in deterministic order.

        ``flow_ctx`` defaults to ``event["flow_context"]``. Never raises: an
        error inside one rule is logged and that rule is skipped.
        """
        if event.get("processing_action") == "drop" or (
            event.get("preprocess_status") == "invalid"
        ):
            self.events_skipped += 1
            return []
        if flow_ctx is None:
            flow_ctx = event.get("flow_context")
        self.events_evaluated += 1
        candidates = (
            self.repository.candidates(event)
            if self.use_index
            else self.repository.all()
        )
        self.candidates_total += len(candidates)

        results: list[MatchResult] = []
        for rule in candidates:
            try:
                result = self.matcher.match(rule, event, flow_ctx)
            except Exception:  # a bug/odd data in one rule must not stop others
                logger.exception(
                    "rule %s failed on packet %s", rule.sid, event.get("packet_id")
                )
                self.rule_errors += 1
                continue
            if not result.matched:
                reason = result.reason_no_match or "unknown"
                self.rejections[reason.split(":")[0]] += 1
                if reason in _HEADER_REASONS:
                    self.rules_rejected_by_header += 1
                continue
            self.rules_matched += 1
            self.hits[rule.sid] += 1
            results.append(result)
            if self.stop_on_first_match:
                break
        return results

    def summary(self) -> dict[str, Any]:
        events = self.events_evaluated
        return {
            "rules": len(self.repository),
            "events_evaluated": events,
            "events_skipped": self.events_skipped,
            "candidates_total": self.candidates_total,
            "candidates_per_event": (
                round(self.candidates_total / events, 3) if events else 0.0
            ),
            "rules_rejected_by_header": self.rules_rejected_by_header,
            "rules_matched": self.rules_matched,
            "rule_errors": self.rule_errors,
            "rejections": dict(sorted(self.rejections.items())),
            "hits_by_sid": dict(sorted(self.hits.items())),
        }
