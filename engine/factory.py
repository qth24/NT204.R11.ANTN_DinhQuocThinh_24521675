"""Build the BT3 engine from the config: load rules once, index, wire stages."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from config import EngineConfig
from engine.detection import DetectionEventGenerator
from engine.evaluator import RuleEvaluationEngine
from engine.matching import RuleMatcher
from engine.rule_index import RuleRepository
from engine.rule_loader import LoadResult, load_rules
from engine.rule_parser import make_parser


@dataclass
class EngineBundle:
    """Everything the pipeline needs for detection."""

    evaluator: RuleEvaluationEngine
    generator: DetectionEventGenerator
    load: LoadResult


def build_engine(
    cfg: EngineConfig, rule_paths: Sequence[str] | None = None
) -> EngineBundle:
    """Load + parse + index the rules (``rule_paths`` overrides cfg.rule_files)."""
    paths = list(rule_paths) if rule_paths else list(cfg.rule_files)
    load = load_rules(
        paths,
        make_parser(cfg.ignorable_keywords),
        disabled_files=cfg.disabled_rule_files,
        disabled_sids=cfg.disabled_sids,
    )
    repository = RuleRepository()
    for rule in load.rules:
        repository.add(rule)
    matcher = RuleMatcher(
        dsize_inclusive=cfg.dsize_range_inclusive,
        max_content_backtrack=cfg.max_content_backtrack,
    )
    evaluator = RuleEvaluationEngine(
        repository, matcher, stop_on_first_match=cfg.stop_on_first_match
    )
    generator = DetectionEventGenerator(repository, cfg.default_priority)
    return EngineBundle(evaluator, generator, load)
