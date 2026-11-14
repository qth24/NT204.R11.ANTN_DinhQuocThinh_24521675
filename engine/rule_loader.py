"""Rule loader: read ``.rules`` files and hand rule lines to the parser.

Input:  files and/or directories (``*.rules``), disabled files / sids.
Output: ``LoadResult`` = valid ``Rule`` objects in file order + a summary.

What the loader does (and nothing more):
    * skips blank lines and lines starting with ``#`` (a commented-out rule is
      a comment: it is never "re-enabled");
    * joins physical lines ending with ``\\`` into one logical rule line;
    * skips files / sids switched off by config (counted as ``disabled``);
    * rejects a second rule with an already used sid (``invalid:duplicate_sid``);
    * survives a missing file or a file that is not valid UTF-8 (warning only).

Parsing itself is injected (``parse``) so the loader stays independent of the
rule syntax; ``engine.rule_parser.parse_rule`` is the default.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from engine.rule_model import ParseResult, Rule

logger = logging.getLogger(__name__)

ParseFn = Callable[[str, str, int], ParseResult]  # (line, source_file, line_no)


@dataclass(frozen=True)
class RuleLine:
    """One logical rule line (continuations already joined)."""

    text: str
    source_file: str
    line_no: int  # first physical line of the rule


@dataclass
class LoadSummary:
    """Counters printed at the end of a run.

    ``loaded`` = rule lines found in all files, and
    ``loaded == valid + invalid + unsupported + disabled``.
    """

    loaded: int = 0
    valid: int = 0
    invalid: int = 0
    unsupported: int = 0
    disabled: int = 0
    warnings: list[str] = field(default_factory=list)


@dataclass
class LoadResult:
    rules: list[Rule] = field(default_factory=list)
    summary: LoadSummary = field(default_factory=LoadSummary)
    # invalid + unsupported results, with their reasons
    problems: list[ParseResult] = field(default_factory=list)


def read_rule_lines(path: str | Path) -> list[RuleLine]:
    """Return the logical rule lines of one file.

    Raises OSError / UnicodeDecodeError; ``load_rules`` catches them.
    """
    name = str(path)
    lines: list[RuleLine] = []
    buffer: list[str] = []
    start = 0
    with open(path, encoding="utf-8") as handle:
        for number, raw in enumerate(handle, start=1):
            text = raw.rstrip("\r\n")
            if not buffer:
                stripped = text.strip()
                if not stripped or stripped.startswith("#"):
                    continue  # blank line or comment
                start = number
            if text.rstrip().endswith("\\"):
                # Continuation: drop the backslash, keep reading the rule.
                buffer.append(text.rstrip()[:-1])
                continue
            buffer.append(text)
            lines.append(RuleLine(" ".join(p.strip() for p in buffer), name, start))
            buffer = []
    if buffer:  # file ends right after a trailing backslash
        lines.append(RuleLine(" ".join(p.strip() for p in buffer), name, start))
    return lines


def expand_paths(paths: Iterable[str | Path], summary: LoadSummary) -> list[Path]:
    """Files to read, in a deterministic order (directories: sorted ``*.rules``)."""
    files: list[Path] = []
    for item in paths:
        path = Path(item)
        if path.is_dir():
            files.extend(sorted(path.glob("*.rules")))
        elif path.is_file():
            files.append(path)
        else:
            _warn(summary, f"rule path not found: {path}")
    return files


def load_rules(
    paths: Iterable[str | Path],
    parse: ParseFn,
    disabled_files: Iterable[str] = (),
    disabled_sids: Iterable[int] = (),
) -> LoadResult:
    """Load every rule of ``paths``; never raises on a bad file or rule."""
    result = LoadResult()
    summary = result.summary
    off_files = set(disabled_files)
    off_sids = set(disabled_sids)
    seen_sids: set[int] = set()

    for path in expand_paths(paths, summary):
        try:
            lines = read_rule_lines(path)
        except (OSError, UnicodeDecodeError) as exc:
            _warn(summary, f"cannot read rule file {path}: {exc}")
            continue
        summary.loaded += len(lines)
        if str(path) in off_files or path.name in off_files:
            summary.disabled += len(lines)  # whole file switched off
            continue
        for line in lines:
            try:
                parsed = parse(line.text, line.source_file, line.line_no)
            except Exception as exc:  # a parser bug must not stop loading
                logger.exception("parser crashed on %s:%d", path, line.line_no)
                parsed = ParseResult(
                    "invalid",
                    reasons=(f"invalid:internal_error:{exc}",),
                    source_file=line.source_file,
                    line_no=line.line_no,
                )
            _account(result, parsed, seen_sids, off_sids)
    for problem in result.problems:
        _warn(
            summary,
            f"{problem.source_file}:{problem.line_no}: "
            f"{problem.status} ({', '.join(problem.reasons)})",
        )
    return result


def _account(
    result: LoadResult, parsed: ParseResult, seen: set[int], off_sids: set[int]
) -> None:
    summary = result.summary
    rule = parsed.rule
    if parsed.status == "valid" and rule is not None:
        if rule.sid in seen:
            parsed = ParseResult(
                "invalid",
                reasons=(f"invalid:duplicate_sid:{rule.sid}",),
                source_file=parsed.source_file,
                line_no=parsed.line_no,
            )
        else:
            seen.add(rule.sid)  # a disabled rule still reserves its sid
            if rule.sid in off_sids:
                summary.disabled += 1
                return
            summary.valid += 1
            result.rules.append(rule)
            for warning in parsed.warnings:
                _warn(summary, f"{rule.source_file}:{rule.line_no}: {warning}")
            return
    if parsed.status == "unsupported":
        summary.unsupported += 1
    else:
        summary.invalid += 1
    result.problems.append(parsed)


def _warn(summary: LoadSummary, message: str) -> None:
    logger.warning(message)
    summary.warnings.append(message)
