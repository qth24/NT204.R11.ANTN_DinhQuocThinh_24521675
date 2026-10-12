"""Preprocessor stage (BT2): validate and normalize IDS events.

Input:  event dict after the Decoder.
Output: the same dict with (values present in the input are never changed;
        missing BT1 fields are added as None / [] / {} by their type):

    "preprocess_status": "valid" | "partial" | "invalid"
    "processing_action": "pass" | "mark" | "drop"
    "reason":            [str]   why the event is partial/invalid
    "normalized":        {...}   see preprocess.normalizer

or None when the event is dropped and ``preprocess.log_dropped`` is false.

Action:
    valid   -> "pass"
    partial -> "mark"   (kept, flagged)
    invalid -> preprocess.on_unsupported (protocol not handled, e.g. ARP)
               or preprocess.on_invalid (anything else): "mark" or "drop"
A dropped event never reaches the Flow Tracker.
"""

from __future__ import annotations

from typing import Any

from config import PreprocessConfig
from preprocess.normalizer import fill_missing_fields, normalize_event
from preprocess.validator import ValidationResult, validate_event


def preprocess_event(
    event: dict[str, Any], cfg: PreprocessConfig
) -> dict[str, Any] | None:
    """Validate + normalize ``event``; see the module docstring."""
    if not cfg.enabled:
        event.update(
            preprocess_status="valid",
            processing_action="pass",
            reason=["preprocess_disabled"],
            normalized={},
        )
        return event

    # Each step has its own guard: a bug in one never hides the other.
    step_errors: list[str] = []
    try:
        fill_missing_fields(event)
    except Exception as exc:  # noqa: BLE001 - must not stop the pipeline
        step_errors.append(f"fill_defaults_error:{exc}")
    try:
        validation = validate_event(event)
    except Exception as exc:  # noqa: BLE001 - must not stop the pipeline
        validation = ValidationResult("invalid", [f"validator_error:{exc}"])
    try:
        normalized, norm_reasons = normalize_event(event)
    except Exception as exc:  # noqa: BLE001 - must not stop the pipeline
        normalized, norm_reasons = {}, [f"normalizer_error:{exc}"]
    norm_reasons = step_errors + norm_reasons

    status = validation.status
    if status == "valid" and norm_reasons:
        status = "partial"  # e.g. a domain that could not be IDNA-encoded

    if status == "valid":
        action = "pass"
    elif status == "partial":
        action = "mark"
    elif validation.unsupported:
        action = cfg.on_unsupported
    else:
        action = cfg.on_invalid

    event["preprocess_status"] = status
    event["processing_action"] = action
    event["reason"] = validation.reasons + norm_reasons
    event["normalized"] = normalized
    if action == "drop" and not cfg.log_dropped:
        return None
    return event
