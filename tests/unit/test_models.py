"""Tests for llm_gateway.models."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from llm_gateway.models import (
    Action,
    Decision,
    Direction,
    Finding,
    RiskLevel,
    ScanResult,
)


def make_finding(**overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "detector": "secret",
        "category": "api_key",
        "start": 10,
        "end": 30,
        "confidence": 0.9,
        "severity": RiskLevel.HIGH,
    }
    values.update(overrides)
    return Finding(**values)


def test_valid_finding() -> None:
    finding = make_finding(entity_type="AWS_ACCESS_KEY", rule_id="aws-key")
    assert finding.end - finding.start == 20
    assert finding.severity is RiskLevel.HIGH


@pytest.mark.parametrize(
    "overrides",
    [
        {"start": 30, "end": 30},  # empty span
        {"start": 30, "end": 10},  # end before start
        {"start": -1},
        {"confidence": 1.5},
        {"confidence": -0.1},
        {"detector": ""},
        {"category": ""},
        {"severity": "extreme"},
    ],
)
def test_invalid_finding_is_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_finding(**overrides)


def test_finding_cannot_be_changed() -> None:
    finding = make_finding()
    with pytest.raises(ValidationError):
        finding.confidence = 0.1  # type: ignore[misc]  # failing is the point


def test_finding_has_no_field_for_the_found_text() -> None:
    """By design, a finding never holds the actual secret or PII."""
    risky_names = {"value", "text", "match", "matched_text", "raw"}
    assert risky_names.isdisjoint(Finding.model_fields)


def test_scan_result_defaults_to_nothing_found() -> None:
    result = ScanResult(direction=Direction.INPUT)
    assert result.findings == ()
    assert result.errors == ()


def test_scan_result_holds_findings() -> None:
    result = ScanResult(direction="output", findings=[make_finding()])
    assert result.direction is Direction.OUTPUT
    assert len(result.findings) == 1


def test_decision() -> None:
    decision = Decision(
        action=Action.BLOCK,
        risk_level=RiskLevel.HIGH,
        reasons=["prompt injection found"],
    )
    assert decision.action == "block"
    assert decision.reasons == ("prompt injection found",)


def test_enum_values_are_lowercase_text() -> None:
    """Enum values end up in JSON and the database, so keep them simple."""
    for enum in (Action, RiskLevel, Direction):
        for member in enum:
            assert member.value == member.value.lower()
