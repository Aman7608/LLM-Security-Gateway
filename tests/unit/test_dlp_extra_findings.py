"""Tests for DLPEngine.process(..., extra_findings=...)."""

from __future__ import annotations

import pytest

from llm_gateway.dlp.engine import DLPEngine
from llm_gateway.models import Action, Direction, Finding, RiskLevel
from llm_gateway.policy.engine import PolicyEngine
from llm_gateway.policy.schema import Policy

TEXT = "The secret plan is here."


def leak(start: int = 4, end: int = 15) -> Finding:
    return Finding(
        detector="leak",
        category="system_prompt_leak",
        entity_type="SYSTEM_PROMPT_TEXT",
        start=start,
        end=end,
        confidence=0.85,
        severity=RiskLevel.HIGH,
    )


def engine(action: str) -> DLPEngine:
    policy = Policy.model_validate(
        {
            "version": 1,
            "input": {"rules": []},
            "output": {
                "rules": [
                    {
                        "id": "leak-rule",
                        "description": "d",
                        "when": {"detector": "leak"},
                        "action": action,
                    }
                ]
            },
        }
    )
    return DLPEngine([], PolicyEngine(policy))


def test_extra_findings_go_through_the_policy() -> None:
    result = engine("block").process(TEXT, Direction.OUTPUT, extra_findings=[leak()])
    assert result.blocked
    assert result.scan.findings == (leak(),)
    assert result.decision.matched_rules == ("leak-rule",)


def test_extra_findings_can_be_redacted() -> None:
    result = engine("redact").process(TEXT, Direction.OUTPUT, extra_findings=[leak()])
    assert result.output_text == "The <SYSTEM_PROMPT_TEXT> is here."


def test_without_extra_findings_nothing_changes() -> None:
    result = engine("block").process(TEXT, Direction.OUTPUT)
    assert result.action is Action.ALLOW


def test_extra_finding_outside_the_text_is_an_error() -> None:
    with pytest.raises(ValueError, match="outside the text"):
        engine("block").process("short", Direction.OUTPUT, extra_findings=[leak()])
