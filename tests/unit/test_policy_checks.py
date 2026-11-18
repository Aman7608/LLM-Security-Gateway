"""Tests for the checks made when a policy is loaded (llm_gateway.policy.schema)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from llm_gateway.models import Action, Direction, Finding, RiskLevel, ScanResult
from llm_gateway.policy.engine import PolicyEngine
from llm_gateway.policy.schema import (
    BUILT_IN_DEFAULT_POLICY,
    Match,
    Policy,
    PolicyError,
    load_policy,
    parse_policy,
)
from tests.conftest import PROJECT_ROOT


def rule(
    rule_id: str, action: str, min_confidence: float = 0.0, **when: Any
) -> dict[str, Any]:
    return {
        "id": rule_id,
        "description": "d",
        "when": when,
        "min_confidence": min_confidence,
        "action": action,
    }


def combine(
    rule_id: str, action: str = "block", score: float = 0.8, **when: Any
) -> dict[str, Any]:
    return {
        "id": rule_id,
        "description": "d",
        "when": when,
        "min_combined_confidence": score,
        "action": action,
    }


def make(
    input_part: dict[str, Any], output_part: dict[str, Any] | None = None, **top: Any
) -> Policy:
    return Policy.model_validate(
        {
            "version": 1,
            "input": input_part,
            "output": output_part or {"rules": []},
            **top,
        }
    )


# ---------- Match.covers: is one rule at least as broad as another? ----------


@pytest.mark.parametrize(
    "broad, narrow, expected",
    [
        ({}, {"detector": "pii"}, True),  # empty matches everything
        ({"detector": "pii"}, {"detector": "pii", "entity_types": ["PERSON"]}, True),
        ({"detector": "pii"}, {"detector": "secret"}, False),
        ({"detector": "pii"}, {}, False),  # the second also matches secrets
        ({"entity_types": ["A", "B"]}, {"entity_types": ["A"]}, True),
        ({"entity_types": ["A"]}, {"entity_types": ["A", "B"]}, False),
        ({"entity_types": ["A"]}, {}, False),
        ({"min_severity": "medium"}, {"min_severity": "high"}, True),
        ({"min_severity": "high"}, {"min_severity": "medium"}, False),
        ({"min_severity": "high"}, {}, False),
        ({"category": "pii"}, {"category": "pii", "detector": "pii"}, True),
    ],
)
def test_covers(broad: dict[str, Any], narrow: dict[str, Any], expected: bool) -> None:
    assert Match.model_validate(broad).covers(Match.model_validate(narrow)) is expected


# ---------- unreachable rules ----------


@pytest.mark.parametrize(
    "rules",
    [
        # The second rule repeats the first
        [rule("a", "redact", detector="pii"), rule("b", "warn", detector="pii")],
        # A broad rule above a narrow one steals all its findings
        [
            rule("all-pii", "redact", detector="pii"),
            rule("people", "warn", detector="pii", entity_types=["PERSON"]),
        ],
        # Same rule, but the first one needs LESS confidence
        [
            rule("weak", "warn", detector="injection"),
            rule("strong", "block", 0.7, detector="injection"),
        ],
    ],
)
def test_unreachable_rule_is_rejected(rules: list[dict[str, Any]]) -> None:
    with pytest.raises(ValueError, match="can never be used"):
        make({"rules": rules})


@pytest.mark.parametrize(
    "rules",
    [
        # Narrow first, broad second: both can be reached
        [
            rule("people", "warn", detector="pii", entity_types=["PERSON"]),
            rule("all-pii", "redact", detector="pii"),
        ],
        # Same detector, but the first needs MORE confidence
        [
            rule("strong", "block", 0.7, detector="injection"),
            rule("weak", "warn", detector="injection"),
        ],
        # Different detectors never steal from each other
        [rule("a", "redact", detector="pii"), rule("b", "redact", detector="secret")],
    ],
)
def test_reachable_rules_are_fine(rules: list[dict[str, Any]]) -> None:
    make({"rules": rules})


def test_unreachable_message_explains_the_fix() -> None:
    with pytest.raises(ValueError) as error:
        make(
            {
                "rules": [
                    rule("a", "redact", detector="pii"),
                    rule("b", "warn", detector="pii"),
                ]
            }
        )
    message = str(error.value)
    assert "rule 'b' can never be used" in message
    assert "rule 'a' above it" in message
    assert "Move 'b' higher up" in message


# ---------- combine rules and limits ----------


def test_combine_rule_cannot_redact() -> None:
    with pytest.raises(ValueError, match="action"):
        make({"combine": [combine("c", action="redact", detector="injection")]})


@pytest.mark.parametrize("score", [0, -0.1, 1.5])
def test_combine_score_must_be_between_0_and_1(score: float) -> None:
    with pytest.raises(ValueError, match="min_combined_confidence"):
        make({"combine": [combine("c", score=score)]})


def test_combine_ids_must_not_repeat_rule_ids() -> None:
    with pytest.raises(ValueError, match="duplicate rule ids: same"):
        make({"rules": [rule("same", "warn")], "combine": [combine("same")]})


def test_block_at_risk_none_is_rejected() -> None:
    with pytest.raises(ValueError, match="would block everything"):
        make({"rules": [], "block_at_risk": "none"})


def test_unknown_risk_setting_is_rejected() -> None:
    with pytest.raises(ValueError, match="escalate_sometimes"):
        make({"rules": []}, risk={"escalate_sometimes": True})


def test_python_object_tags_in_yaml_are_refused() -> None:
    """yaml.safe_load refuses tags that would create Python objects."""
    text = (
        "version: 1\ninput: !!python/object/apply:os.system ['echo hi']\noutput: {}\n"
    )
    with pytest.raises(PolicyError, match="not valid YAML"):
        parse_policy(text)


# ---------- the shipped policies ----------


@pytest.mark.parametrize("name", ["policy.yaml", "examples/strict-policy.yaml"])
def test_shipped_policies_load(name: str) -> None:
    load_policy(PROJECT_ROOT / "config" / name)


def finding(
    detector: str, confidence: float, entity_type: str | None = None
) -> Finding:
    return Finding(
        detector=detector,
        category="instruction_override" if detector == "injection" else detector,
        entity_type=entity_type,
        start=0,
        end=4,
        confidence=confidence,
        severity=RiskLevel.HIGH,
    )


@pytest.mark.parametrize(
    "direction, item, expected",
    [
        (Direction.INPUT, finding("injection", 0.5), Action.BLOCK),  # stricter than 0.7
        (Direction.INPUT, finding("injection", 0.3), Action.WARN),
        (Direction.INPUT, finding("secret", 0.5, "SECRET"), Action.REDACT),
        (Direction.INPUT, finding("pii", 0.85, "PERSON"), Action.REDACT),  # names too
        (Direction.OUTPUT, finding("secret", 0.5, "SECRET"), Action.BLOCK),
        (Direction.OUTPUT, finding("pii", 0.9, "EMAIL_ADDRESS"), Action.REDACT),
    ],
)
def test_built_in_default_is_strict(
    direction: Direction, item: Finding, expected: Action
) -> None:
    """Used when the policy file is broken, so it must lean towards safety."""
    decision = PolicyEngine(BUILT_IN_DEFAULT_POLICY).decide(
        ScanResult(direction=direction, findings=(item,))
    )
    assert decision.action is expected


def test_strict_example_differs_from_the_default_where_documented() -> None:
    default = load_policy(PROJECT_ROOT / "config" / "policy.yaml")
    strict = load_policy(PROJECT_ROOT / "config" / "examples" / "strict-policy.yaml")
    assert strict.redaction_mode == "remove" and default.redaction_mode == "label"
    assert strict.input.block_at_risk is RiskLevel.CRITICAL
    assert default.input.block_at_risk is None
    name = finding("pii", 0.85, "PERSON")
    scan = ScanResult(direction=Direction.INPUT, findings=(name,))
    assert PolicyEngine(default).decide(scan).action is Action.WARN
    assert PolicyEngine(strict).decide(scan).action is Action.REDACT


def test_policy_files_are_read_as_utf8(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text(
        "version: 1\ninput:\n  rules:\n    - id: r\n      description: नमस्ते é\n"
        "      action: warn\noutput: {rules: []}\n",
        encoding="utf-8",
    )
    assert load_policy(path).input.rules[0].description == "नमस्ते é"
