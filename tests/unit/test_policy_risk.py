"""Tests for risk scoring, combined signals and risk limits in the policy engine."""

from __future__ import annotations

from typing import Any

import pytest

from llm_gateway.models import (
    Action,
    Direction,
    Finding,
    RiskLevel,
    ScanResult,
    one_level_higher,
)
from llm_gateway.policy.engine import PolicyEngine
from llm_gateway.policy.schema import Policy

WARN_INJECTION = {
    "id": "warn-injection",
    "description": "d",
    "when": {"detector": "injection"},
    "action": "warn",
}
REDACT_PII = {
    "id": "redact-pii",
    "description": "d",
    "when": {"detector": "pii"},
    "action": "redact",
}
REDACT_SECRETS = {
    "id": "redact-secrets",
    "description": "d",
    "when": {"detector": "secret"},
    "action": "redact",
}
COMBINE = {
    "id": "combine-injection",
    "description": "d",
    "when": {"detector": "injection"},
    "min_combined_confidence": 0.8,
    "action": "block",
}


def engine(rules: list[dict[str, Any]], **extra: Any) -> PolicyEngine:
    risk = extra.pop("risk", {})
    direction = {"rules": rules, **extra}
    return PolicyEngine(
        Policy.model_validate(
            {"version": 1, "risk": risk, "input": direction, "output": {"rules": []}}
        )
    )


def item(
    detector: str,
    rule_id: str = "r",
    confidence: float = 0.5,
    severity: RiskLevel = RiskLevel.MEDIUM,
    category: str | None = None,
) -> Finding:
    return Finding(
        detector=detector,
        category=category or ("jailbreak" if detector == "injection" else detector),
        entity_type=None if detector == "injection" else "X",
        start=0,
        end=4,
        confidence=confidence,
        severity=severity,
        rule_id=rule_id,
    )


def decide(e: PolicyEngine, *findings: Finding, errors: tuple[str, ...] = ()):  # type: ignore[no-untyped-def]
    return e.decide(
        ScanResult(direction=Direction.INPUT, findings=findings, errors=errors)
    )


# ---------- one_level_higher ----------


@pytest.mark.parametrize(
    "level, raised",
    [
        (RiskLevel.NONE, RiskLevel.NONE),
        (RiskLevel.LOW, RiskLevel.MEDIUM),
        (RiskLevel.MEDIUM, RiskLevel.HIGH),
        (RiskLevel.HIGH, RiskLevel.CRITICAL),
        (RiskLevel.CRITICAL, RiskLevel.CRITICAL),
    ],
)
def test_one_level_higher(level: RiskLevel, raised: RiskLevel) -> None:
    assert one_level_higher(level) is raised


# ---------- escalation ----------


def test_mixed_categories_raise_the_risk() -> None:
    e = engine([REDACT_PII, REDACT_SECRETS])
    decision = decide(e, item("pii"), item("secret"))
    assert decision.risk_level is RiskLevel.HIGH  # medium + one level
    assert "risk raised from medium to high" in decision.reasons[-1]
    assert "pii, secret" in decision.reasons[-1]


def test_same_category_does_not_raise_the_risk() -> None:
    e = engine([REDACT_PII])
    decision = decide(e, item("pii", "a"), item("pii", "b"))
    assert decision.risk_level is RiskLevel.MEDIUM


def test_escalation_can_be_turned_off() -> None:
    e = engine(
        [REDACT_PII, REDACT_SECRETS], risk={"escalate_on_mixed_categories": False}
    )
    assert decide(e, item("pii"), item("secret")).risk_level is RiskLevel.MEDIUM


def test_allowed_findings_do_not_count_for_escalation() -> None:
    allow_secrets = {**REDACT_SECRETS, "id": "allow-secrets", "action": "allow"}
    e = engine([REDACT_PII, allow_secrets])
    assert decide(e, item("pii"), item("secret")).risk_level is RiskLevel.MEDIUM


def test_critical_stays_critical() -> None:
    e = engine([REDACT_PII, REDACT_SECRETS])
    decision = decide(e, item("pii", severity=RiskLevel.CRITICAL), item("secret"))
    assert decision.risk_level is RiskLevel.CRITICAL
    assert not any("risk raised" in r for r in decision.reasons)


# ---------- combined weak signals ----------


def test_two_different_weak_signals_combine_into_a_block() -> None:
    e = engine([WARN_INJECTION], combine=[COMBINE])
    # 1 - (1 - 0.6) * (1 - 0.6) = 0.84, which is >= 0.8
    decision = decide(e, item("injection", "a", 0.6), item("injection", "b", 0.6))
    assert decision.action is Action.BLOCK
    assert decision.risk_level is RiskLevel.HIGH
    assert "combine-injection" in decision.matched_rules
    assert any(
        "2 different signals, combined confidence 0.84" in r for r in decision.reasons
    )


def test_combined_score_below_the_threshold_only_warns() -> None:
    e = engine([WARN_INJECTION], combine=[COMBINE])
    # 1 - 0.6 * 0.6 = 0.64
    decision = decide(e, item("injection", "a", 0.4), item("injection", "b", 0.4))
    assert decision.action is Action.WARN


def test_one_rule_matching_many_times_does_not_combine() -> None:
    """Repeating one weak phrase 10 times is still just one signal."""
    e = engine([WARN_INJECTION], combine=[COMBINE])
    same = [item("injection", "same-rule", 0.6) for _ in range(10)]
    assert decide(e, *same).action is Action.WARN


def test_combine_is_skipped_when_already_blocked() -> None:
    """No extra noise in the reasons if the normal rules already blocked."""
    block_injection = {**WARN_INJECTION, "id": "block-injection", "action": "block"}
    e = engine([block_injection], combine=[COMBINE])
    decision = decide(e, item("injection", "a", 0.6), item("injection", "b", 0.6))
    assert decision.action is Action.BLOCK
    assert "combine-injection" not in decision.matched_rules


def test_single_strong_signal_is_left_to_the_normal_rules() -> None:
    e = engine([WARN_INJECTION], combine=[COMBINE])
    decision = decide(e, item("injection", "a", 0.95))
    assert decision.action is Action.WARN  # needs 2 different rules to combine


def test_combine_only_counts_matching_findings() -> None:
    e = engine([WARN_INJECTION, REDACT_PII], combine=[COMBINE])
    decision = decide(e, item("injection", "a", 0.7), item("pii", "b", 0.9))
    assert decision.action is Action.REDACT  # the PII finding does not combine


# ---------- block_at_risk ----------


def test_block_at_risk_blocks_at_and_above_the_limit() -> None:
    e = engine([REDACT_PII], block_at_risk="high")
    assert decide(e, item("pii", severity=RiskLevel.MEDIUM)).action is Action.REDACT
    decision = decide(e, item("pii", severity=RiskLevel.HIGH))
    assert decision.action is Action.BLOCK
    assert "at or above the limit for input (high)" in decision.reasons[-1]


def test_escalation_can_reach_the_block_limit() -> None:
    """Medium PII + medium secret = high risk, which reaches a 'high' limit."""
    e = engine([REDACT_PII, REDACT_SECRETS], block_at_risk="high")
    assert decide(e, item("pii"), item("secret")).action is Action.BLOCK


# ---------- the structured decision ----------


def test_decision_records_policy_version_and_redaction_mode() -> None:
    e = engine([REDACT_PII])
    decision = decide(e, item("pii"))
    assert decision.policy_version == 1
    assert decision.redaction_mode == "label"


@pytest.mark.parametrize(
    "action, allowed",
    [
        (Action.ALLOW, True),
        (Action.WARN, True),
        (Action.REDACT, True),
        (Action.BLOCK, False),
    ],
)
def test_decision_allowed(action: Action, allowed: bool) -> None:
    rule = {
        "id": "r",
        "description": "d",
        "when": {"detector": "pii"},
        "action": action.value,
    }
    assert decide(engine([rule]), item("pii")).allowed is allowed


def test_detector_error_still_blocks_after_all_other_steps() -> None:
    e = engine([REDACT_PII], combine=[COMBINE])
    decision = decide(e, item("pii"), errors=("pii",))
    assert decision.action is Action.BLOCK
    assert "fail mode is closed" in decision.reasons[-1]
