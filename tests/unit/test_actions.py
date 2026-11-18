"""Tests for action and risk ordering in llm_gateway.models."""

from __future__ import annotations

from llm_gateway.models import (
    Action,
    Decision,
    Finding,
    RiskLevel,
    RuleMatch,
    highest,
    strictest,
)


def test_action_order() -> None:
    order = [Action.ALLOW, Action.WARN, Action.REDACT, Action.BLOCK]
    assert [a.strictness for a in order] == [0, 1, 2, 3]


def test_strictest_action_wins() -> None:
    assert strictest([Action.WARN, Action.BLOCK, Action.REDACT]) == Action.BLOCK
    assert strictest([Action.WARN, Action.REDACT]) == Action.REDACT
    assert strictest([Action.ALLOW, Action.WARN]) == Action.WARN


def test_no_actions_means_allow() -> None:
    assert strictest([]) == Action.ALLOW


def test_risk_order() -> None:
    assert RiskLevel.NONE.rank < RiskLevel.LOW.rank < RiskLevel.CRITICAL.rank
    assert highest([RiskLevel.LOW, RiskLevel.CRITICAL, RiskLevel.MEDIUM]) == (
        RiskLevel.CRITICAL
    )
    assert highest([]) == RiskLevel.NONE


def make_finding(entity_type: str | None, category: str = "pii") -> Finding:
    return Finding(
        detector="pii",
        category=category,
        entity_type=entity_type,
        start=0,
        end=3,
        confidence=0.9,
        severity=RiskLevel.MEDIUM,
    )


def test_finding_label() -> None:
    assert make_finding("EMAIL_ADDRESS").label == "EMAIL_ADDRESS"
    assert make_finding(None, category="jailbreak").label == "jailbreak"


def test_decision_findings_with() -> None:
    email = make_finding("EMAIL_ADDRESS")
    person = make_finding("PERSON")
    decision = Decision(
        action=Action.REDACT,
        risk_level=RiskLevel.MEDIUM,
        matches=(
            RuleMatch(finding=email, rule_id="a", action=Action.REDACT),
            RuleMatch(finding=person, rule_id="b", action=Action.WARN),
        ),
    )
    assert decision.findings_with(Action.REDACT) == (email,)
    assert decision.findings_with(Action.WARN) == (person,)
    assert decision.findings_with(Action.BLOCK) == ()
