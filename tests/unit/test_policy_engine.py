"""Tests for llm_gateway.policy.engine: loading the policy and making decisions.

Findings here are made by hand, so these tests do not need any detector.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from llm_gateway.models import Action, Direction, Finding, RiskLevel, ScanResult
from llm_gateway.policy.engine import PolicyEngine
from llm_gateway.policy.schema import Policy, PolicyError, load_policy
from llm_gateway.settings import FailMode
from tests.conftest import PROJECT_ROOT

POLICY_FILE = PROJECT_ROOT / "config" / "policy.yaml"


# ---------- helpers ----------


def finding(
    detector: str = "pii",
    category: str = "pii",
    entity_type: str | None = "EMAIL_ADDRESS",
    confidence: float = 0.9,
    severity: RiskLevel = RiskLevel.MEDIUM,
    start: int = 0,
) -> Finding:
    return Finding(
        detector=detector,
        category=category,
        entity_type=entity_type,
        start=start,
        end=start + 5,
        confidence=confidence,
        severity=severity,
    )


def injection(confidence: float = 0.9) -> Finding:
    return finding(
        detector="injection",
        category="instruction_override",
        entity_type=None,
        confidence=confidence,
        severity=RiskLevel.HIGH,
    )


def scan(
    *findings: Finding,
    direction: Direction = Direction.INPUT,
    errors: tuple[str, ...] = (),
) -> ScanResult:
    return ScanResult(direction=direction, findings=findings, errors=errors)


def rule(rule_id: str, action: str, **when: Any) -> dict[str, Any]:
    min_confidence = when.pop("min_confidence", 0.0)
    return {
        "id": rule_id,
        "description": "test rule",
        "when": when,
        "min_confidence": min_confidence,
        "action": action,
    }


def policy(
    input_rules: list[dict[str, Any]], output_rules: list[dict[str, Any]] | None = None
) -> Policy:
    return Policy.model_validate(
        {
            "version": 1,
            "input": {"rules": input_rules},
            "output": {"rules": output_rules or []},
        }
    )


def engine(input_rules: list[dict[str, Any]], **kwargs: Any) -> PolicyEngine:
    return PolicyEngine(policy(input_rules), **kwargs)


# ---------- loading ----------


def test_the_real_policy_loads() -> None:
    loaded = load_policy(POLICY_FILE)
    assert loaded.input.rules and loaded.output.rules
    assert loaded.redaction_mode == "label"


def write(tmp_path: Path, data: Any) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "nope.yaml")


def test_broken_yaml(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("input: {rules: [", encoding="utf-8")
    with pytest.raises(PolicyError, match="not valid YAML"):
        load_policy(path)


def test_top_level_must_be_a_mapping(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="mapping"):
        load_policy(write(tmp_path, ["rules"]))


@pytest.mark.parametrize(
    "bad_rule, message",
    [
        (rule("r", "explode"), "action"),
        (rule("r", "block", min_confidence=1.5), "min_confidence"),
        (rule("Bad Id", "block"), "id"),
        ({**rule("r", "block"), "actoin": "block"}, "actoin"),
        (rule("r", "block", detectr="pii"), "detectr"),
        (rule("r", "block", min_severity="huge"), "min_severity"),
    ],
)
def test_bad_rules_are_rejected(
    tmp_path: Path, bad_rule: dict[str, Any], message: str
) -> None:
    data = {"version": 1, "input": {"rules": [bad_rule]}, "output": {"rules": []}}
    with pytest.raises(PolicyError, match=message):
        load_policy(write(tmp_path, data))


def test_missing_direction_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="output"):
        load_policy(write(tmp_path, {"version": 1, "input": {"rules": []}}))


def test_duplicate_rule_ids_across_directions_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate rule ids: same"):
        policy([rule("same", "block")], [rule("same", "warn")])


@pytest.mark.parametrize(
    "when",
    [
        {},  # matches everything, including injection
        {"detector": "injection"},
        {"category": "jailbreak"},
        {"min_severity": "high"},
    ],
)
def test_injection_can_never_be_redacted(when: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="cannot|could redact"):
        policy([rule("r", "redact", **when)])


@pytest.mark.parametrize(
    "when",
    [
        {"detector": "pii"},
        {"detector": "secret"},
        {"category": "pii"},
        {"entity_types": ["EMAIL_ADDRESS"]},
    ],
)
def test_redact_is_fine_when_it_cannot_match_injection(when: dict[str, Any]) -> None:
    policy([rule("r", "redact", **when)])


# ---------- deciding ----------


def test_no_findings_means_allow() -> None:
    decision = engine([rule("r", "block")]).decide(scan())
    assert decision.action is Action.ALLOW
    assert decision.risk_level is RiskLevel.NONE
    assert decision.matches == ()
    assert decision.reasons == ()


def test_finding_with_no_matching_rule_is_allowed() -> None:
    decision = engine([rule("r", "block", detector="secret")]).decide(scan(finding()))
    assert decision.action is Action.ALLOW
    assert decision.matches == ()


def test_first_matching_rule_wins() -> None:
    rules = [
        rule("specific", "warn", entity_types=["EMAIL_ADDRESS"]),
        rule("general", "redact", detector="pii"),
    ]
    decision = engine(rules).decide(scan(finding()))
    assert decision.action is Action.WARN
    assert [m.rule_id for m in decision.matches] == ["specific"]


def test_min_confidence_moves_to_the_next_rule() -> None:
    rules = [
        rule("strong", "block", detector="injection", min_confidence=0.7),
        rule("weak", "warn", detector="injection"),
    ]
    decide = engine(rules).decide
    assert decide(scan(injection(0.9))).action is Action.BLOCK
    assert decide(scan(injection(0.7))).action is Action.BLOCK  # 0.7 is enough
    assert decide(scan(injection(0.5))).action is Action.WARN


def test_strictest_action_wins_across_findings() -> None:
    rules = [
        rule("block-injection", "block", detector="injection"),
        rule("redact-pii", "redact", detector="pii"),
    ]
    decision = engine(rules).decide(scan(finding(), injection(), finding(start=20)))
    assert decision.action is Action.BLOCK
    assert decision.matched_rules == ("redact-pii", "block-injection")


@pytest.mark.parametrize(
    "when, matches",
    [
        ({"detector": "pii"}, True),
        ({"detector": "secret"}, False),
        ({"category": "pii"}, True),
        ({"entity_types": ["EMAIL_ADDRESS", "PHONE_NUMBER"]}, True),
        ({"entity_types": ["PERSON"]}, False),
        ({"min_severity": "medium"}, True),
        ({"min_severity": "high"}, False),
        ({"detector": "pii", "entity_types": ["PERSON"]}, False),  # all must match
    ],
)
def test_when_conditions(when: dict[str, Any], matches: bool) -> None:
    decision = engine([rule("r", "warn", **when)]).decide(scan(finding()))
    assert (decision.action is Action.WARN) is matches


def test_each_direction_uses_its_own_rules() -> None:
    both = PolicyEngine(
        policy(
            [rule("in", "redact", detector="pii")],
            [rule("out", "block", detector="pii")],
        )
    )
    assert both.decide(scan(finding())).action is Action.REDACT
    assert (
        both.decide(scan(finding(), direction=Direction.OUTPUT)).action is Action.BLOCK
    )


def test_risk_is_the_most_serious_finding_acted_on() -> None:
    rules = [rule("warn-all-pii", "warn", detector="pii")]
    low = finding(severity=RiskLevel.LOW)
    critical = finding(severity=RiskLevel.CRITICAL, start=10)
    assert engine(rules).decide(scan(low, critical)).risk_level is RiskLevel.CRITICAL


def test_allowed_findings_do_not_raise_the_risk() -> None:
    rules = [rule("allow-pii", "allow", detector="pii")]
    decision = engine(rules).decide(scan(finding(severity=RiskLevel.CRITICAL)))
    assert decision.action is Action.ALLOW
    assert decision.risk_level is RiskLevel.NONE
    assert len(decision.matches) == 1  # still recorded, for the audit log


def test_reasons_name_the_rule_and_type_but_never_the_text() -> None:
    rules = [rule("redact-pii", "redact", detector="pii")]
    decision = engine(rules).decide(scan(finding(), finding(start=20)))
    assert decision.reasons == ("redact-pii: 2 x EMAIL_ADDRESS -> redact",)


def test_detector_error_blocks_when_fail_mode_is_closed() -> None:
    decision = engine([rule("r", "warn")]).decide(scan(errors=("pii",)))
    assert decision.action is Action.BLOCK
    assert decision.risk_level is RiskLevel.MEDIUM
    assert "detector error (pii)" in decision.reasons[-1]
    assert "fail mode is closed" in decision.reasons[-1]


def test_detector_error_only_warns_when_fail_mode_is_open() -> None:
    open_engine = engine([rule("r", "warn")], fail_mode=FailMode.OPEN)
    decision = open_engine.decide(scan(errors=("pii",)))
    assert decision.action is Action.WARN
    assert "fail mode is open" in decision.reasons[-1]


def test_fail_open_never_lowers_a_stricter_decision() -> None:
    open_engine = engine(
        [rule("r", "block", detector="injection")], fail_mode=FailMode.OPEN
    )
    decision = open_engine.decide(scan(injection(), errors=("pii",)))
    assert decision.action is Action.BLOCK
