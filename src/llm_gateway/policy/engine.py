"""Policy engine: turns findings into one decision (allow, warn, redact, block).

This is the Phase 8 version: ordered rules from config/policy.yaml, where the
first matching rule decides each finding, and the strictest action wins.
Phase 9 builds on it (risk scoring, policy versions, safe reloading).

The policy engine only DECIDES. It never changes text and never runs
detectors. The DLP engine does those things.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from llm_gateway.models import (
    Action,
    Decision,
    Direction,
    Finding,
    RiskLevel,
    RuleMatch,
    ScanResult,
    highest,
    strictest,
)
from llm_gateway.settings import FailMode

# Categories that can never be redacted, because they come from the injection
# detector. A rule with these detectors/categories may only warn or block.
_NOT_INJECTION_CATEGORIES = frozenset({"pii", "secret"})


class PolicyError(ValueError):
    """The policy file is missing or has mistakes."""


class Match(BaseModel):
    """Which findings a rule applies to. Every field that is set must match."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    detector: str | None = None
    category: str | None = None
    entity_types: tuple[str, ...] = ()
    min_severity: RiskLevel | None = None

    def matches(self, finding: Finding) -> bool:
        if self.detector is not None and finding.detector != self.detector:
            return False
        if self.category is not None and finding.category != self.category:
            return False
        if self.entity_types and finding.entity_type not in self.entity_types:
            return False
        if (
            self.min_severity is not None
            and finding.severity.rank < self.min_severity.rank
        ):
            return False
        return True

    def could_match_injection(self) -> bool:
        """Could an injection finding ever match this? Used to forbid redacting them."""
        if self.detector not in (None, "injection"):
            return False
        if self.category in _NOT_INJECTION_CATEGORIES:
            return False
        # Injection findings have no entity type, so a rule that needs one never matches
        return not self.entity_types


class PolicyRule(BaseModel):
    """One line of the policy: which findings, how confident, what to do."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    description: str = Field(min_length=1)
    when: Match = Match()
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    action: Action

    @model_validator(mode="after")
    def injection_is_never_redacted(self) -> PolicyRule:
        if self.action is Action.REDACT and self.when.could_match_injection():
            raise ValueError(
                f"rule '{self.id}' could redact prompt injection findings. "
                "Injection can only be warned about or blocked: cutting out part "
                "of an attack does not make the rest safe. Add 'detector: pii' "
                "or 'detector: secret' to the rule."
            )
        return self

    def applies_to(self, finding: Finding) -> bool:
        return self.when.matches(finding) and finding.confidence >= self.min_confidence


class DirectionPolicy(BaseModel):
    """The rules for one direction (input or output), in order."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rules: tuple[PolicyRule, ...] = ()


class Policy(BaseModel):
    """The whole policy file, checked when it is loaded."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1]
    redaction_mode: Literal["label", "mask", "remove"] = "label"
    input: DirectionPolicy
    output: DirectionPolicy

    @model_validator(mode="after")
    def rule_ids_are_unique(self) -> Policy:
        ids = [rule.id for rule in (*self.input.rules, *self.output.rules)]
        duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate rule ids: {', '.join(duplicates)}")
        return self

    def rules_for(self, direction: Direction) -> tuple[PolicyRule, ...]:
        return self.input.rules if direction is Direction.INPUT else self.output.rules


def load_policy(path: Path) -> Policy:
    """Read and check the policy file. Raises PolicyError with a clear message."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise PolicyError(f"cannot read policy file {path}: {error}") from error
    except yaml.YAMLError as error:
        raise PolicyError(f"{path} is not valid YAML: {error}") from error
    if not isinstance(raw, dict):
        raise PolicyError(f"{path} must contain a YAML mapping at the top level")
    try:
        return Policy.model_validate(raw)
    except ValidationError as error:
        raise PolicyError(f"{path} has mistakes:\n{error}") from error


class PolicyEngine:
    """Decides what to do with a ScanResult, using the policy rules."""

    def __init__(self, policy: Policy, fail_mode: FailMode = FailMode.CLOSED) -> None:
        self.policy = policy
        self.fail_mode = fail_mode

    @classmethod
    def from_file(
        cls, path: Path, fail_mode: FailMode = FailMode.CLOSED
    ) -> PolicyEngine:
        return cls(load_policy(path), fail_mode)

    def decide(self, scan: ScanResult) -> Decision:
        rules = self.policy.rules_for(scan.direction)

        # 1. Give each finding the action of the FIRST rule that applies to it
        matches = []
        for finding in scan.findings:
            rule = next((r for r in rules if r.applies_to(finding)), None)
            if rule is not None:
                matches.append(
                    RuleMatch(finding=finding, rule_id=rule.id, action=rule.action)
                )

        # 2. The strictest action wins
        action = strictest(m.action for m in matches)

        # 3. Risk = the most serious finding that the policy acted on
        acted_on = [m for m in matches if m.action is not Action.ALLOW]
        risk = highest(m.finding.severity for m in acted_on)

        reasons = _explain(matches)

        # 4. A crashed detector means we do not know what was missed
        if scan.errors:
            crashed = ", ".join(scan.errors)
            if self.fail_mode is FailMode.CLOSED:
                action = Action.BLOCK
                risk = highest([risk, RiskLevel.MEDIUM])
                reasons.append(
                    f"detector error ({crashed}): blocked because fail mode is closed"
                )
            else:
                action = strictest([action, Action.WARN])
                reasons.append(
                    f"detector error ({crashed}): allowed with a warning because "
                    "fail mode is open"
                )

        return Decision(
            action=action,
            risk_level=risk,
            matched_rules=tuple(dict.fromkeys(m.rule_id for m in matches)),
            reasons=tuple(reasons),
            matches=tuple(matches),
        )


def _explain(matches: Iterable[RuleMatch]) -> list[str]:
    """Plain reasons like 'in-redact-personal-data: 2 x EMAIL_ADDRESS -> redact'.

    Reasons name the TYPE of data and the rule, never the text itself, so
    they are safe to log and to show to users.
    """
    counts = Counter((m.rule_id, m.finding.label, m.action) for m in matches)
    return [
        f"{rule_id}: {count} x {label} -> {action.value}"
        for (rule_id, label, action), count in counts.items()
    ]
