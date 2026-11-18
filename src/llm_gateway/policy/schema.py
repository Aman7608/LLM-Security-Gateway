"""The policy file format, and every check made when a policy is loaded.

A policy is only ever used AFTER it passes these checks. A broken or unsafe
policy is rejected with a message that says what is wrong and how to fix it.

Checks:
  - every field has the right type, and misspelled fields are errors
  - prompt injection can never be redacted (only warned about or blocked)
  - rule ids are unique across both directions
  - no rule is "unreachable" (always beaten by a broader rule above it)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from llm_gateway.models import Action, Direction, Finding, RiskLevel

# A rule limited to these categories can never see an injection finding
_NOT_INJECTION_CATEGORIES = frozenset({"pii", "secret"})

_RULE_ID = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"


class PolicyError(ValueError):
    """The policy is missing or has mistakes."""


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

    def covers(self, other: Match) -> bool:
        """True if this matches EVERY finding that `other` matches.

        In other words, this is at least as broad as `other`. Used to find
        rules that can never be reached.
        """
        if self.detector is not None and self.detector != other.detector:
            return False
        if self.category is not None and self.category != other.category:
            return False
        if self.entity_types and not (
            other.entity_types and set(other.entity_types) <= set(self.entity_types)
        ):
            return False
        if self.min_severity is not None and (
            other.min_severity is None
            or other.min_severity.rank < self.min_severity.rank
        ):
            return False
        return True


class PolicyRule(BaseModel):
    """One line of the policy: which findings, how confident, what to do."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=_RULE_ID)
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


class CombineRule(BaseModel):
    """Several weak findings together can mean a real problem.

    If the findings matching `when` come from at least two different rules,
    and their combined confidence (noisy-OR) reaches min_combined_confidence,
    this rule's action applies to the whole text.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=_RULE_ID)
    description: str = Field(min_length=1)
    when: Match = Match()
    min_combined_confidence: float = Field(gt=0.0, le=1.0)
    action: Literal[Action.WARN, Action.BLOCK]
    severity: RiskLevel = RiskLevel.HIGH


class RiskSettings(BaseModel):
    """How the overall risk level is worked out."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    # Raise the risk one level when different kinds of problems are found
    # together, e.g. an attack AND hidden characters, or PII AND a secret.
    escalate_on_mixed_categories: bool = True


class DirectionPolicy(BaseModel):
    """The rules for one direction (input or output)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rules: tuple[PolicyRule, ...] = ()
    combine: tuple[CombineRule, ...] = ()
    # Block anything whose final risk is at this level or higher (optional)
    block_at_risk: RiskLevel | None = None

    @model_validator(mode="after")
    def check_direction(self) -> DirectionPolicy:
        if self.block_at_risk is RiskLevel.NONE:
            raise ValueError(
                "block_at_risk cannot be 'none': that would block everything. "
                "Leave it out to turn it off."
            )
        for position, later in enumerate(self.rules):
            for earlier in self.rules[:position]:
                if (
                    earlier.when.covers(later.when)
                    and earlier.min_confidence <= later.min_confidence
                ):
                    raise ValueError(
                        f"rule '{later.id}' can never be used: rule '{earlier.id}' "
                        "above it matches the same findings first. Move "
                        f"'{later.id}' higher up, or remove it."
                    )
        return self


class Policy(BaseModel):
    """The whole policy, checked when it is loaded."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1]
    redaction_mode: Literal["label", "mask", "remove"] = "label"
    risk: RiskSettings = RiskSettings()
    input: DirectionPolicy
    output: DirectionPolicy

    @model_validator(mode="after")
    def rule_ids_are_unique(self) -> Policy:
        ids: list[str] = []
        for direction in (self.input, self.output):
            ids += [rule.id for rule in direction.rules]
            ids += [combo.id for combo in direction.combine]
        duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate rule ids: {', '.join(duplicates)}")
        return self

    def for_direction(self, direction: Direction) -> DirectionPolicy:
        return self.input if direction is Direction.INPUT else self.output


def parse_policy(text: str, source: str = "policy") -> Policy:
    """Check policy YAML text. Raises PolicyError with a clear message."""
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise PolicyError(f"{source} is not valid YAML: {error}") from error
    if not isinstance(raw, dict):
        raise PolicyError(f"{source} must contain a YAML mapping at the top level")
    try:
        return Policy.model_validate(raw)
    except ValidationError as error:
        raise PolicyError(f"{source} has mistakes:\n{error}") from error


def load_policy(path: Path) -> Policy:
    """Read and check a policy file. Raises PolicyError with a clear message."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise PolicyError(f"cannot read policy file {path}: {error}") from error
    return parse_policy(text, str(path))


def _rule(rule_id: str, action: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": rule_id,
        "description": "built-in safe default",
        "action": action,
        **extra,
    }


# Used ONLY when the policy file is missing or broken at startup. It is
# deliberately strict: when we cannot read the real policy, it is safer to
# block too much than too little.
BUILT_IN_DEFAULT_POLICY = Policy.model_validate(
    {
        "version": 1,
        "input": {
            "rules": [
                _rule(
                    "default-in-block-injection",
                    "block",
                    when={"detector": "injection"},
                    min_confidence=0.5,
                ),
                _rule(
                    "default-in-warn-injection", "warn", when={"detector": "injection"}
                ),
                _rule(
                    "default-in-redact-secrets", "redact", when={"detector": "secret"}
                ),
                _rule("default-in-redact-pii", "redact", when={"detector": "pii"}),
            ]
        },
        "output": {
            "rules": [
                _rule(
                    "default-out-block-secrets", "block", when={"detector": "secret"}
                ),
                _rule("default-out-redact-pii", "redact", when={"detector": "pii"}),
                _rule(
                    "default-out-warn-injection", "warn", when={"detector": "injection"}
                ),
            ]
        },
    }
)
