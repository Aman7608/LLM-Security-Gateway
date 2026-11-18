"""Shared data objects that the gateway's parts pass to each other.

These match section 3.3 of docs/02-system-architecture.md. They are frozen
(read-only) so that no part of the code can quietly change a finding after
a detector has made it.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Direction(StrEnum):
    """Which way the text is travelling."""

    INPUT = "input"  # prompt going to the AI
    OUTPUT = "output"  # answer coming back from the AI


class Action(StrEnum):
    """What the gateway does with a request or answer, from mildest to strictest."""

    ALLOW = "allow"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"

    @property
    def strictness(self) -> int:
        """0 for ALLOW up to 3 for BLOCK, so actions can be compared."""
        return list(Action).index(self)


class RiskLevel(StrEnum):
    """How serious a finding or a whole request is, from lowest to highest."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """0 for NONE up to 4 for CRITICAL, so levels can be compared."""
        return list(RiskLevel).index(self)


def strictest(actions: Iterable[Action]) -> Action:
    """The strictest of the actions (BLOCK > REDACT > WARN > ALLOW).

    With no actions at all, the answer is ALLOW.
    """
    return max(actions, key=lambda action: action.strictness, default=Action.ALLOW)


def highest(levels: Iterable[RiskLevel]) -> RiskLevel:
    """The highest risk level, or NONE if there are none."""
    return max(levels, key=lambda level: level.rank, default=RiskLevel.NONE)


class Finding(BaseModel):
    """One thing a detector found.

    It stores where the item is (start and end positions) but never the
    found text itself, so findings are safe to log.
    """

    model_config = ConfigDict(frozen=True)

    detector: str = Field(min_length=1)  # e.g. "injection", "pii", "secret"
    category: str = Field(min_length=1)  # e.g. "instruction_override"
    entity_type: str | None = None  # e.g. "EMAIL_ADDRESS" for PII
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    severity: RiskLevel
    rule_id: str | None = None
    fingerprint: str | None = None  # one-way code of the value (Phase 12)

    @model_validator(mode="after")
    def check_positions(self) -> Finding:
        if self.end <= self.start:
            raise ValueError("end must be greater than start")
        return self

    @property
    def label(self) -> str:
        """Short name for messages, e.g. "EMAIL_ADDRESS" or "instruction_override"."""
        return self.entity_type or self.category


class ScanResult(BaseModel):
    """Everything all detectors found in one piece of text, in one direction."""

    model_config = ConfigDict(frozen=True)

    direction: Direction
    findings: tuple[Finding, ...] = ()
    duration_ms: float = Field(default=0.0, ge=0.0)
    detector_ms: dict[str, float] = Field(default_factory=dict)  # time per detector
    errors: tuple[str, ...] = ()  # names of detectors that crashed


class RuleMatch(BaseModel):
    """Which policy rule a finding matched, and the action that rule gave it."""

    model_config = ConfigDict(frozen=True)

    finding: Finding
    rule_id: str
    action: Action


class Decision(BaseModel):
    """What the policy engine decided, with reasons a person can read."""

    model_config = ConfigDict(frozen=True)

    action: Action
    risk_level: RiskLevel
    matched_rules: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    matches: tuple[RuleMatch, ...] = ()

    def findings_with(self, action: Action) -> tuple[Finding, ...]:
        """The findings that a rule gave this action, e.g. everything to redact."""
        return tuple(m.finding for m in self.matches if m.action is action)
