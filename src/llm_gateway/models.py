"""Shared data objects that the gateway's parts pass to each other.

These match section 3.3 of docs/02-system-architecture.md. They are frozen
(read-only) so that no part of the code can quietly change a finding after
a detector has made it.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Direction(StrEnum):
    """Which way the text is travelling."""

    INPUT = "input"  # prompt going to the AI
    OUTPUT = "output"  # answer coming back from the AI


class Action(StrEnum):
    """What the gateway does with a request or answer."""

    ALLOW = "allow"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"


class RiskLevel(StrEnum):
    """How serious a finding or a whole request is."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


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


class ScanResult(BaseModel):
    """Everything found in one piece of text, in one direction."""

    model_config = ConfigDict(frozen=True)

    direction: Direction
    findings: tuple[Finding, ...] = ()
    redacted_text: str | None = None
    duration_ms: float = Field(default=0.0, ge=0.0)
    errors: tuple[str, ...] = ()  # names of detectors that crashed


class Decision(BaseModel):
    """What the policy engine decided, with reasons a person can read."""

    model_config = ConfigDict(frozen=True)

    action: Action
    risk_level: RiskLevel
    matched_rules: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
