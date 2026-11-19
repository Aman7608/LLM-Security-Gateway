"""The safe audit record: what we are allowed to remember about a request.

An AuditEntry is built in memory first and only then saved. Because it has
no field for the prompt, the answer or any found value, those can never
end up in the database by accident. The only text field is
`redacted_prompt`, which is empty unless the admin turns it on.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from llm_gateway.models import Action, Direction, Finding, RiskLevel

# Request ids come from the API (Phase 13); keep them short and plain
REQUEST_ID_PATTERN = r"^[A-Za-z0-9._:\-]{1,64}$"


class EventStatus(StrEnum):
    """How a request ended."""

    COMPLETED = "completed"  # the AI answered and the answer was checked
    INPUT_BLOCKED = "input_blocked"  # the prompt was blocked, nothing was sent
    OUTPUT_BLOCKED = "output_blocked"  # the answer was withheld
    PROVIDER_ERROR = "provider_error"  # the AI could not be reached
    SCAN_ONLY = "scan_only"  # text was only checked (POST /v1/scan)


class FindingEntry(BaseModel):
    """One finding as it is saved: type, position, fingerprint. No value."""

    model_config = ConfigDict(frozen=True)

    direction: Direction
    detector: str
    category: str
    entity_type: str | None
    rule_id: str | None
    confidence: float
    severity: RiskLevel
    span_start: int
    span_end: int
    fingerprint: str | None = None

    @classmethod
    def from_finding(
        cls, finding: Finding, direction: Direction, fingerprint: str | None = None
    ) -> FindingEntry:
        return cls(
            direction=direction,
            detector=finding.detector,
            category=finding.category,
            entity_type=finding.entity_type,
            rule_id=finding.rule_id,
            confidence=finding.confidence,
            severity=finding.severity,
            span_start=finding.start,
            span_end=finding.end,
            fingerprint=fingerprint,
        )


class AuditEntry(BaseModel):
    """Everything the audit log keeps about one request (FR-44)."""

    model_config = ConfigDict(frozen=True)

    request_id: str = Field(pattern=REQUEST_ID_PATTERN)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    client_id: str | None = None
    policy_version: int | None = None
    provider: str | None = None
    model: str | None = None
    input_action: Action
    output_action: Action | None = None
    risk_level: RiskLevel
    status: EventStatus
    input_chars: int = Field(ge=0)
    output_chars: int = Field(default=0, ge=0)
    scan_ms: float = Field(default=0.0, ge=0.0)
    provider_ms: float = Field(default=0.0, ge=0.0)
    total_ms: float = Field(default=0.0, ge=0.0)
    redacted_prompt: str | None = None
    findings: tuple[FindingEntry, ...] = ()

    @property
    def finding_count(self) -> int:
        return len(self.findings)


def finding_entries(
    findings: Iterable[Finding],
    direction: Direction,
    text: str,
    fingerprint: Callable[[str], str] | None,
) -> tuple[FindingEntry, ...]:
    """Turn findings into safe entries, adding a fingerprint of each value.

    `text` is only used here, to read each found value and fingerprint it.
    The value itself is never kept.
    """
    entries = []
    for finding in findings:
        value = text[finding.start : finding.end]
        code = fingerprint(value) if fingerprint is not None and value else None
        entries.append(FindingEntry.from_finding(finding, direction, code))
    return tuple(entries)
