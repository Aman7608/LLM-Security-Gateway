"""Tests for llm_gateway.audit.records: the safe record format."""

from __future__ import annotations

from datetime import UTC

import pytest
from pydantic import ValidationError

from llm_gateway.audit.fingerprint import Fingerprinter
from llm_gateway.audit.records import (
    AuditEntry,
    EventStatus,
    FindingEntry,
    finding_entries,
)
from llm_gateway.models import Action, Direction, Finding, RiskLevel

TEXT = "Mail priya@example.com today"
EMAIL = Finding(
    detector="pii",
    category="personal_data",
    entity_type="EMAIL_ADDRESS",
    start=5,
    end=22,
    confidence=1.0,
    severity=RiskLevel.MEDIUM,
    rule_id="pii-email",
)


def entry(**overrides: object) -> AuditEntry:
    values: dict[str, object] = {
        "request_id": "req-1",
        "input_action": Action.ALLOW,
        "risk_level": RiskLevel.NONE,
        "status": EventStatus.SCAN_ONLY,
        "input_chars": 10,
    }
    values.update(overrides)
    return AuditEntry.model_validate(values)


def test_records_have_no_place_for_prompts_answers_or_values() -> None:
    """The safest bug is one that cannot be written: there is no such field."""
    risky = {"prompt", "answer", "content", "text", "value", "original", "secret"}
    assert not risky & set(AuditEntry.model_fields)
    assert not risky & set(FindingEntry.model_fields)


def test_findings_get_a_fingerprint_of_their_value(
    fingerprinter: Fingerprinter,
) -> None:
    (saved,) = finding_entries([EMAIL], Direction.INPUT, TEXT, fingerprinter.of)
    assert saved.fingerprint == fingerprinter.of("priya@example.com")
    assert (saved.span_start, saved.span_end) == (5, 22)
    assert saved.entity_type == "EMAIL_ADDRESS"
    assert saved.direction is Direction.INPUT
    assert "priya" not in saved.model_dump_json()


def test_no_fingerprinter_means_no_fingerprint() -> None:
    (saved,) = finding_entries([EMAIL], Direction.OUTPUT, TEXT, None)
    assert saved.fingerprint is None


def test_timestamp_is_utc() -> None:
    assert entry().timestamp.tzinfo is UTC


@pytest.mark.parametrize(
    "bad_id", ["", "has space", "new\nline", "x" * 65, "quote'", "<script>"]
)
def test_odd_request_ids_are_rejected(bad_id: str) -> None:
    with pytest.raises(ValidationError):
        entry(request_id=bad_id)


def test_records_cannot_be_changed() -> None:
    record = entry()
    with pytest.raises(ValidationError):
        record.risk_level = RiskLevel.HIGH  # type: ignore[misc]
