"""Tests for llm_gateway.dlp.engine.DLPEngine, using small fake detectors.

Fake detectors make these tests fast and let us control exactly what is
"found", including a detector that crashes.
"""

from __future__ import annotations

import logging

import pytest

from llm_gateway.detectors.base import Detector
from llm_gateway.detectors.normalizer import NormalizedText
from llm_gateway.dlp.engine import DLPEngine
from llm_gateway.dlp.redactor import RedactionMode
from llm_gateway.models import (
    Action,
    Decision,
    Direction,
    Finding,
    RiskLevel,
    RuleMatch,
    ScanResult,
)
from llm_gateway.policy.engine import Policy, PolicyEngine

TEXT = "Hello, write to me at me@example.com please"
EMAIL_START = TEXT.index("me@")
EMAIL_END = EMAIL_START + len("me@example.com")


class FakeDetector(Detector):
    """Returns the findings it was given, and counts how often it was called."""

    def __init__(self, name: str, findings: list[Finding] | None = None) -> None:
        self.name = name
        self.findings = findings or []
        self.calls: list[NormalizedText] = []

    def scan(self, text: NormalizedText) -> list[Finding]:
        self.calls.append(text)
        return list(self.findings)


class CrashingDetector(Detector):
    name = "broken"

    def scan(self, text: NormalizedText) -> list[Finding]:
        # The message contains the text, like a careless library might do
        raise ValueError(f"could not handle: {text.original}")


def email_finding() -> Finding:
    return Finding(
        detector="pii",
        category="pii",
        entity_type="EMAIL_ADDRESS",
        start=EMAIL_START,
        end=EMAIL_END,
        confidence=0.9,
        severity=RiskLevel.MEDIUM,
    )


class FixedPolicy:
    """A fake policy that always gives the same action to every finding."""

    def __init__(self, action: Action) -> None:
        self.action = action
        self.seen: list[ScanResult] = []

    def decide(self, scan: ScanResult) -> Decision:
        self.seen.append(scan)
        matches = tuple(
            RuleMatch(finding=f, rule_id="fixed", action=self.action)
            for f in scan.findings
        )
        action = self.action if matches else Action.ALLOW
        return Decision(action=action, risk_level=RiskLevel.LOW, matches=matches)


def make_engine(action: Action, *detectors: Detector, **kwargs: object) -> DLPEngine:
    detectors = detectors or (FakeDetector("pii", [email_finding()]),)
    return DLPEngine(list(detectors), FixedPolicy(action), **kwargs)  # type: ignore[arg-type]


def test_allow_passes_the_text_unchanged() -> None:
    result = make_engine(Action.ALLOW).process(TEXT, Direction.INPUT)
    assert result.action is Action.ALLOW
    assert result.output_text == TEXT
    assert not result.blocked


def test_warn_passes_the_text_unchanged_and_lists_warnings() -> None:
    result = make_engine(Action.WARN).process(TEXT, Direction.INPUT)
    assert result.output_text == TEXT
    assert result.warnings == (email_finding(),)


def test_redact_hides_the_found_text() -> None:
    result = make_engine(Action.REDACT).process(TEXT, Direction.INPUT)
    assert result.output_text == "Hello, write to me at <EMAIL_ADDRESS> please"


def test_redaction_mode_is_used() -> None:
    engine = make_engine(Action.REDACT, redaction_mode=RedactionMode.REMOVE)
    result = engine.process(TEXT, Direction.INPUT)
    assert result.output_text == "Hello, write to me at [REDACTED] please"


def test_block_returns_no_text() -> None:
    result = make_engine(Action.BLOCK).process(TEXT, Direction.INPUT)
    assert result.blocked
    assert result.output_text is None


def test_only_redact_findings_are_hidden_when_actions_are_mixed() -> None:
    """A WARN finding next to a REDACT finding stays visible."""
    person = Finding(
        detector="pii",
        category="pii",
        entity_type="PERSON",
        start=0,
        end=5,
        confidence=0.85,
        severity=RiskLevel.LOW,
    )
    policy = PolicyEngine(
        Policy.model_validate(
            {
                "version": 1,
                "input": {
                    "rules": [
                        {
                            "id": "warn-people",
                            "description": "d",
                            "when": {"entity_types": ["PERSON"]},
                            "action": "warn",
                        },
                        {
                            "id": "redact-pii",
                            "description": "d",
                            "when": {"detector": "pii"},
                            "action": "redact",
                        },
                    ]
                },
                "output": {"rules": []},
            }
        )
    )
    engine = DLPEngine([FakeDetector("pii", [person, email_finding()])], policy)
    result = engine.process(TEXT, Direction.INPUT)
    assert result.action is Action.REDACT
    assert result.output_text == "Hello, write to me at <EMAIL_ADDRESS> please"
    assert result.warnings == (person,)


def test_text_is_normalized_once_and_shared() -> None:
    first, second = FakeDetector("a"), FakeDetector("b")
    make_engine(Action.ALLOW, first, second).process(TEXT, Direction.INPUT)
    assert len(first.calls) == 1
    assert first.calls[0] is second.calls[0]  # the very same object


def test_findings_from_all_detectors_are_merged_and_sorted() -> None:
    late = email_finding()
    early = Finding(
        detector="secret",
        category="secret",
        start=0,
        end=5,
        confidence=0.9,
        severity=RiskLevel.HIGH,
    )
    engine = make_engine(
        Action.WARN, FakeDetector("pii", [late]), FakeDetector("secret", [early])
    )
    result = engine.process(TEXT, Direction.INPUT)
    assert result.scan.findings == (early, late)


def test_scan_records_direction_and_timings() -> None:
    engine = make_engine(Action.ALLOW, FakeDetector("a"), FakeDetector("b"))
    result = engine.process(TEXT, Direction.OUTPUT)
    assert result.direction is Direction.OUTPUT
    assert result.scan.direction is Direction.OUTPUT
    assert set(result.scan.detector_ms) == {"a", "b"}
    assert result.duration_ms >= result.scan.duration_ms >= 0


def test_crashing_detector_is_recorded_and_others_still_run() -> None:
    working = FakeDetector("pii", [email_finding()])
    policy = FixedPolicy(Action.WARN)
    engine = DLPEngine([CrashingDetector(), working], policy)
    result = engine.process(TEXT, Direction.INPUT)
    assert result.scan.errors == ("broken",)
    assert result.scan.findings == (email_finding(),)
    assert len(working.calls) == 1


def test_crash_is_logged_without_the_text(caplog: pytest.LogCaptureFixture) -> None:
    """The error message contains the text, so it must NOT be logged."""
    engine = make_engine(Action.ALLOW, CrashingDetector())
    with caplog.at_level(logging.ERROR):
        engine.process(TEXT, Direction.INPUT)
    assert "broken" in caplog.text
    assert "ValueError" in caplog.text
    assert "me@example.com" not in caplog.text


def test_crashing_detector_blocks_with_the_real_policy() -> None:
    policy = PolicyEngine(
        Policy.model_validate(
            {"version": 1, "input": {"rules": []}, "output": {"rules": []}}
        )
    )
    engine = DLPEngine([CrashingDetector()], policy)
    result = engine.process(TEXT, Direction.INPUT)
    assert result.blocked
    assert result.output_text is None


def test_too_long_text_is_blocked_without_scanning() -> None:
    detector = FakeDetector("pii")
    engine = make_engine(Action.ALLOW, detector, max_chars=10)
    result = engine.process("x" * 11, Direction.INPUT)
    assert result.blocked
    assert detector.calls == []
    assert "more than the limit of 10" in result.decision.reasons[0]


def test_text_exactly_at_the_limit_is_scanned() -> None:
    detector = FakeDetector("pii")
    engine = make_engine(Action.ALLOW, detector, max_chars=10)
    assert not engine.process("x" * 10, Direction.INPUT).blocked
    assert len(detector.calls) == 1


def test_empty_text() -> None:
    result = make_engine(Action.ALLOW, FakeDetector("pii")).process("", Direction.INPUT)
    assert result.action is Action.ALLOW
    assert result.output_text == ""


def test_detector_names_must_be_unique() -> None:
    with pytest.raises(ValueError, match="unique"):
        make_engine(Action.ALLOW, FakeDetector("pii"), FakeDetector("pii"))
