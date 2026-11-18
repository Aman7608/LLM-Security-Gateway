"""Tests for the PII detector working together with Presidio and spaCy.

These are integration tests because they use the real language model.
The model is loaded once (see the pii_detector fixture in conftest.py).
"""

from __future__ import annotations

import pytest

from llm_gateway.detectors.pii import (
    EntitySettings,
    PIIConfig,
    PIIConfigError,
    PIIDetector,
)
from llm_gateway.dlp.redactor import redact
from llm_gateway.models import RiskLevel
from tests.data.pii_samples import NO_PII, PII_SAMPLES


def small_config(**entities: EntitySettings) -> PIIConfig:
    return PIIConfig(
        version=1,
        language="en",
        spacy_model="en_core_web_lg",
        phone_regions=("IN", "US"),
        entities=entities,
    )


@pytest.mark.parametrize("text, expected", PII_SAMPLES)
def test_personal_data_is_found(
    pii_detector: PIIDetector, text: str, expected: set[str]
) -> None:
    found = {f.entity_type for f in pii_detector.scan_text(text)}
    assert expected <= found


@pytest.mark.parametrize("text", NO_PII)
def test_text_without_personal_data_is_clean(
    pii_detector: PIIDetector, text: str
) -> None:
    assert pii_detector.scan_text(text) == []


def test_finding_fields(pii_detector: PIIDetector) -> None:
    text = "Contact me at Priya.Sharma@Example.com today"
    (finding,) = pii_detector.scan_text(text)
    assert finding.detector == "pii"
    assert finding.category == "pii"
    assert finding.entity_type == "EMAIL_ADDRESS"
    assert finding.severity is RiskLevel.MEDIUM  # from pii_entities.yaml
    assert finding.rule_id == "EmailRecognizer"
    assert 0 < finding.confidence <= 1
    # Spans point at the original text, with its original capital letters
    assert text[finding.start : finding.end] == "Priya.Sharma@Example.com"


def test_findings_are_sorted(pii_detector: PIIDetector) -> None:
    text = "Rahul Verma, rahul@example.com, +91 98765 43210"
    starts = [f.start for f in pii_detector.scan_text(text)]
    assert starts == sorted(starts)


@pytest.mark.parametrize("text", ["", "   ", "\n\t"])
def test_empty_text(pii_detector: PIIDetector, text: str) -> None:
    assert pii_detector.scan_text(text) == []


def test_each_entity_has_its_own_threshold(pii_detector: PIIDetector) -> None:
    """The US phone below scores 0.4, so a 0.9 threshold must drop it."""
    strict = PIIDetector(
        small_config(PHONE_NUMBER=EntitySettings(min_confidence=0.9, severity="low")),
        analyzer=pii_detector.analyzer,  # reuse the loaded model
    )
    assert strict.scan_text("Call (212) 555-0147") == []
    assert pii_detector.scan_text("Call (212) 555-0147")  # found with the real config


def test_disabled_entities_are_not_reported(pii_detector: PIIDetector) -> None:
    only_email = PIIDetector(
        small_config(
            EMAIL_ADDRESS=EntitySettings(min_confidence=0.5, severity="medium"),
            PERSON=EntitySettings(min_confidence=0.5, severity="low", enabled=False),
        ),
        analyzer=pii_detector.analyzer,
    )
    found = {
        f.entity_type for f in only_email.scan_text("Rahul Verma, rahul@example.com")
    }
    assert found == {"EMAIL_ADDRESS"}


def test_unknown_entity_name_is_rejected(pii_detector: PIIDetector) -> None:
    config = small_config(
        MADE_UP_THING=EntitySettings(min_confidence=0.5, severity="low")
    )
    with pytest.raises(PIIConfigError, match="MADE_UP_THING"):
        PIIDetector(config, analyzer=pii_detector.analyzer)


def test_findings_can_be_redacted(pii_detector: PIIDetector) -> None:
    text = "I'm Neha Kapoor, email neha.k@example.com, card 4111 1111 1111 1111"
    result = redact(text, pii_detector.scan_text(text))
    assert result == "I'm <PERSON>, email <EMAIL_ADDRESS>, card <CREDIT_CARD>"
