"""Security tests for the PII detector.

- personal data must be found and hidden before it can leak
- the detector must never use the internet or install anything at runtime
- known blind spots are kept visible as expected failures
"""

from __future__ import annotations

import socket
import time
from typing import Any

import pytest
import spacy.cli
import tldextract.tldextract as tld

from llm_gateway.detectors.pii import (
    PIIConfig,
    PIIConfigError,
    PIIDetector,
    build_analyzer,
)
from llm_gateway.dlp.redactor import RedactionMode, redact
from tests.data.pii_samples import KNOWN_FALSE_POSITIVES, KNOWN_MISSES, PII_SAMPLES


def test_no_personal_data_survives_redaction(pii_detector: PIIDetector) -> None:
    """After redaction, none of the original personal values may remain."""
    for text, _ in PII_SAMPLES:
        findings = pii_detector.scan_text(text)
        hidden = redact(text, findings, RedactionMode.REMOVE)
        for finding in findings:
            assert text[finding.start : finding.end] not in hidden, text


def test_scanning_uses_no_internet(
    pii_detector: PIIDetector, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Block every network connection, then scan. It must still work."""

    def no_network(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("the PII detector tried to use the network")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)

    findings = pii_detector.scan_text("Write to someone@new-domain.example.co.uk")
    assert [f.entity_type for f in findings] == ["EMAIL_ADDRESS"]


def test_domain_list_download_is_turned_off(pii_detector: PIIDetector) -> None:
    assert tld.TLD_EXTRACTOR.suffix_list_urls == ()


def test_missing_model_is_not_downloaded(
    pii_detector: PIIDetector, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Presidio would install a missing model from the internet. We must stop that."""

    def no_download(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("tried to download a spaCy model")

    monkeypatch.setattr(spacy.cli, "download", no_download)
    config = PIIConfig.model_validate(
        {
            **pii_detector.config.model_dump(),
            "spacy_model": "en_core_web_doesnotexist",
        }
    )
    with pytest.raises(PIIConfigError, match="not installed"):
        build_analyzer(config)


def test_long_text_is_scanned_quickly(pii_detector: PIIDetector) -> None:
    """20,000 characters (the default prompt limit) with PII spread through it."""
    chunk = "Notes from the meeting. Contact rahul@example.com for details. "
    text = (chunk * 400)[:20_000]
    started = time.perf_counter()
    findings = pii_detector.scan_text(text)
    assert time.perf_counter() - started < 10.0
    assert sum(f.entity_type == "EMAIL_ADDRESS" for f in findings) >= 300


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(text, marks=pytest.mark.xfail(strict=True, reason=why))
        for text, why in KNOWN_FALSE_POSITIVES.items()
    ],
)
def test_general_knowledge_is_not_flagged(pii_detector: PIIDetector, text: str) -> None:
    assert pii_detector.scan_text(text) == []


@pytest.mark.parametrize(
    "text, entity_type",
    [
        pytest.param(text, entity, marks=pytest.mark.xfail(strict=True, reason=why))
        for text, entity, why in KNOWN_MISSES
    ],
)
def test_known_misses_are_still_missed(
    pii_detector: PIIDetector, text: str, entity_type: str
) -> None:
    """These fail on purpose. If one starts passing, move it to PII_SAMPLES."""
    assert entity_type in {f.entity_type for f in pii_detector.scan_text(text)}
