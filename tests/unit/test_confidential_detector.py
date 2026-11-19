"""Tests for llm_gateway.detectors.confidential."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from llm_gateway.detectors.base import DetectorConfigError
from llm_gateway.detectors.confidential import (
    ConfidentialConfigError,
    ConfidentialDetector,
    load_terms,
)
from tests.conftest import CONFIDENTIAL_TERMS_FILE


def ids(detector: ConfidentialDetector, text: str) -> list[str | None]:
    return [f.rule_id for f in detector.scan_text(text)]


def test_the_real_terms_file_loads() -> None:
    assert len(load_terms(CONFIDENTIAL_TERMS_FILE).terms) >= 5


def test_errors_are_detector_config_errors() -> None:
    assert issubclass(ConfidentialConfigError, DetectorConfigError)


@pytest.mark.parametrize(
    "text, rule_id",
    [
        ("Update on Project Nightingale", "example-project-nightingale"),
        ("PROJECT   NIGHTINGALE is late", "example-project-nightingale"),
        ("The Bluebird Pro ships soon", "example-unreleased-product"),
        ("This is HIGHLY CONFIDENTIAL", "marking-strictly-confidential"),
        ("For internal use only", "marking-internal-only"),
        ("Shared under NDA", "marking-internal-only"),
        ("Is this confidential?", "marking-confidential-word"),
    ],
)
def test_terms_are_found(
    confidential_detector: ConfidentialDetector, text: str, rule_id: str
) -> None:
    assert rule_id in ids(confidential_detector, text)


def test_disguised_letters_are_still_found(
    confidential_detector: ConfidentialDetector,
) -> None:
    text = "Project Nightingalе"  # Cyrillic "е" at the end
    assert "example-project-nightingale" in ids(confidential_detector, text)


def test_finding_fields_and_span(confidential_detector: ConfidentialDetector) -> None:
    text = "Status of Project  Nightingale: green"
    finding = confidential_detector.scan_text(text)[0]
    assert finding.detector == "confidential"
    assert finding.category == "confidential"
    assert finding.entity_type == "CONFIDENTIAL_TERM"
    assert text[finding.start : finding.end] == "Project  Nightingale"


@pytest.mark.parametrize(
    "text",
    [
        "The nightingale sang",
        "A bluebird landed",
        "Confide in me",
        "Internal combustion",
    ],
)
def test_normal_words_are_not_found(
    confidential_detector: ConfidentialDetector, text: str
) -> None:
    assert confidential_detector.scan_text(text) == []


def a_term(**overrides: Any) -> dict[str, Any]:
    term: dict[str, Any] = {
        "id": "t",
        "description": "d",
        "pattern": r"\bsecret thing\b",
        "confidence": 0.9,
        "severity": "high",
    }
    term.update(overrides)
    return term


def write(tmp_path: Path, data: Any) -> Path:
    path = tmp_path / "terms.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_a_custom_file_works(tmp_path: Path) -> None:
    detector = ConfidentialDetector.from_file(
        write(tmp_path, {"version": 1, "terms": [a_term()]})
    )
    assert ids(detector, "about the Secret  Thing") == ["t"]


@pytest.mark.parametrize(
    "data, message",
    [
        ({"version": 1, "terms": []}, "terms"),
        ({"version": 1, "terms": [a_term(pattern="(oops")]}, "invalid regular"),
        ({"version": 1, "terms": [a_term(severity="none")]}, "cannot be 'none'"),
        ({"version": 1, "terms": [a_term(), a_term()]}, "duplicate term ids: t"),
        ({"version": 2, "terms": [a_term()]}, "version"),
        ({"version": 1, "terms": [{**a_term(), "patern": "x"}]}, "patern"),
    ],
)
def test_bad_files_are_rejected(tmp_path: Path, data: Any, message: str) -> None:
    with pytest.raises(ConfidentialConfigError, match=message):
        load_terms(write(tmp_path, data))


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfidentialConfigError, match="cannot read"):
        load_terms(tmp_path / "nope.yaml")


def test_disabled_terms_are_skipped(tmp_path: Path) -> None:
    data = {"version": 1, "terms": [a_term(), a_term(id="off", enabled=False)]}
    detector = ConfidentialDetector.from_file(write(tmp_path, data))
    assert ids(detector, "secret thing") == ["t"]
