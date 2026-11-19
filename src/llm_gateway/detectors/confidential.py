"""Confidential-terms detector: your organisation's own secret words.

General detectors know what an email or an API key looks like. They cannot
know that "Project Nightingale" is your secret merger, or that a document
says "INTERNAL USE ONLY". This detector looks for the terms YOU list in
config/confidential_terms.yaml.

Patterns run on the cleaned text from the normalizer, so "PROJECT
NIGHTINGALE", "Project  Nightingale" and look-alike-letter tricks all match.
Several rules can match the same words (for example "strictly confidential"
also contains "confidential"); the policy then uses the strongest one.
"""

from __future__ import annotations

import re
from itertools import islice
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
    model_validator,
)

from llm_gateway.detectors.base import Detector, DetectorConfigError
from llm_gateway.detectors.normalizer import NormalizedText
from llm_gateway.models import Finding, RiskLevel

MAX_MATCHES_PER_TERM = 500  # every match may need hiding, so a high limit


class ConfidentialConfigError(DetectorConfigError):
    """The confidential terms file is missing or has mistakes."""


class TermRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    description: str = Field(min_length=1)
    pattern: str = Field(min_length=1)
    confidence: float = Field(gt=0.0, le=1.0)
    severity: RiskLevel
    enabled: bool = True
    _compiled: re.Pattern[str] = PrivateAttr()

    @field_validator("pattern")
    @classmethod
    def pattern_compiles(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as error:
            raise ValueError(f"invalid regular expression: {error}") from error
        return value

    @model_validator(mode="after")
    def severity_is_not_none(self) -> TermRule:
        if self.severity is RiskLevel.NONE:
            raise ValueError("a rule's severity cannot be 'none'")
        return self

    def model_post_init(self, context: Any) -> None:
        self._compiled = re.compile(self.pattern)

    @property
    def compiled(self) -> re.Pattern[str]:
        return self._compiled


class TermSet(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1]
    terms: tuple[TermRule, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def ids_are_unique(self) -> TermSet:
        ids = [term.id for term in self.terms]
        duplicates = sorted({term_id for term_id in ids if ids.count(term_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate term ids: {', '.join(duplicates)}")
        return self


def load_terms(path: Path) -> TermSet:
    """Read and check the terms file. Raises ConfidentialConfigError on mistakes."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ConfidentialConfigError(
            f"cannot read terms file {path}: {error}"
        ) from error
    except yaml.YAMLError as error:
        raise ConfidentialConfigError(f"{path} is not valid YAML: {error}") from error
    if not isinstance(raw, dict):
        raise ConfidentialConfigError(f"{path} must contain a YAML mapping at the top")
    try:
        return TermSet.model_validate(raw)
    except ValidationError as error:
        raise ConfidentialConfigError(f"{path} has mistakes:\n{error}") from error


class ConfidentialDetector(Detector):
    """Finds the confidential terms listed in the config file."""

    name = "confidential"

    def __init__(self, terms: TermSet) -> None:
        self.terms = terms
        self._rules = [term for term in terms.terms if term.enabled]

    @classmethod
    def from_file(cls, path: Path) -> ConfidentialDetector:
        return cls(load_terms(path))

    def scan(self, text: NormalizedText) -> list[Finding]:
        findings = []
        for rule in self._rules:
            matches = rule.compiled.finditer(text.text)
            for match in islice(matches, MAX_MATCHES_PER_TERM):
                if match.end() == match.start():
                    continue
                start, end = text.original_span(match.start(), match.end())
                findings.append(
                    Finding(
                        detector=self.name,
                        category="confidential",
                        entity_type="CONFIDENTIAL_TERM",
                        start=start,
                        end=end,
                        confidence=rule.confidence,
                        severity=rule.severity,
                        rule_id=rule.id,
                    )
                )
        return sorted(findings, key=lambda f: (f.start, f.end, f.rule_id or ""))
