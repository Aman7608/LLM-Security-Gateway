"""Personal data (PII) detector, built on Microsoft Presidio.

Presidio does the hard work:
  - pattern recognizers with extra checks, for example the Luhn checksum for
    card numbers, so "1234 5678 9012 3456" is not reported as a card
  - the spaCy language model, which finds names and places from the sentence
    around them

This module adds:
  - settings from config/pii_entities.yaml (which types, how confident)
  - Indian ID recognizers (Aadhaar, PAN, passport), which Presidio has but
    does not turn on by default
  - turning Presidio results into our own Finding objects
  - NO internet access while scanning (see _turn_off_domain_list_download)

Loading the language model takes a few seconds and about 1 GB of memory, so
create ONE PIIDetector when the gateway starts and reuse it.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

import spacy.util
import yaml
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import (
    InAadhaarRecognizer,
    InPanRecognizer,
    InPassportRecognizer,
    PhoneRecognizer,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from llm_gateway.detectors.base import Detector, DetectorConfigError
from llm_gateway.detectors.normalizer import NormalizedText
from llm_gateway.models import Finding, RiskLevel


class PIIConfigError(DetectorConfigError):
    """The PII config file is missing or has mistakes."""


class EntitySettings(BaseModel):
    """Settings for one kind of personal data, e.g. EMAIL_ADDRESS."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    min_confidence: float = Field(gt=0.0, le=1.0)
    severity: RiskLevel
    enabled: bool = True

    @model_validator(mode="after")
    def severity_is_not_none(self) -> EntitySettings:
        if self.severity is RiskLevel.NONE:
            raise ValueError("severity cannot be 'none'")
        return self


class PIIConfig(BaseModel):
    """The whole PII config file, checked when it is loaded."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1]
    language: Literal["en"]
    spacy_model: str = Field(pattern=r"^[a-z]{2}_[a-z0-9_]+$")
    phone_regions: tuple[str, ...] = Field(min_length=1)
    entities: dict[str, EntitySettings]

    @model_validator(mode="after")
    def check_values(self) -> PIIConfig:
        bad_regions = [
            r for r in self.phone_regions if not (len(r) == 2 and r.isupper())
        ]
        if bad_regions:
            raise ValueError(
                f"phone_regions must be 2-letter codes like IN: {bad_regions}"
            )
        bad_names = [n for n in self.entities if not n.replace("_", "").isupper()]
        if bad_names:
            raise ValueError(f"entity names must be UPPER_CASE: {bad_names}")
        if not any(e.enabled for e in self.entities.values()):
            raise ValueError("at least one entity must be enabled")
        return self

    @property
    def enabled_entities(self) -> dict[str, EntitySettings]:
        return {name: e for name, e in self.entities.items() if e.enabled}


def load_pii_config(path: Path) -> PIIConfig:
    """Read and check the PII config file. Raises PIIConfigError on mistakes."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise PIIConfigError(f"cannot read PII config {path}: {error}") from error
    except yaml.YAMLError as error:
        raise PIIConfigError(f"{path} is not valid YAML: {error}") from error
    if not isinstance(raw, dict):
        raise PIIConfigError(f"{path} must contain a YAML mapping at the top level")
    try:
        return PIIConfig.model_validate(raw)
    except ValidationError as error:
        raise PIIConfigError(f"{path} has mistakes:\n{error}") from error


def _turn_off_domain_list_download() -> None:
    """Stop Presidio's email check from downloading a file from the internet.

    Presidio checks email domains with the tldextract library. By default,
    tldextract downloads the "public suffix list" from publicsuffix.org the
    first time it runs. A security gateway should not make surprise internet
    calls (it may run where there is no internet, and outgoing traffic is
    something we control on purpose). So we tell tldextract to use the copy
    of the list that ships inside the package, and to write no cache files.
    """
    import tldextract.tldextract as tld

    tld.TLD_EXTRACTOR = tld.TLDExtract(suffix_list_urls=(), cache_dir=None)


def build_analyzer(config: PIIConfig) -> AnalyzerEngine:
    """Create the Presidio analyzer with our settings. Slow: call it once."""
    _turn_off_domain_list_download()
    # Presidio prints a warning for every recognizer it skips; we only want errors
    logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)

    # If the model is missing, Presidio would quietly DOWNLOAD and INSTALL it
    # from the internet. Installing code at runtime is a supply-chain risk, so
    # we check first and stop with a clear error instead.
    if not spacy.util.is_package(config.spacy_model):
        raise PIIConfigError(
            f"spaCy model '{config.spacy_model}' is not installed. "
            "Install it with: pip install -r requirements.txt"
        )

    nlp_engine = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [
                {"lang_code": config.language, "model_name": config.spacy_model}
            ],
        }
    ).create_engine()

    registry = RecognizerRegistry(supported_languages=[config.language])
    registry.load_predefined_recognizers(
        languages=[config.language], nlp_engine=nlp_engine
    )

    # Replace the phone recognizer with one that knows our list of countries
    registry.remove_recognizer("PhoneRecognizer")
    registry.add_recognizer(PhoneRecognizer(supported_regions=config.phone_regions))

    # Indian ID recognizers exist in Presidio but are not loaded by default
    registry.add_recognizer(InAadhaarRecognizer())
    registry.add_recognizer(InPanRecognizer())
    registry.add_recognizer(InPassportRecognizer())

    return AnalyzerEngine(
        nlp_engine=nlp_engine,
        registry=registry,
        supported_languages=[config.language],
    )


class PIIDetector(Detector):
    """Finds personal data using Presidio and the settings from the config file."""

    name = "pii"

    def __init__(
        self, config: PIIConfig, analyzer: AnalyzerEngine | None = None
    ) -> None:
        self.config = config
        self.analyzer = analyzer or build_analyzer(config)
        self._entities = config.enabled_entities

        unknown = set(self._entities) - set(
            self.analyzer.get_supported_entities(config.language)
        )
        if unknown:
            raise PIIConfigError(
                f"Presidio does not know these entities: {sorted(unknown)}"
            )

        # Ask Presidio for everything above the lowest threshold, then apply
        # each entity's own threshold ourselves.
        self._lowest_threshold = min(e.min_confidence for e in self._entities.values())

    @classmethod
    def from_file(cls, path: Path) -> PIIDetector:
        return cls(load_pii_config(path))

    def scan(self, text: NormalizedText) -> list[Finding]:
        # Presidio needs the ORIGINAL text: the language model uses capital
        # letters and punctuation to recognise names, so the lowercase cleaned
        # view would make it worse.
        if not text.original.strip():
            return []

        results = self.analyzer.analyze(
            text=text.original,
            language=self.config.language,
            entities=list(self._entities),
            score_threshold=self._lowest_threshold,
        )

        findings = []
        for result in results:
            settings = self._entities[result.entity_type]
            if result.score < settings.min_confidence:
                continue
            recognizer = (result.recognition_metadata or {}).get("recognizer_name")
            findings.append(
                Finding(
                    detector=self.name,
                    category="pii",
                    entity_type=result.entity_type,
                    start=result.start,
                    end=result.end,
                    confidence=round(min(result.score, 1.0), 4),
                    severity=settings.severity,
                    rule_id=recognizer,
                )
            )
        return sorted(findings, key=lambda f: (f.start, f.end, f.entity_type or ""))
