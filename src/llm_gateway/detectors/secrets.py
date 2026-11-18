"""Secret detector: API keys, tokens, passwords and private keys.

How it works:
1. Patterns from config/secret_patterns.yaml run on the ORIGINAL text, because
   keys are case-sensitive.
2. Some rules only hide part of the match (secret_group), so for
   "password=<value>" only <value> is hidden and the reader still sees which
   setting it was.
3. Rules for passwords skip obvious placeholders like ${DB_PASS} or <your-key>,
   and values that are too simple to be a password ("my password is strong").
4. An entropy check finds long random-looking strings in formats we have no
   pattern for. It is noisy, so it has low confidence.

Unlike the injection detector, this one reports EVERY match (up to a high
limit). Each match may need to be redacted, so stopping at five could let
the sixth secret leak.
"""

from __future__ import annotations

import math
import re
from collections import Counter
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

# High enough to find every secret in a 20,000-character prompt,
# low enough that a crafted input cannot create millions of findings.
MAX_MATCHES_PER_RULE = 500

# Candidate strings for the entropy check: base64 / URL-safe characters only.
_LONG_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{8,512}(?![A-Za-z0-9+/=_-])"
)


class SecretConfigError(DetectorConfigError):
    """The secret pattern file is missing or has mistakes."""


class SecretRule(BaseModel):
    """One secret pattern from the YAML file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    description: str = Field(min_length=1)
    secret_type: str = Field(pattern=r"^[A-Z][A-Z0-9_]*$")
    pattern: str = Field(min_length=1)
    secret_group: int = Field(default=0, ge=0)
    confidence: float = Field(gt=0.0, le=1.0)
    severity: RiskLevel
    check_placeholders: bool = False
    require_mixed_chars: bool = False
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
    def check_rule(self) -> SecretRule:
        if self.severity is RiskLevel.NONE:
            raise ValueError("a rule's severity cannot be 'none'")
        groups = re.compile(self.pattern).groups
        if self.secret_group > groups:
            raise ValueError(
                f"secret_group is {self.secret_group} but the pattern "
                f"only has {groups} group(s)"
            )
        return self

    def model_post_init(self, context: Any) -> None:
        self._compiled = re.compile(self.pattern)

    @property
    def compiled(self) -> re.Pattern[str]:
        return self._compiled


class EntropySettings(BaseModel):
    """Settings for the random-looking-string check."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = True
    min_length: int = Field(default=24, ge=8, le=512)
    min_entropy: float = Field(default=4.3, gt=0.0, le=8.0)
    confidence: float = Field(default=0.5, gt=0.0, le=1.0)
    severity: RiskLevel = RiskLevel.MEDIUM
    max_candidates: int = Field(default=200, ge=1, le=10_000)


class SecretRuleSet(BaseModel):
    """The whole secret pattern file, checked when it is loaded."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1]
    placeholder_values: tuple[str, ...] = ()
    entropy: EntropySettings = EntropySettings()
    rules: tuple[SecretRule, ...]
    _placeholder: re.Pattern[str] | None = PrivateAttr(default=None)

    @field_validator("placeholder_values")
    @classmethod
    def placeholders_compile(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        # Checked here (not in model_post_init) so a bad pattern becomes a
        # clear config error instead of a raw re.error.
        for value in values:
            try:
                re.compile(value)
            except re.error as error:
                raise ValueError(
                    f"invalid placeholder pattern {value!r}: {error}"
                ) from error
        return values

    @model_validator(mode="after")
    def check_rules(self) -> SecretRuleSet:
        ids = [rule.id for rule in self.rules]
        duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate rule ids: {', '.join(duplicates)}")
        if not any(rule.enabled for rule in self.rules):
            raise ValueError("at least one rule must be enabled")
        return self

    def model_post_init(self, context: Any) -> None:
        if self.placeholder_values:
            joined = "|".join(f"(?:{p})" for p in self.placeholder_values)
            self._placeholder = re.compile(joined, re.IGNORECASE)

    def is_placeholder(self, value: str) -> bool:
        """True if the WHOLE value matches one of the placeholder patterns."""
        return bool(self._placeholder and self._placeholder.fullmatch(value))


def load_secret_rules(path: Path) -> SecretRuleSet:
    """Read and check the secret pattern file. Raises SecretConfigError on mistakes."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise SecretConfigError(
            f"cannot read secret pattern file {path}: {error}"
        ) from error
    except yaml.YAMLError as error:
        raise SecretConfigError(f"{path} is not valid YAML: {error}") from error
    if not isinstance(raw, dict):
        raise SecretConfigError(f"{path} must contain a YAML mapping at the top level")
    try:
        return SecretRuleSet.model_validate(raw)
    except ValidationError as error:
        raise SecretConfigError(f"{path} has mistakes:\n{error}") from error


_MARKDOWN_WRAPPERS = "`*_~"


def _strip_markdown(value: str, start: int) -> tuple[str, int, int]:
    """Remove Markdown formatting around a value, like `code` or **bold**.

    Prompts and AI answers are full of Markdown. Without this, "my password
    is `<value>`" would not be seen as a placeholder (because of the
    backticks), and "my password is **strong**" would pass the
    mixed-characters check (because "*" counts as a symbol).
    Returns the cleaned value and its new start and end positions.
    """
    left = len(value) - len(value.lstrip(_MARKDOWN_WRAPPERS))
    cleaned = value.strip(_MARKDOWN_WRAPPERS)
    return cleaned, start + left, start + left + len(cleaned)


def shannon_entropy(value: str) -> float:
    """How random a string looks, in bits per character.

    Each character's share of the string is p, and entropy is the sum of
    -p * log2(p). "aaaaaaaa" scores 0 (no surprise at all). Random letters
    and digits score about 4.5 to 5. English words score about 3 to 4.
    """
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def character_kinds(value: str) -> int:
    """How many kinds of character the value uses: lower, upper, digit, other."""
    return sum(
        [
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        ]
    )


class SecretDetector(Detector):
    """Finds secrets using the patterns from the YAML file plus an entropy check."""

    name = "secret"

    def __init__(self, rules: SecretRuleSet) -> None:
        self.rules = rules
        self._rules = [rule for rule in rules.rules if rule.enabled]

    @classmethod
    def from_file(cls, path: Path) -> SecretDetector:
        return cls(load_secret_rules(path))

    def scan(self, text: NormalizedText) -> list[Finding]:
        original = text.original
        findings: list[Finding] = []

        for rule in self._rules:
            for match in islice(rule.compiled.finditer(original), MAX_MATCHES_PER_RULE):
                value, start, end = _strip_markdown(
                    match.group(rule.secret_group), match.start(rule.secret_group)
                )
                if not value or not self._looks_real(rule, value):
                    continue
                findings.append(
                    Finding(
                        detector=self.name,
                        category="secret",
                        entity_type=rule.secret_type,
                        start=start,
                        end=end,
                        confidence=rule.confidence,
                        severity=rule.severity,
                        rule_id=rule.id,
                    )
                )

        if self.rules.entropy.enabled:
            findings += self._entropy_findings(original, findings)

        return sorted(findings, key=lambda f: (f.start, f.end, f.rule_id or ""))

    def _looks_real(self, rule: SecretRule, value: str) -> bool:
        if rule.check_placeholders and self.rules.is_placeholder(value):
            return False
        if rule.require_mixed_chars and character_kinds(value) < 2:
            return False
        return True

    def _entropy_findings(self, original: str, found: list[Finding]) -> list[Finding]:
        """Report long random-looking strings that no pattern already found."""
        settings = self.rules.entropy
        findings = []
        for match in islice(_LONG_TOKEN.finditer(original), settings.max_candidates):
            token = match.group()
            start, end = match.span()
            if len(token) < settings.min_length:
                continue
            # Random keys mix lowercase, uppercase and digits. This skips long
            # words, hex hashes (no uppercase) and most code identifiers.
            if not (
                any(c.islower() for c in token)
                and any(c.isupper() for c in token)
                and any(c.isdigit() for c in token)
            ):
                continue
            if shannon_entropy(token) < settings.min_entropy:
                continue
            if any(f.start < end and start < f.end for f in found):
                continue  # a specific pattern already found it
            findings.append(
                Finding(
                    detector=self.name,
                    category="secret",
                    entity_type="HIGH_ENTROPY_STRING",
                    start=start,
                    end=end,
                    confidence=settings.confidence,
                    severity=settings.severity,
                    rule_id="entropy-check",
                )
            )
        return findings
