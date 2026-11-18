"""Prompt injection detector.

How it works:
1. The rules live in a YAML file (config/injection_rules.yaml), so new attack
   patterns can be added without changing code.
2. Each rule has a category, a confidence score (how sure we are that a match
   is really an attack) and a severity.
3. Regex rules are matched against the cleaned text from the normalizer.
   Short "compact phrases" are matched against the letters-only view, which
   catches tricks like "I.g.n.o.r.e a.l.l p.r.e.v.i.o.u.s instructions".
4. Base64-encoded text is decoded and checked with the same rules.
5. Hidden characters and mixed-alphabet words are reported as "obfuscation",
   because normal text rarely contains them.

The detector only reports findings. It does not block anything.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable, Iterator
from enum import StrEnum
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

from llm_gateway.detectors.base import Detector
from llm_gateway.detectors.normalizer import NormalizedText, normalize
from llm_gateway.models import Finding, RiskLevel

# Limits that stop a huge or crafted input from making the detector slow.
MAX_MATCHES_PER_RULE = 5
MAX_BASE64_TOKEN_LENGTH = 8_000
MAX_OBFUSCATION_FINDINGS = 5

# Text made only of base64 characters, at least 16 long, not part of a longer word.
_BASE64_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])"
)


class Category(StrEnum):
    """The kinds of prompt injection we classify findings into."""

    INSTRUCTION_OVERRIDE = "instruction_override"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    ROLE_MANIPULATION = "role_manipulation"
    JAILBREAK = "jailbreak"
    DELIMITER_INJECTION = "delimiter_injection"
    SUSPICIOUS_INSTRUCTION = "suspicious_instruction"
    OBFUSCATION = "obfuscation"


class RuleConfigError(ValueError):
    """The rule file is missing or has mistakes."""


# ---------------------------------------------------------------------------
# Rule file format
# ---------------------------------------------------------------------------


class _Rule(BaseModel):
    """Fields shared by both kinds of rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    category: Category
    description: str = Field(min_length=1)
    confidence: float = Field(gt=0.0, le=1.0)
    severity: RiskLevel
    enabled: bool = True

    @field_validator("severity")
    @classmethod
    def severity_is_not_none(cls, value: RiskLevel) -> RiskLevel:
        if value is RiskLevel.NONE:
            raise ValueError("a rule's severity cannot be 'none'")
        return value


class RegexRule(_Rule):
    """A regular expression matched against the cleaned (lowercase) text."""

    pattern: str = Field(min_length=1)
    _compiled: re.Pattern[str] = PrivateAttr()

    @field_validator("pattern")
    @classmethod
    def pattern_compiles(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as error:
            raise ValueError(f"invalid regular expression: {error}") from error
        return value

    def model_post_init(self, context: Any) -> None:
        # Compile once when the rule is loaded, not on every scan.
        self._compiled = re.compile(self.pattern)

    @property
    def compiled(self) -> re.Pattern[str]:
        return self._compiled


class PhraseRule(_Rule):
    """A phrase matched against the letters-and-digits-only view of the text."""

    phrase: str = Field(pattern=r"^[a-z0-9]{6,}$")


class InjectionRuleSet(BaseModel):
    """The whole rule file, checked when it is loaded."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1]
    max_base64_candidates: int = Field(default=20, ge=0, le=100)
    regex_rules: tuple[RegexRule, ...]
    compact_phrases: tuple[PhraseRule, ...] = ()

    @model_validator(mode="after")
    def check_rules(self) -> InjectionRuleSet:
        ids = [rule.id for rule in (*self.regex_rules, *self.compact_phrases)]
        duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate rule ids: {', '.join(duplicates)}")
        if not any(rule.enabled for rule in self.regex_rules):
            raise ValueError("at least one regex rule must be enabled")
        return self


def load_rules(path: Path) -> InjectionRuleSet:
    """Read and check the rule file. Raises RuleConfigError with a clear message."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise RuleConfigError(f"cannot read rule file {path}: {error}") from error
    except yaml.YAMLError as error:
        raise RuleConfigError(f"{path} is not valid YAML: {error}") from error

    if not isinstance(raw, dict):
        raise RuleConfigError(f"{path} must contain a YAML mapping at the top level")
    try:
        return InjectionRuleSet.model_validate(raw)
    except ValidationError as error:
        raise RuleConfigError(f"{path} has mistakes:\n{error}") from error


# ---------------------------------------------------------------------------
# The detector
# ---------------------------------------------------------------------------


class InjectionDetector(Detector):
    """Finds prompt injection attempts using the rules from the YAML file."""

    name = "injection"

    def __init__(self, rules: InjectionRuleSet) -> None:
        self.rules = rules
        self._regex_rules = [rule for rule in rules.regex_rules if rule.enabled]
        self._phrase_rules = [rule for rule in rules.compact_phrases if rule.enabled]

    @classmethod
    def from_file(cls, path: Path) -> InjectionDetector:
        return cls(load_rules(path))

    def scan(self, text: NormalizedText) -> list[Finding]:
        findings = self._match_rules(text)
        findings += self._obfuscation_findings(text)
        findings += self._base64_findings(text.original)
        return sorted(findings, key=lambda f: (f.start, f.end, f.rule_id or ""))

    def _match_rules(
        self,
        text: NormalizedText,
        whole_span: tuple[int, int] | None = None,
        rule_suffix: str = "",
    ) -> list[Finding]:
        """Run every enabled rule on the text.

        whole_span is used for decoded base64: the finding then points at the
        whole encoded block in the original text.
        """
        findings: list[Finding] = []
        seen: set[tuple[str, int, int]] = set()

        def add(rule: _Rule, start: int, end: int) -> None:
            key = (rule.id, start, end)
            if key not in seen:
                seen.add(key)
                findings.append(self._make_finding(rule, start, end, rule_suffix))

        for regex_rule in self._regex_rules:
            matches = regex_rule.compiled.finditer(text.text)
            for match in islice(matches, MAX_MATCHES_PER_RULE):
                if match.end() > match.start():
                    start, end = whole_span or text.original_span(
                        match.start(), match.end()
                    )
                    add(regex_rule, start, end)

        for phrase_rule in self._phrase_rules:
            for position in islice(
                _find_all(text.compact, phrase_rule.phrase), MAX_MATCHES_PER_RULE
            ):
                start, end = whole_span or text.original_span(
                    position, position + len(phrase_rule.phrase), compact=True
                )
                # Skip it if a regex rule already found the same kind of attack
                # here with at least the same confidence. The phrase rules are a
                # backup for disguised text, so they should not double-count.
                already_found = any(
                    f.category == phrase_rule.category
                    and f.confidence >= phrase_rule.confidence
                    and f.start < end
                    and start < f.end
                    for f in findings
                )
                if not already_found:
                    add(phrase_rule, start, end)

        return findings

    def _make_finding(
        self, rule: _Rule, start: int, end: int, rule_suffix: str
    ) -> Finding:
        return Finding(
            detector=self.name,
            category=rule.category.value,
            start=start,
            end=end,
            confidence=rule.confidence,
            severity=rule.severity,
            rule_id=rule.id + rule_suffix,
        )

    def _obfuscation_findings(self, text: NormalizedText) -> list[Finding]:
        """Report hidden characters and mixed-alphabet words."""
        findings = []
        if text.invisible_positions:
            findings.append(
                Finding(
                    detector=self.name,
                    category=Category.OBFUSCATION.value,
                    start=min(text.invisible_positions),
                    end=max(text.invisible_positions) + 1,
                    confidence=0.5,
                    severity=RiskLevel.MEDIUM,
                    rule_id="obfuscation-invisible-characters",
                )
            )
        for start, end in text.mixed_script_spans[:MAX_OBFUSCATION_FINDINGS]:
            findings.append(
                Finding(
                    detector=self.name,
                    category=Category.OBFUSCATION.value,
                    start=start,
                    end=end,
                    confidence=0.5,
                    severity=RiskLevel.MEDIUM,
                    rule_id="obfuscation-mixed-script",
                )
            )
        return findings

    def _base64_findings(self, original: str) -> list[Finding]:
        """Decode base64-looking blocks and run the rules on the decoded text.

        Only one level is decoded (base64 inside base64 is not followed), and
        the number of blocks is limited, so this cannot be used to slow us down.
        """
        findings: list[Finding] = []
        candidates = _BASE64_TOKEN.finditer(original)
        for match in islice(candidates, self.rules.max_base64_candidates):
            token = match.group()
            if len(token) > MAX_BASE64_TOKEN_LENGTH:
                continue
            decoded = _decode_base64_text(token)
            if decoded is not None:
                findings += self._match_rules(
                    normalize(decoded),
                    whole_span=(match.start(), match.end()),
                    rule_suffix="+base64",
                )
        return findings


def _find_all(text: str, phrase: str) -> Iterator[int]:
    """Yield every position where phrase appears in text."""
    position = text.find(phrase)
    while position != -1:
        yield position
        position = text.find(phrase, position + 1)


def _decode_base64_text(token: str) -> str | None:
    """Return the decoded text if token is base64 for readable text, else None."""
    padded = token + "=" * (-len(token) % 4)
    standard = padded.replace("-", "+").replace("_", "/")  # also accept URL-safe
    try:
        decoded = base64.b64decode(standard, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    if len(decoded) < 8:
        return None
    readable = sum(char.isprintable() or char.isspace() for char in decoded)
    if readable / len(decoded) < 0.9:
        return None
    return decoded


def combined_confidence(findings: Iterable[Finding]) -> float:
    """How sure we are, overall, that the text is an attack (0 to 1).

    Uses the "noisy-OR" formula: each rule that matched is an independent
    chance of being right, so the chance that ALL of them are wrong is
    (1 - c1) * (1 - c2) * ..., and the overall confidence is 1 minus that.
    Example: two rules at 0.6 give 1 - 0.4 * 0.4 = 0.84.
    The same rule matching many times only counts once.
    """
    best: dict[str, float] = {}
    for finding in findings:
        key = finding.rule_id or finding.category
        best[key] = max(best.get(key, 0.0), finding.confidence)
    chance_all_wrong = 1.0
    for confidence in best.values():
        chance_all_wrong *= 1.0 - confidence
    return round(1.0 - chance_all_wrong, 4)
