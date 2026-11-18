"""Tests for llm_gateway.detectors.secrets.SecretDetector and its helpers."""

from __future__ import annotations

import pytest

from llm_gateway.detectors.secrets import (
    EntropySettings,
    SecretDetector,
    SecretRule,
    SecretRuleSet,
    character_kinds,
    load_secret_rules,
    shannon_entropy,
)
from llm_gateway.dlp.redactor import redact
from llm_gateway.models import RiskLevel
from tests.conftest import SECRET_PATTERNS_FILE
from tests.data.secret_samples import (
    AWS_ACCESS_KEY_ID,
    FAKE_CONFIG_PASS,
    FAKE_SENTENCE_PASS,
    PW,
    RANDOM_TOKEN,
    SECRET_SAMPLES,
)


def test_every_rule_is_used_by_a_sample(secret_detector: SecretDetector) -> None:
    """Each rule in the YAML must catch at least one sample, so no rule is untested."""
    used = {
        f.rule_id
        for text, _, _ in SECRET_SAMPLES
        for f in secret_detector.scan_text(text)
    }
    all_ids = {r.id for r in load_secret_rules(SECRET_PATTERNS_FILE).rules}
    assert all_ids <= used, f"rules with no sample: {sorted(all_ids - used)}"


def test_finding_fields(secret_detector: SecretDetector) -> None:
    text = f"key id {AWS_ACCESS_KEY_ID} here"
    (finding,) = secret_detector.scan_text(text)
    assert finding.detector == "secret"
    assert finding.category == "secret"
    assert finding.entity_type == "AWS_ACCESS_KEY_ID"
    assert finding.rule_id == "aws-access-key-id"
    assert finding.severity is RiskLevel.CRITICAL
    assert text[finding.start : finding.end] == AWS_ACCESS_KEY_ID


def test_only_the_secret_part_is_hidden(secret_detector: SecretDetector) -> None:
    """For password=VALUE, only VALUE is hidden, so the reader knows what it was."""
    text = f"{PW}={FAKE_CONFIG_PASS}"
    assert redact(text, secret_detector.scan_text(text)) == f"{PW}=<SECRET_ASSIGNMENT>"


def test_markdown_around_a_secret_is_kept(secret_detector: SecretDetector) -> None:
    """Only the secret inside `code` or **bold** is hidden, not the formatting."""
    for wrapper in ("`", "**", "_"):
        text = f"My {PW} is {wrapper}{FAKE_SENTENCE_PASS}{wrapper}"
        expected = f"My {PW} is {wrapper}<PASSWORD>{wrapper}"
        assert redact(text, secret_detector.scan_text(text)) == expected


def test_findings_are_sorted(secret_detector: SecretDetector) -> None:
    text = f"{PW}={FAKE_CONFIG_PASS} and {AWS_ACCESS_KEY_ID}"
    starts = [f.start for f in secret_detector.scan_text(text)]
    assert starts == sorted(starts)


@pytest.mark.parametrize("text", ["", "   ", "hello world"])
def test_nothing_found(secret_detector: SecretDetector, text: str) -> None:
    assert secret_detector.scan_text(text) == []


def test_every_secret_in_a_big_dump_is_found(secret_detector: SecretDetector) -> None:
    """Unlike the injection detector, secrets are NOT capped at 5 per rule:
    every one may need to be hidden."""
    text = "\n".join(f"KEY_{i}={AWS_ACCESS_KEY_ID}" for i in range(100))
    findings = [
        f for f in secret_detector.scan_text(text) if f.rule_id == "aws-access-key-id"
    ]
    assert len(findings) == 100
    assert AWS_ACCESS_KEY_ID not in redact(text, findings)


@pytest.mark.parametrize(
    "value",
    [
        "${DB_PASSWORD}",
        "$DB_PASSWORD",
        "%DB_PASSWORD%",
        "<your-api-key>",
        "{{ secrets.api_key }}",
        "{api_key}",
        "{settings.token}",
        "********",
        "xxxxxxxx",
        "your_api_key_here",
        "changeme",
        "os.environ.get",
        "settings.db_password",
        "get_secret('db')",
        "env[KEY]",
        "user_password",
        "confirmPassword",
    ],
)
def test_placeholders_are_recognised(value: str) -> None:
    rules = load_secret_rules(SECRET_PATTERNS_FILE)
    assert rules.is_placeholder(value)


@pytest.mark.parametrize(
    "value", ["Hunter2024!", "password123", "x9!Kq2@Lm", "S3cr3tP4ss"]
)
def test_real_looking_values_are_not_placeholders(value: str) -> None:
    rules = load_secret_rules(SECRET_PATTERNS_FILE)
    assert not rules.is_placeholder(value)


def test_shannon_entropy() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("abab") == 1.0  # two equally common characters = 1 bit
    assert shannon_entropy("abcd") == 2.0
    assert shannon_entropy(RANDOM_TOKEN) > 4.3  # random letters and digits


@pytest.mark.parametrize(
    "value, kinds",
    [("abc", 1), ("abcDEF", 2), ("abc123", 2), ("aB3", 3), ("aB3!", 4), ("!!!", 1)],
)
def test_character_kinds(value: str, kinds: int) -> None:
    assert character_kinds(value) == kinds


def a_rule(**overrides: object) -> SecretRule:
    values: dict[str, object] = {
        "id": "r",
        "description": "d",
        "secret_type": "TEST_KEY",
        "pattern": r"key=(\S+)",
        "secret_group": 1,
        "confidence": 0.9,
        "severity": "high",
    }
    values.update(overrides)
    return SecretRule.model_validate(values)


def test_disabled_rules_are_not_used() -> None:
    detector = SecretDetector(
        SecretRuleSet(
            version=1,
            entropy=EntropySettings(enabled=False),
            rules=(a_rule(), a_rule(id="off", pattern=r"pin=(\S+)", enabled=False)),
        )
    )
    assert [f.rule_id for f in detector.scan_text("key=abc pin=123")] == ["r"]


def test_require_mixed_chars() -> None:
    detector = SecretDetector(
        SecretRuleSet(
            version=1,
            entropy=EntropySettings(enabled=False),
            rules=(a_rule(require_mixed_chars=True),),
        )
    )
    assert detector.scan_text("key=simple") == []
    assert len(detector.scan_text("key=simple1")) == 1


def test_entropy_check_can_be_turned_off(secret_detector: SecretDetector) -> None:
    quiet = SecretDetector(
        SecretRuleSet(
            version=1, entropy=EntropySettings(enabled=False), rules=(a_rule(),)
        )
    )
    text = f"session {RANDOM_TOKEN}"
    assert [f.entity_type for f in secret_detector.scan_text(text)] == [
        "HIGH_ENTROPY_STRING"
    ]
    assert quiet.scan_text(text) == []


def test_entropy_skips_strings_a_pattern_already_found(
    secret_detector: SecretDetector,
) -> None:
    text = f"Authorization: Bearer {RANDOM_TOKEN}"
    types = [f.entity_type for f in secret_detector.scan_text(text)]
    assert types == ["BEARER_TOKEN"]


@pytest.mark.parametrize(
    "text",
    [
        "3f69f445a0d1004168ad8a86bb490014204898f7",  # git hash: hex, no uppercase
        "ThisIsAVeryLongVariableNameWithoutAnyDigits",  # no digits
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAAAA1111",  # not random enough
        "Short1Token",  # too short
    ],
)
def test_entropy_ignores_non_random_strings(
    secret_detector: SecretDetector, text: str
) -> None:
    assert secret_detector.scan_text(text) == []
