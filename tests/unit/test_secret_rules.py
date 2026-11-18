"""Tests for loading and checking config/secret_patterns.yaml."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from llm_gateway.detectors.base import DetectorConfigError
from llm_gateway.detectors.secrets import SecretConfigError, load_secret_rules
from tests.conftest import SECRET_PATTERNS_FILE


def a_rule(**overrides: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": "test-rule",
        "description": "a test rule",
        "secret_type": "TEST_KEY",
        "pattern": r"key=(\w+)",
        "secret_group": 1,
        "confidence": 0.9,
        "severity": "high",
    }
    rule.update(overrides)
    return rule


def write_rules(tmp_path: Path, data: Any) -> Path:
    path = tmp_path / "secrets.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_the_real_pattern_file_loads() -> None:
    rules = load_secret_rules(SECRET_PATTERNS_FILE)
    assert len(rules.rules) >= 20
    assert rules.entropy.enabled


def test_secret_errors_are_detector_config_errors() -> None:
    assert issubclass(SecretConfigError, DetectorConfigError)


def test_a_small_valid_file_loads(tmp_path: Path) -> None:
    rules = load_secret_rules(
        write_rules(tmp_path, {"version": 1, "rules": [a_rule()]})
    )
    assert rules.rules[0].compiled.search("key=abc").group(1) == "abc"  # type: ignore[union-attr]
    assert rules.entropy.min_length == 24  # default when not given


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SecretConfigError, match="cannot read"):
        load_secret_rules(tmp_path / "nope.yaml")


def test_broken_yaml(tmp_path: Path) -> None:
    path = tmp_path / "secrets.yaml"
    path.write_text("rules: [unclosed", encoding="utf-8")
    with pytest.raises(SecretConfigError, match="not valid YAML"):
        load_secret_rules(path)


def test_top_level_must_be_a_mapping(tmp_path: Path) -> None:
    with pytest.raises(SecretConfigError, match="mapping"):
        load_secret_rules(write_rules(tmp_path, [a_rule()]))


@pytest.mark.parametrize(
    "bad_rule, message",
    [
        (a_rule(pattern="(unclosed"), "invalid regular expression"),
        (a_rule(secret_group=2), "only has 1 group"),
        # Bandit thinks "secret_type=" is a password; it is just the rule's type name
        (a_rule(secret_type="lower_case"), "secret_type"),  # noqa: S106
        (a_rule(confidence=0), "confidence"),
        (a_rule(severity="none"), "cannot be 'none'"),
        (a_rule(id="Bad ID"), "id"),
        ({**a_rule(), "patern": "typo"}, "patern"),
    ],
)
def test_bad_rules_are_rejected(
    tmp_path: Path, bad_rule: dict[str, Any], message: str
) -> None:
    path = write_rules(tmp_path, {"version": 1, "rules": [bad_rule]})
    with pytest.raises(SecretConfigError, match=message):
        load_secret_rules(path)


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    path = write_rules(tmp_path, {"version": 1, "rules": [a_rule(), a_rule()]})
    with pytest.raises(SecretConfigError, match="duplicate rule ids: test-rule"):
        load_secret_rules(path)


def test_all_rules_disabled_is_rejected(tmp_path: Path) -> None:
    path = write_rules(tmp_path, {"version": 1, "rules": [a_rule(enabled=False)]})
    with pytest.raises(SecretConfigError, match="at least one"):
        load_secret_rules(path)


def test_bad_placeholder_pattern_is_rejected(tmp_path: Path) -> None:
    data = {"version": 1, "placeholder_values": ["(oops"], "rules": [a_rule()]}
    with pytest.raises(SecretConfigError, match="placeholder"):
        load_secret_rules(write_rules(tmp_path, data))


@pytest.mark.parametrize(
    "entropy, message",
    [
        ({"min_length": 4}, "min_length"),
        ({"min_entropy": 9}, "min_entropy"),
        ({"surprise": 1}, "surprise"),
    ],
)
def test_bad_entropy_settings_are_rejected(
    tmp_path: Path, entropy: dict[str, Any], message: str
) -> None:
    data = {"version": 1, "entropy": entropy, "rules": [a_rule()]}
    with pytest.raises(SecretConfigError, match=message):
        load_secret_rules(write_rules(tmp_path, data))
