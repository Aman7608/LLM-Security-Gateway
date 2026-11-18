"""Tests for loading and checking the injection rule file."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from llm_gateway.detectors.injection import RuleConfigError, load_rules
from tests.conftest import INJECTION_RULES_FILE


def a_rule(**overrides: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": "test-rule",
        "category": "instruction_override",
        "description": "a test rule",
        "confidence": 0.8,
        "severity": "high",
        "pattern": r"\bevil\b",
    }
    rule.update(overrides)
    return rule


def write_rules(tmp_path: Path, data: Any) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_the_real_rule_file_loads() -> None:
    rules = load_rules(INJECTION_RULES_FILE)
    assert len(rules.regex_rules) >= 30
    assert len(rules.compact_phrases) >= 5


def test_a_small_valid_file_loads(tmp_path: Path) -> None:
    path = write_rules(tmp_path, {"version": 1, "regex_rules": [a_rule()]})
    rules = load_rules(path)
    assert rules.regex_rules[0].compiled.search("an evil plan")


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(RuleConfigError, match="cannot read"):
        load_rules(tmp_path / "nope.yaml")


def test_broken_yaml(tmp_path: Path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text("version: 1\nregex_rules: [unclosed", encoding="utf-8")
    with pytest.raises(RuleConfigError, match="not valid YAML"):
        load_rules(path)


def test_top_level_must_be_a_mapping(tmp_path: Path) -> None:
    path = write_rules(tmp_path, [a_rule()])
    with pytest.raises(RuleConfigError, match="mapping"):
        load_rules(path)


@pytest.mark.parametrize(
    "bad_rule, message",
    [
        (a_rule(pattern="(unclosed"), "invalid regular expression"),
        (a_rule(confidence=0), "confidence"),
        (a_rule(confidence=1.5), "confidence"),
        (a_rule(category="made_up"), "category"),
        (a_rule(severity="none"), "cannot be 'none'"),
        (a_rule(id="Bad ID"), "id"),
        (a_rule(description=""), "description"),
        ({**a_rule(), "patern": "typo"}, "patern"),  # unknown field
    ],
)
def test_bad_rules_are_rejected(
    tmp_path: Path, bad_rule: dict[str, Any], message: str
) -> None:
    path = write_rules(tmp_path, {"version": 1, "regex_rules": [bad_rule]})
    with pytest.raises(RuleConfigError, match=message):
        load_rules(path)


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    path = write_rules(tmp_path, {"version": 1, "regex_rules": [a_rule(), a_rule()]})
    with pytest.raises(RuleConfigError, match="duplicate rule ids: test-rule"):
        load_rules(path)


def test_all_rules_disabled_is_rejected(tmp_path: Path) -> None:
    path = write_rules(tmp_path, {"version": 1, "regex_rules": [a_rule(enabled=False)]})
    with pytest.raises(RuleConfigError, match="at least one"):
        load_rules(path)


def test_unknown_version_is_rejected(tmp_path: Path) -> None:
    path = write_rules(tmp_path, {"version": 2, "regex_rules": [a_rule()]})
    with pytest.raises(RuleConfigError, match="version"):
        load_rules(path)


@pytest.mark.parametrize("phrase", ["has space", "short", "UPPER-case"])
def test_bad_compact_phrases_are_rejected(tmp_path: Path, phrase: str) -> None:
    phrase_rule = {k: v for k, v in a_rule(id="p").items() if k != "pattern"}
    phrase_rule["phrase"] = phrase
    path = write_rules(
        tmp_path,
        {"version": 1, "regex_rules": [a_rule()], "compact_phrases": [phrase_rule]},
    )
    with pytest.raises(RuleConfigError, match="phrase"):
        load_rules(path)
