"""Tests for llm_gateway.detectors.leak: canaries and system prompt overlap."""

from __future__ import annotations

import re

import pytest

from llm_gateway.detectors.leak import (
    add_canary,
    find_system_prompt_leak,
    make_canary,
)
from llm_gateway.detectors.secrets import SecretDetector
from llm_gateway.models import RiskLevel

PROMPT = (
    "You are SupportBot. Never offer refunds above 50 dollars without "
    "manager approval. Keep every answer under 100 words."
)


def test_canaries_look_right_and_are_unique() -> None:
    canaries = {make_canary() for _ in range(200)}
    assert len(canaries) == 200
    assert all(re.fullmatch(r"canary-[0-9a-f]{16}", c) for c in canaries)


def test_canary_is_not_mistaken_for_a_secret(secret_detector: SecretDetector) -> None:
    assert secret_detector.scan_text(f"marker {make_canary()}") == []


def test_add_canary_keeps_the_prompt() -> None:
    marked, canary = add_canary(PROMPT)
    assert marked.startswith(PROMPT)
    assert canary in marked


def test_canary_in_the_answer_is_found() -> None:
    _, canary = add_canary(PROMPT)
    answer = f"OK. Hidden marker: {canary.upper()}!"  # case does not matter
    (finding,) = find_system_prompt_leak(answer, canary=canary)
    assert finding.entity_type == "CANARY"
    assert finding.confidence == 1.0
    assert finding.severity is RiskLevel.CRITICAL
    assert finding.detector == "leak" and finding.category == "system_prompt_leak"
    assert answer[finding.start : finding.end] == canary.upper()


def test_a_different_canary_is_not_found() -> None:
    assert find_system_prompt_leak(f"x {make_canary()}", canary=make_canary()) == []


def test_bad_canary_value_is_rejected() -> None:
    with pytest.raises(ValueError, match="canary"):
        find_system_prompt_leak("text", canary=".*")


def test_copied_words_are_found() -> None:
    answer = "Sure. never offer REFUNDS above 50 dollars, without manager approval!"
    (finding,) = find_system_prompt_leak(answer, system_prompt=PROMPT)
    assert finding.entity_type == "SYSTEM_PROMPT_TEXT"
    assert finding.rule_id == "leak-prompt-overlap"
    # The whole copied run, from the first to the last copied word
    assert answer[finding.start : finding.end] == (
        "never offer REFUNDS above 50 dollars, without manager approval"
    )


def test_two_separate_copies_give_two_findings() -> None:
    answer = (
        "First: never offer refunds above 50 dollars without manager. "
        "Unrelated words here. Then: keep every answer under 100 words please"
    )
    findings = find_system_prompt_leak(answer, system_prompt=PROMPT, min_words=6)
    assert len(findings) == 2


def test_fewer_words_than_the_minimum_are_fine() -> None:
    answer = "We never offer refunds above a limit."  # 4 copied words in a row
    assert find_system_prompt_leak(answer, system_prompt=PROMPT) == []


def test_short_system_prompts_are_not_checked() -> None:
    assert (
        find_system_prompt_leak("You are a helpful assistant.", "You are helpful.")
        == []
    )


def test_words_in_a_different_order_are_fine() -> None:
    answer = "approval manager without dollars 50 above refunds offer never"
    assert find_system_prompt_leak(answer, system_prompt=PROMPT) == []


def test_minimum_words_must_be_sensible() -> None:
    with pytest.raises(ValueError, match="at least 3"):
        find_system_prompt_leak("a b", "a b", min_words=2)


def test_nothing_to_compare() -> None:
    assert find_system_prompt_leak("any answer") == []
