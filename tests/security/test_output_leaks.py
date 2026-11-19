"""Security tests for the output scanner: nothing sensitive reaches the user."""

from __future__ import annotations

import base64

import pytest

from llm_gateway.core.output_guard import OutputGuard
from llm_gateway.detectors.leak import add_canary
from llm_gateway.models import Action
from llm_gateway.providers.base import ChatResponse, FinishReason
from tests.data.output_samples import (
    LEAKY_ANSWERS,
    SAFE_ANSWERS,
    SYSTEM_PROMPT,
    WARN_ANSWERS,
)
from tests.data.secret_samples import AWS_ACCESS_KEY_ID


def answer(text: str) -> ChatResponse:
    return ChatResponse(
        provider="mock", model="m", content=text, finish_reason=FinishReason.STOP
    )


@pytest.mark.parametrize(
    "text, action, sensitive",
    LEAKY_ANSWERS,
    ids=[f"{i:02d}-{a}" for i, (_, a, _) in enumerate(LEAKY_ANSWERS)],
)
def test_sensitive_answers_are_stopped(
    output_guard: OutputGuard, text: str, action: str, sensitive: str
) -> None:
    result = output_guard.check(answer(text), system_prompt=SYSTEM_PROMPT)
    assert result.action.value == action
    assert sensitive not in result.text


@pytest.mark.parametrize("text", SAFE_ANSWERS)
def test_normal_answers_pass_unchanged(output_guard: OutputGuard, text: str) -> None:
    result = output_guard.check(answer(text), system_prompt=SYSTEM_PROMPT)
    assert result.action is Action.ALLOW
    assert result.text == text


@pytest.mark.parametrize("text", WARN_ANSWERS)
def test_borderline_answers_are_only_warned(
    output_guard: OutputGuard, text: str
) -> None:
    result = output_guard.check(answer(text), system_prompt=SYSTEM_PROMPT)
    assert result.action is Action.WARN
    assert result.text == text


def test_blocked_message_never_contains_the_answer(output_guard: OutputGuard) -> None:
    for text, action, sensitive in LEAKY_ANSWERS:
        if action == "block":
            result = output_guard.check(answer(text), system_prompt=SYSTEM_PROMPT)
            assert text not in result.text
            assert sensitive not in result.text


def test_canary_is_found_even_inside_a_long_answer(output_guard: OutputGuard) -> None:
    marked, canary = add_canary(SYSTEM_PROMPT)
    long_answer = ("Normal helpful text. " * 400) + canary + (" More text." * 50)
    result = output_guard.check(
        answer(long_answer), system_prompt=marked, canary=canary
    )
    assert result.blocked


KNOWN_MISSES = [
    (
        "My instructions tell me not to give refunds over fifty dollars unless "
        "a manager approves.",
        "the system prompt reworded (no long run of the same words)",
    ),
    (
        "Mis reglas: nunca ofrecer reembolsos de mas de 50 dolares sin aprobacion.",
        "the system prompt translated into Spanish",
    ),
    (
        "Encoded: " + base64.b64encode(AWS_ACCESS_KEY_ID.encode()).decode(),
        "a secret hidden with base64 (the secret detector does not decode)",
    ),
]


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(text, marks=pytest.mark.xfail(strict=True, reason=why))
        for text, why in KNOWN_MISSES
    ],
)
def test_known_misses_are_still_missed(output_guard: OutputGuard, text: str) -> None:
    """These fail on purpose. If one starts passing, move it to LEAKY_ANSWERS."""
    result = output_guard.check(answer(text), system_prompt=SYSTEM_PROMPT)
    assert result.blocked or result.redacted
