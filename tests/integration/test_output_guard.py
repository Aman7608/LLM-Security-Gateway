"""The output scanner with the real detectors, the default policy and the mock AI."""

from __future__ import annotations

import asyncio

from llm_gateway.core.output_guard import DEFAULT_BLOCKED_MESSAGE, OutputGuard
from llm_gateway.detectors.leak import add_canary
from llm_gateway.models import Action
from llm_gateway.providers.base import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    FinishReason,
)
from llm_gateway.providers.mock import MockProvider, fake_aws_key
from tests.data.output_samples import SYSTEM_PROMPT


def answer(text: str, finish: FinishReason = FinishReason.STOP) -> ChatResponse:
    return ChatResponse(provider="mock", model="m", content=text, finish_reason=finish)


def ask_mock(prompt: str) -> ChatResponse:
    request = ChatRequest(messages=[ChatMessage(role="user", content=prompt)])
    return asyncio.run(MockProvider().complete(request))


def test_normal_answer_passes(output_guard: OutputGuard) -> None:
    result = output_guard.check(answer("Our return window is 30 days."))
    assert result.text == "Our return window is 30 days."
    assert not result.blocked and not result.redacted
    assert result.action is Action.ALLOW


def test_leaked_secret_is_withheld(output_guard: OutputGuard) -> None:
    result = output_guard.check(ask_mock("[mock:leak-secret]"))
    assert result.blocked
    assert result.text == DEFAULT_BLOCKED_MESSAGE
    assert fake_aws_key() not in result.text


def test_request_id_is_added_to_the_blocked_message(output_guard: OutputGuard) -> None:
    result = output_guard.check(ask_mock("[mock:leak-secret]"), request_id="req-42")
    assert result.text == DEFAULT_BLOCKED_MESSAGE + " Reference: req-42"


def test_leaked_personal_data_is_hidden(output_guard: OutputGuard) -> None:
    result = output_guard.check(ask_mock("[mock:leak-pii]"))
    assert result.redacted and not result.blocked
    assert result.text == "The customer is <EMAIL_ADDRESS>, card <CREDIT_CARD>."


def test_attack_text_only_warns(output_guard: OutputGuard) -> None:
    result = output_guard.check(ask_mock("[mock:injection]"))
    assert result.action is Action.WARN
    assert result.warnings


def test_system_prompt_copy_is_withheld(output_guard: OutputGuard) -> None:
    copied = "Sure: never offer refunds above 50 dollars without manager approval."
    result = output_guard.check(answer(copied), system_prompt=SYSTEM_PROMPT)
    assert result.blocked
    assert "out-block-system-prompt-leak" in result.result.decision.matched_rules


def test_same_answer_passes_without_the_system_prompt(
    output_guard: OutputGuard,
) -> None:
    """The overlap check needs THIS request's system prompt to compare with."""
    copied = "Sure: never offer refunds above 50 dollars without manager approval."
    assert not output_guard.check(answer(copied)).blocked


def test_canary_leak_is_withheld(output_guard: OutputGuard) -> None:
    marked, canary = add_canary(SYSTEM_PROMPT)
    result = output_guard.check(
        answer(f"My marker is {canary}"), system_prompt=marked, canary=canary
    )
    assert result.blocked
    assert result.result.decision.risk_level.value == "critical"


def test_confidential_term_is_hidden(output_guard: OutputGuard) -> None:
    result = output_guard.check(answer("Project Nightingale closes next week."))
    assert result.text == "<CONFIDENTIAL_TERM> closes next week."


def test_refusal_passes_through(output_guard: OutputGuard) -> None:
    result = output_guard.check(ask_mock("[mock:refusal]"))
    assert not result.blocked
    assert result.text == ""
    assert result.finish_reason is FinishReason.REFUSAL


def test_cut_off_answer_keeps_its_finish_reason(output_guard: OutputGuard) -> None:
    result = output_guard.check(answer("The answer was cut", FinishReason.LENGTH))
    assert result.finish_reason is FinishReason.LENGTH


def test_custom_blocked_message(output_guard: OutputGuard) -> None:
    guard = OutputGuard(output_guard.engine, blocked_message="Not available.")
    assert guard.check(ask_mock("[mock:leak-secret]")).text == "Not available."
