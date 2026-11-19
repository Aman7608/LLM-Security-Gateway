"""Tests for the offline mock provider and its test tags."""

from __future__ import annotations

import asyncio

import pytest

from llm_gateway.providers.base import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    FinishReason,
    ProviderAuthError,
    ProviderBadRequest,
    ProviderError,
    ProviderRateLimited,
    ProviderTimeout,
    ProviderUnavailable,
    RetryPolicy,
)
from llm_gateway.providers.mock import MOCK_MODEL, MockProvider, fake_aws_key


def ask(text: str, provider: MockProvider | None = None) -> ChatResponse:
    request = ChatRequest(messages=[ChatMessage(role="user", content=text)])
    return asyncio.run((provider or MockProvider()).complete(request))


def test_echoes_the_prompt() -> None:
    result = ask("Hello <EMAIL_ADDRESS>")
    assert result.content == "Mock answer. You said: Hello <EMAIL_ADDRESS>"
    assert result.provider == "mock"
    assert result.model == MOCK_MODEL
    assert result.finish_reason is FinishReason.STOP
    assert result.usage.input_tokens == 2


def test_leak_secret_tag() -> None:
    assert fake_aws_key() in ask("[mock:leak-secret]").content


def test_fake_key_has_the_aws_shape_and_is_stable() -> None:
    key = fake_aws_key()
    assert key.startswith("AK" + "IA") and len(key) == 20
    assert key == fake_aws_key()


def test_leak_pii_tag() -> None:
    content = ask("[mock:leak-pii]").content
    assert "priya@example.com" in content and "4111 1111 1111 1111" in content


def test_injection_tag() -> None:
    assert "Ignore all previous instructions" in ask("[mock:injection]").content


def test_refusal_tag() -> None:
    result = ask("[mock:refusal]")
    assert result.finish_reason is FinishReason.REFUSAL
    assert result.content == ""


@pytest.mark.parametrize(
    "kind, error_class",
    [
        ("timeout", ProviderTimeout),
        ("rate_limit", ProviderRateLimited),
        ("server", ProviderUnavailable),
        ("auth", ProviderAuthError),
        ("bad_request", ProviderBadRequest),
    ],
)
def test_error_tags(kind: str, error_class: type[ProviderError]) -> None:
    no_retries = MockProvider(retry=RetryPolicy(max_retries=0))
    with pytest.raises(error_class):
        ask(f"[mock:error:{kind}]", no_retries)


def test_slow_tag_can_trigger_a_timeout() -> None:
    quick = MockProvider(timeout_seconds=0.05, retry=RetryPolicy(max_retries=0))
    with pytest.raises(ProviderTimeout):
        ask("[mock:slow:1]", quick)


def test_only_the_last_message_is_read() -> None:
    request = ChatRequest(
        messages=[
            ChatMessage(role="user", content="[mock:leak-secret]"),
            ChatMessage(role="assistant", content="ok"),
            ChatMessage(role="user", content="normal question"),
        ]
    )
    result = asyncio.run(MockProvider().complete(request))
    assert result.content == "Mock answer. You said: normal question"
