"""Tests for llm_gateway.providers.base: requests, retries and timeouts.

A small fake provider plays back a list of results (errors or answers), and a
fake sleep records the waits instead of really waiting, so these tests run
instantly.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any

import pytest
from pydantic import ValidationError

from llm_gateway.providers.base import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    FinishReason,
    LLMProvider,
    ProviderAuthError,
    ProviderBadRequest,
    ProviderError,
    ProviderRateLimited,
    ProviderTimeout,
    ProviderUnavailable,
    RetryPolicy,
)


def request(text: str = "Hi") -> ChatRequest:
    return ChatRequest(messages=[ChatMessage(role="user", content=text)])


def answer(text: str = "ok") -> ChatResponse:
    return ChatResponse(
        provider="fake", model="fake-1", content=text, finish_reason=FinishReason.STOP
    )


class Script(LLMProvider):
    """Plays back results in order. A ProviderError is raised, a response returned."""

    name = "fake"

    def __init__(self, results: list[Any], max_retries: int = 2, **kwargs: Any) -> None:
        self.waits: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            self.waits.append(seconds)

        super().__init__(
            "fake-1",
            retry=RetryPolicy(max_retries=max_retries),
            sleep=fake_sleep,
            rng=random.Random(1),
            **kwargs,
        )
        self.results = list(results)
        self.calls = 0

    async def _complete_once(self, request: ChatRequest, model: str) -> ChatResponse:
        self.calls += 1
        result = self.results.pop(0)
        if isinstance(result, ProviderError):
            raise result
        if result == "hang":
            await asyncio.sleep(10)
        return result  # type: ignore[no-any-return]


def run(provider: LLMProvider, req: ChatRequest | None = None) -> ChatResponse:
    return asyncio.run(provider.complete(req or request()))


# ---------- ChatRequest ----------


def test_valid_request_defaults() -> None:
    req = request()
    assert req.max_tokens == 16_000
    assert req.model is None


@pytest.mark.parametrize(
    "messages, message",
    [
        ([], "at least 1"),
        ([{"role": "system", "content": "x"}], "from the user"),
        (
            [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}],
            "last message",
        ),
        (
            [{"role": "assistant", "content": "a"}, {"role": "user", "content": "b"}],
            "first non-system",
        ),
        ([{"role": "tool", "content": "x"}], "role"),
    ],
)
def test_bad_requests_are_rejected(
    messages: list[dict[str, str]], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        ChatRequest.model_validate({"messages": messages})


def test_system_message_first_is_fine() -> None:
    ChatRequest.model_validate(
        {
            "messages": [
                {"role": "system", "content": "Be brief."},
                {"role": "user", "content": "Hi"},
            ]
        }
    )


@pytest.mark.parametrize("model", ["bad model", "../x", "a" * 101, "x;rm"])
def test_strange_model_names_are_rejected(model: str) -> None:
    with pytest.raises(ValidationError):
        ChatRequest(messages=[ChatMessage(role="user", content="hi")], model=model)


@pytest.mark.parametrize("max_tokens", [0, 32_001])
def test_max_tokens_limits(max_tokens: int) -> None:
    with pytest.raises(ValidationError):
        ChatRequest(
            messages=[ChatMessage(role="user", content="hi")], max_tokens=max_tokens
        )


def test_unknown_fields_are_rejected() -> None:
    """Only fields we control can reach a provider (no 'temperature' sneaking in)."""
    with pytest.raises(ValidationError, match="temperature"):
        ChatRequest.model_validate(
            {"messages": [{"role": "user", "content": "hi"}], "temperature": 2}
        )


# ---------- RetryPolicy ----------


def test_delays_grow_but_stay_under_the_cap() -> None:
    policy = RetryPolicy(base_delay=0.5, max_delay=4.0)
    rng = random.Random(7)
    for retry_number, ceiling in [(1, 0.5), (2, 1.0), (3, 2.0), (4, 4.0), (10, 4.0)]:
        for _ in range(50):
            assert 0 <= policy.delay(retry_number, rng) <= ceiling


# ---------- complete(): retries ----------


def test_success_on_the_first_try() -> None:
    provider = Script([answer("hello")])
    result = run(provider)
    assert result.content == "hello"
    assert result.attempts == 1
    assert provider.waits == []
    assert result.latency_ms >= 0


@pytest.mark.parametrize(
    "error",
    [
        ProviderTimeout("fake", "slow"),
        ProviderRateLimited("fake", "busy", 429),
        ProviderUnavailable("fake", "down", 503),
    ],
)
def test_temporary_errors_are_retried(error: ProviderError) -> None:
    provider = Script([error, answer()])
    result = run(provider)
    assert result.attempts == 2
    assert len(provider.waits) == 1


@pytest.mark.parametrize(
    "error",
    [ProviderAuthError("fake", "bad key", 401), ProviderBadRequest("fake", "bad", 400)],
)
def test_permanent_errors_are_not_retried(error: ProviderError) -> None:
    provider = Script([error, answer()])
    with pytest.raises(type(error)):
        run(provider)
    assert provider.calls == 1


def test_gives_up_after_max_retries() -> None:
    errors = [ProviderUnavailable("fake", "down", 503) for _ in range(5)]
    provider = Script(errors, max_retries=2)
    with pytest.raises(ProviderUnavailable):
        run(provider)
    assert provider.calls == 3  # the first try + 2 retries
    assert len(provider.waits) == 2


def test_zero_retries_means_one_try() -> None:
    provider = Script([ProviderUnavailable("fake", "down"), answer()], max_retries=0)
    with pytest.raises(ProviderUnavailable):
        run(provider)
    assert provider.calls == 1


def test_slow_answer_times_out_and_is_retried() -> None:
    provider = Script(["hang", answer()], timeout_seconds=0.05)
    result = run(provider)
    assert result.attempts == 2


def test_timeout_error_message_says_how_long() -> None:
    provider = Script(["hang"], max_retries=0, timeout_seconds=0.05)
    with pytest.raises(ProviderTimeout, match="0.05 seconds"):
        run(provider)


def test_request_model_overrides_the_default() -> None:
    seen: list[str] = []

    class Recorder(Script):
        async def _complete_once(
            self, request: ChatRequest, model: str
        ) -> ChatResponse:
            seen.append(model)
            return answer()

    run(
        Recorder([]),
        ChatRequest(messages=[ChatMessage(role="user", content="x")], model="m2"),
    )
    run(Recorder([]))
    assert seen == ["m2", "fake-1"]


def test_errors_say_which_provider_and_whether_to_retry() -> None:
    error = ProviderRateLimited("openai", "too many requests", 429)
    assert str(error) == "openai: too many requests"
    assert error.retryable and error.status_code == 429
    assert not ProviderAuthError("x", "y").retryable


def test_repr_shows_no_secrets() -> None:
    assert repr(Script([])) == "Script(model='fake-1')"
