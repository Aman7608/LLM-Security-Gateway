"""The real OpenAI and Anthropic providers, tested OFFLINE.

The official SDKs are given a fake network (httpx2.MockTransport). Every
"request" is recorded and answered with a response we choose, so we can test
the request format, answer parsing, error handling and retries for free,
without an API key and without the internet.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from collections.abc import Callable
from typing import Any

import anthropic
import httpx2
import openai
import pytest

from llm_gateway.providers.anthropic_provider import AnthropicProvider
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
    ProviderResponseError,
    ProviderTimeout,
    ProviderUnavailable,
    RetryPolicy,
)
from llm_gateway.providers.openai_provider import OpenAIProvider

FAKE_KEY = "fake-key-for-tests-9f8e7d"


class FakeNetwork:
    """Answers each request with the next planned reply, and records requests."""

    def __init__(self, *replies: Any) -> None:
        self.replies = list(replies)
        self.requests: list[httpx2.Request] = []

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        status, body = reply
        return httpx2.Response(status, json=body)

    def body(self, index: int = -1) -> dict[str, Any]:
        return json.loads(self.requests[index].content)  # type: ignore[no-any-return]


async def _no_wait(seconds: float) -> None:
    return None


def claude(net: FakeNetwork, **kwargs: Any) -> AnthropicProvider:
    kwargs.setdefault("retry", RetryPolicy(max_retries=0))
    return AnthropicProvider(
        api_key=FAKE_KEY,
        sleep=_no_wait,
        rng=random.Random(1),
        http_client=anthropic.DefaultAsyncHttpxClient(
            transport=httpx2.MockTransport(net.handler)
        ),
        **kwargs,
    )


def gpt(net: FakeNetwork, **kwargs: Any) -> OpenAIProvider:
    kwargs.setdefault("retry", RetryPolicy(max_retries=0))
    return OpenAIProvider(
        api_key=FAKE_KEY,
        default_model="test-model",
        sleep=_no_wait,
        rng=random.Random(1),
        http_client=openai.DefaultAsyncHttpxClient(
            transport=httpx2.MockTransport(net.handler)
        ),
        **kwargs,
    )


def claude_reply(
    text: str = "Hello from Claude", stop_reason: str = "end_turn", **extra: Any
) -> tuple[int, dict[str, Any]]:
    content = [{"type": "thinking", "thinking": "", "signature": "sig"}]
    if text:
        content.append({"type": "text", "text": text})
    return 200, {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5-5",
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 12, "output_tokens": 4},
        **extra,
    }


def gpt_reply(
    text: str | None = "Hello from OpenAI",
    finish: str = "stop",
    refusal: str | None = None,
) -> tuple[int, dict[str, Any]]:
    return 200, {
        "id": "c1",
        "object": "chat.completion",
        "created": 1,
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "finish_reason": finish,
                "message": {"role": "assistant", "content": text, "refusal": refusal},
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13},
    }


def error_reply(status: int) -> tuple[int, dict[str, Any]]:
    # Like some real providers, the error message repeats part of the key
    message = f"Incorrect API key provided: {FAKE_KEY[:12]}...{FAKE_KEY[-4:]}"
    return status, {"type": "error", "error": {"type": "error", "message": message}}


REQUEST = ChatRequest(
    messages=[
        ChatMessage(role="system", content="Be brief."),
        ChatMessage(role="user", content="Hi"),
    ]
)


def run(provider: LLMProvider, request: ChatRequest = REQUEST) -> ChatResponse:
    return asyncio.run(provider.complete(request))


# ---------------------------------------------------------------------------
# Anthropic: request format and answer parsing
# ---------------------------------------------------------------------------


def test_claude_request_format() -> None:
    net = FakeNetwork(claude_reply())
    run(claude(net))
    sent = net.requests[0]
    assert str(sent.url) == "https://api.anthropic.com/v1/messages"
    # The anthropic 2.x SDK sends the key in the Authorization header
    assert FAKE_KEY in sent.headers["authorization"]
    assert sent.headers["anthropic-beta"] == "server-side-fallback-2026-07-01"
    body = net.body()
    assert body["model"] == "claude-opus-5-5"
    assert body["system"] == "Be brief."  # system messages go to the top-level field
    assert body["messages"] == [{"role": "user", "content": "Hi"}]
    assert body["output_config"] == {"effort": "medium"}
    assert body["fallbacks"] == "default"
    assert body["max_tokens"] == 16_000
    assert "temperature" not in body  # current Claude models reject it


def test_claude_answer_is_normalised() -> None:
    result = run(claude(FakeNetwork(claude_reply("Hello from Claude"))))
    assert result.provider == "anthropic"
    assert result.content == "Hello from Claude"  # the thinking block is skipped
    assert result.finish_reason is FinishReason.STOP
    assert (result.usage.input_tokens, result.usage.output_tokens) == (12, 4)
    assert result.model == "claude-opus-5-5"


def test_claude_without_fallbacks_and_custom_effort() -> None:
    net = FakeNetwork(claude_reply())
    run(claude(net, refusal_fallbacks=False, effort="high"))
    assert "anthropic-beta" not in net.requests[0].headers
    assert "fallbacks" not in net.body()
    assert net.body()["output_config"] == {"effort": "high"}


def test_claude_no_system_field_without_system_messages() -> None:
    net = FakeNetwork(claude_reply())
    run(claude(net), ChatRequest(messages=[ChatMessage(role="user", content="Hi")]))
    assert "system" not in net.body()


@pytest.mark.parametrize(
    "stop_reason, finish",
    [
        ("end_turn", FinishReason.STOP),
        ("stop_sequence", FinishReason.STOP),
        ("max_tokens", FinishReason.LENGTH),
        ("tool_use", FinishReason.TOOL_USE),
        ("pause_turn", FinishReason.OTHER),
    ],
)
def test_claude_stop_reasons(stop_reason: str, finish: FinishReason) -> None:
    result = run(claude(FakeNetwork(claude_reply("text", stop_reason))))
    assert result.finish_reason is finish


def test_claude_refusal() -> None:
    reply = claude_reply(
        "",
        "refusal",
        stop_details={"type": "refusal", "category": None, "explanation": None},
    )
    result = run(claude(FakeNetwork(reply)))
    assert result.finish_reason is FinishReason.REFUSAL
    assert result.content == ""


def test_claude_empty_normal_answer_is_an_error() -> None:
    with pytest.raises(ProviderResponseError, match="empty"):
        run(claude(FakeNetwork(claude_reply(""))))


# ---------------------------------------------------------------------------
# OpenAI: request format and answer parsing
# ---------------------------------------------------------------------------


def test_openai_request_format() -> None:
    net = FakeNetwork(gpt_reply())
    run(gpt(net))
    sent = net.requests[0]
    assert str(sent.url) == "https://api.openai.com/v1/chat/completions"
    assert sent.headers["authorization"] == f"Bearer {FAKE_KEY}"
    body = net.body()
    assert body == {
        "model": "test-model",
        "messages": [
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": "Hi"},
        ],
        "max_completion_tokens": 16_000,
    }


def test_openai_answer_is_normalised() -> None:
    result = run(gpt(FakeNetwork(gpt_reply("Hello from OpenAI"))))
    assert result.provider == "openai"
    assert result.content == "Hello from OpenAI"
    assert result.finish_reason is FinishReason.STOP
    assert (result.usage.input_tokens, result.usage.output_tokens) == (10, 3)


@pytest.mark.parametrize(
    "finish, expected",
    [
        ("length", FinishReason.LENGTH),
        ("content_filter", FinishReason.CONTENT_FILTER),
        ("tool_calls", FinishReason.TOOL_USE),
    ],
)
def test_openai_finish_reasons(finish: str, expected: FinishReason) -> None:
    result = run(gpt(FakeNetwork(gpt_reply("x", finish))))
    assert result.finish_reason is expected


def test_openai_refusal() -> None:
    result = run(gpt(FakeNetwork(gpt_reply(None, refusal="I can't help with that."))))
    assert result.finish_reason is FinishReason.REFUSAL
    assert result.content == "I can't help with that."


def test_openai_empty_answer_is_an_error() -> None:
    with pytest.raises(ProviderResponseError, match="empty"):
        run(gpt(FakeNetwork(gpt_reply(""))))


def test_openai_no_choices_is_an_error() -> None:
    status, body = gpt_reply()
    body["choices"] = []
    with pytest.raises(ProviderResponseError, match="unexpected shape"):
        run(gpt(FakeNetwork((status, body))))


# ---------------------------------------------------------------------------
# Errors, retries and secrets (both providers)
# ---------------------------------------------------------------------------

MAKERS = {"anthropic": claude, "openai": gpt}
REPLIES: dict[str, Callable[[], tuple[int, dict[str, Any]]]] = {
    "anthropic": claude_reply,
    "openai": gpt_reply,
}


@pytest.mark.parametrize("name", MAKERS)
@pytest.mark.parametrize(
    "status, error_class",
    [
        (400, ProviderBadRequest),
        (401, ProviderAuthError),
        (403, ProviderAuthError),
        (404, ProviderBadRequest),
        (422, ProviderBadRequest),
        (429, ProviderRateLimited),
        (500, ProviderUnavailable),
        (503, ProviderUnavailable),
        (529, ProviderUnavailable),  # Anthropic "overloaded"
    ],
)
def test_http_errors_become_our_errors(
    name: str, status: int, error_class: type[ProviderError]
) -> None:
    with pytest.raises(error_class) as caught:
        run(MAKERS[name](FakeNetwork(error_reply(status))))
    assert caught.value.status_code == status


@pytest.mark.parametrize("name", MAKERS)
def test_network_timeout(name: str) -> None:
    with pytest.raises(ProviderTimeout):
        run(MAKERS[name](FakeNetwork(httpx2.ReadTimeout("slow"))))


@pytest.mark.parametrize("name", MAKERS)
def test_connection_error(name: str) -> None:
    with pytest.raises(ProviderUnavailable, match="could not connect"):
        run(MAKERS[name](FakeNetwork(httpx2.ConnectError("no route"))))


@pytest.mark.parametrize("name", MAKERS)
def test_retry_through_the_real_sdk(name: str) -> None:
    net = FakeNetwork(error_reply(503), error_reply(429), REPLIES[name]())
    result = run(MAKERS[name](net, retry=RetryPolicy(max_retries=2)))
    assert result.attempts == 3
    assert len(net.requests) == 3  # the SDK's own retries are off


@pytest.mark.parametrize("name", MAKERS)
def test_auth_error_is_not_retried(name: str) -> None:
    net = FakeNetwork(error_reply(401), REPLIES[name]())
    with pytest.raises(ProviderAuthError):
        run(MAKERS[name](net, retry=RetryPolicy(max_retries=2)))
    assert len(net.requests) == 1


@pytest.mark.parametrize("name", MAKERS)
def test_key_never_appears_in_errors_or_logs(
    name: str, caplog: pytest.LogCaptureFixture
) -> None:
    """The fake server echoes part of the key in its error message.
    None of it may reach our error text or our logs."""
    with caplog.at_level(logging.DEBUG), pytest.raises(ProviderAuthError) as caught:
        run(MAKERS[name](FakeNetwork(error_reply(401))))
    for piece in (FAKE_KEY, FAKE_KEY[:12], FAKE_KEY[-4:]):
        assert piece not in str(caught.value)
        assert piece not in repr(caught.value)
        assert piece not in caplog.text
    assert caught.value.__cause__ is None  # the SDK error is not chained on


@pytest.mark.parametrize("name", MAKERS)
def test_repr_never_shows_the_key(name: str) -> None:
    provider = MAKERS[name](FakeNetwork())
    assert FAKE_KEY not in repr(provider)
    assert FAKE_KEY not in str(vars(provider).get("default_model"))


def test_base_url_environment_variables_are_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Someone sets ANTHROPIC_BASE_URL / OPENAI_BASE_URL to steal prompts and keys.
    The providers must still talk to the real addresses."""
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://evil.example")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://evil.example/v1")
    a_net, o_net = FakeNetwork(claude_reply()), FakeNetwork(gpt_reply())
    run(claude(a_net))
    run(gpt(o_net))
    assert a_net.requests[0].url.host == "api.anthropic.com"
    assert o_net.requests[0].url.host == "api.openai.com"
