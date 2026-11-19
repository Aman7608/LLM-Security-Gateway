"""The shared shape of every AI provider (mock, OpenAI, Anthropic Claude).

Each provider only has to write ONE method, `_complete_once()`, that sends one
request and turns the answer into our own ChatResponse. Everything that must
work the same for every provider lives here, in `complete()`:

  - a time limit for each attempt (timeout)
  - retrying temporary errors, waiting a little longer each time
    (exponential backoff with random "jitter")
  - turning every provider's errors into our own error classes

The SDKs' own automatic retries are switched OFF (max_retries=0), so all
providers retry in exactly the same, tested way, and every attempt is counted.

Security rule: our error messages never contain the provider's raw error text.
Some providers repeat part of the API key in their error messages, and error
messages end up in logs.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

logger = logging.getLogger(__name__)

# Largest prompt the providers accept, as a last safety net. The DLP engine
# (and later the API) already limits prompts to GATEWAY_MAX_PROMPT_CHARS.
MAX_MESSAGE_CHARS = 200_000


# ---------------------------------------------------------------------------
# Requests and responses (the same shape for every provider)
# ---------------------------------------------------------------------------


class ChatMessage(BaseModel):
    """One message in a conversation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: str = Field(max_length=MAX_MESSAGE_CHARS)


class ChatRequest(BaseModel):
    """What the gateway asks the AI. Only these fields can be sent."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    messages: tuple[ChatMessage, ...] = Field(min_length=1)
    model: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:\-]{1,100}$")
    max_tokens: int = Field(default=16_000, ge=1, le=32_000)

    @model_validator(mode="after")
    def needs_a_user_message(self) -> ChatRequest:
        if not any(m.role == "user" for m in self.messages):
            raise ValueError("at least one message must come from the user")
        if self.messages[-1].role != "user":
            raise ValueError("the last message must come from the user")
        conversation = [m for m in self.messages if m.role != "system"]
        if conversation[0].role != "user":
            # Claude requires this, so every provider follows the same rule
            raise ValueError("the first non-system message must come from the user")
        return self


class FinishReason(StrEnum):
    """Why the AI stopped, in the same words for every provider."""

    STOP = "stop"  # finished normally
    LENGTH = "length"  # hit max_tokens: the answer is cut off
    CONTENT_FILTER = "content_filter"  # the provider's own filter stopped it
    REFUSAL = "refusal"  # the model declined to answer
    TOOL_USE = "tool_use"  # wants to call a tool (we do not use tools)
    OTHER = "other"


class Usage(BaseModel):
    model_config = ConfigDict(frozen=True)

    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)


class ChatResponse(BaseModel):
    """The AI's answer, in the same shape for every provider."""

    model_config = ConfigDict(frozen=True)

    provider: str
    model: str
    content: str
    finish_reason: FinishReason
    usage: Usage = Usage()
    latency_ms: float = Field(default=0.0, ge=0.0)
    attempts: int = Field(default=1, ge=1)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ProviderError(Exception):
    """Something went wrong talking to an AI provider.

    `retryable` says whether trying again might help. The message is always
    written by us, never copied from the provider.
    """

    retryable = False

    def __init__(self, provider: str, message: str, status_code: int | None = None):
        super().__init__(f"{provider}: {message}")
        self.provider = provider
        self.status_code = status_code


class ProviderTimeout(ProviderError):
    retryable = True


class ProviderRateLimited(ProviderError):
    retryable = True


class ProviderUnavailable(ProviderError):
    """Server errors (5xx), overload and network problems."""

    retryable = True


class ProviderAuthError(ProviderError):
    """Wrong or missing API key, or no permission. Retrying cannot help."""


class ProviderBadRequest(ProviderError):
    """The provider rejected the request (bad model name, too long, ...)."""


class ProviderResponseError(ProviderError):
    """The provider answered, but with something we could not use."""


class ProviderNotConfigured(ProviderError):
    """This provider is not set up (no API key, no model, package missing)."""


# ---------------------------------------------------------------------------
# Retries
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RetryPolicy:
    """How many times to retry, and how long to wait between tries."""

    max_retries: int = 2
    base_delay: float = 0.5  # seconds before the first retry
    max_delay: float = 8.0  # never wait longer than this

    def delay(self, retry_number: int, rng: random.Random | None = None) -> float:
        """Exponential backoff with "full jitter".

        The longest possible wait doubles each time (0.5s, 1s, 2s, ...), and
        the real wait is a random time between 0 and that. The randomness
        stops many gateways from all retrying at the very same moment.
        """
        ceiling = min(self.max_delay, self.base_delay * (2 ** (retry_number - 1)))
        return (rng or random).uniform(0, ceiling)  # noqa: S311 - timing, not security


Sleep = Callable[[float], Awaitable[None]]


class LLMProvider(ABC):
    """Base class for every AI provider."""

    #: Short name used in settings, logs and responses, e.g. "mock".
    name: str = "provider"

    def __init__(
        self,
        default_model: str,
        timeout_seconds: float = 30.0,
        retry: RetryPolicy | None = None,
        sleep: Sleep = asyncio.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self.default_model = default_model
        self.timeout_seconds = timeout_seconds
        self.retry = retry or RetryPolicy()
        self._sleep = sleep  # tests pass a fake sleep, so they never really wait
        self._rng = rng

    def __repr__(self) -> str:
        # Never show anything secret here; repr() ends up in logs and errors.
        return f"{type(self).__name__}(model={self.default_model!r})"

    @abstractmethod
    async def _complete_once(self, request: ChatRequest, model: str) -> ChatResponse:
        """Send ONE request and return the answer. Raise ProviderError on failure."""

    async def complete(self, request: ChatRequest) -> ChatResponse:
        """Ask the AI, with a time limit per attempt and retries on temporary errors."""
        model = request.model or self.default_model
        started = time.perf_counter()
        attempt = 0
        while True:
            attempt += 1
            try:
                response = await asyncio.wait_for(
                    self._complete_once(request, model), timeout=self.timeout_seconds
                )
            except TimeoutError:
                error: ProviderError = ProviderTimeout(
                    self.name, f"no answer within {self.timeout_seconds:g} seconds"
                )
            except ProviderError as provider_error:
                error = provider_error
            else:
                return response.model_copy(
                    update={
                        "attempts": attempt,
                        "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                    }
                )

            if not error.retryable or attempt > self.retry.max_retries:
                logger.warning(
                    "provider %s gave up after %d attempt(s): %s (status %s)",
                    self.name,
                    attempt,
                    type(error).__name__,
                    error.status_code,
                )
                raise error
            wait = self.retry.delay(attempt, self._rng)
            logger.info(
                "provider %s: %s on attempt %d, retrying in %.2fs",
                self.name,
                type(error).__name__,
                attempt,
                wait,
            )
            await self._sleep(wait)
