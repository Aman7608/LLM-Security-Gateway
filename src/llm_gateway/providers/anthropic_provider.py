"""Anthropic Claude provider, using the official `anthropic` Python SDK.

Optional: only used when GATEWAY_ANTHROPIC_API_KEY is set, and the package
is installed (requirements-providers.txt).

Claude-specific choices (from the official API reference):
  - The default model is claude-opus-5-5. On this model thinking is always
    on; how much it thinks is set with "effort" (low ... max, default medium).
  - We never send `temperature`: current Claude models reject it.
  - Server-side refusal fallbacks are ON by default: if the model declines a
    request for safety reasons, the API retries it on another Claude model
    inside the same call. Turn it off with GATEWAY_ANTHROPIC_REFUSAL_FALLBACKS=false
    (for example, for a model that does not support it).
  - Only the answer's `text` blocks are returned. Thinking blocks and
    fallback markers are skipped.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any, Literal

from llm_gateway.providers.base import (
    ChatRequest,
    ChatResponse,
    FinishReason,
    LLMProvider,
    ProviderAuthError,
    ProviderBadRequest,
    ProviderError,
    ProviderNotConfigured,
    ProviderRateLimited,
    ProviderResponseError,
    ProviderTimeout,
    ProviderUnavailable,
    RetryPolicy,
    Sleep,
    Usage,
)

logger = logging.getLogger(__name__)

ANTHROPIC_BASE_URL = "https://api.anthropic.com"  # fixed on purpose (see below)
DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"

Effort = Literal["low", "medium", "high", "xhigh", "max"]

_FINISH = {
    "end_turn": FinishReason.STOP,
    "stop_sequence": FinishReason.STOP,
    "max_tokens": FinishReason.LENGTH,
    "refusal": FinishReason.REFUSAL,
    "tool_use": FinishReason.TOOL_USE,
}


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(
        self,
        api_key: str,
        default_model: str = DEFAULT_MODEL,
        effort: Effort = "medium",
        refusal_fallbacks: bool = True,
        timeout_seconds: float = 120.0,
        retry: RetryPolicy | None = None,
        sleep: Sleep = asyncio.sleep,
        rng: random.Random | None = None,
        http_client: Any = None,
    ) -> None:
        try:
            import anthropic
        except ImportError as error:
            raise ProviderNotConfigured(
                self.name,
                "the 'anthropic' package is not installed. "
                "Run: pip install -r requirements-providers.txt",
            ) from error
        if not api_key:
            raise ProviderNotConfigured(
                self.name, "GATEWAY_ANTHROPIC_API_KEY is not set"
            )

        super().__init__(default_model, timeout_seconds, retry, sleep, rng)
        self._sdk = anthropic
        self.effort = effort
        self.refusal_fallbacks = refusal_fallbacks
        # base_url is set explicitly so the ANTHROPIC_BASE_URL environment
        # variable cannot quietly send our prompts (and key) somewhere else.
        # max_retries=0: the base class does the retrying for every provider.
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key,
            base_url=ANTHROPIC_BASE_URL,
            timeout=timeout_seconds,
            max_retries=0,
            http_client=http_client,
        )

    async def _complete_once(self, request: ChatRequest, model: str) -> ChatResponse:
        system = "\n\n".join(m.content for m in request.messages if m.role == "system")
        messages = [
            {"role": m.role, "content": m.content}
            for m in request.messages
            if m.role != "system"
        ]
        arguments: dict[str, Any] = {
            "model": model,
            "max_tokens": request.max_tokens,
            "messages": messages,
            "output_config": {"effort": self.effort},
        }
        if system:
            arguments["system"] = system
        if self.refusal_fallbacks:
            arguments["betas"] = [FALLBACK_BETA]
            arguments["fallbacks"] = "default"

        try:
            message = await self._client.beta.messages.create(**arguments)
        except self._sdk.APIError as error:
            raise self._translate(error) from None

        try:
            text = "".join(b.text for b in message.content if b.type == "text")
            finish = _FINISH.get(str(message.stop_reason), FinishReason.OTHER)
            usage = Usage(
                input_tokens=message.usage.input_tokens or 0,
                output_tokens=message.usage.output_tokens or 0,
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise ProviderResponseError(
                self.name, "the answer had an unexpected shape"
            ) from error

        if not text and finish is FinishReason.STOP:
            raise ProviderResponseError(self.name, "the answer was empty")
        return ChatResponse(
            provider=self.name,
            model=str(message.model),
            content=text,
            finish_reason=finish,
            usage=usage,
        )

    def _translate(self, error: Exception) -> ProviderError:
        """Turn an SDK error into ours. Never copies the SDK's message."""
        sdk = self._sdk
        status = getattr(error, "status_code", None)
        logger.warning(
            "anthropic request failed: %s (status %s, request id %s)",
            type(error).__name__,
            status,
            getattr(error, "request_id", None),
        )
        if isinstance(error, sdk.APITimeoutError):  # check before connection errors
            return ProviderTimeout(self.name, "the request timed out")
        if isinstance(error, sdk.APIConnectionError):
            return ProviderUnavailable(self.name, "could not connect to the provider")
        if isinstance(error, sdk.AuthenticationError | sdk.PermissionDeniedError):
            return ProviderAuthError(self.name, "the API key was rejected", status)
        if isinstance(error, sdk.RateLimitError):
            return ProviderRateLimited(self.name, "too many requests", status)
        if isinstance(error, sdk.APIStatusError) and status is not None:
            if status >= 500 or status in (408, 409):
                return ProviderUnavailable(
                    self.name, "the provider had an error", status
                )
            return ProviderBadRequest(
                self.name, "the request was rejected (check the model name)", status
            )
        return ProviderUnavailable(self.name, "unexpected provider error")
