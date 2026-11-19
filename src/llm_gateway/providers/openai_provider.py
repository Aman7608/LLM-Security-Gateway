"""OpenAI provider, using the official `openai` Python SDK (chat completions).

Optional: only used when BOTH GATEWAY_OPENAI_API_KEY and GATEWAY_OPENAI_MODEL
are set, and the package is installed (requirements-providers.txt).

There is no default OpenAI model on purpose: model names change often, and a
hard-coded name could stop working. You choose the model in the settings.

We do not send `temperature`, because some current OpenAI models reject it.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any

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

OPENAI_BASE_URL = "https://api.openai.com/v1"  # fixed on purpose (see below)

_FINISH = {
    "stop": FinishReason.STOP,
    "length": FinishReason.LENGTH,
    "content_filter": FinishReason.CONTENT_FILTER,
    "tool_calls": FinishReason.TOOL_USE,
    "function_call": FinishReason.TOOL_USE,
}


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(
        self,
        api_key: str,
        default_model: str,
        timeout_seconds: float = 120.0,
        retry: RetryPolicy | None = None,
        sleep: Sleep = asyncio.sleep,
        rng: random.Random | None = None,
        http_client: Any = None,
    ) -> None:
        try:
            import openai
        except ImportError as error:
            raise ProviderNotConfigured(
                self.name,
                "the 'openai' package is not installed. "
                "Run: pip install -r requirements-providers.txt",
            ) from error
        if not api_key:
            raise ProviderNotConfigured(self.name, "GATEWAY_OPENAI_API_KEY is not set")
        if not default_model:
            raise ProviderNotConfigured(self.name, "GATEWAY_OPENAI_MODEL is not set")

        super().__init__(default_model, timeout_seconds, retry, sleep, rng)
        self._sdk = openai
        # base_url is set explicitly so the OPENAI_BASE_URL environment variable
        # cannot quietly send our prompts (and key) somewhere else.
        # max_retries=0: the base class does the retrying for every provider.
        self._client = openai.AsyncOpenAI(
            api_key=api_key,
            base_url=OPENAI_BASE_URL,
            timeout=timeout_seconds,
            max_retries=0,
            http_client=http_client,
        )

    async def _complete_once(self, request: ChatRequest, model: str) -> ChatResponse:
        messages: Any = [
            {"role": m.role, "content": m.content} for m in request.messages
        ]
        try:
            completion = await self._client.chat.completions.create(
                model=model,
                messages=messages,
                max_completion_tokens=request.max_tokens,
            )
        except self._sdk.APIError as error:
            raise self._translate(error) from None

        try:
            choice = completion.choices[0]
            refusal = choice.message.refusal
            if refusal:
                content, finish = refusal, FinishReason.REFUSAL
            else:
                content = choice.message.content or ""
                finish = _FINISH.get(str(choice.finish_reason), FinishReason.OTHER)
            usage = Usage(
                input_tokens=completion.usage.prompt_tokens if completion.usage else 0,
                output_tokens=completion.usage.completion_tokens
                if completion.usage
                else 0,
            )
        except (AttributeError, IndexError, TypeError, ValueError) as error:
            raise ProviderResponseError(
                self.name, "the answer had an unexpected shape"
            ) from error

        if not content and finish is FinishReason.STOP:
            raise ProviderResponseError(self.name, "the answer was empty")
        return ChatResponse(
            provider=self.name,
            model=str(completion.model),
            content=content,
            finish_reason=finish,
            usage=usage,
        )

    def _translate(self, error: Exception) -> ProviderError:
        """Turn an SDK error into ours. Never copies the SDK's message, which
        for a wrong key can include part of the key."""
        sdk = self._sdk
        status = getattr(error, "status_code", None)
        logger.warning(
            "openai request failed: %s (status %s, request id %s)",
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
