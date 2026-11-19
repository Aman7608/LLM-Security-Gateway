"""Builds the AI providers from the settings and picks one by name.

  - "mock" is always available (no key, no internet, free).
  - "openai" is available only when GATEWAY_OPENAI_API_KEY and
    GATEWAY_OPENAI_MODEL are both set.
  - "anthropic" is available only when GATEWAY_ANTHROPIC_API_KEY is set.

A provider that is not set up is not an error at startup: the registry just
remembers WHY, and explains it if someone asks for that provider.
"""

from __future__ import annotations

from typing import Any

from llm_gateway.providers.anthropic_provider import AnthropicProvider
from llm_gateway.providers.base import LLMProvider, ProviderNotConfigured, RetryPolicy
from llm_gateway.providers.mock import MockProvider
from llm_gateway.providers.openai_provider import OpenAIProvider
from llm_gateway.settings import Settings


class ProviderRegistry:
    """The providers that are ready to use, and why the others are not."""

    def __init__(
        self,
        providers: dict[str, LLMProvider],
        default: str,
        not_available: dict[str, str] | None = None,
    ) -> None:
        if default not in providers:
            reason = (not_available or {}).get(default, "unknown provider")
            raise ProviderNotConfigured(
                default, f"the default provider is not ready: {reason}"
            )
        self._providers = dict(providers)
        self.default = default
        self.not_available = dict(not_available or {})

    @classmethod
    def from_settings(
        cls, settings: Settings, http_client: Any = None
    ) -> ProviderRegistry:
        """Create every provider the settings allow.

        `http_client` lets tests give the real SDKs a fake network.
        """
        retry = RetryPolicy(max_retries=settings.provider_max_retries)
        timeout = settings.provider_timeout_seconds
        providers: dict[str, LLMProvider] = {
            "mock": MockProvider(timeout_seconds=timeout, retry=retry)
        }
        not_available: dict[str, str] = {}

        if settings.openai_api_key and settings.openai_model:
            try:
                providers["openai"] = OpenAIProvider(
                    api_key=settings.openai_api_key.get_secret_value(),
                    default_model=settings.openai_model,
                    timeout_seconds=timeout,
                    retry=retry,
                    http_client=http_client,
                )
            except ProviderNotConfigured as error:
                not_available["openai"] = str(error)
        else:
            not_available["openai"] = (
                "set GATEWAY_OPENAI_API_KEY and GATEWAY_OPENAI_MODEL to use it"
            )

        if settings.anthropic_api_key:
            try:
                providers["anthropic"] = AnthropicProvider(
                    api_key=settings.anthropic_api_key.get_secret_value(),
                    default_model=settings.anthropic_model,
                    effort=settings.anthropic_effort,
                    refusal_fallbacks=settings.anthropic_refusal_fallbacks,
                    timeout_seconds=timeout,
                    retry=retry,
                    http_client=http_client,
                )
            except ProviderNotConfigured as error:
                not_available["anthropic"] = str(error)
        else:
            not_available["anthropic"] = "set GATEWAY_ANTHROPIC_API_KEY to use it"

        return cls(providers, settings.default_provider.value, not_available)

    @property
    def available(self) -> list[str]:
        return sorted(self._providers)

    def get(self, name: str | None = None) -> LLMProvider:
        """The provider with this name, or the default one."""
        name = name or self.default
        if name in self._providers:
            return self._providers[name]
        reason = self.not_available.get(name, "there is no provider with this name")
        raise ProviderNotConfigured(name, reason)

    def describe(self) -> list[dict[str, object]]:
        """A safe summary for the API and dashboard. Never includes keys."""
        rows: list[dict[str, object]] = [
            {
                "name": name,
                "available": True,
                "default": name == self.default,
                "model": provider.default_model,
            }
            for name, provider in sorted(self._providers.items())
        ]
        rows += [
            {"name": name, "available": False, "default": False, "reason": reason}
            for name, reason in sorted(self.not_available.items())
        ]
        return rows
