"""Tests for llm_gateway.providers.registry.ProviderRegistry."""

from __future__ import annotations

import sys
from collections.abc import Callable

import pytest

from llm_gateway.providers.anthropic_provider import AnthropicProvider
from llm_gateway.providers.base import ProviderNotConfigured
from llm_gateway.providers.mock import MockProvider
from llm_gateway.providers.openai_provider import OpenAIProvider
from llm_gateway.providers.registry import ProviderRegistry
from llm_gateway.settings import Settings

MakeSettings = Callable[..., Settings]
FAKE_KEY = "fake-key-for-tests-123"


def test_only_mock_without_keys(make_settings: MakeSettings) -> None:
    registry = ProviderRegistry.from_settings(make_settings())
    assert registry.available == ["mock"]
    assert registry.default == "mock"
    assert isinstance(registry.get(), MockProvider)


def test_anthropic_needs_only_a_key(make_settings: MakeSettings) -> None:
    registry = ProviderRegistry.from_settings(make_settings(anthropic_api_key=FAKE_KEY))
    provider = registry.get("anthropic")
    assert isinstance(provider, AnthropicProvider)
    assert provider.default_model == "claude-opus-5-5"
    assert provider.effort == "medium"
    assert provider.refusal_fallbacks is True


def test_anthropic_settings_are_passed_on(make_settings: MakeSettings) -> None:
    settings = make_settings(
        anthropic_api_key=FAKE_KEY,
        anthropic_model="claude-sonnet-5-5",
        anthropic_effort="low",
        anthropic_refusal_fallbacks=False,
        provider_timeout_seconds=9,
        provider_max_retries=4,
    )
    provider = ProviderRegistry.from_settings(settings).get("anthropic")
    assert isinstance(provider, AnthropicProvider)
    assert provider.default_model == "claude-sonnet-5-5"
    assert provider.effort == "low"
    assert provider.refusal_fallbacks is False
    assert provider.timeout_seconds == 9
    assert provider.retry.max_retries == 4


def test_openai_needs_a_key_and_a_model(make_settings: MakeSettings) -> None:
    key_only = ProviderRegistry.from_settings(make_settings(openai_api_key=FAKE_KEY))
    assert "openai" not in key_only.available
    with pytest.raises(ProviderNotConfigured, match="GATEWAY_OPENAI_MODEL"):
        key_only.get("openai")

    both = ProviderRegistry.from_settings(
        make_settings(openai_api_key=FAKE_KEY, openai_model="test-model")
    )
    assert isinstance(both.get("openai"), OpenAIProvider)


def test_default_provider_from_settings(make_settings: MakeSettings) -> None:
    settings = make_settings(default_provider="anthropic", anthropic_api_key=FAKE_KEY)
    registry = ProviderRegistry.from_settings(settings)
    assert registry.default == "anthropic"
    assert isinstance(registry.get(), AnthropicProvider)


def test_unknown_provider(make_settings: MakeSettings) -> None:
    registry = ProviderRegistry.from_settings(make_settings())
    with pytest.raises(ProviderNotConfigured, match="no provider with this name"):
        registry.get("gemini")


def test_default_must_be_ready() -> None:
    with pytest.raises(ProviderNotConfigured, match="default provider is not ready"):
        ProviderRegistry({"mock": MockProvider()}, default="openai")


def test_describe_never_shows_keys(make_settings: MakeSettings) -> None:
    settings = make_settings(anthropic_api_key=FAKE_KEY)
    rows = ProviderRegistry.from_settings(settings).describe()
    assert FAKE_KEY not in str(rows)
    names = {row["name"]: row for row in rows}
    assert names["anthropic"]["available"] is True
    assert names["openai"]["available"] is False
    assert "GATEWAY_OPENAI_API_KEY" in str(names["openai"]["reason"])
    assert names["mock"]["default"] is True


# ---------- real providers are optional ----------


@pytest.mark.parametrize("package", ["anthropic", "openai"])
def test_missing_package_gives_a_clear_reason(
    monkeypatch: pytest.MonkeyPatch, make_settings: MakeSettings, package: str
) -> None:
    """If the SDK is not installed, the gateway still starts with the mock,
    and explains how to fix the missing provider."""
    monkeypatch.setitem(sys.modules, package, None)  # makes "import <package>" fail
    settings = make_settings(
        anthropic_api_key=FAKE_KEY, openai_api_key=FAKE_KEY, openai_model="test-model"
    )
    registry = ProviderRegistry.from_settings(settings)
    assert package not in registry.available
    assert "mock" in registry.available
    with pytest.raises(ProviderNotConfigured, match="requirements-providers.txt"):
        registry.get(package)


def test_empty_keys_are_refused() -> None:
    with pytest.raises(ProviderNotConfigured, match="GATEWAY_ANTHROPIC_API_KEY"):
        AnthropicProvider(api_key="")
    with pytest.raises(ProviderNotConfigured, match="GATEWAY_OPENAI_API_KEY"):
        OpenAIProvider(api_key="", default_model="m")
    with pytest.raises(ProviderNotConfigured, match="GATEWAY_OPENAI_MODEL"):
        OpenAIProvider(api_key=FAKE_KEY, default_model="")
