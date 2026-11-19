"""Tests for llm_gateway.settings."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from llm_gateway.settings import (
    Environment,
    FailMode,
    ProviderName,
    Settings,
    get_settings,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MakeSettings = Callable[..., Settings]


def test_defaults_are_safe(make_settings: MakeSettings) -> None:
    settings = make_settings()
    assert settings.default_provider is ProviderName.MOCK
    assert settings.fail_mode is FailMode.CLOSED
    assert settings.store_redacted_prompts is False
    assert settings.openai_api_key is None
    assert settings.anthropic_api_key is None
    assert settings.host == "127.0.0.1"  # only reachable from this computer


def test_reads_environment_variables(
    monkeypatch: pytest.MonkeyPatch, make_settings: MakeSettings
) -> None:
    monkeypatch.setenv("GATEWAY_PORT", "9000")
    monkeypatch.setenv("GATEWAY_FAIL_MODE", "open")
    settings = make_settings()
    assert settings.port == 9000
    assert settings.fail_mode is FailMode.OPEN


@pytest.mark.parametrize("port", [0, -1, 70000])
def test_rejects_invalid_port(make_settings: MakeSettings, port: int) -> None:
    with pytest.raises(ValidationError):
        make_settings(port=port)


@pytest.mark.parametrize(
    "field, value",
    [
        ("log_level", "LOUD"),
        ("fail_mode", "sometimes"),
        ("default_provider", "gemini"),
        ("provider_max_retries", 50),
        ("provider_timeout_seconds", 0),
        ("max_prompt_chars", 10),
    ],
)
def test_rejects_invalid_values(
    make_settings: MakeSettings, field: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        make_settings(**{field: value})


def test_real_provider_needs_a_key(make_settings: MakeSettings) -> None:
    with pytest.raises(ValidationError, match="GATEWAY_OPENAI_API_KEY"):
        make_settings(default_provider="openai")
    with pytest.raises(ValidationError, match="GATEWAY_ANTHROPIC_API_KEY"):
        make_settings(default_provider="anthropic")


def test_real_provider_works_with_a_key(make_settings: MakeSettings) -> None:
    settings = make_settings(
        default_provider="openai",
        openai_api_key="fake-openai-key-for-tests",
        openai_model="test-model",
    )
    assert settings.default_provider is ProviderName.OPENAI


def test_openai_also_needs_a_model(make_settings: MakeSettings) -> None:
    with pytest.raises(ValidationError, match="GATEWAY_OPENAI_MODEL"):
        make_settings(default_provider="openai", openai_api_key="fake-key-for-tests")


def test_production_needs_fingerprint_key(make_settings: MakeSettings) -> None:
    with pytest.raises(ValidationError, match="GATEWAY_FINGERPRINT_KEY"):
        make_settings(environment="production")
    settings = make_settings(environment="production", fingerprint_key="x" * 64)
    assert settings.environment is Environment.PRODUCTION


def test_api_keys_are_hidden_when_printed(make_settings: MakeSettings) -> None:
    fake_key = "sk-test-hidden-value-123"
    settings = make_settings(openai_api_key=fake_key)

    assert isinstance(settings.openai_api_key, SecretStr)
    assert fake_key not in repr(settings)
    assert fake_key not in str(settings)
    assert fake_key not in settings.model_dump_json()
    # The real value is still there when the code asks for it on purpose
    assert settings.openai_api_key.get_secret_value() == fake_key


def test_empty_key_counts_as_not_set(
    monkeypatch: pytest.MonkeyPatch, make_settings: MakeSettings
) -> None:
    monkeypatch.setenv("GATEWAY_OPENAI_API_KEY", "")
    assert make_settings().openai_api_key is None


def test_env_example_file_loads() -> None:
    """The example file must work as a real .env when copied."""
    settings = Settings(_env_file=PROJECT_ROOT / ".env.example")
    assert settings.default_provider is ProviderName.MOCK
    assert settings.openai_api_key is None


def test_env_example_matches_settings() -> None:
    """Every setting is listed in .env.example, and nothing extra is listed.

    This keeps the example file up to date when we add new settings.
    """
    text = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")
    listed = {
        line.split("=", 1)[0].strip()
        for line in text.splitlines()
        if line.startswith("GATEWAY_")
    }
    expected = {f"GATEWAY_{name.upper()}" for name in Settings.model_fields}
    assert listed == expected


def test_get_settings_is_cached() -> None:
    get_settings.cache_clear()
    assert get_settings() is get_settings()
    get_settings.cache_clear()
