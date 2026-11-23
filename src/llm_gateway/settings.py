"""All gateway settings, read from environment variables or a .env file.

Every setting has a safe default, so the gateway runs with no .env file at
all (using the mock AI provider). Each environment variable starts with
GATEWAY_, for example GATEWAY_PORT=8080.

API keys use SecretStr, so they show up as '**********' if settings are
printed or logged by mistake.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class FailMode(StrEnum):
    """What to do when a detector crashes.

    CLOSED blocks the request (safe default). OPEN lets it through with a
    warning, which keeps apps working but is less safe.
    """

    CLOSED = "closed"
    OPEN = "open"


class ProviderName(StrEnum):
    MOCK = "mock"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class Settings(BaseSettings):
    """Typed settings. Pydantic checks every value when the gateway starts."""

    model_config = SettingsConfigDict(
        env_prefix="GATEWAY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # Treat "GATEWAY_OPENAI_API_KEY=" (empty) the same as not set
        env_ignore_empty=True,
    )

    # General
    environment: Environment = Environment.DEVELOPMENT
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR)$")
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)

    # Files and storage
    policy_file: Path = Path("config/policy.yaml")
    injection_rules_file: Path = Path("config/injection_rules.yaml")
    pii_entities_file: Path = Path("config/pii_entities.yaml")
    secret_patterns_file: Path = Path("config/secret_patterns.yaml")
    confidential_terms_file: Path = Path("config/confidential_terms.yaml")
    database_url: str = "sqlite:///./data/gateway.db"

    # AI providers
    default_provider: ProviderName = ProviderName.MOCK
    openai_api_key: SecretStr | None = None
    # No default OpenAI model on purpose: names change, you pick one
    openai_model: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:\-]{1,100}$")
    anthropic_api_key: SecretStr | None = None
    anthropic_model: str = Field(
        default="claude-opus-5-5", pattern=r"^[A-Za-z0-9._:\-]{1,100}$"
    )
    # How hard Claude thinks before answering (more effort = slower, costlier)
    anthropic_effort: Literal["low", "medium", "high", "xhigh", "max"] = "medium"
    # Let the API retry a refused request on another Claude model
    anthropic_refusal_fallbacks: bool = True
    # Per attempt. Claude with thinking can need more than 30 seconds.
    provider_timeout_seconds: float = Field(default=120.0, gt=0, le=600)
    provider_max_retries: int = Field(default=2, ge=0, le=5)

    # API limits (checked before any scanning, so they are cheap)
    rate_limit_per_minute: int = Field(default=60, ge=1, le=100_000)  # per API key
    max_request_bytes: int = Field(default=1_000_000, ge=1_000, le=50_000_000)
    # All messages and documents of one chat together. Scanning gets slow for
    # long texts (19,000 characters took 2 to 4 seconds), so this keeps one
    # request from keeping the gateway busy for minutes.
    max_request_chars: int = Field(default=50_000, ge=1_000, le=200_000)

    # Security behaviour
    fail_mode: FailMode = FailMode.CLOSED
    max_prompt_chars: int = Field(default=20_000, ge=100, le=1_000_000)
    # Save the REDACTED prompt with each audit event (never the original)
    store_redacted_prompts: bool = False
    # Audit events older than this are deleted
    log_retention_days: int = Field(default=30, ge=1, le=3650)
    # True: refuse requests (503) when the audit log cannot be saved.
    # False: log the record to the console instead and carry on.
    audit_required: bool = False
    # Shown instead of an AI answer that was blocked. Never includes the answer.
    output_blocked_message: str = Field(
        default=(
            "The answer was withheld by the security gateway because it may "
            "contain sensitive information."
        ),
        min_length=1,
        max_length=500,
    )

    # Secret key for fingerprints of found values (see audit/fingerprint.py).
    # At least 32 characters. Needed in production so fingerprints cannot be
    # guessed. Make one with: python -c "import secrets; print(secrets.token_hex(32))"
    fingerprint_key: SecretStr | None = None

    @model_validator(mode="after")
    def check_settings_fit_together(self) -> Settings:
        """Catch setting combinations that would fail later, at startup instead."""
        if self.default_provider is ProviderName.OPENAI and not self.openai_api_key:
            raise ValueError(
                "default_provider is 'openai' but GATEWAY_OPENAI_API_KEY is not set"
            )
        if self.default_provider is ProviderName.OPENAI and not self.openai_model:
            raise ValueError(
                "default_provider is 'openai' but GATEWAY_OPENAI_MODEL is not set"
            )
        if (
            self.default_provider is ProviderName.ANTHROPIC
            and not self.anthropic_api_key
        ):
            raise ValueError(
                "default_provider is 'anthropic' but GATEWAY_ANTHROPIC_API_KEY "
                "is not set"
            )
        if self.environment is Environment.PRODUCTION and not self.fingerprint_key:
            raise ValueError("GATEWAY_FINGERPRINT_KEY must be set in production")
        if (
            self.fingerprint_key is not None
            and len(self.fingerprint_key.get_secret_value()) < 32
        ):
            raise ValueError("GATEWAY_FINGERPRINT_KEY must be at least 32 characters")
        return self


@lru_cache
def get_settings() -> Settings:
    """Load the settings once and reuse them.

    lru_cache means the .env file is only read the first time this runs.
    Tests can create their own Settings(...) object instead of using this.
    """
    return Settings()
