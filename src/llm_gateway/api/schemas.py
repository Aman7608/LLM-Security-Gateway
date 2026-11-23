"""The shapes of API requests and replies.

FastAPI checks every request against these before the route runs, and
turns them into the API docs at /docs. `extra="forbid"` means an unknown
field is an error instead of being quietly ignored: a typo like
"mesages" should fail loudly.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from llm_gateway.audit.records import AuditEntry
from llm_gateway.core.gateway import Document
from llm_gateway.models import Action, Direction, RiskLevel
from llm_gateway.providers.base import (
    MAX_MESSAGE_CHARS,
    ChatMessage,
    ChatRequest,
    FinishReason,
    Usage,
)

MAX_MESSAGES = 50
MAX_DOCUMENTS = 10
MAX_POLICY_CHARS = 200_000


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------- errors ----------


class ErrorInfo(BaseModel):
    code: str
    message: str
    request_id: str | None
    details: Any = None


class ErrorReply(BaseModel):
    error: ErrorInfo


# For the API docs: which error replies a route can give
ERRORS: dict[int | str, dict[str, Any]] = {
    code: {"model": ErrorReply}
    for code in (400, 401, 403, 404, 413, 422, 429, 502, 503, 504)
}


# ---------- chat ----------


class ChatBody(Body):
    messages: list[ChatMessage] = Field(min_length=1, max_length=MAX_MESSAGES)
    documents: list[Document] = Field(default_factory=list, max_length=MAX_DOCUMENTS)
    provider: str | None = Field(default=None, pattern=r"^[a-z]{1,30}$")
    model: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:\-]{1,100}$")
    # A cap on the answer length also caps the cost of one request (threat D4)
    max_tokens: int = Field(default=1024, ge=1, le=16_000)

    @model_validator(mode="after")
    def conversation_is_valid(self) -> ChatBody:
        """The same order rules every provider needs (last message from the user...)."""
        try:
            ChatRequest(messages=tuple(self.messages))
        except ValidationError as error:
            # Only the messages, never the input that was rejected
            problems = [str(e["msg"]) for e in error.errors(include_input=False)]
            raise ValueError("; ".join(problems)) from None
        return self


class SecuritySummary(BaseModel):
    """What the gateway did, so the app can tell its user."""

    prompt_action: Action
    answer_action: Action
    risk_level: RiskLevel
    hidden: list[str]  # kinds of things replaced by labels, e.g. EMAIL_ADDRESS
    warnings: list[str]  # kinds of things that were only noted


class ChatReply(BaseModel):
    request_id: str
    provider: str
    model: str
    content: str  # the checked answer, or the "withheld" message
    finish_reason: FinishReason
    blocked: bool  # true: the answer was withheld
    redacted: bool  # true: parts of the answer were hidden
    usage: Usage
    security: SecuritySummary


# ---------- scan ----------


class ScanBody(Body):
    text: str = Field(max_length=MAX_MESSAGE_CHARS)
    direction: Direction = Direction.INPUT  # "output" checks it like an AI answer
    system_prompt: str | None = Field(default=None, max_length=MAX_MESSAGE_CHARS)


class FindingOut(BaseModel):
    """One finding. The kind, not the rule (naming rules helps attackers)."""

    category: str
    entity_type: str | None
    start: int
    end: int
    confidence: float
    severity: RiskLevel


class ScanReply(BaseModel):
    request_id: str
    direction: Direction
    action: Action
    risk_level: RiskLevel
    allowed: bool
    text: str | None  # the text with findings hidden; null when blocked
    findings: list[FindingOut]


# ---------- providers, health ----------


class ProvidersReply(BaseModel):
    default: str
    providers: list[dict[str, Any]]


class ReadyReply(BaseModel):
    status: str
    checks: dict[str, str]


# ---------- admin ----------


class EventsReply(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[AuditEntry]


class PolicyBody(Body):
    policy: str = Field(min_length=1, max_length=MAX_POLICY_CHARS)


class ActivePolicy(BaseModel):
    version: int
    checksum: str
    created_by: str
    source: str
    created_at: datetime
    text: str


class ValidateReply(BaseModel):
    valid: bool
    problem: str | None = None
