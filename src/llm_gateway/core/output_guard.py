"""The output security scanner: checks an AI answer before anyone sees it.

    AI answer
       |-- system prompt leak check (needs this request's system prompt/canary)
       |-- DLP engine, direction OUTPUT (injection, PII, secrets, confidential)
       v
    one policy decision -> safe text, hidden text, or a "withheld" message

Why a separate "output" check at all, when prompts are already checked?
  - The AI can produce sensitive data that was never in the prompt: from its
    training data, from documents it was given, or by making it up.
  - The AI can be tricked into repeating its hidden system prompt.
  - Answers are shown to people (and sometimes passed to other programs), so
    they are a second place where data can leak.

A blocked answer is replaced by a neutral message that never repeats any of
the blocked content (not even a summary of it).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from llm_gateway.detectors.leak import DEFAULT_MIN_WORDS, find_system_prompt_leak
from llm_gateway.dlp.engine import DLPEngine, DLPResult
from llm_gateway.models import Action, Direction, Finding
from llm_gateway.providers.base import ChatResponse, FinishReason

DEFAULT_BLOCKED_MESSAGE = (
    "The answer was withheld by the security gateway because it may contain "
    "sensitive information."
)


class GuardedAnswer(BaseModel):
    """What the user may see, plus everything needed to explain and log it."""

    model_config = ConfigDict(frozen=True)

    text: str  # what to show: the (possibly hidden) answer, or the message
    blocked: bool
    redacted: bool
    finish_reason: FinishReason
    result: DLPResult

    @property
    def action(self) -> Action:
        return self.result.action

    @property
    def warnings(self) -> tuple[Finding, ...]:
        return self.result.warnings


class OutputGuard:
    """Runs every output check and applies the policy to an AI answer."""

    def __init__(
        self,
        engine: DLPEngine,
        blocked_message: str = DEFAULT_BLOCKED_MESSAGE,
        min_overlap_words: int = DEFAULT_MIN_WORDS,
    ) -> None:
        self.engine = engine
        self.blocked_message = blocked_message
        self.min_overlap_words = min_overlap_words

    def check(
        self,
        answer: ChatResponse,
        system_prompt: str | None = None,
        canary: str | None = None,
        request_id: str | None = None,
    ) -> GuardedAnswer:
        """Check one AI answer. Pass the system prompt and canary of the SAME
        request, so leaks of them can be found."""
        leaks = find_system_prompt_leak(
            answer.content, system_prompt, canary, self.min_overlap_words
        )
        result = self.engine.process(
            answer.content, Direction.OUTPUT, extra_findings=leaks
        )

        if result.output_text is None:
            message = self.blocked_message
            if request_id:
                message += f" Reference: {request_id}"
            return GuardedAnswer(
                text=message,
                blocked=True,
                redacted=False,
                finish_reason=answer.finish_reason,
                result=result,
            )

        return GuardedAnswer(
            text=result.output_text,
            blocked=False,
            redacted=result.action is Action.REDACT,
            finish_reason=answer.finish_reason,
            result=result,
        )
