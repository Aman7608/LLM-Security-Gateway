"""The mock provider's "leaky" answers, run through the real DLP engine.

This joins Phase 10 (providers) to Phase 11 (checking AI answers): an AI that
leaks a secret or personal data must be caught on the way OUT.
"""

from __future__ import annotations

import asyncio

from llm_gateway.dlp.engine import DLPEngine
from llm_gateway.models import Action, Direction
from llm_gateway.providers.base import ChatMessage, ChatRequest, ChatResponse
from llm_gateway.providers.mock import MockProvider, fake_aws_key


def ask_mock(text: str) -> ChatResponse:
    request = ChatRequest(messages=[ChatMessage(role="user", content=text)])
    return asyncio.run(MockProvider().complete(request))


def test_leaked_secret_in_an_answer_is_blocked(dlp_engine: DLPEngine) -> None:
    answer = ask_mock("[mock:leak-secret]")
    result = dlp_engine.process(answer.content, Direction.OUTPUT)
    assert result.blocked
    assert result.output_text is None


def test_leaked_personal_data_in_an_answer_is_hidden(dlp_engine: DLPEngine) -> None:
    answer = ask_mock("[mock:leak-pii]")
    result = dlp_engine.process(answer.content, Direction.OUTPUT)
    assert result.action is Action.REDACT
    assert result.output_text == "The customer is <EMAIL_ADDRESS>, card <CREDIT_CARD>."


def test_attack_text_in_an_answer_is_flagged(dlp_engine: DLPEngine) -> None:
    answer = ask_mock("[mock:injection]")
    result = dlp_engine.process(answer.content, Direction.OUTPUT)
    assert result.action is Action.WARN


def test_redacted_prompt_reaches_the_ai_redacted(dlp_engine: DLPEngine) -> None:
    """The full round trip: prompt is cleaned, the (mock) AI only sees the label."""
    prompt = dlp_engine.process("Email priya@example.com the report", Direction.INPUT)
    assert prompt.output_text is not None
    answer = ask_mock(prompt.output_text)
    assert "priya@example.com" not in answer.content
    assert "<EMAIL_ADDRESS>" in answer.content


def test_the_mock_key_is_detected_as_a_real_looking_secret(
    dlp_engine: DLPEngine,
) -> None:
    findings = dlp_engine.scan(fake_aws_key(), Direction.OUTPUT).findings
    assert [f.entity_type for f in findings] == ["AWS_ACCESS_KEY_ID"]
