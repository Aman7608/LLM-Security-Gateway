"""Turns one checked request into a safe audit record.

This sits in core/ because it needs results from several parts (the DLP
engine, the output guard and the AI answer), and only core may import all
of them. The audit package itself only knows about the safe AuditEntry.

The prompt and the answer pass through here only so each finding can get a
fingerprint. Neither is copied into the record, except the REDACTED prompt
when GATEWAY_STORE_REDACTED_PROMPTS is turned on.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from llm_gateway.audit.fingerprint import Fingerprinter
from llm_gateway.audit.records import AuditEntry, EventStatus, finding_entries
from llm_gateway.core.output_guard import GuardedAnswer
from llm_gateway.dlp.engine import DLPResult
from llm_gateway.models import Direction, highest, strictest
from llm_gateway.providers.base import ChatResponse


@dataclass(frozen=True)
class CheckedPart:
    """One checked piece of a request, e.g. messages[2] or documents[0]."""

    location: str
    text: str
    result: DLPResult


def build_audit_entry(
    request_id: str,
    prompt: str,
    prompt_check: DLPResult,
    fingerprinter: Fingerprinter | None,
    *,
    answer: ChatResponse | None = None,
    answer_check: GuardedAnswer | None = None,
    status: EventStatus | None = None,
    client_id: str | None = None,
    provider: str | None = None,
    total_ms: float = 0.0,
    store_redacted_prompt: bool = False,
) -> AuditEntry:
    """The record for a request with ONE prompt (see build_request_entry)."""
    return build_request_entry(
        request_id,
        [CheckedPart("prompt", prompt, prompt_check)],
        fingerprinter,
        answer=answer,
        answer_check=answer_check,
        status=status,
        client_id=client_id,
        provider=provider,
        total_ms=total_ms,
        store_redacted_prompt=store_redacted_prompt,
    )


def build_request_entry(
    request_id: str,
    parts: Sequence[CheckedPart],
    fingerprinter: Fingerprinter | None,
    *,
    answer: ChatResponse | None = None,
    answer_check: GuardedAnswer | None = None,
    status: EventStatus | None = None,
    client_id: str | None = None,
    provider: str | None = None,
    total_ms: float = 0.0,
    store_redacted_prompt: bool = False,
) -> AuditEntry:
    """Build the record for one request.

    `parts` are the checked pieces of the prompt (empty for a scan of an
    answer only). Pass `answer` and `answer_check` when the AI answered.
    Without them the record is for a blocked prompt, a scan-only request,
    or (with status=PROVIDER_ERROR) a request where the AI could not be
    reached.
    """
    blocked = any(part.result.blocked for part in parts)
    if status is None:
        status = _status(blocked, answer_check)
    fingerprint = fingerprinter.of if fingerprinter is not None else None

    findings = tuple(
        entry
        for part in parts
        for entry in finding_entries(
            part.result.scan.findings,
            Direction.INPUT,
            part.text,
            fingerprint,
            part.location,
        )
    )
    risks = [part.result.decision.risk_level for part in parts]
    scan_ms = sum(part.result.duration_ms for part in parts)
    versions = [part.result.decision.policy_version for part in parts]
    if answer is not None and answer_check is not None:
        findings += finding_entries(
            answer_check.result.scan.findings,
            Direction.OUTPUT,
            answer.content,
            fingerprint,
            "answer",
        )
        risks.append(answer_check.result.decision.risk_level)
        scan_ms += answer_check.result.duration_ms
        versions.append(answer_check.result.decision.policy_version)

    redacted_prompt = None
    if store_redacted_prompt and parts and not blocked:
        # output_text is the redacted text (what was sent to the AI)
        redacted_prompt = "\n\n".join(part.result.output_text or "" for part in parts)
    return AuditEntry(
        request_id=request_id,
        client_id=client_id,
        policy_version=next((v for v in versions if v is not None), None),
        provider=answer.provider if answer is not None else provider,
        model=answer.model if answer is not None else None,
        input_action=strictest(part.result.action for part in parts),
        output_action=answer_check.action if answer_check is not None else None,
        risk_level=highest(risks),
        status=status,
        input_chars=sum(len(part.text) for part in parts),
        output_chars=len(answer.content) if answer is not None else 0,
        scan_ms=round(scan_ms, 3),
        provider_ms=round(answer.latency_ms, 3) if answer is not None else 0.0,
        total_ms=round(total_ms, 3),
        redacted_prompt=redacted_prompt,
        findings=findings,
    )


def _status(blocked: bool, answer_check: GuardedAnswer | None) -> EventStatus:
    if blocked:
        return EventStatus.INPUT_BLOCKED
    if answer_check is None:
        return EventStatus.SCAN_ONLY
    if answer_check.blocked:
        return EventStatus.OUTPUT_BLOCKED
    return EventStatus.COMPLETED
