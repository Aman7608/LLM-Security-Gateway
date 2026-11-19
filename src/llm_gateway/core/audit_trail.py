"""Turns one checked request into a safe audit record.

This sits in core/ because it needs results from several parts (the DLP
engine, the output guard and the AI answer), and only core may import all
of them. The audit package itself only knows about the safe AuditEntry.

The prompt and the answer pass through here only so each finding can get a
fingerprint. Neither is copied into the record, except the REDACTED prompt
when GATEWAY_STORE_REDACTED_PROMPTS is turned on.
"""

from __future__ import annotations

from llm_gateway.audit.fingerprint import Fingerprinter
from llm_gateway.audit.records import AuditEntry, EventStatus, finding_entries
from llm_gateway.core.output_guard import GuardedAnswer
from llm_gateway.dlp.engine import DLPResult
from llm_gateway.models import Direction, highest
from llm_gateway.providers.base import ChatResponse


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
    """Build the record for one request.

    Pass `answer` and `answer_check` when the AI answered. Without them the
    record is for a blocked prompt, a scan-only request, or (with
    status=PROVIDER_ERROR) a request where the AI could not be reached.
    """
    if status is None:
        status = _status(prompt_check, answer_check)
    fingerprint = fingerprinter.of if fingerprinter is not None else None

    findings = finding_entries(
        prompt_check.scan.findings, Direction.INPUT, prompt, fingerprint
    )
    risk = prompt_check.decision.risk_level
    scan_ms = prompt_check.duration_ms
    if answer is not None and answer_check is not None:
        findings += finding_entries(
            answer_check.result.scan.findings,
            Direction.OUTPUT,
            answer.content,
            fingerprint,
        )
        risk = highest([risk, answer_check.result.decision.risk_level])
        scan_ms += answer_check.result.duration_ms

    keep_prompt = store_redacted_prompt and not prompt_check.blocked
    return AuditEntry(
        request_id=request_id,
        client_id=client_id,
        policy_version=prompt_check.decision.policy_version,
        provider=answer.provider if answer is not None else provider,
        model=answer.model if answer is not None else None,
        input_action=prompt_check.action,
        output_action=answer_check.action if answer_check is not None else None,
        risk_level=risk,
        status=status,
        input_chars=len(prompt),
        output_chars=len(answer.content) if answer is not None else 0,
        scan_ms=round(scan_ms, 3),
        provider_ms=round(answer.latency_ms, 3) if answer is not None else 0.0,
        total_ms=round(total_ms, 3),
        # output_text is the redacted prompt (what was sent to the AI)
        redacted_prompt=prompt_check.output_text if keep_prompt else None,
        findings=findings,
    )


def _status(prompt_check: DLPResult, answer_check: GuardedAnswer | None) -> EventStatus:
    if prompt_check.blocked:
        return EventStatus.INPUT_BLOCKED
    if answer_check is None:
        return EventStatus.SCAN_ONLY
    if answer_check.blocked:
        return EventStatus.OUTPUT_BLOCKED
    return EventStatus.COMPLETED
