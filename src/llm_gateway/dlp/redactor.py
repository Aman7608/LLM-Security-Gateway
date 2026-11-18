"""Hides (redacts) found items in text.

The redactor works with findings from ANY detector (PII now, secrets in
Phase 7), so all kinds of sensitive data are hidden the same way.

Three modes:
    label   "Email me at <EMAIL_ADDRESS>"   (default: keeps the meaning clear)
    mask    "Email me at ****************"  (same length, shows something was there)
    remove  "Email me at [REDACTED]"        (gives away nothing about the type)

The redactor does not decide WHAT to hide. The policy engine (Phase 9) picks
which findings to pass in.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from llm_gateway.models import Finding


class RedactionMode(StrEnum):
    LABEL = "label"
    MASK = "mask"
    REMOVE = "remove"


@dataclass
class _Span:
    start: int
    end: int
    best: Finding  # the finding whose label is used when spans overlap


def redact(
    text: str,
    findings: Iterable[Finding],
    mode: RedactionMode = RedactionMode.LABEL,
) -> str:
    """Return text with every finding's span replaced.

    Overlapping findings are merged into one span first. For
    example, if "4111 1111 1111 1111" is found as both a card number and a
    phone number, it is replaced once, not twice.
    """
    spans = _merge(findings, len(text))
    pieces = []
    position = 0
    for span in spans:
        pieces.append(text[position : span.start])
        pieces.append(_replacement(span, mode))
        position = span.end
    pieces.append(text[position:])
    return "".join(pieces)


def _merge(findings: Iterable[Finding], text_length: int) -> list[_Span]:
    """Sort findings and join the ones that overlap."""
    merged: list[_Span] = []
    for finding in sorted(findings, key=lambda f: (f.start, -f.end)):
        if finding.end > text_length:
            raise ValueError(
                f"finding {finding.start}:{finding.end} is outside the text "
                f"(length {text_length})"
            )
        last = merged[-1] if merged else None
        # Overlap means the new one starts before the last one ends. Findings
        # that only touch (end == start) are two separate items.
        if last is not None and finding.start < last.end:
            last.end = max(last.end, finding.end)
            if _is_better_label(finding, last.best):
                last.best = finding
        else:
            merged.append(_Span(finding.start, finding.end, finding))
    return merged


def _is_better_label(new: Finding, current: Finding) -> bool:
    """Prefer the more confident finding, then the longer one."""
    return (new.confidence, new.end - new.start) > (
        current.confidence,
        current.end - current.start,
    )


def _replacement(span: _Span, mode: RedactionMode) -> str:
    if mode is RedactionMode.MASK:
        return "*" * (span.end - span.start)
    if mode is RedactionMode.REMOVE:
        return "[REDACTED]"
    label = span.best.entity_type or span.best.category.upper()
    return f"<{label}>"
