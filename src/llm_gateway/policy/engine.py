"""Policy engine: turns a ScanResult into one structured Decision.

The policy engine only DECIDES. It never changes text and never runs
detectors; the DLP engine does those things.

How a decision is made (docs/10-policy-engine.md explains each step):
    1. Each finding gets the action of the FIRST rule that applies to it.
    2. The strictest action wins (block > redact > warn > allow).
    3. Combine rules: several weak findings together can raise the action.
    4. Risk = the most serious finding acted on, raised one level when
       different kinds of problems appear together.
    5. block_at_risk: block anything at or above a set risk level.
    6. A crashed detector blocks (fail closed) or warns (fail open).
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable

from llm_gateway.models import (
    Action,
    Decision,
    Finding,
    RiskLevel,
    RuleMatch,
    ScanResult,
    combined_confidence,
    highest,
    one_level_higher,
    strictest,
)
from llm_gateway.policy.schema import Policy, PolicyRule
from llm_gateway.policy.store import PolicyStore
from llm_gateway.settings import FailMode

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Decides what to do with a ScanResult, using the current policy."""

    def __init__(
        self,
        policy: Policy | PolicyStore,
        fail_mode: FailMode = FailMode.CLOSED,
    ) -> None:
        # Accepting a plain Policy keeps tests and simple scripts short
        self.store = (
            policy
            if isinstance(policy, PolicyStore)
            else PolicyStore.from_policy(policy)
        )
        self.fail_mode = fail_mode
        if fail_mode is FailMode.OPEN:
            # Safer default turned off: make sure it shows up in the logs (NFR-02)
            logger.warning(
                "Fail mode is OPEN: if a detector crashes, prompts and answers "
                "are let through unchecked (only warned). Use "
                "GATEWAY_FAIL_MODE=closed to block them instead."
            )

    @property
    def policy(self) -> Policy:
        """The policy in use right now (it can change when the store reloads)."""
        return self.store.current.policy

    def decide(self, scan: ScanResult) -> Decision:
        # Read the current version ONCE, so a reload in the middle of a
        # decision cannot mix two policies.
        version = self.store.current
        policy = version.policy
        direction = policy.for_direction(scan.direction)

        # 1. Each finding gets the action of the FIRST rule that applies to it
        matches: list[RuleMatch] = []
        for finding in scan.findings:
            rule = _first_rule(direction.rules, finding)
            if rule is not None:
                matches.append(
                    RuleMatch(finding=finding, rule_id=rule.id, action=rule.action)
                )
        reasons = _explain(matches)
        fired: list[str] = []

        # 2. The strictest action wins
        action = strictest(m.action for m in matches)
        acted_on = [m for m in matches if m.action is not Action.ALLOW]
        risk = highest(m.finding.severity for m in acted_on)

        # 3. Several weak signals together
        for combo in direction.combine:
            if action.strictness >= combo.action.strictness:
                continue  # already at least this strict: nothing to add
            group = [f for f in scan.findings if combo.when.matches(f)]
            different_rules = {f.rule_id or f.category for f in group}
            if len(different_rules) < 2:
                continue
            score = combined_confidence(group)
            if score >= combo.min_combined_confidence:
                fired.append(combo.id)
                action = strictest([action, combo.action])
                risk = highest([risk, combo.severity])
                reasons.append(
                    f"{combo.id}: {len(different_rules)} different signals, combined "
                    f"confidence {score:.2f} -> {combo.action.value}"
                )

        # 4. Different kinds of problems together are worse than either alone
        categories = {m.finding.category for m in acted_on}
        if policy.risk.escalate_on_mixed_categories and len(categories) >= 2:
            raised = one_level_higher(risk)
            if raised is not risk:
                reasons.append(
                    f"risk raised from {risk.value} to {raised.value}: different kinds "
                    f"of problems found together ({', '.join(sorted(categories))})"
                )
                risk = raised

        # 5. Block anything at or above this direction's risk limit
        limit = direction.block_at_risk
        if limit is not None and risk.rank >= limit.rank and action is not Action.BLOCK:
            action = Action.BLOCK
            reasons.append(
                f"blocked: risk {risk.value} is at or above the limit "
                f"for {scan.direction.value} ({limit.value})"
            )

        # 6. A crashed detector means we do not know what was missed
        if scan.errors:
            crashed = ", ".join(scan.errors)
            if self.fail_mode is FailMode.CLOSED:
                action = Action.BLOCK
                risk = highest([risk, RiskLevel.MEDIUM])
                reasons.append(
                    f"detector error ({crashed}): blocked because fail mode is closed"
                )
            else:
                action = strictest([action, Action.WARN])
                reasons.append(
                    f"detector error ({crashed}): allowed with a warning because "
                    "fail mode is open"
                )

        return Decision(
            action=action,
            risk_level=risk,
            matched_rules=tuple(dict.fromkeys([*(m.rule_id for m in matches), *fired])),
            reasons=tuple(reasons),
            matches=tuple(matches),
            policy_version=version.version,
            redaction_mode=policy.redaction_mode,
        )


def _first_rule(rules: Iterable[PolicyRule], finding: Finding) -> PolicyRule | None:
    return next((r for r in rules if r.applies_to(finding)), None)


def _explain(matches: Iterable[RuleMatch]) -> list[str]:
    """Plain reasons like 'in-redact-personal-data: 2 x EMAIL_ADDRESS -> redact'.

    Reasons name the TYPE of data and the rule, never the text itself, so
    they are safe to log and to show to users.
    """
    counts = Counter((m.rule_id, m.finding.label, m.action) for m in matches)
    return [
        f"{rule_id}: {count} x {label} -> {action.value}"
        for (rule_id, label, action), count in counts.items()
    ]
