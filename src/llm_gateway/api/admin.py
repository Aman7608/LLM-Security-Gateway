"""Routes for admins only: the audit log, statistics and the policy (SB2).

These are plain `def` functions (not `async def`), because they only talk
to the database. FastAPI runs them in a worker thread for us.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Path, Query
from pydantic import AwareDatetime

from llm_gateway.api.auth import Admin, GatewayDep
from llm_gateway.api.errors import ApiError
from llm_gateway.api.schemas import (
    ERRORS,
    ActivePolicy,
    EventsReply,
    PolicyBody,
    ValidateReply,
)
from llm_gateway.audit.logger import (
    MAX_TIMELINE_POINTS,
    AuditStats,
    EventFilter,
    TimelinePoint,
)
from llm_gateway.audit.policy_history import SavedPolicy
from llm_gateway.audit.records import REQUEST_ID_PATTERN, AuditEntry
from llm_gateway.policy.schema import PolicyError
from llm_gateway.policy.store import PolicySaveError, PolicyVersion

router = APIRouter(prefix="/v1", tags=["admin"], responses=ERRORS)


# ---------- audit log ----------


@router.get("/events")
def list_events(
    admin: Admin, gateway: GatewayDep, filters: Annotated[EventFilter, Query()]
) -> EventsReply:
    """Security events, newest first.

    Times need a timezone, for example `2026-11-20T10:00:00Z`.
    """
    logger = gateway.audit.logger
    return EventsReply(
        total=logger.count(filters),
        limit=filters.limit,
        offset=filters.offset,
        items=logger.search(filters),
    )


@router.get("/events/{request_id}")
def get_event(
    admin: Admin,
    gateway: GatewayDep,
    request_id: Annotated[str, Path(pattern=REQUEST_ID_PATTERN)],
) -> AuditEntry:
    """One event with all its findings."""
    event = gateway.audit.logger.get(request_id)
    if event is None:
        raise ApiError(404, "event_not_found", "There is no event with this id.")
    return event


@router.get("/stats")
def stats(
    admin: Admin, gateway: GatewayDep, since: AwareDatetime | None = None
) -> AuditStats:
    """Counts for the dashboard, optionally only since a given time."""
    return gateway.audit.logger.stats(since=since)


STEPS = {"hour": timedelta(hours=1), "day": timedelta(days=1)}


@router.get("/stats/timeline")
def timeline(
    admin: Admin,
    gateway: GatewayDep,
    hours: Annotated[int, Query(ge=1, le=24 * 90)] = 24,
    step: Literal["hour", "day"] = "hour",
) -> list[TimelinePoint]:
    """Events per hour or per day over the last `hours`, for the risk chart.

    Steps start on whole hours or whole days (UTC), and the last step is the
    current one, so the newest events are always included.
    """
    size = STEPS[step]
    points = math.ceil(timedelta(hours=hours) / size)
    if points > MAX_TIMELINE_POINTS:
        raise ApiError(
            422,
            "invalid_request",
            f"That is {points} points; the most is {MAX_TIMELINE_POINTS}. "
            "Use step=day for long periods.",
        )
    end = _round_down(datetime.now(UTC), size) + size
    return gateway.audit.logger.timeline(end - points * size, end, size)


def _round_down(moment: datetime, size: timedelta) -> datetime:
    """The start of the hour or the day (UTC) that `moment` is in."""
    if size == timedelta(days=1):
        return moment.replace(hour=0, minute=0, second=0, microsecond=0)
    return moment.replace(minute=0, second=0, microsecond=0)


# ---------- policy ----------


@router.get("/policies/active")
def active_policy(admin: Admin, gateway: GatewayDep) -> ActivePolicy:
    """The policy in use right now, with its exact text."""
    return _active(gateway.policy_store.current)


@router.put("/policies/active")
def replace_policy(admin: Admin, gateway: GatewayDep, body: PolicyBody) -> ActivePolicy:
    """Replace the policy. It is checked first; a broken policy changes nothing.

    Every change becomes a new version, saved with who made it.
    """
    who = f"{admin.name} ({admin.id})"[:100]
    try:
        version = gateway.policy_store.update(body.policy, created_by=who)
    except PolicySaveError:
        raise ApiError(
            503,
            "audit_unavailable",
            "The new policy could not be saved, so nothing was changed.",
        ) from None
    except PolicyError as error:
        raise ApiError(422, "invalid_policy", str(error)) from None
    return _active(version)


@router.post("/policies/validate")
def validate_policy(
    admin: Admin, gateway: GatewayDep, body: PolicyBody
) -> ValidateReply:
    """Check a policy WITHOUT using it (a dry run)."""
    try:
        gateway.policy_store.validate(body.policy)
    except PolicyError as error:
        return ValidateReply(valid=False, problem=str(error))
    return ValidateReply(valid=True)


@router.get("/policies/history")
def policy_history(
    admin: Admin,
    gateway: GatewayDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> list[SavedPolicy]:
    """Every saved policy version, newest first."""
    return gateway.audit.policy_history.list(limit)


def _active(version: PolicyVersion) -> ActivePolicy:
    return ActivePolicy(
        version=version.version,
        checksum=version.checksum,
        created_by=version.created_by,
        source=version.source,
        created_at=version.created_at,
        text=version.text,
    )
