"""Who is calling? API key login, roles and rate limits (FR-51, FR-52).

Every /v1 route depends on `current_client` (or `admin_client`), so FastAPI
runs these checks BEFORE the route, and before any slow scanning. A caller
without a valid key cannot make the gateway do heavy work (threat D1).

    no key          -> 401 missing_api_key
    wrong/off key   -> 401 invalid_api_key
    too many        -> 429 rate_limited (+ Retry-After header)
    not an admin    -> 403 admin_required   (admin routes only)
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request, Security
from fastapi.security import APIKeyHeader

from llm_gateway.api.errors import ApiError
from llm_gateway.api.rate_limit import RateLimiter
from llm_gateway.audit.clients import ClientInfo
from llm_gateway.core.gateway import Gateway

# Also makes the "Authorize" button appear in the API docs (/docs)
api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,  # we send our own error format instead
    description="Your gateway API key (starts with lsg_).",
)


def get_gateway(request: Request) -> Gateway:
    gateway: Gateway | None = getattr(request.app.state, "gateway", None)
    if gateway is None:
        raise ApiError(503, "unavailable", "The gateway is still starting.")
    return gateway


def current_client(
    request: Request, key: Annotated[str | None, Security(api_key_header)] = None
) -> ClientInfo:
    """The app making this request. Runs in a worker thread (database lookup)."""
    if not key:
        raise ApiError(
            401,
            "missing_api_key",
            "Send your API key in the X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    client = get_gateway(request).audit.api_keys.verify(key)
    if client is None:
        # The same answer for "no such key" and "key turned off", so a
        # caller cannot learn which keys once existed
        raise ApiError(
            401,
            "invalid_api_key",
            "The API key is not valid or has been turned off.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    limiter: RateLimiter = request.app.state.rate_limiter
    wait = limiter.check(client.id)
    if wait is not None:
        seconds = RateLimiter.retry_after_header(wait)
        raise ApiError(
            429,
            "rate_limited",
            f"Too many requests. Try again in {seconds} seconds.",
            headers={"Retry-After": seconds},
        )
    return client


def admin_client(
    client: Annotated[ClientInfo, Depends(current_client)],
) -> ClientInfo:
    if not client.is_admin:
        raise ApiError(403, "admin_required", "This needs an admin API key.")
    return client


Client = Annotated[ClientInfo, Depends(current_client)]
Admin = Annotated[ClientInfo, Depends(admin_client)]
GatewayDep = Annotated[Gateway, Depends(get_gateway)]
