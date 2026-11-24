"""Code that runs around EVERY request, before and after the route.

RequestContextMiddleware
    - gives the request a new id (also sent back as the X-Request-ID header)
    - adds security headers to every answer
    - writes one log line per request: method, path, status, time

BodySizeLimitMiddleware
    - refuses bodies bigger than GATEWAY_MAX_REQUEST_BYTES with 413,
      before FastAPI reads them into memory (threat D2)

These are "pure ASGI" middleware: small functions around the raw request,
which is faster and simpler than Starlette's BaseHTTPMiddleware.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from typing import Any

from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("llm_gateway.access")

SECURITY_HEADERS = {
    b"x-content-type-options": b"nosniff",  # do not guess the content type
    b"x-frame-options": b"DENY",  # never show the API inside another page
    b"referrer-policy": b"no-referrer",
    b"cache-control": b"no-store",  # answers may hold private data
}
# Content-Security-Policy tells the browser what a page may load and run.
# The API only returns JSON, so its replies may load nothing at all.
API_CSP = (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'")
API_PATHS = ("/v1/", "/health", "/ready")
# The dashboard pages may only load scripts, styles and data from this same
# address. Even if attack text from the audit log somehow became HTML, the
# browser would refuse to run it (no inline or outside scripts).
DASHBOARD_CSP = (
    b"content-security-policy",
    b"default-src 'none'; script-src 'self'; style-src 'self'; "
    b"img-src 'self' data:; font-src 'self'; connect-src 'self'; "
    b"base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
)
# The API docs (/docs, /redoc) load their scripts from a CDN, so they get none
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


def content_security_policy(path: str) -> tuple[bytes, bytes] | None:
    """Which Content-Security-Policy a reply for this path gets."""
    if path.startswith(DOCS_PATHS):
        return None
    if path.startswith(API_PATHS):
        return API_CSP
    return DASHBOARD_CSP  # the dashboard files (and 404s for unknown paths)


def new_request_id() -> str:
    return "req-" + secrets.token_hex(8)


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        # Always our own id: an id chosen by the client could clash with
        # another request's id in the audit log
        request_id = new_request_id()
        scope.setdefault("state", {})["request_id"] = request_id
        path: str = scope.get("path", "")
        started = time.perf_counter()
        status = 500

        async def send_with_headers(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode()))
                headers += list(SECURITY_HEADERS.items())
                policy = content_security_policy(path)
                if policy is not None:
                    headers.append(policy)
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        finally:
            # The path only, never the query string (it could hold a search)
            logger.info(
                "%s %s -> %s",
                scope.get("method"),
                path,
                status,
                extra={
                    "request_id": request_id,
                    "status": status,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                },
            )


class BodyTooLarge(HTTPException):
    """Raised while the body is being read. FastAPI passes it on as it is."""

    def __init__(self) -> None:
        super().__init__(413, "The request body is too large.")


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1. The client says how big the body is: refuse at once if too big
        length = dict(scope.get("headers", [])).get(b"content-length")
        if length is not None and (
            not length.isdigit() or int(length) > self.max_bytes
        ):
            await _send_413(scope, send)
            return

        # 2. No (honest) length given: count the bytes while they arrive
        received = 0

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise BodyTooLarge
            return message

        await self.app(scope, counting_receive, send)


async def _send_413(scope: Scope, send: Send) -> None:
    request_id: Any = scope.get("state", {}).get("request_id")
    body = json.dumps(
        {
            "error": {
                "code": "request_too_large",
                "message": "The request body is too large.",
                "request_id": request_id,
            }
        }
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
