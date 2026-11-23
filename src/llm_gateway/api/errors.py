"""One error format for every error the API returns (FR-53).

  {"error": {"code": "request_blocked",
             "message": "The request was blocked by the security policy.",
             "request_id": "req-3f9a0c2b7e4d1a68"}}

- `code` is a fixed word a program can check; `message` is for people.
- The request id lets an admin find the full audit record.
- Internal details (stack traces, provider messages, database errors)
  never appear here. They only go to our own log.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

# Codes for errors raised by FastAPI itself (wrong path, wrong method, ...)
STATUS_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    413: "request_too_large",
    415: "unsupported_media_type",
    422: "invalid_request",
    429: "rate_limited",
    500: "internal_error",
    503: "unavailable",
}


class ApiError(Exception):
    """An error we raise on purpose, with a status code and a fixed code word."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers or {}


def request_id_of(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def error_response(
    request: Request,
    status: int,
    code: str,
    message: str,
    details: Any = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "code": code,
        "message": message,
        "request_id": request_id_of(request),
    }
    if details is not None:
        body["details"] = details
    return JSONResponse({"error": body}, status_code=status, headers=headers)


async def _api_error(request: Request, error: Exception) -> JSONResponse:
    assert isinstance(error, ApiError)  # noqa: S101 - registered for ApiError only
    return error_response(
        request, error.status, error.code, error.message, error.details, error.headers
    )


async def _http_error(request: Request, error: Exception) -> JSONResponse:
    assert isinstance(error, StarletteHTTPException)  # noqa: S101
    code = STATUS_CODES.get(error.status_code, "error")
    message = error.detail if isinstance(error.detail, str) else code
    return error_response(
        request,
        error.status_code,
        code,
        message,
        headers=dict(error.headers) if error.headers else None,
    )


async def _validation_error(request: Request, error: Exception) -> JSONResponse:
    """422 with WHERE each problem is and what is wrong, but not the input.

    Pydantic normally copies the rejected input into its error. That input
    could be a secret the client sent, so it is left out on purpose.
    """
    assert isinstance(error, RequestValidationError)  # noqa: S101
    details = [
        {
            "location": [str(part) for part in item.get("loc", ())],
            "problem": str(item.get("msg", "invalid value")),
        }
        for item in error.errors()
    ]
    return error_response(
        request, 422, "invalid_request", "The request is not valid.", details
    )


async def _unexpected_error(request: Request, error: Exception) -> JSONResponse:
    # Only the type goes to the log here; the server logs the full traceback
    logger.error(
        "Unexpected error (%s) for request %s",
        type(error).__name__,
        request_id_of(request),
    )
    return error_response(
        request, 500, "internal_error", "Something went wrong inside the gateway."
    )


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(ApiError, _api_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(Exception, _unexpected_error)
