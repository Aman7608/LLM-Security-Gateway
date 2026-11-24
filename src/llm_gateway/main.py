"""Creates the FastAPI app: the gateway's web API.

Run it with:
    .\\.venv\\Scripts\\python.exe -m uvicorn llm_gateway.main:app

Then open http://127.0.0.1:8000/docs for the API documentation.

At startup (the "lifespan"), the gateway:
  1. switches the logs to JSON
  2. loads the detectors (the PII model takes a few seconds), the policy,
     the AI providers and the audit database
  3. starts a small background job that deletes old audit events every hour
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from llm_gateway import __version__
from llm_gateway.api import admin, routes
from llm_gateway.api.errors import install_error_handlers
from llm_gateway.api.middleware import BodySizeLimitMiddleware, RequestContextMiddleware
from llm_gateway.api.rate_limit import RateLimiter
from llm_gateway.api.schemas import ReadyReply
from llm_gateway.audit.json_logging import configure_logging
from llm_gateway.core.factory import build_gateway
from llm_gateway.core.gateway import Gateway
from llm_gateway.settings import Environment, Settings, get_settings

logger = logging.getLogger(__name__)

CLEANUP_EVERY_SECONDS = 3600


def create_app(
    settings: Settings | None = None, gateway: Gateway | None = None
) -> FastAPI:
    """Build the app. Tests pass their own settings and a ready-made gateway."""
    settings = settings or get_settings()

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if settings.environment is not Environment.TEST:
            configure_logging(settings.log_level)  # tests keep pytest's logging
        built_here = app.state.gateway is None
        if built_here:
            app.state.gateway = await asyncio.to_thread(build_gateway, settings)
        cleanup = asyncio.create_task(_delete_old_events_forever(app.state.gateway))
        logger.info("The gateway is ready")
        try:
            yield
        finally:
            cleanup.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cleanup
            if built_here:
                app.state.gateway.audit.engine.dispose()

    app = FastAPI(
        title="LLM Security Gateway",
        version=__version__,
        description=(
            "Checks prompts and AI answers for attacks and data leaks.\n\n"
            "Send your API key in the `X-API-Key` header (use **Authorize** "
            "above). Make keys with `scripts/manage_keys.py`."
        ),
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.gateway = gateway
    app.state.rate_limiter = RateLimiter(settings.rate_limit_per_minute)

    install_error_handlers(app)
    # The middleware added LAST runs FIRST. The request id must exist before
    # anything else can fail, so RequestContextMiddleware goes on the outside.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(RequestContextMiddleware)

    @app.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        """Is the program running? (No login needed, checks nothing else.)"""
        return {
            "status": "ok",
            "version": __version__,
            "environment": settings.environment.value,
        }

    @app.get("/ready", tags=["health"], response_model=ReadyReply)
    def ready() -> JSONResponse:
        """Can the gateway serve requests? 503 if a part is not working."""
        current: Gateway | None = app.state.gateway
        if current is None:
            reply = ReadyReply(status="starting", checks={})
            return JSONResponse(reply.model_dump(), status_code=503)
        ok, checks = current.readiness()
        reply = ReadyReply(status="ready" if ok else "not_ready", checks=checks)
        return JSONResponse(reply.model_dump(), status_code=200 if ok else 503)

    app.include_router(routes.router)
    app.include_router(admin.router)
    _add_dashboard(app, settings)
    return app


def _add_dashboard(app: FastAPI, settings: Settings) -> None:
    """Serve the built dashboard at "/", so everything runs at one address.

    It is added LAST, so every API route above wins over a file with the same
    name. The browser then sees the dashboard and the API at the same
    address, so the API needs no CORS settings.
    """
    folder = settings.dashboard_dir
    if folder is None:
        return
    if not (folder / "index.html").is_file():
        logger.info(
            "No dashboard at %s (build it with: cd frontend; npm run build)", folder
        )
        return
    # html=True: "/" shows index.html. StaticFiles refuses paths that try to
    # leave the folder (like /../.env)
    app.mount("/", StaticFiles(directory=folder, html=True), name="dashboard")


async def _delete_old_events_forever(gateway: Gateway) -> None:
    """Keep the audit log short (NFR-04): now, then every hour."""
    while True:
        try:
            await asyncio.to_thread(gateway.delete_old_events)
        except Exception as error:  # noqa: BLE001 - must never stop the gateway
            logger.error("Deleting old audit events failed (%s)", type(error).__name__)
        await asyncio.sleep(CLEANUP_EVERY_SECONDS)


app = create_app()
