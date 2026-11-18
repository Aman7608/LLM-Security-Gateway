"""Creates the FastAPI app.

This is only a starting point: a single /health route that proves the
project structure works. Phase 13 adds the real API routes.

Run it with:
    .\\.venv\\Scripts\\python.exe -m uvicorn llm_gateway.main:app --reload
"""

from __future__ import annotations

from fastapi import FastAPI

from llm_gateway import __version__
from llm_gateway.settings import Settings, get_settings


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the app. Tests can pass in their own settings."""
    settings = settings or get_settings()

    app = FastAPI(
        title="LLM Security Gateway",
        version=__version__,
        description="Checks prompts and AI answers for attacks and data leaks.",
    )
    app.state.settings = settings

    @app.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        """Returns ok if the program is running."""
        return {
            "status": "ok",
            "version": __version__,
            "environment": settings.environment.value,
        }

    return app


app = create_app()
