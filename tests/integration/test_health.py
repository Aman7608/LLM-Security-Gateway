"""Tests for the starting app: the /health route and the API docs."""

from __future__ import annotations

from fastapi.testclient import TestClient

from llm_gateway import __version__


def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "version": __version__,
        "environment": "test",
    }


def test_api_docs_are_available(client: TestClient) -> None:
    assert client.get("/docs").status_code == 200
    schema = client.get("/openapi.json").json()
    assert schema["info"]["title"] == "LLM Security Gateway"
    assert "/health" in schema["paths"]


def test_unknown_route_returns_404(client: TestClient) -> None:
    assert client.get("/does-not-exist").status_code == 404


def test_health_only_allows_get(client: TestClient) -> None:
    assert client.post("/health").status_code == 405
