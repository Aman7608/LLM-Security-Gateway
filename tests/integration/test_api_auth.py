"""API keys, roles and rate limits through the real app."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from llm_gateway.core.gateway import Gateway
from llm_gateway.main import create_app
from llm_gateway.settings import Settings

Keys = dict[str, dict[str, str]]
SCAN = {"text": "hello"}


def error_code(response: object) -> str:
    return response.json()["error"]["code"]  # type: ignore[attr-defined, no-any-return]


def test_no_key(client: TestClient) -> None:
    response = client.post("/v1/scan", json=SCAN)
    assert response.status_code == 401
    assert error_code(response) == "missing_api_key"
    assert response.headers["www-authenticate"] == "ApiKey"


def test_wrong_key(client: TestClient) -> None:
    response = client.post("/v1/scan", json=SCAN, headers={"X-API-Key": "lsg_nope"})
    assert response.status_code == 401
    assert error_code(response) == "invalid_api_key"


def test_turned_off_key_gets_the_same_answer_as_a_wrong_one(
    client: TestClient, gateway: Gateway
) -> None:
    info, key = gateway.audit.api_keys.create("Old app")
    gateway.audit.api_keys.set_active(info.id, False)
    response = client.post("/v1/scan", json=SCAN, headers={"X-API-Key": key})
    assert response.status_code == 401
    assert error_code(response) == "invalid_api_key"


def test_client_key_works_on_client_routes(client: TestClient, api_keys: Keys) -> None:
    assert (
        client.post("/v1/scan", json=SCAN, headers=api_keys["client"]).status_code
        == 200
    )
    assert client.get("/v1/providers", headers=api_keys["client"]).status_code == 200


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/events"),
        ("GET", "/v1/events/req-1"),
        ("GET", "/v1/stats"),
        ("GET", "/v1/stats/timeline"),
        ("GET", "/v1/policies/active"),
        ("PUT", "/v1/policies/active"),
        ("POST", "/v1/policies/validate"),
        ("GET", "/v1/policies/history"),
    ],
)
def test_client_key_cannot_use_admin_routes(
    client: TestClient, api_keys: Keys, method: str, path: str
) -> None:
    response = client.request(
        method, path, headers=api_keys["client"], json={"policy": "x"}
    )
    assert response.status_code == 403
    assert error_code(response) == "admin_required"


def test_admin_key_works_everywhere(client: TestClient, api_keys: Keys) -> None:
    assert (
        client.post("/v1/scan", json=SCAN, headers=api_keys["admin"]).status_code == 200
    )
    assert client.get("/v1/events", headers=api_keys["admin"]).status_code == 200


def test_health_and_ready_need_no_key(client: TestClient) -> None:
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200


def test_key_is_checked_before_the_body(client: TestClient) -> None:
    """A caller without a key learns nothing, not even if the body was valid."""
    response = client.post("/v1/chat", json={"messages": []})
    assert response.status_code == 401


@pytest.fixture
def strict_client(gateway_settings: Settings, gateway: Gateway) -> Iterator[TestClient]:
    settings = gateway_settings.model_copy(update={"rate_limit_per_minute": 2})
    with TestClient(create_app(settings, gateway)) as test_client:
        yield test_client


def test_rate_limit(strict_client: TestClient, api_keys: Keys) -> None:
    headers = api_keys["client"]
    for _ in range(2):
        assert (
            strict_client.post("/v1/scan", json=SCAN, headers=headers).status_code
            == 200
        )
    response = strict_client.post("/v1/scan", json=SCAN, headers=headers)
    assert response.status_code == 429
    assert error_code(response) == "rate_limited"
    assert 1 <= int(response.headers["retry-after"]) <= 60


def test_rate_limit_is_per_key(strict_client: TestClient, api_keys: Keys) -> None:
    for _ in range(3):
        strict_client.post("/v1/scan", json=SCAN, headers=api_keys["client"])
    other = strict_client.post("/v1/scan", json=SCAN, headers=api_keys["admin"])
    assert other.status_code == 200
