"""Security checks for the API: keys, logs and replies must not leak anything."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from llm_gateway.core.gateway import Gateway
from llm_gateway.settings import Settings
from tests.data.secret_samples import AWS_ACCESS_KEY_ID, GITHUB_TOKEN

Keys = dict[str, dict[str, str]]

SENSITIVE_PROMPTS = [
    "Email priya@example.com or call +91 98765 43210",
    f"My deploy key is {AWS_ACCESS_KEY_ID}",
    f"Use the token {GITHUB_TOKEN} please",
    "My Aadhaar number is 2345 6789 0124",
]
SENSITIVE = [
    "priya@example.com",
    "98765 43210",
    AWS_ACCESS_KEY_ID,
    GITHUB_TOKEN,
    "2345 6789 0124",
]


def send_everything(client: TestClient, keys: Keys) -> None:
    for prompt in SENSITIVE_PROMPTS:
        body = {"messages": [{"role": "user", "content": prompt}]}
        client.post("/v1/chat", json=body, headers=keys["client"])
        client.post("/v1/scan", json={"text": prompt}, headers=keys["client"])
    for tag in ("[mock:leak-pii]", "[mock:leak-secret]"):
        body = {"messages": [{"role": "user", "content": tag}]}
        client.post("/v1/chat", json=body, headers=keys["client"])


def test_nothing_sensitive_in_the_database(
    client: TestClient, api_keys: Keys, gateway: Gateway, gateway_settings: Settings
) -> None:
    send_everything(client, api_keys)
    gateway.audit.engine.dispose()
    folder = Path(gateway_settings.database_url.removeprefix("sqlite:///")).parent
    raw = b"".join(
        p.read_bytes() for p in folder.iterdir() if p.is_file() and ".db" in p.name
    )
    assert raw  # the database really was written
    for value in SENSITIVE:
        assert value.encode() not in raw, value[:6]
    for headers in api_keys.values():
        assert headers["X-API-Key"].encode() not in raw


def test_nothing_sensitive_in_the_logs(
    client: TestClient, api_keys: Keys, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        send_everything(client, api_keys)
        client.get(
            "/v1/events",
            params={"finding_type": "EMAIL_ADDRESS"},
            headers=api_keys["admin"],
        )
    logs = "\n".join(
        f"{record.getMessage()} {vars(record)}" for record in caplog.records
    )
    ours = "\n".join(
        f"{record.getMessage()} {vars(record)}"
        for record in caplog.records
        if record.name.startswith("llm_gateway")  # not the test's own HTTP client
    )
    assert "GET /v1/events -> 200" in ours  # the access log is there
    assert "EMAIL_ADDRESS" not in ours  # but not the query string
    for value in SENSITIVE:  # and in no log line at all, from anyone
        assert value not in logs, value[:6]
    for headers in api_keys.values():
        assert headers["X-API-Key"] not in logs


def test_replies_never_repeat_a_sensitive_value(
    client: TestClient, api_keys: Keys
) -> None:
    for prompt in SENSITIVE_PROMPTS:
        body = {"messages": [{"role": "user", "content": prompt}]}
        reply = client.post("/v1/chat", json=body, headers=api_keys["client"]).text
        for value in SENSITIVE:
            assert value not in reply, value[:6]


def test_there_is_no_api_route_for_making_keys(client: TestClient) -> None:
    """A stolen admin key must not be able to make more keys."""
    paths = client.get("/openapi.json").json()["paths"]
    assert not [p for p in paths if "key" in p or "client" in p]


def test_key_in_the_url_is_not_accepted(client: TestClient, api_keys: Keys) -> None:
    """Keys in URLs end up in browser history and server logs."""
    key = api_keys["client"]["X-API-Key"]
    response = client.post(f"/v1/scan?api_key={key}", json={"text": "hi"})
    assert response.status_code == 401


def test_turning_a_key_off_works_at_once(
    client: TestClient, api_keys: Keys, gateway: Gateway
) -> None:
    headers = api_keys["client"]
    assert (
        client.post("/v1/scan", json={"text": "hi"}, headers=headers).status_code == 200
    )
    (app,) = [c for c in gateway.audit.api_keys.list() if c.name == "Test app"]
    gateway.audit.api_keys.set_active(app.id, False)
    assert (
        client.post("/v1/scan", json={"text": "hi"}, headers=headers).status_code == 401
    )
