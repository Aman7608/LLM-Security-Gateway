"""API keys for the apps that use the gateway (threat S1, SB1, SB2).

A key looks like `lsg_` followed by 43 random characters (256 random bits).
It is shown ONCE, when it is created. The database only keeps a SHA-256
hash of it, the same way websites keep passwords, so a stolen copy of the
database does not give anyone a working key.

Why a plain SHA-256 here, when fingerprints need HMAC? Fingerprints are made
from values that can be guessed (a 12-digit Aadhaar number). Our keys are
256 random bits, so guessing one from its hash is impossible anyway.

Two roles:
    client  may use /v1/chat, /v1/scan and /v1/providers
    admin   may also read the audit log and change the policy
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from llm_gateway.audit.tables import ApiClient

Role = Literal["client", "admin"]
KEY_PREFIX = "lsg_"  # "LLM security gateway": makes keys easy to spot in a leak


class ClientInfo(BaseModel):
    """An app that may use the gateway. Never holds the key."""

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    role: Role
    active: bool
    created_at: datetime

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class ApiKeys:
    """Creates, checks and turns off API keys."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self.sessions = sessions

    def create(self, name: str, role: Role = "client") -> tuple[ClientInfo, str]:
        """Make a new key. Returns the client and the key (shown only now)."""
        name = name.strip()
        if not 1 <= len(name) <= 100:
            raise ValueError("the name must be 1 to 100 characters")
        if role not in ("client", "admin"):
            raise ValueError("role must be 'client' or 'admin'")
        key = KEY_PREFIX + secrets.token_urlsafe(32)
        row = ApiClient(
            id="app_" + secrets.token_hex(6),
            name=name,
            key_hash=hash_key(key),
            role=role,
            active=True,
            created_at=datetime.now(UTC),
        )
        with self.sessions.begin() as session:
            session.add(row)
        return _info(row), key

    def verify(self, key: str) -> ClientInfo | None:
        """The active client this key belongs to, or None."""
        if not key.startswith(KEY_PREFIX) or len(key) > 200:
            return None  # not one of our keys: skip the database
        wanted = hash_key(key)
        with self.sessions() as session:
            row = session.scalar(select(ApiClient).where(ApiClient.key_hash == wanted))
        # compare_digest takes the same time whether the first or the last
        # character differs, so timing cannot reveal how close a guess was
        if row is None or not hmac.compare_digest(row.key_hash, wanted):
            return None
        return _info(row) if row.active else None

    def set_active(self, client_id: str, active: bool) -> bool:
        """Turn a key off (or back on). Returns False if there is no such client."""
        with self.sessions.begin() as session:
            row = session.get(ApiClient, client_id)
            if row is None:
                return False
            row.active = active
        return True

    def list(self) -> list[ClientInfo]:
        with self.sessions() as session:
            rows = session.scalars(select(ApiClient).order_by(ApiClient.created_at))
            return [_info(row) for row in rows]


def _info(row: ApiClient) -> ClientInfo:
    return ClientInfo(
        id=row.id,
        name=row.name,
        role="admin" if row.role == "admin" else "client",
        active=row.active,
        created_at=row.created_at,
    )
