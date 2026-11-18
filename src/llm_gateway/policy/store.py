"""Keeps the current policy, its version history, and changes it safely.

Rules this file follows:
  - A policy is only made active AFTER it passes every check. A broken new
    policy is rejected, and the last working one stays active.
  - Every change gets a new version number, a checksum (a fingerprint of the
    exact text) and who made it, so past decisions can be explained later.
  - If the policy file is missing or broken when the gateway STARTS, a strict
    built-in policy is used, and the problem is logged loudly. The gateway
    must never run with no policy at all.
  - Writing the file is atomic: the new text goes to a temporary file first,
    then replaces the old file in one step, so a crash halfway through can
    never leave a half-written policy behind.

History is kept in memory for now. Phase 12 saves it to the database.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from llm_gateway.policy.schema import (
    BUILT_IN_DEFAULT_POLICY,
    Policy,
    PolicyError,
    parse_policy,
)

logger = logging.getLogger(__name__)

MAX_HISTORY = 50


@dataclass(frozen=True)
class PolicyVersion:
    """One version of the policy, and where it came from."""

    version: int
    policy: Policy
    checksum: str  # SHA-256 of the policy text, to spot any change
    created_by: str
    source: str  # "file", "update", "built-in default" or "code"
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def checksum(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class PolicyStore:
    """Holds the active policy and its history. Safe to use from many threads."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._lock = threading.Lock()  # protects the history list
        # Only ONE change (reload or update) runs at a time, from start to end.
        # Without this, two updates could write the file in one order and
        # activate in the other, so the file and the active policy would
        # disagree. On Windows, two threads replacing the same file at once
        # also fails with "Access is denied". (Found by a test with 4 threads.)
        self._change_lock = threading.Lock()
        self._history: list[PolicyVersion] = []
        self.last_error: str | None = None

    # ---------- creating ----------

    @classmethod
    def from_policy(cls, policy: Policy, created_by: str = "code") -> PolicyStore:
        """A store holding one policy made in code (used by tests and scripts)."""
        store = cls()
        store._add(policy, checksum(policy.model_dump_json()), created_by, "code")
        return store

    def load(self) -> PolicyVersion:
        """Load the policy file at startup. Falls back to the built-in policy."""
        if self.path is None:
            raise PolicyError("this store has no policy file to load")
        try:
            text = self._read()
            return self._add(
                parse_policy(text, str(self.path)), checksum(text), "startup", "file"
            )
        except PolicyError as error:
            self.last_error = str(error)
            logger.critical(
                "Policy file could not be used, so the strict BUILT-IN policy is "
                "active instead. Fix the file and reload. Problem: %s",
                error,
            )
            return self._add(
                BUILT_IN_DEFAULT_POLICY,
                checksum(BUILT_IN_DEFAULT_POLICY.model_dump_json()),
                "startup",
                "built-in default",
            )

    # ---------- reading ----------

    @property
    def current(self) -> PolicyVersion:
        if not self._history:
            raise PolicyError("no policy has been loaded yet")
        return self._history[-1]

    @property
    def history(self) -> tuple[PolicyVersion, ...]:
        return tuple(self._history)

    # ---------- changing ----------

    @staticmethod
    def validate(text: str) -> Policy:
        """Check policy text WITHOUT making it active (a dry run)."""
        return parse_policy(text, "new policy")

    def reload(self) -> PolicyVersion:
        """Read the policy file again.

        If the file did not change, nothing happens. If it is broken, a
        PolicyError is raised and the current policy STAYS active.
        """
        if self.path is None:
            raise PolicyError("this store has no policy file to reload")
        with self._change_lock:
            text = self._read()
            if checksum(text) == self.current.checksum:
                return self.current
            try:
                policy = parse_policy(text, str(self.path))
            except PolicyError as error:
                self.last_error = str(error)
                logger.error(
                    "Policy reload rejected; keeping version %s", self.current.version
                )
                raise
            self.last_error = None
            return self._add(policy, checksum(text), "reload", "file")

    def update(self, text: str, created_by: str) -> PolicyVersion:
        """Check new policy text, save it to the file, and make it active.

        Nothing changes unless the text passes every check.
        """
        created_by = created_by.strip()
        if not created_by or len(created_by) > 100:
            raise PolicyError("created_by must be 1 to 100 characters")
        policy = self.validate(text)  # checking needs no lock: it changes nothing
        with self._change_lock:
            if self.path is not None:
                self._write_atomically(text)
            self.last_error = None
            return self._add(policy, checksum(text), created_by, "update")

    # ---------- helpers ----------

    def _add(
        self, policy: Policy, text_checksum: str, created_by: str, source: str
    ) -> PolicyVersion:
        with self._lock:
            number = self._history[-1].version + 1 if self._history else 1
            version = PolicyVersion(
                version=number,
                policy=policy,
                checksum=text_checksum,
                created_by=created_by,
                source=source,
            )
            # Assigning the new list in one step means readers always see
            # either the old history or the new one, never something half-built.
            self._history = [*self._history, version][-MAX_HISTORY:]
            logger.info("Policy version %s is now active (%s)", number, source)
            return version

    def _read(self) -> str:
        assert self.path is not None  # noqa: S101 - callers check this first
        try:
            return self.path.read_text(encoding="utf-8")
        except OSError as error:
            raise PolicyError(
                f"cannot read policy file {self.path}: {error}"
            ) from error

    def _write_atomically(self, text: str) -> None:
        assert self.path is not None  # noqa: S101 - callers check this first
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle, temp_name = tempfile.mkstemp(
            dir=self.path.parent, prefix=".policy-", suffix=".tmp"
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as temp_file:
                temp_file.write(text)
            os.replace(temp_name, self.path)  # one step, even on Windows
        except BaseException:
            Path(temp_name).unlink(missing_ok=True)
            raise
