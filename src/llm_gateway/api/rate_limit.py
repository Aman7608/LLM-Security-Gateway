"""A simple rate limiter: at most N requests per API key per minute (SB4).

How it works ("sliding window"): for each key we remember the times of its
requests in the last 60 seconds. A new request is allowed if there are
fewer than N. Old times are dropped as they get older than 60 seconds.

    limit 3:   |--x----x---x--------| now   -> 3 in the window: refuse
               ^ 60 seconds ago

It lives in memory, so:
  - it resets when the gateway restarts
  - two copies of the gateway each count on their own
That is fine for one gateway. For several copies, a shared counter (Redis)
would be needed (see the requirements, section 4).
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from collections.abc import Callable

WINDOW_SECONDS = 60.0


class RateLimiter:
    def __init__(
        self, per_minute: int, clock: Callable[[], float] = time.monotonic
    ) -> None:
        if per_minute < 1:
            raise ValueError("per_minute must be at least 1")
        self.per_minute = per_minute
        self._clock = clock  # tests pass a fake clock instead of waiting
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> float | None:
        """Count one request. Returns None if allowed, or seconds to wait."""
        now = self._clock()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= now - WINDOW_SECONDS:
                hits.popleft()
            if len(hits) >= self.per_minute:
                # The oldest request leaves the window first
                return max(hits[0] + WINDOW_SECONDS - now, 0.0)
            hits.append(now)
            return None

    @staticmethod
    def retry_after_header(wait: float) -> str:
        return str(max(1, math.ceil(wait)))
