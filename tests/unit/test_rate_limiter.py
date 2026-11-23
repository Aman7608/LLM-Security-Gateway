"""Tests for llm_gateway.api.rate_limit, with a fake clock (no waiting)."""

from __future__ import annotations

import threading

import pytest

from llm_gateway.api.rate_limit import RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_allows_up_to_the_limit_then_refuses() -> None:
    clock = FakeClock()
    limiter = RateLimiter(3, clock)
    assert [limiter.check("a") for _ in range(3)] == [None, None, None]
    assert limiter.check("a") == 60.0  # the first request leaves in 60 s


def test_window_slides() -> None:
    clock = FakeClock()
    limiter = RateLimiter(2, clock)
    limiter.check("a")
    clock.now += 30
    limiter.check("a")
    clock.now += 10
    assert limiter.check("a") == pytest.approx(20.0)
    clock.now += 20  # the first request is now 60 s old
    assert limiter.check("a") is None


def test_refused_requests_do_not_count() -> None:
    clock = FakeClock()
    limiter = RateLimiter(1, clock)
    limiter.check("a")
    for _ in range(5):
        limiter.check("a")  # refused
    clock.now += 60
    assert limiter.check("a") is None


def test_each_key_has_its_own_limit() -> None:
    limiter = RateLimiter(1, FakeClock())
    assert limiter.check("a") is None
    assert limiter.check("b") is None
    assert limiter.check("a") is not None


@pytest.mark.parametrize(("wait", "header"), [(0.0, "1"), (0.2, "1"), (59.1, "60")])
def test_retry_after_is_whole_seconds(wait: float, header: str) -> None:
    assert RateLimiter.retry_after_header(wait) == header


def test_limit_must_be_positive() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        RateLimiter(0)


def test_exact_count_with_many_threads() -> None:
    limiter = RateLimiter(100, FakeClock())
    allowed = []

    def hammer() -> None:
        for _ in range(50):
            if limiter.check("a") is None:
                allowed.append(1)

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(allowed) == 100  # never one too many
