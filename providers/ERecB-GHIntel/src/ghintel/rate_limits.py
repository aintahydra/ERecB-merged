"""GitHub response-header based retry and shared rate-limit coordination."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Awaitable, Callable, Mapping


def retry_delay_seconds(headers: Mapping[str, str], *, now: datetime | None = None, fallback: float = 60.0) -> float:
    lowered = {key.casefold(): value for key, value in headers.items()}
    retry_after = lowered.get("retry-after")
    if retry_after:
        try:
            return max(0.0, float(retry_after))
        except ValueError:
            try:
                target = parsedate_to_datetime(retry_after)
                return max(0.0, (target - (now or datetime.now(UTC))).total_seconds())
            except (TypeError, ValueError):
                pass
    if lowered.get("x-ratelimit-remaining") == "0" and lowered.get("x-ratelimit-reset"):
        try:
            return max(0.0, float(lowered["x-ratelimit-reset"]) - (now or datetime.now(UTC)).timestamp())
        except ValueError:
            pass
    return fallback


def backoff_seconds(attempt: int, *, base: float = 1.0, maximum: float = 60.0) -> float:
    return min(maximum, base * (2**max(0, attempt)))


class RateLimitCoordinator:
    """One process-wide gate for requests sharing a GitHub token/client."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._not_before = 0.0
        self._lock = asyncio.Lock()

    async def wait(self, sleep: Callable[[float], Awaitable[object]]) -> None:
        async with self._lock:
            delay = max(0.0, self._not_before - self._clock())
        if delay:
            await sleep(delay)

    async def defer(self, delay: float) -> None:
        async with self._lock:
            self._not_before = max(self._not_before, self._clock() + max(0.0, delay))
