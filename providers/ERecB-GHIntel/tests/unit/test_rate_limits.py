import asyncio
import time

import httpx
import pytest

from ghintel.github_client import GithubClient, GithubRateLimitExhausted


def test_successful_rate_limit_header_stops_before_the_next_request() -> None:
    calls: list[str] = []
    delays: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        headers = {
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": str(time.time() + 120),
        } if request.url.path.endswith("/One") else {}
        return httpx.Response(200, json={"full_name": request.url.path}, headers=headers)

    async def sleep(delay: float) -> None:
        delays.append(delay)

    async def run() -> None:
        async with GithubClient(token=None, offline=False, transport=httpx.MockTransport(handler), sleep=sleep) as client:
            await client.repository("Example", "One")
            with pytest.raises(GithubRateLimitExhausted) as raised:
                await client.repository("Example", "Two")
            assert raised.value.retry_after_seconds > 0

    asyncio.run(run())
    assert calls == ["/repos/Example/One"]
    assert delays == []


def test_rate_limited_response_is_not_retried_or_slept() -> None:
    calls = 0
    delays: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, json={"message": "rate limited"}, headers={"retry-after": "120"})

    async def sleep(delay: float) -> None:
        delays.append(delay)

    async def run() -> None:
        async with GithubClient(token=None, offline=False, transport=httpx.MockTransport(handler), sleep=sleep) as client:
            with pytest.raises(GithubRateLimitExhausted) as raised:
                await client.repository("Example", "One")
            assert raised.value.retry_after_seconds == pytest.approx(120, abs=0.1)

    asyncio.run(run())
    assert calls == 1
    assert delays == []


def test_transient_failure_retries_through_the_shared_gate() -> None:
    attempts = 0
    delays: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(500 if attempts == 1 else 200, json={"full_name": "Example/Tool"})

    async def sleep(delay: float) -> None:
        delays.append(delay)

    async def run() -> None:
        async with GithubClient(token=None, offline=False, transport=httpx.MockTransport(handler), sleep=sleep) as client:
            response = await client.repository("Example", "Tool")
            assert response.payload["full_name"] == "Example/Tool"

    asyncio.run(run())
    assert attempts == 2
    assert delays == pytest.approx([1.0], abs=0.01)
