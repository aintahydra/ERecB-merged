import asyncio

import httpx
import pytest

from ghintel.github_client import GithubClient, OfflineError


def test_conditional_request_reuses_304_body() -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.headers.get("if-none-match"):
            return httpx.Response(304, headers={"etag": '"abc"'})
        return httpx.Response(200, json={"full_name": "Owner/Repo"}, headers={"etag": '"abc"'})

    async def run() -> None:
        async with GithubClient(token="secret", offline=False, transport=httpx.MockTransport(handler), sleep=lambda _: None) as client:
            first = await client.repository("Owner", "Repo")
            second = await client.repository("Owner", "Repo", refresh=True)
        assert first.payload == second.payload == {"full_name": "Owner/Repo"}
        assert second.from_cache

    asyncio.run(run())
    assert len(calls) == 2
    assert "secret" not in str(calls[0].headers)


def test_offline_client_does_not_call_transport() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={})

    async def run() -> None:
        async with GithubClient(token=None, offline=True, transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(OfflineError):
                await client.repository("Owner", "Repo")

    asyncio.run(run())
    assert not called
