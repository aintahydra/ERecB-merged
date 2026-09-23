"""Read-only, async GitHub REST client with conditional cache support."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import httpx

from .cache import CacheEntry, MemoryCache, cache_key, expires_in, safe_headers
from .rate_limits import RateLimitCoordinator, backoff_seconds, retry_delay_seconds

_API = "https://api.github.com"
_ACCEPT = "application/vnd.github+json"
_VERSION = "2022-11-28"


class OfflineError(RuntimeError):
    pass


class GithubRequestError(RuntimeError):
    pass


class GithubRateLimitExhausted(GithubRequestError):
    """The current GitHub quota window cannot accept another request."""

    def __init__(self, *, reset_at: datetime, retry_after_seconds: float, status_code: int | None = None) -> None:
        self.reset_at = reset_at
        self.retry_after_seconds = max(0.0, retry_after_seconds)
        self.status_code = status_code
        super().__init__(f"GitHub rate limit exhausted until {reset_at.isoformat()}")


class HttpCache(Protocol):
    def get(self, key: str) -> CacheEntry | None: ...
    def set(self, key: str, entry: CacheEntry) -> None: ...


@dataclass(frozen=True, slots=True)
class GithubResponse:
    status_code: int
    payload: dict[str, Any]
    from_cache: bool
    headers: dict[str, str]


class GithubClient:
    def __init__(
        self,
        *,
        token: str | None,
        offline: bool,
        timeout_seconds: float = 30,
        max_retries: int = 5,
        cache_ttl_hours: int = 24,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Any = asyncio.sleep,
        cache: HttpCache | None = None,
        rate_limits: RateLimitCoordinator | None = None,
    ) -> None:
        self.offline = offline
        self.max_retries = max_retries
        self.cache_ttl_hours = cache_ttl_hours
        self.sleep = sleep
        headers = {"Accept": _ACCEPT, "X-GitHub-Api-Version": _VERSION, "User-Agent": "ghintel/0.1"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(base_url=_API, headers=headers, timeout=timeout_seconds, follow_redirects=True, transport=transport)
        self.cache = cache or MemoryCache()
        self.rate_limits = rate_limits or RateLimitCoordinator()
        self._exhausted_until: datetime | None = None

    async def __aenter__(self) -> "GithubClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self._client.aclose()

    async def repository(self, owner: str, name: str, *, refresh: bool = False) -> GithubResponse:
        return await self._get(f"/repos/{owner}/{name}", refresh=refresh)

    async def readme(self, owner: str, name: str, *, refresh: bool = False) -> GithubResponse:
        return await self._get(f"/repos/{owner}/{name}/readme", refresh=refresh)

    async def profile(self, login: str, *, refresh: bool = False) -> GithubResponse:
        return await self._get(f"/users/{login}", refresh=refresh)

    async def _get(self, path: str, *, refresh: bool) -> GithubResponse:
        if self.offline:
            raise OfflineError("GitHub HTTP is disabled by github.offline")
        url = str(self._client.base_url.join(path))
        key = cache_key("GET", url, _ACCEPT, _VERSION)
        cached = self.cache.get(key)
        now = datetime.now(UTC)
        if cached and not refresh and cached.expires_at > now:
            return GithubResponse(cached.status_code, _json(cached.body), True, cached.headers)
        self._raise_if_exhausted(now)
        headers: dict[str, str] = {}
        if cached and cached.etag:
            headers["If-None-Match"] = cached.etag
        elif cached and cached.last_modified:
            headers["If-Modified-Since"] = cached.last_modified
        for attempt in range(self.max_retries + 1):
            await self.rate_limits.wait(self.sleep)
            response = await self._client.get(path, headers=headers)
            rate_limit = _rate_limit_from_response(response.status_code, response.headers)
            if rate_limit is not None:
                self._exhausted_until = rate_limit.reset_at
            if response.status_code == 304 and cached:
                refreshed = CacheEntry(cached.status_code, cached.body, cached.etag, cached.last_modified, cached.headers, cached.fetched_at, expires_in(self.cache_ttl_hours))
                self.cache.set(key, refreshed)
                return GithubResponse(cached.status_code, _json(cached.body), True, cached.headers)
            if response.status_code < 400:
                entry = CacheEntry(response.status_code, response.content, response.headers.get("etag"), response.headers.get("last-modified"), safe_headers(response.headers), now, expires_in(self.cache_ttl_hours))
                self.cache.set(key, entry)
                return GithubResponse(response.status_code, _json(response.content), False, entry.headers)
            if rate_limit is not None:
                raise rate_limit
            if response.status_code in {500, 502, 503, 504} and attempt < self.max_retries:
                delay = backoff_seconds(attempt)
                await self.rate_limits.defer(delay)
                continue
            detail = "private or unavailable resource" if response.status_code == 404 else f"HTTP {response.status_code}"
            raise GithubRequestError(detail)
        raise GithubRequestError("retry budget exhausted")

    def _raise_if_exhausted(self, now: datetime) -> None:
        if self._exhausted_until is None:
            return
        remaining = (self._exhausted_until - now).total_seconds()
        if remaining <= 0:
            self._exhausted_until = None
            return
        raise GithubRateLimitExhausted(reset_at=self._exhausted_until, retry_after_seconds=remaining)


def _json(body: bytes) -> dict[str, Any]:
    try:
        value = httpx.Response(200, content=body).json()
    except ValueError as error:
        raise GithubRequestError("GitHub response was not valid JSON") from error
    if not isinstance(value, dict):
        raise GithubRequestError("GitHub response was not an object")
    return value


def _rate_limit_from_response(status_code: int, headers: httpx.Headers) -> GithubRateLimitExhausted | None:
    lowered = {key.casefold(): value for key, value in headers.items()}
    exhausted = lowered.get("x-ratelimit-remaining") == "0" or "retry-after" in lowered or status_code == 429
    if not exhausted:
        return None
    now = datetime.now(UTC)
    delay = retry_delay_seconds(headers, now=now)
    return GithubRateLimitExhausted(
        reset_at=now + timedelta(seconds=delay),
        retry_after_seconds=delay,
        status_code=status_code,
    )
