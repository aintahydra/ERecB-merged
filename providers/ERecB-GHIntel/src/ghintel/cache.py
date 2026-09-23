"""Safe HTTP cache primitives; cache entries never contain request credentials."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Mapping


@dataclass(frozen=True, slots=True)
class CacheEntry:
    status_code: int
    body: bytes
    etag: str | None
    last_modified: str | None
    headers: dict[str, str]
    fetched_at: datetime
    expires_at: datetime


def cache_key(method: str, url: str, accept: str, api_version: str) -> str:
    canonical = json.dumps({"method": method.upper(), "url": url, "accept": accept, "api_version": api_version}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def safe_headers(headers: Mapping[str, str]) -> dict[str, str]:
    permitted = {"etag", "last-modified", "content-type", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after"}
    return {key.casefold(): value for key, value in headers.items() if key.casefold() in permitted}


def expires_in(hours: int) -> datetime:
    return datetime.now(UTC) + timedelta(hours=hours)


class MemoryCache:
    def __init__(self) -> None:
        self._entries: dict[str, CacheEntry] = {}

    def get(self, key: str) -> CacheEntry | None:
        return self._entries.get(key)

    def set(self, key: str, entry: CacheEntry) -> None:
        self._entries[key] = entry


class SqliteCache:
    """Persistent cache shared by fetch runs; credentials are never stored."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def get(self, key: str) -> CacheEntry | None:
        row = self.connection.execute(
            "SELECT status_code, body, etag, last_modified, response_headers_json, fetched_at, expires_at "
            "FROM http_cache_entries WHERE request_key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        return CacheEntry(
            status_code=int(row["status_code"]), body=bytes(row["body"]), etag=row["etag"], last_modified=row["last_modified"],
            headers=json.loads(row["response_headers_json"]),
            fetched_at=datetime.fromisoformat(row["fetched_at"]), expires_at=datetime.fromisoformat(row["expires_at"]),
        )

    def set(self, key: str, entry: CacheEntry) -> None:
        now = datetime.now(UTC).isoformat(timespec="seconds")
        self.connection.execute(
            """INSERT INTO http_cache_entries(request_key, status_code, body, etag, last_modified,
               response_headers_json, fetched_at, validated_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(request_key) DO UPDATE SET status_code=excluded.status_code, body=excluded.body,
               etag=excluded.etag, last_modified=excluded.last_modified, response_headers_json=excluded.response_headers_json,
               validated_at=excluded.validated_at, expires_at=excluded.expires_at""",
            (key, entry.status_code, entry.body, entry.etag, entry.last_modified, json.dumps(entry.headers, sort_keys=True),
             entry.fetched_at.isoformat(), now, entry.expires_at.isoformat()),
        )
