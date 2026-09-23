"""Read-only, capture-scoped access to the erecb-fileintel database."""

from __future__ import annotations

import sqlite3
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .contracts import (
    FileName, HistoricalObservation, LookupStatus, Malicious, MatchType,
    ProviderLookup, Tag,
)
from ..processors.base import ProcessorError


_FILE_COLUMNS = (
    "id", "sha256_hash", "md5_hash", "magic", "malicious", "created_at", "updated_at",
)
_CHILD_QUERIES = {
    "file_names": (
        ("file_name", "source", "first_seen_at"), "source, file_name, id",
    ),
    "tags": (("tag", "source", "first_seen_at"), "source, tag, id"),
    "provider_lookups": (
        ("provider", "query_hash", "query_hash_type", "status", "http_status",
         "requested_at", "completed_at", "raw_response_path", "error_message"),
        "completed_at DESC, requested_at DESC, id DESC",
    ),
    "file_observations": (
        ("file_path", "file_name", "magic", "observed_at"),
        "observed_at DESC, file_path, id",
    ),
}
_REQUIRED_COLUMNS = {
    "files": set(_FILE_COLUMNS),
    **{table: {"id", "file_id", *columns}
       for table, (columns, _) in _CHILD_QUERIES.items()},
    "scan_jobs": {
        "id", "mode", "root_path", "status", "started_at", "finished_at", "files_seen",
        "executables_found", "error_count",
    },
    "scan_errors": {
        "id", "scan_job_id", "file_path", "phase", "error_type", "error_message", "occurred_at",
    },
}


@dataclass(frozen=True)
class FileIntelligence:
    """Database metadata only; no current-capture identity or evidence paths."""

    match_type: MatchType
    file_entity_id: int
    db_sha256_hash: str | None
    db_md5_hash: str | None
    magic: str | None
    malicious: Malicious
    created_at: str
    updated_at: str
    file_names: list[FileName]
    tags: list[Tag]
    provider_lookups: list[ProviderLookup]
    historical_observations: list[HistoricalObservation]


@dataclass(frozen=True)
class LookupResult:
    status: LookupStatus
    intelligence: FileIntelligence | None = None
    candidate_file_entity_ids: tuple[int, ...] = ()
    reason: Literal["multiple_md5_rows", "conflicting_sha256"] | None = None
    error: ProcessorError | None = None


class _IncompatibleSchema(Exception):
    pass


class FileIntelRepository:
    """Use one context manager per capture, including captures with zero hashes.

    Initialization failures are exposed via initialization_error and unavailable
    lookup results. The caller emits that warning once per capture. Individual
    query failures carry their own error. Instances cannot be reopened or shared
    across captures; close discards the cache and lookup after close is invalid.
    """

    def __init__(self, db_path: Path):
        if not db_path.is_absolute():
            raise ValueError("FileIntel database path must be absolute")
        self.db_path = db_path
        self.initialization_error: ProcessorError | None = None
        self._connection: sqlite3.Connection | None = None
        self._entered = False
        self._closed = False
        self._cache: dict[str, tuple[str, LookupResult]] = {}

    @property
    def available(self) -> bool:
        return self._connection is not None

    def __enter__(self) -> FileIntelRepository:
        if self._entered or self._closed:
            raise RuntimeError("FileIntel repository sessions are single-use")
        self._entered = True
        try:
            self._connection = sqlite3.connect(
                self.db_path.as_uri() + "?mode=ro", uri=True, isolation_level=None,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA query_only = ON")
            self._connection.execute("PRAGMA trusted_schema = OFF")
            self._check_schema()
        except (sqlite3.Error, OSError, _IncompatibleSchema) as exc:
            code = (
                "fileintel_schema_incompatible" if isinstance(exc, _IncompatibleSchema)
                else "fileintel_db_unavailable"
            )
            self.initialization_error = ProcessorError(self.db_path, str(exc), code)
            self._close_connection()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def _close_connection(self) -> None:
        if self._connection is not None:
            connection, self._connection = self._connection, None
            connection.close()

    def close(self) -> None:
        self._closed = True
        self._cache.clear()
        self._close_connection()

    def _check_schema(self) -> None:
        assert self._connection is not None
        for table, required in _REQUIRED_COLUMNS.items():
            row = self._connection.execute(
                "SELECT type FROM sqlite_schema WHERE name = ?", (table,),
            ).fetchone()
            if row is None or row["type"] != "table":
                raise _IncompatibleSchema(f"Missing lookup table: {table}")
            # Identifiers are fixed constants, never database or caller text.
            columns = {
                row["name"] for row in self._connection.execute(f'PRAGMA table_info("{table}")')
            }
            missing = required - columns
            if missing:
                raise _IncompatibleSchema(
                    f"Missing columns in {table}: {', '.join(sorted(missing))}"
                )

    def lookup(self, sha256_hash: str, md5_hash: str) -> LookupResult:
        if not self._entered or self._closed:
            raise RuntimeError("Lookup requires an active FileIntel repository context")
        for name, value, length in (("SHA-256", sha256_hash, 64), ("MD5", md5_hash, 32)):
            if (not isinstance(value, str) or len(value) != length
                    or any(char not in "0123456789abcdef" for char in value)):
                raise ValueError(f"{name} must be a lowercase hexadecimal digest")
        if sha256_hash in self._cache:
            cached_md5, result = self._cache[sha256_hash]
            if md5_hash != cached_md5:
                raise ValueError("Conflicting MD5 values for the same observed SHA-256")
            return deepcopy(result)
        if self.initialization_error is not None:
            result = LookupResult("unavailable", error=self.initialization_error)
        else:
            assert self._connection is not None
            try:
                # A short snapshot keeps the parent and all child queries coherent
                # without pinning a read transaction for the whole capture.
                self._connection.execute("BEGIN")
                try:
                    result = self._lookup(sha256_hash, md5_hash)
                finally:
                    self._connection.rollback()
            except sqlite3.Error as exc:
                result = LookupResult("error", error=ProcessorError(
                    self.db_path, str(exc), "fileintel_lookup_error",
                ))
        self._cache[sha256_hash] = (md5_hash, result)
        return deepcopy(result)

    def _lookup(self, sha256_hash: str, md5_hash: str) -> LookupResult:
        assert self._connection is not None
        select = f"SELECT {', '.join(_FILE_COLUMNS)} FROM files"
        rows = self._connection.execute(
            select + " WHERE sha256_hash = ? ORDER BY id", (sha256_hash,),
        ).fetchall()
        match_type: MatchType = "sha256"
        if len(rows) > 1:
            raise sqlite3.DatabaseError("Multiple file entities have the same SHA-256")
        if not rows:
            match_type = "md5"
            rows = self._connection.execute(
                select + " WHERE md5_hash = ? ORDER BY id", (md5_hash,),
            ).fetchall()
            if not rows:
                return LookupResult("miss")
            if len(rows) > 1 or rows[0]["sha256_hash"] not in (None, sha256_hash):
                return LookupResult(
                    "ambiguous",
                    candidate_file_entity_ids=tuple(sorted({row["id"] for row in rows})),
                    reason="multiple_md5_rows" if len(rows) > 1 else "conflicting_sha256",
                )
        row = rows[0]
        if row["malicious"] not in {"yes", "no", "unknown"}:
            raise sqlite3.DatabaseError("File entity has an invalid malicious verdict")
        children = {}
        for table, (columns, ordering) in _CHILD_QUERIES.items():
            children[table] = [dict(child) for child in self._connection.execute(
                f"SELECT {', '.join(columns)} FROM {table} WHERE file_id = ? ORDER BY {ordering}",
                (row["id"],),
            )]
        return LookupResult("hit", intelligence=FileIntelligence(
            match_type=match_type,
            file_entity_id=row["id"],
            db_sha256_hash=row["sha256_hash"],
            db_md5_hash=row["md5_hash"],
            magic=row["magic"],
            malicious=row["malicious"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            file_names=children["file_names"],
            tags=children["tags"],
            provider_lookups=children["provider_lookups"],
            historical_observations=children["file_observations"],
        ))
