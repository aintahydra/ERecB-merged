"""Read-only project-card lookup against the producer-owned GHIntel database."""
from __future__ import annotations

import json
import sqlite3
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

from erecb_triage.processors.base import ProcessorError


_VIEW_COLUMNS = {"repository_id", "identity_key", "canonical_url", "owner", "name", "finding_id",
                 "finding_version", "purpose", "tool_types_json", "capabilities_json", "intended_uses_json",
                 "finding_provenance", "finding_created_at", "owner_login", "owner_display_name", "owner_type",
                 "github_captured_at", "documented_people_json", "information_status"}
_TABLES = {"repositories", "findings", "repository_current_findings", "corrections", "github_snapshots",
           "people", "repository_people", "language_inferences"}


@dataclass(frozen=True)
class LookupResult:
    status: str
    card: dict | None = None
    error: ProcessorError | None = None


class GHIntelRepository:
    def __init__(self, db_path: Path) -> None:
        if not db_path.is_absolute():
            raise ValueError("GHIntel database path must be absolute")
        self.db_path, self.connection, self.initialization_error = db_path, None, None
        self._cache: dict[str, LookupResult] = {}
        self._entered = self._closed = False

    @property
    def available(self) -> bool:
        return self.connection is not None

    def __enter__(self):
        self._entered = True
        try:
            self.connection = sqlite3.connect(self.db_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA query_only=ON")
            self.connection.execute("PRAGMA trusted_schema=OFF")
            self._check_schema()
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.initialization_error = ProcessorError(self.db_path, str(exc), "ghintel_db_unavailable")
            self._close()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True
        self._cache.clear()
        self._close()

    def _close(self) -> None:
        if self.connection is not None:
            connection, self.connection = self.connection, None
            connection.close()

    def _check_schema(self) -> None:
        assert self.connection is not None
        for table in _TABLES:
            row = self.connection.execute("SELECT type FROM sqlite_schema WHERE name=?", (table,)).fetchone()
            if row is None or row["type"] != "table":
                raise ValueError(f"missing GHIntel table: {table}")
        columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(repository_project_cards)")}
        if not _VIEW_COLUMNS.issubset(columns):
            raise ValueError("incompatible repository_project_cards view")

    def lookup(self, identity_key: str) -> LookupResult:
        if not self._entered or self._closed:
            raise RuntimeError("lookup requires an active GHIntel repository")
        if identity_key in self._cache:
            return deepcopy(self._cache[identity_key])
        if self.initialization_error:
            result = LookupResult("unavailable", error=self.initialization_error)
        else:
            try:
                assert self.connection is not None
                self.connection.execute("BEGIN")
                row = self.connection.execute("SELECT * FROM repository_project_cards WHERE identity_key=?", (identity_key,)).fetchone()
                self.connection.rollback()
                if row is None:
                    result = LookupResult("miss")
                else:
                    card = dict(row)
                    for field in ("tool_types_json", "capabilities_json", "intended_uses_json", "documented_people_json"):
                        value = json.loads(card[field] or "[]")
                        if not isinstance(value, list):
                            raise ValueError(f"invalid project-card JSON: {field}")
                        card[field.removesuffix("_json")] = value
                    if card["information_status"] not in {"ready", "deterministic-only", "not-enriched"}:
                        raise ValueError("invalid project-card information status")
                    result = LookupResult("hit", card=card)
            except (sqlite3.Error, ValueError, json.JSONDecodeError) as exc:
                result = LookupResult("error", error=ProcessorError(self.db_path, str(exc), "ghintel_lookup_error"))
        self._cache[identity_key] = result
        return deepcopy(result)
