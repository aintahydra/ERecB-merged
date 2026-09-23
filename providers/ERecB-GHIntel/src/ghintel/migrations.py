"""Numbered, checksummed SQLite migration runner."""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path


class MigrationError(RuntimeError):
    pass


def apply_migrations(connection: sqlite3.Connection, directory: Path | None = None) -> list[int]:
    """Apply numbered SQL migrations from a caller override or packaged resources."""
    migration_files = (
        sorted(directory.glob("[0-9][0-9][0-9]_*.sql"))
        if directory is not None
        else sorted(
            (
                resource
                for resource in files("ghintel").joinpath("sql_migrations").iterdir()
                if resource.name.endswith(".sql") and len(resource.name) >= 5 and resource.name[:3].isdigit()
            ),
            key=lambda resource: resource.name,
        )
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    applied = {row[0]: (row[1], row[2]) for row in connection.execute("SELECT version, name, checksum FROM schema_migrations")}
    applied_now: list[int] = []
    for path in migration_files:
        version = int(path.name.split("_", 1)[0])
        sql = path.read_text(encoding="utf-8")
        checksum = hashlib.sha256(sql.encode()).hexdigest()
        if version in applied:
            if applied[version] != (path.name, checksum):
                raise MigrationError(f"migration checksum mismatch: {path.name}")
            continue
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                (version, path.name, checksum, _now()),
            )
            connection.commit()
        except sqlite3.Error:
            connection.rollback()
            raise
        applied_now.append(version)
    return applied_now


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
