"""Consistent, checksummed SQLite exchange snapshots for merged providers."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


class SnapshotError(ValueError):
    pass


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _schema(connection: sqlite3.Connection, table: str) -> int:
    if table not in {"schema_migrations", "schema_version"}:
        raise SnapshotError("unsupported schema version table")
    row = connection.execute(f"SELECT MAX(version) FROM {table}").fetchone()
    if row is None or row[0] is None:
        raise SnapshotError("database has no schema version")
    return int(row[0])


def _check(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise SnapshotError("SQLite integrity check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchone():
        raise SnapshotError("SQLite foreign key check failed")


def create_snapshot(source: Path, destination: Path, *, producer: str, version_table: str) -> dict:
    if source.is_symlink():
        raise SnapshotError("source database must not be a symlink")
    source, destination = source.resolve(), destination.absolute()
    manifest = Path(str(destination) + ".manifest.json")
    if not source.is_file() or source.is_symlink():
        raise SnapshotError("source database must be an existing regular file")
    if destination.exists() or destination.is_symlink() or manifest.exists() or manifest.is_symlink():
        raise SnapshotError("snapshot destination or manifest already exists")
    if source == destination:
        raise SnapshotError("source and destination must differ")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(fd)
    temporary = Path(name)
    try:
        with (closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as source_db,
              closing(sqlite3.connect(temporary)) as output_db):
            source_db.execute("PRAGMA foreign_keys = ON")
            _check(source_db)
            _schema(source_db, version_table)
            source_db.backup(output_db)
            _check(output_db)
            version = _schema(output_db, version_table)
        os.replace(temporary, destination)
        payload = {"schema_version": 1, "producer": producer, "snapshot": destination.name,
                   "sha256": _hash(destination), "byte_count": destination.stat().st_size,
                   "producer_schema_version": version,
                   "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")}
        manifest.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return payload
    finally:
        temporary.unlink(missing_ok=True)


def verify_snapshot(path: Path, *, producer: str, version_table: str) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise SnapshotError("snapshot must be a regular file")
    path = path.resolve()
    manifest = Path(str(path) + ".manifest.json")
    if manifest.is_symlink() or not manifest.is_file():
        raise SnapshotError("snapshot manifest is missing or unsafe")
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise SnapshotError("invalid snapshot manifest") from exc
    expected = {"schema_version", "producer", "snapshot", "sha256", "byte_count",
                "producer_schema_version", "created_at"}
    if not isinstance(payload, dict) or set(payload) != expected:
        raise SnapshotError("snapshot manifest fields are invalid")
    if payload["schema_version"] != 1 or payload["producer"] != producer or payload["snapshot"] != path.name:
        raise SnapshotError("snapshot producer, filename, or schema version mismatch")
    if payload["sha256"] != _hash(path) or payload["byte_count"] != path.stat().st_size:
        raise SnapshotError("snapshot checksum or size mismatch")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _check(connection)
        if _schema(connection, version_table) != payload["producer_schema_version"]:
            raise SnapshotError("snapshot schema version mismatch")
    return payload
