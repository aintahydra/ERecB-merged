"""Online SQLite backup snapshots with integrity and checksum verification."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

APP_VERSION = "0.1.2"


class SnapshotError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SnapshotInfo:
    snapshot: str
    manifest: str
    sha256: str
    byte_count: int
    schema_version: int
    integrity_check: str
    created_at: str


def create_snapshot(source: Path, destination: Path) -> SnapshotInfo:
    """Use SQLite's online-backup API, then atomically publish a verified file."""
    source = source.resolve()
    destination = destination.resolve()
    manifest = manifest_path(destination)
    if not source.is_file():
        raise SnapshotError(f"database does not exist: {source}")
    if destination.exists() or manifest.exists():
        raise SnapshotError("snapshot destination or manifest already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, raw_temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    os.close(handle)
    temporary = Path(raw_temporary)
    try:
        source_connection = sqlite3.connect(source)
        target_connection = sqlite3.connect(temporary)
        try:
            source_connection.backup(target_connection)
            target_connection.commit()
            integrity = _integrity(target_connection)
            if integrity != "ok":
                raise SnapshotError(f"snapshot integrity_check failed: {integrity}")
            version = _schema_version(target_connection)
        finally:
            target_connection.close()
            source_connection.close()
        os.replace(temporary, destination)
        info = SnapshotInfo(destination.name, manifest.name, _sha256(destination), destination.stat().st_size, version, integrity, _now())
        _atomic_json(manifest, asdict(info))
        return info
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def verify_snapshot(snapshot: Path, manifest: Path | None = None) -> SnapshotInfo:
    snapshot = snapshot.resolve()
    manifest = (manifest or manifest_path(snapshot)).resolve()
    if not snapshot.is_file() or not manifest.is_file():
        raise SnapshotError("snapshot and manifest must both exist")
    try:
        payload: dict[str, Any] = json.loads(manifest.read_text(encoding="utf-8"))
        expected = SnapshotInfo(**payload)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise SnapshotError(f"invalid snapshot manifest: {error}") from error
    if expected.snapshot != snapshot.name or expected.manifest != manifest.name:
        raise SnapshotError("snapshot manifest names do not match the requested files")
    if _sha256(snapshot) != expected.sha256 or snapshot.stat().st_size != expected.byte_count:
        raise SnapshotError("snapshot checksum or byte count does not match manifest")
    connection = sqlite3.connect(snapshot)
    try:
        integrity = _integrity(connection)
        version = _schema_version(connection)
    finally:
        connection.close()
    if integrity != "ok" or version != expected.schema_version:
        raise SnapshotError("snapshot integrity or schema version does not match manifest")
    return expected


def manifest_path(snapshot: Path) -> Path:
    return snapshot.with_suffix(snapshot.suffix + ".manifest.json")


def _integrity(connection: sqlite3.Connection) -> str:
    row = connection.execute("PRAGMA integrity_check").fetchone()
    return str(row[0]) if row else "missing integrity result"


def _schema_version(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()
    return int(row[0])


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    handle, raw_temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(raw_temporary)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
