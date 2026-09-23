"""Portable scan-root listing and explicit remapping."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


class RootRemapError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RootRemapPlan:
    root_id: int
    name: str
    old_path: str
    new_path: str
    changed: bool
    dry_run: bool


def list_roots(connection: sqlite3.Connection) -> list[dict[str, object]]:
    return [dict(row) for row in connection.execute(
        "SELECT id, name, absolute_path, created_at, updated_at FROM scan_roots ORDER BY name"
    )]


def remap_root(connection: sqlite3.Connection, name: str, new_path: Path, *, reason: str, dry_run: bool = False) -> RootRemapPlan:
    row = connection.execute("SELECT id, name, absolute_path FROM scan_roots WHERE name=?", (name,)).fetchone()
    if row is None:
        raise RootRemapError(f"scan root not found: {name}")
    if not new_path.is_dir():
        raise RootRemapError(f"new root is not a directory: {new_path}")
    absolute = str(new_path.resolve())
    key = absolute.casefold()
    collision = connection.execute("SELECT name FROM scan_roots WHERE path_key=? AND id<>?", (key, row["id"])).fetchone()
    if collision is not None:
        raise RootRemapError(f"new root path is already assigned to scan root: {collision['name']}")
    if not reason.strip() or len(reason) > 2000:
        raise RootRemapError("reason must be 1 to 2000 characters")
    changed = absolute != row["absolute_path"]
    plan = RootRemapPlan(int(row["id"]), row["name"], row["absolute_path"], absolute, changed, dry_run)
    if dry_run or not changed:
        return plan
    now = _now()
    connection.execute("UPDATE scan_roots SET absolute_path=?, path_key=?, updated_at=? WHERE id=?", (absolute, key, now, row["id"]))
    connection.execute(
        "INSERT INTO root_mapping_events(root_id, old_path, new_path, reason, created_at) VALUES (?, ?, ?, ?, ?)",
        (row["id"], row["absolute_path"], absolute, reason.strip(), now),
    )
    connection.commit()
    return plan


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
