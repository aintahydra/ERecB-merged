from __future__ import annotations

import sqlite3
from pathlib import Path

from erecb_fileintel.errors import DatabaseError


def connect(database_path: Path) -> sqlite3.Connection:
    try:
        database_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(database_path)
    except sqlite3.Error as exc:
        raise DatabaseError(f"cannot open database {database_path}: {exc}") from exc
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def connect_read_only(database_path: Path) -> sqlite3.Connection:
    """Open an existing SQLite database without granting write access."""
    if not database_path.is_file():
        raise DatabaseError(f"source database does not exist or is not a file: {database_path}")
    try:
        uri = database_path.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    except sqlite3.Error as exc:
        raise DatabaseError(f"cannot open source database {database_path}: {exc}") from exc
