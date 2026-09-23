from __future__ import annotations

import sqlite3

from erecb_fileintel.errors import DatabaseError

from .schema import SCHEMA_SQL


SCHEMA_VERSION = 1

REQUIRED_COLUMNS: dict[str, set[str]] = {
    "schema_version": {"version", "applied_at"},
    "files": {"id", "sha256_hash", "md5_hash", "magic", "malicious", "created_at", "updated_at"},
    "file_names": {"id", "file_id", "file_name", "source", "first_seen_at"},
    "tags": {"id", "file_id", "tag", "source", "first_seen_at"},
    "scan_jobs": {
        "id", "mode", "root_path", "status", "started_at", "finished_at", "files_seen", "executables_found", "error_count"
    },
    "scan_errors": {"id", "scan_job_id", "file_path", "phase", "error_type", "error_message", "occurred_at"},
    "file_observations": {
        "id", "scan_job_id", "file_id", "file_path", "file_name", "magic", "sha256_hash", "md5_hash", "observed_at"
    },
    "provider_lookups": {
        "id", "file_id", "provider", "query_hash", "query_hash_type", "status", "http_status", "requested_at",
        "completed_at", "raw_response_path", "error_message"
    },
    "watch_directories": {
        "id", "input_dir", "relative_path", "absolute_path", "watch_depth", "first_seen_at", "last_scan_job_id", "status"
    },
}


def initialize_schema(conn: sqlite3.Connection) -> None:
    tables = _user_tables(conn)
    if not tables:
        try:
            conn.executescript(SCHEMA_SQL)
            conn.execute(
                "INSERT OR IGNORE INTO schema_version(version, applied_at) VALUES (?, datetime('now'))",
                (SCHEMA_VERSION,),
            )
            conn.commit()
        except sqlite3.Error as exc:
            raise DatabaseError(f"cannot initialize database schema: {exc}") from exc
    validate_fileintel_db(conn)


def validate_fileintel_db(conn: sqlite3.Connection) -> None:
    """Reject a database that is not compatible with this File Intel version."""
    try:
        tables = _user_tables(conn)
        missing_tables = set(REQUIRED_COLUMNS) - tables
        if missing_tables:
            raise DatabaseError(f"not a compatible File Intel database; missing tables: {', '.join(sorted(missing_tables))}")

        for table, required_columns in REQUIRED_COLUMNS.items():
            actual_columns = {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})")}
            missing_columns = required_columns - actual_columns
            if missing_columns:
                raise DatabaseError(
                    f"not a compatible File Intel database; table {table} is missing columns: "
                    f"{', '.join(sorted(missing_columns))}"
                )

        version_row = conn.execute("SELECT MAX(version) AS version FROM schema_version").fetchone()
        version = version_row["version"] if version_row is not None else None
        if version != SCHEMA_VERSION:
            raise DatabaseError(
                f"unsupported database schema version {version!r}; this version requires {SCHEMA_VERSION}"
            )

        integrity = conn.execute("PRAGMA quick_check").fetchone()[0]
        if integrity != "ok":
            raise DatabaseError(f"database integrity check failed: {integrity}")
        foreign_key_errors = conn.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_key_errors:
            raise DatabaseError("database foreign key check failed")
    except DatabaseError:
        raise
    except sqlite3.Error as exc:
        raise DatabaseError(f"cannot validate File Intel database: {exc}") from exc


def _user_tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").fetchall()
    return {str(row[0]) for row in rows}
