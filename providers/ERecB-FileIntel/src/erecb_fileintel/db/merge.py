from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from erecb_fileintel.enrichment.merge import merge_malicious, normalize_hash
from erecb_fileintel.errors import DatabaseError

from .connection import connect, connect_read_only
from .migrations import initialize_schema, validate_fileintel_db


WATCH_STATUS_RANK = {"failed": 0, "new": 1, "scanning": 2, "scanned": 3}


@dataclass
class MergeSummary:
    source: Path
    destination: Path
    dry_run: bool
    backup_path: Path | None = None
    files_inserted: int = 0
    files_merged: int = 0
    tags_inserted: int = 0
    file_names_inserted: int = 0
    scan_jobs_copied: int = 0
    scan_errors_copied: int = 0
    observations_copied: int = 0
    provider_lookups_copied: int = 0
    watch_directories_inserted: int = 0
    watch_directories_merged: int = 0
    warnings: list[str] = field(default_factory=list)


def merge_databases(
    source_path: str | Path,
    destination_path: str | Path,
    *,
    backup: bool = False,
    dry_run: bool = False,
    conflict_policy: str = "warn",
) -> MergeSummary:
    """Merge a source File Intel DB into a destination File Intel DB in one transaction."""
    if conflict_policy != "warn":
        raise DatabaseError(f"unsupported conflict policy: {conflict_policy}")

    source = Path(source_path).resolve()
    destination = Path(destination_path).resolve()
    if source == destination:
        raise DatabaseError("source and destination database paths must be different")

    source_conn = connect_read_only(source)
    destination_conn: sqlite3.Connection | None = None
    try:
        validate_fileintel_db(source_conn)
        destination_conn = _open_destination(destination, dry_run)
        summary = MergeSummary(source=source, destination=destination, dry_run=dry_run)

        if backup and not dry_run and destination.exists():
            summary.backup_path = _create_backup(destination_conn, destination)

        destination_conn.execute("BEGIN")
        try:
            file_id_map = _merge_files(source_conn, destination_conn, summary)
            _merge_set_rows(source_conn, destination_conn, "file_names", "file_name", file_id_map, summary)
            _merge_set_rows(source_conn, destination_conn, "tags", "tag", file_id_map, summary)
            scan_job_id_map = _copy_scan_jobs(source_conn, destination_conn, summary)
            _copy_scan_errors(source_conn, destination_conn, scan_job_id_map, summary)
            _copy_observations(source_conn, destination_conn, file_id_map, scan_job_id_map, summary)
            _copy_provider_lookups(source_conn, destination_conn, file_id_map, summary)
            _merge_watch_directories(source_conn, destination_conn, scan_job_id_map, summary)

            foreign_key_errors = destination_conn.execute("PRAGMA foreign_key_check").fetchall()
            if foreign_key_errors:
                raise DatabaseError("merged database failed foreign key check")

            if dry_run:
                destination_conn.rollback()
            else:
                destination_conn.commit()
        except Exception:
            destination_conn.rollback()
            raise
        return summary
    except sqlite3.Error as exc:
        raise DatabaseError(f"database merge failed: {exc}") from exc
    finally:
        source_conn.close()
        if destination_conn is not None:
            destination_conn.close()


def _open_destination(path: Path, dry_run: bool) -> sqlite3.Connection:
    if dry_run and not path.exists():
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        initialize_schema(conn)
        return conn
    conn = connect(path)
    initialize_schema(conn)
    return conn


def _create_backup(conn: sqlite3.Connection, destination: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    candidate = destination.with_name(f"{destination.stem}.{timestamp}.bak{destination.suffix}")
    sequence = 1
    while candidate.exists():
        candidate = destination.with_name(f"{destination.stem}.{timestamp}.{sequence}.bak{destination.suffix}")
        sequence += 1
    backup_conn = sqlite3.connect(candidate)
    try:
        conn.backup(backup_conn)
    except sqlite3.Error as exc:
        raise DatabaseError(f"cannot create destination backup {candidate}: {exc}") from exc
    finally:
        backup_conn.close()
    return candidate


def _merge_files(source: sqlite3.Connection, destination: sqlite3.Connection, summary: MergeSummary) -> dict[int, int]:
    file_id_map: dict[int, int] = {}
    for source_row in source.execute("SELECT * FROM files ORDER BY id"):
        source_sha256 = normalize_hash(source_row["sha256_hash"])
        source_md5 = normalize_hash(source_row["md5_hash"])
        destination_row = None
        matched_by = None
        if source_sha256:
            destination_row = destination.execute(
                "SELECT * FROM files WHERE sha256_hash = ?", (source_sha256,)
            ).fetchone()
            if destination_row is not None:
                matched_by = "sha256"
        if destination_row is None and source_md5:
            md5_row = destination.execute("SELECT * FROM files WHERE md5_hash = ? ORDER BY id LIMIT 1", (source_md5,)).fetchone()
            if md5_row is not None:
                destination_sha256 = normalize_hash(md5_row["sha256_hash"])
                if source_sha256 and destination_sha256 and source_sha256 != destination_sha256:
                    summary.warnings.append(
                        f"MD5 conflict for source file {source_row['id']}: destination file {md5_row['id']} has a different SHA-256"
                    )
                else:
                    destination_row = md5_row
                    matched_by = "md5"

        if destination_row is None:
            cur = destination.execute(
                """
                INSERT INTO files(sha256_hash, md5_hash, magic, malicious, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    source_sha256,
                    source_md5,
                    _clean_text(source_row["magic"]),
                    _malicious_value(source_row["malicious"]),
                    source_row["created_at"],
                    source_row["updated_at"],
                ),
            )
            destination_file_id = int(cur.lastrowid)
            summary.files_inserted += 1
        else:
            destination_file_id = int(destination_row["id"])
            _merge_file_row(destination, source_row, destination_row, matched_by or "unknown", summary)
            summary.files_merged += 1
        file_id_map[int(source_row["id"])] = destination_file_id
    return file_id_map


def _merge_file_row(
    destination: sqlite3.Connection,
    source_row: sqlite3.Row,
    destination_row: sqlite3.Row,
    matched_by: str,
    summary: MergeSummary,
) -> None:
    source_sha256 = normalize_hash(source_row["sha256_hash"])
    source_md5 = normalize_hash(source_row["md5_hash"])
    destination_sha256 = normalize_hash(destination_row["sha256_hash"])
    destination_md5 = normalize_hash(destination_row["md5_hash"])

    if destination_sha256 and source_sha256 and destination_sha256 != source_sha256:
        summary.warnings.append(
            f"SHA-256 conflict for source file {source_row['id']} and destination file {destination_row['id']}"
        )
    if destination_md5 and source_md5 and destination_md5 != source_md5:
        summary.warnings.append(
            f"MD5 conflict for source file {source_row['id']} and destination file {destination_row['id']}"
        )

    magic = _choose_magic(source_row, destination_row, summary)
    destination.execute(
        """
        UPDATE files
        SET sha256_hash = ?, md5_hash = ?, magic = ?, malicious = ?, created_at = ?, updated_at = ?
        WHERE id = ?
        """,
        (
            destination_sha256 or source_sha256,
            destination_md5 or source_md5,
            magic,
            merge_malicious(_malicious_value(destination_row["malicious"]), _malicious_value(source_row["malicious"])),
            _earliest(destination_row["created_at"], source_row["created_at"]),
            _latest(destination_row["updated_at"], source_row["updated_at"]),
            destination_row["id"],
        ),
    )


def _choose_magic(source_row: sqlite3.Row, destination_row: sqlite3.Row, summary: MergeSummary) -> str | None:
    source_magic = _clean_text(source_row["magic"])
    destination_magic = _clean_text(destination_row["magic"])
    if not destination_magic:
        return source_magic
    if not source_magic or source_magic == destination_magic:
        return destination_magic
    if _is_later(source_row["updated_at"], destination_row["updated_at"]):
        return source_magic
    summary.warnings.append(
        f"magic conflict for destination file {destination_row['id']}; retained destination value because source is not newer"
    )
    return destination_magic


def _merge_set_rows(
    source: sqlite3.Connection,
    destination: sqlite3.Connection,
    table: str,
    value_column: str,
    file_id_map: dict[int, int],
    summary: MergeSummary,
) -> None:
    for row in source.execute(f"SELECT file_id, {value_column}, source, first_seen_at FROM {table} ORDER BY id"):
        destination_file_id = file_id_map[int(row["file_id"])]
        existing = destination.execute(
            f"SELECT id, first_seen_at FROM {table} WHERE file_id = ? AND {value_column} = ? AND source = ?",
            (destination_file_id, row[value_column], row["source"]),
        ).fetchone()
        if existing is None:
            destination.execute(
                f"INSERT INTO {table}(file_id, {value_column}, source, first_seen_at) VALUES (?, ?, ?, ?)",
                (destination_file_id, row[value_column], row["source"], row["first_seen_at"]),
            )
            if table == "tags":
                summary.tags_inserted += 1
            else:
                summary.file_names_inserted += 1
        else:
            destination.execute(
                f"UPDATE {table} SET first_seen_at = ? WHERE id = ?",
                (_earliest(existing["first_seen_at"], row["first_seen_at"]), existing["id"]),
            )


def _copy_scan_jobs(source: sqlite3.Connection, destination: sqlite3.Connection, summary: MergeSummary) -> dict[int, int]:
    scan_job_id_map: dict[int, int] = {}
    columns = "mode, root_path, status, started_at, finished_at, files_seen, executables_found, error_count"
    for row in source.execute(f"SELECT id, {columns} FROM scan_jobs ORDER BY id"):
        values = tuple(row[column.strip()] for column in columns.split(","))
        cur = destination.execute(f"INSERT INTO scan_jobs({columns}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", values)
        scan_job_id_map[int(row["id"])] = int(cur.lastrowid)
        summary.scan_jobs_copied += 1
    return scan_job_id_map


def _copy_scan_errors(
    source: sqlite3.Connection, destination: sqlite3.Connection, scan_job_id_map: dict[int, int], summary: MergeSummary
) -> None:
    for row in source.execute("SELECT * FROM scan_errors ORDER BY id"):
        destination.execute(
            """
            INSERT INTO scan_errors(scan_job_id, file_path, phase, error_type, error_message, occurred_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan_job_id_map[int(row["scan_job_id"])], row["file_path"], row["phase"], row["error_type"],
                row["error_message"], row["occurred_at"],
            ),
        )
        summary.scan_errors_copied += 1


def _copy_observations(
    source: sqlite3.Connection,
    destination: sqlite3.Connection,
    file_id_map: dict[int, int],
    scan_job_id_map: dict[int, int],
    summary: MergeSummary,
) -> None:
    for row in source.execute("SELECT * FROM file_observations ORDER BY id"):
        destination.execute(
            """
            INSERT INTO file_observations(
              scan_job_id, file_id, file_path, file_name, magic, sha256_hash, md5_hash, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_job_id_map[int(row["scan_job_id"])], file_id_map[int(row["file_id"])], row["file_path"],
                row["file_name"], row["magic"], row["sha256_hash"], row["md5_hash"], row["observed_at"],
            ),
        )
        summary.observations_copied += 1


def _copy_provider_lookups(
    source: sqlite3.Connection, destination: sqlite3.Connection, file_id_map: dict[int, int], summary: MergeSummary
) -> None:
    columns = "file_id, provider, query_hash, query_hash_type, status, http_status, requested_at, completed_at, raw_response_path, error_message"
    for row in source.execute(f"SELECT {columns} FROM provider_lookups ORDER BY id"):
        source_file_id = row["file_id"]
        destination_file_id = file_id_map[int(source_file_id)] if source_file_id is not None else None
        values = [destination_file_id]
        values.extend(row[column.strip()] for column in columns.split(",")[1:])
        destination.execute(f"INSERT INTO provider_lookups({columns}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", values)
        raw_response_path = _clean_text(row["raw_response_path"])
        if raw_response_path and not Path(raw_response_path).exists():
            summary.warnings.append(f"raw provider response file is not available locally: {raw_response_path}")
        summary.provider_lookups_copied += 1


def _merge_watch_directories(
    source: sqlite3.Connection,
    destination: sqlite3.Connection,
    scan_job_id_map: dict[int, int],
    summary: MergeSummary,
) -> None:
    for row in source.execute("SELECT * FROM watch_directories ORDER BY id"):
        existing = destination.execute(
            """
            SELECT * FROM watch_directories
            WHERE input_dir = ? AND relative_path = ? AND watch_depth = ?
            """,
            (row["input_dir"], row["relative_path"], row["watch_depth"]),
        ).fetchone()
        mapped_scan_job_id = (
            scan_job_id_map[int(row["last_scan_job_id"])] if row["last_scan_job_id"] is not None else None
        )
        if existing is None:
            destination.execute(
                """
                INSERT INTO watch_directories(
                  input_dir, relative_path, absolute_path, watch_depth, first_seen_at, last_scan_job_id, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["input_dir"], row["relative_path"], row["absolute_path"], row["watch_depth"],
                    row["first_seen_at"], mapped_scan_job_id, row["status"],
                ),
            )
            summary.watch_directories_inserted += 1
            continue

        source_rank = WATCH_STATUS_RANK.get(str(row["status"]), -1)
        destination_rank = WATCH_STATUS_RANK.get(str(existing["status"]), -1)
        source_wins = source_rank > destination_rank
        if source_wins:
            status = row["status"]
            last_scan_job_id = mapped_scan_job_id or existing["last_scan_job_id"]
        else:
            status = existing["status"]
            last_scan_job_id = existing["last_scan_job_id"] or mapped_scan_job_id
        if str(row["status"]) != str(existing["status"]):
            summary.warnings.append(
                f"watcher status conflict for {row['input_dir']}/{row['relative_path']}; retained {status}"
            )
        destination.execute(
            """
            UPDATE watch_directories
            SET first_seen_at = ?, status = ?, last_scan_job_id = ?
            WHERE id = ?
            """,
            (_earliest(existing["first_seen_at"], row["first_seen_at"]), status, last_scan_job_id, existing["id"]),
        )
        summary.watch_directories_merged += 1


def _clean_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _malicious_value(value: object) -> str:
    return str(value) if value in {"yes", "no", "unknown"} else "unknown"


def _is_later(left: object, right: object) -> bool:
    left_key = _timestamp_key(left)
    right_key = _timestamp_key(right)
    return left_key[0] == 1 and right_key[0] == 1 and left_key > right_key


def _earliest(left: object, right: object) -> str:
    return str(left) if _timestamp_key(left) <= _timestamp_key(right) else str(right)


def _latest(left: object, right: object) -> str:
    return str(left) if _timestamp_key(left) >= _timestamp_key(right) else str(right)


def _timestamp_key(value: object) -> tuple[int, str]:
    text = _clean_text(value)
    if text is None:
        return (0, "")
    try:
        return (1, datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat())
    except ValueError:
        return (0, text)
