from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from erecb_fileintel.enrichment.merge import merge_malicious, normalize_hash
from erecb_fileintel.models import FileForEnrichment, FileObservation, NormalizedIntel, ScanCounters

from .migrations import initialize_schema


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Repository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def initialize_schema(self) -> None:
        initialize_schema(self.conn)

    def create_scan_job(self, mode: str, root_path: Path) -> int:
        now = utc_now()
        cur = self.conn.execute(
            "INSERT INTO scan_jobs(mode, root_path, status, started_at) VALUES (?, ?, 'running', ?)",
            (mode, str(root_path), now),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_scan_job(self, scan_job_id: int, status: str, counters: ScanCounters) -> None:
        self.conn.execute(
            """
            UPDATE scan_jobs
            SET status = ?, finished_at = ?, files_seen = ?, executables_found = ?, error_count = ?
            WHERE id = ?
            """,
            (
                status,
                utc_now(),
                counters.files_seen,
                counters.executables_found,
                counters.error_count,
                scan_job_id,
            ),
        )
        self.conn.commit()

    def record_scan_error(
        self,
        scan_job_id: int,
        file_path: Path | str | None,
        phase: str,
        error_type: str,
        error_message: str,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO scan_errors(scan_job_id, file_path, phase, error_type, error_message, occurred_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (scan_job_id, str(file_path) if file_path is not None else None, phase, error_type, error_message, utc_now()),
        )
        self.conn.commit()

    def upsert_local_observation(self, observation: FileObservation) -> int:
        now = utc_now()
        sha256_hash = normalize_hash(observation.sha256_hash)
        md5_hash = normalize_hash(observation.md5_hash)
        if sha256_hash is None or md5_hash is None:
            raise ValueError("local observation requires sha256 and md5")

        with self.conn:
            row = self.conn.execute("SELECT * FROM files WHERE sha256_hash = ?", (sha256_hash,)).fetchone()
            if row is None:
                cur = self.conn.execute(
                    """
                    INSERT INTO files(sha256_hash, md5_hash, magic, malicious, created_at, updated_at)
                    VALUES (?, ?, ?, 'unknown', ?, ?)
                    """,
                    (sha256_hash, md5_hash, observation.magic, now, now),
                )
                file_id = int(cur.lastrowid)
            else:
                file_id = int(row["id"])
                new_md5 = row["md5_hash"] or md5_hash
                new_magic = row["magic"] or observation.magic
                self.conn.execute(
                    "UPDATE files SET md5_hash = ?, magic = ?, updated_at = ? WHERE id = ?",
                    (new_md5, new_magic, now, file_id),
                )

            self.conn.execute(
                """
                INSERT OR IGNORE INTO file_names(file_id, file_name, source, first_seen_at)
                VALUES (?, ?, 'local', ?)
                """,
                (file_id, observation.file_name, now),
            )
            self.conn.execute(
                """
                INSERT INTO file_observations(
                  scan_job_id, file_id, file_path, file_name, magic, sha256_hash, md5_hash, observed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation.scan_job_id,
                    file_id,
                    str(observation.file_path),
                    observation.file_name,
                    observation.magic,
                    sha256_hash,
                    md5_hash,
                    now,
                ),
            )
        return file_id

    def get_files_for_enrichment(self, scan_job_id: int) -> list[FileForEnrichment]:
        rows = self.conn.execute(
            """
            SELECT DISTINCT f.id, f.sha256_hash, f.md5_hash
            FROM files f
            JOIN file_observations o ON o.file_id = f.id
            WHERE o.scan_job_id = ?
            ORDER BY f.id
            """,
            (scan_job_id,),
        ).fetchall()
        return [FileForEnrichment(int(row["id"]), row["sha256_hash"], row["md5_hash"]) for row in rows]

    def create_provider_lookup(self, file_id: int, provider: str, query_hash: str, query_hash_type: str) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO provider_lookups(file_id, provider, query_hash, query_hash_type, status, requested_at)
            VALUES (?, ?, ?, ?, 'running', ?)
            """,
            (file_id, provider, query_hash, query_hash_type, utc_now()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_provider_lookup(
        self,
        lookup_id: int,
        status: str,
        http_status: int | None,
        raw_response_path: str | None,
        error_message: str | None,
    ) -> None:
        self.conn.execute(
            """
            UPDATE provider_lookups
            SET status = ?, http_status = ?, completed_at = ?, raw_response_path = ?, error_message = ?
            WHERE id = ?
            """,
            (status, http_status, utc_now(), raw_response_path, error_message, lookup_id),
        )
        self.conn.commit()

    def should_skip_provider_lookup(
        self,
        file_id: int,
        provider: str,
        requery_success_after_days: int | None,
        requery_failure_after_hours: int,
    ) -> bool:
        row = self.conn.execute(
            """
            SELECT status, completed_at
            FROM provider_lookups
            WHERE file_id = ? AND provider = ? AND completed_at IS NOT NULL
            ORDER BY completed_at DESC
            LIMIT 1
            """,
            (file_id, provider),
        ).fetchone()
        if row is None:
            return False

        completed_at = datetime.fromisoformat(row["completed_at"])
        now = datetime.now(timezone.utc)
        if row["status"] == "success":
            if requery_success_after_days is None:
                return True
            return completed_at + timedelta(days=requery_success_after_days) > now

        return completed_at + timedelta(hours=requery_failure_after_hours) > now

    def merge_intelligence(self, file_id: int, intel: NormalizedIntel) -> None:
        now = utc_now()
        incoming_sha256 = normalize_hash(intel.sha256_hash)
        incoming_md5 = normalize_hash(intel.md5_hash)
        with self.conn:
            row = self.conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
            if row is None:
                raise ValueError(f"file_id does not exist: {file_id}")

            current_sha256 = normalize_hash(row["sha256_hash"])
            if current_sha256 and incoming_sha256 and current_sha256 != incoming_sha256:
                raise ValueError("provider sha256 conflicts with canonical sha256")

            current_md5 = normalize_hash(row["md5_hash"])
            new_sha256 = current_sha256 or incoming_sha256
            new_md5 = current_md5 or incoming_md5
            new_magic = row["magic"] or intel.magic
            new_malicious = merge_malicious(row["malicious"], intel.malicious)

            self.conn.execute(
                """
                UPDATE files
                SET sha256_hash = ?, md5_hash = ?, magic = ?, malicious = ?, updated_at = ?
                WHERE id = ?
                """,
                (new_sha256, new_md5, new_magic, new_malicious, now, file_id),
            )

            for tag in intel.tags:
                self.conn.execute(
                    "INSERT OR IGNORE INTO tags(file_id, tag, source, first_seen_at) VALUES (?, ?, ?, ?)",
                    (file_id, tag, intel.provider_name, now),
                )
            for file_name in intel.file_names:
                self.conn.execute(
                    "INSERT OR IGNORE INTO file_names(file_id, file_name, source, first_seen_at) VALUES (?, ?, ?, ?)",
                    (file_id, file_name, intel.provider_name, now),
                )

    def list_known_watch_directories(self, input_dir: Path, watch_depth: int) -> set[str]:
        rows = self.conn.execute(
            "SELECT relative_path FROM watch_directories WHERE input_dir = ? AND watch_depth = ?",
            (str(input_dir), watch_depth),
        ).fetchall()
        return {str(row["relative_path"]) for row in rows}

    def insert_watch_directory(self, input_dir: Path, relative_path: str, absolute_path: Path, watch_depth: int) -> int:
        now = utc_now()
        cur = self.conn.execute(
            """
            INSERT OR IGNORE INTO watch_directories(
              input_dir, relative_path, absolute_path, watch_depth, first_seen_at, status
            )
            VALUES (?, ?, ?, ?, ?, 'new')
            """,
            (str(input_dir), relative_path, str(absolute_path), watch_depth, now),
        )
        self.conn.commit()
        if cur.lastrowid:
            return int(cur.lastrowid)
        row = self.conn.execute(
            """
            SELECT id FROM watch_directories
            WHERE input_dir = ? AND relative_path = ? AND watch_depth = ?
            """,
            (str(input_dir), relative_path, watch_depth),
        ).fetchone()
        return int(row["id"])

    def update_watch_directory_status(self, watch_directory_id: int, status: str, last_scan_job_id: int | None) -> None:
        self.conn.execute(
            "UPDATE watch_directories SET status = ?, last_scan_job_id = ? WHERE id = ?",
            (status, last_scan_job_id, watch_directory_id),
        )
        self.conn.commit()

    def summary_counts(self) -> dict[str, int]:
        files = self.conn.execute("SELECT COUNT(*) AS c FROM files").fetchone()["c"]
        malicious = self.conn.execute("SELECT COUNT(*) AS c FROM files WHERE malicious = 'yes'").fetchone()["c"]
        tags = self.conn.execute("SELECT COUNT(*) AS c FROM tags").fetchone()["c"]
        scans = self.conn.execute("SELECT COUNT(*) AS c FROM scan_jobs").fetchone()["c"]
        return {"files": files, "malicious": malicious, "tags": tags, "scans": scans}

