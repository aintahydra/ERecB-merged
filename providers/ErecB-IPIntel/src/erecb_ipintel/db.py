from __future__ import annotations

import ipaddress
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .models import NormalizedIntelRecord


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def initialize(self) -> None:
        with self.transaction() as conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (1, utc_now()),
            )

    def ensure_ip_entity(self, ip: str) -> int:
        parsed = ipaddress.ip_address(ip)
        now = utc_now()
        ipv4 = ip if parsed.version == 4 else None
        ipv6 = ip if parsed.version == 6 else None
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO ip_entities
                  (ip, ip_version, ipv4, ipv6, first_seen_local, last_updated_local)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (ip, parsed.version, ipv4, ipv6, now, now),
            )
            row = conn.execute("SELECT id FROM ip_entities WHERE ip = ?", (ip,)).fetchone()
        return int(row["id"])

    def add_observation(self, ip: str, source_path: str, extraction_file: str | None = None) -> None:
        entity_id = self.ensure_ip_entity(ip)
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO ip_observations
                  (ip_entity_id, source_path, extraction_file, observed_at)
                VALUES (?, ?, ?, ?)
                """,
                (entity_id, source_path, extraction_file, utc_now()),
            )

    def create_provider_run(self, provider_name: str, input_file: str | None, ip_count: int) -> int:
        with self.transaction() as conn:
            cur = conn.execute(
                """
                INSERT INTO provider_runs(provider_name, started_at, status, input_file, ip_count)
                VALUES (?, ?, 'running', ?, ?)
                """,
                (provider_name, utc_now(), input_file, ip_count),
            )
        return int(cur.lastrowid)

    def finish_provider_run(self, run_id: int, status: str, success_count: int, failure_count: int) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE provider_runs
                SET finished_at = ?, status = ?, success_count = ?, failure_count = ?
                WHERE id = ?
                """,
                (utc_now(), status, success_count, failure_count, run_id),
            )

    def merge_intel(self, record: NormalizedIntelRecord, provider_run_id: int, provider_status: str, error_summary: str | None = None) -> None:
        entity_id = self.ensure_ip_entity(record.ip)
        now = utc_now()
        with self.transaction() as conn:
            current = conn.execute("SELECT * FROM ip_entities WHERE id = ?", (entity_id,)).fetchone()
            malicious = _merge_malicious(current["malicious"], record.malicious)
            conn.execute(
                """
                UPDATE ip_entities
                SET ipv4 = COALESCE(?, ipv4),
                    ipv6 = COALESCE(?, ipv6),
                    country_code = COALESCE(?, country_code),
                    whois = COALESCE(?, whois),
                    malicious = COALESCE(?, malicious),
                    last_updated_local = ?
                WHERE id = ?
                """,
                (record.ipv4, record.ipv6, record.country_code, record.whois, malicious, now, entity_id),
            )
            _insert_values(conn, "ip_reverse_dns", "domain", entity_id, record.reverse_dns)
            _insert_values(conn, "ip_related_iocs", "ioc", entity_id, record.related_iocs)
            _insert_values(conn, "ip_related_actors", "actor", entity_id, record.related_actors)
            conn.execute(
                """
                INSERT INTO provider_ip_results
                  (provider_run_id, ip_entity_id, provider_name, provider_status,
                   provider_result_code, provider_transaction_id, fetched_at, error_summary,
                   raw_response_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    provider_run_id,
                    entity_id,
                    record.provider_name,
                    provider_status,
                    record.provider_result_code,
                    record.provider_transaction_id,
                    now,
                    error_summary,
                    record.raw_response_json,
                ),
            )

    def get_visit(self, input_root: str, relative_path: str, recognition_depth: int) -> sqlite3.Row | None:
        return self.conn.execute(
            """
            SELECT * FROM visited_directories
            WHERE input_root = ? AND relative_path = ? AND recognition_depth = ?
            """,
            (input_root, relative_path, recognition_depth),
        ).fetchone()

    def insert_visit(self, input_root: str, relative_path: str, absolute_path: str, recognition_depth: int) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO visited_directories
                  (input_root, relative_path, absolute_path, recognition_depth, first_detected_at, status)
                VALUES (?, ?, ?, ?, ?, 'pending')
                """,
                (input_root, relative_path, absolute_path, recognition_depth, utc_now()),
            )

    def update_visit(self, visit_id: int, status: str, output_file: str | None = None, error: str | None = None) -> None:
        processed_at = utc_now() if status in ("done", "failed") else None
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE visited_directories
                SET status = ?, processed_at = COALESCE(?, processed_at),
                    output_file = COALESCE(?, output_file), last_error = ?
                WHERE id = ?
                """,
                (status, processed_at, output_file, error, visit_id),
            )

    def pending_visits(self, retry_failed: bool = False) -> list[sqlite3.Row]:
        statuses = ("pending", "failed") if retry_failed else ("pending",)
        placeholders = ",".join("?" for _ in statuses)
        return list(
            self.conn.execute(
                f"SELECT * FROM visited_directories WHERE status IN ({placeholders}) ORDER BY relative_path",
                statuses,
            )
        )

    def status_summary(self) -> dict[str, object]:
        visits = {
            row["status"]: row["count"]
            for row in self.conn.execute("SELECT status, COUNT(*) AS count FROM visited_directories GROUP BY status")
        }
        entities = self.conn.execute("SELECT COUNT(*) AS count FROM ip_entities").fetchone()["count"]
        failures = [
            dict(row)
            for row in self.conn.execute(
                """
                SELECT provider_name, provider_status, error_summary, fetched_at
                FROM provider_ip_results
                WHERE provider_status = 'failed'
                ORDER BY fetched_at DESC
                LIMIT 5
                """
            )
        ]
        return {"db_path": str(self.path), "ip_entities": entities, "visits": visits, "recent_provider_failures": failures}


def _insert_values(conn: sqlite3.Connection, table: str, column: str, entity_id: int, values: list[str]) -> None:
    for value in _unique_nonempty(values):
        conn.execute(
            f"INSERT OR IGNORE INTO {table}(ip_entity_id, {column}, first_seen_local) VALUES (?, ?, ?)",
            (entity_id, value, utc_now()),
        )


def _unique_nonempty(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _merge_malicious(old: str | None, new: str | None) -> str | None:
    if old == "Yes" or new == "Yes":
        return "Yes"
    return new or old


def raw_json(data: dict | None, enabled: bool) -> str | None:
    if not enabled or data is None:
        return None
    return json.dumps(data, ensure_ascii=False, sort_keys=True)


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_entities (
  id INTEGER PRIMARY KEY,
  ip TEXT NOT NULL UNIQUE,
  ip_version INTEGER NOT NULL CHECK (ip_version IN (4, 6)),
  ipv4 TEXT NULL,
  ipv6 TEXT NULL,
  country_code TEXT NULL,
  whois TEXT NULL,
  malicious TEXT NULL CHECK (malicious IN ('Yes', 'No')),
  first_seen_local TEXT NOT NULL,
  last_updated_local TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_observations (
  id INTEGER PRIMARY KEY,
  ip_entity_id INTEGER NOT NULL,
  source_path TEXT NOT NULL,
  extraction_file TEXT NULL,
  observed_at TEXT NOT NULL,
  FOREIGN KEY (ip_entity_id) REFERENCES ip_entities(id),
  UNIQUE (ip_entity_id, source_path)
);

CREATE TABLE IF NOT EXISTS ip_reverse_dns (
  ip_entity_id INTEGER NOT NULL,
  domain TEXT NOT NULL,
  first_seen_local TEXT NOT NULL,
  FOREIGN KEY (ip_entity_id) REFERENCES ip_entities(id),
  UNIQUE (ip_entity_id, domain)
);

CREATE TABLE IF NOT EXISTS ip_related_iocs (
  ip_entity_id INTEGER NOT NULL,
  ioc TEXT NOT NULL,
  first_seen_local TEXT NOT NULL,
  FOREIGN KEY (ip_entity_id) REFERENCES ip_entities(id),
  UNIQUE (ip_entity_id, ioc)
);

CREATE TABLE IF NOT EXISTS ip_related_actors (
  ip_entity_id INTEGER NOT NULL,
  actor TEXT NOT NULL,
  first_seen_local TEXT NOT NULL,
  FOREIGN KEY (ip_entity_id) REFERENCES ip_entities(id),
  UNIQUE (ip_entity_id, actor)
);

CREATE TABLE IF NOT EXISTS provider_runs (
  id INTEGER PRIMARY KEY,
  provider_name TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NULL,
  status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'partial_failed', 'failed')),
  input_file TEXT NULL,
  ip_count INTEGER NOT NULL DEFAULT 0,
  success_count INTEGER NOT NULL DEFAULT 0,
  failure_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS provider_ip_results (
  id INTEGER PRIMARY KEY,
  provider_run_id INTEGER NOT NULL,
  ip_entity_id INTEGER NOT NULL,
  provider_name TEXT NOT NULL,
  provider_status TEXT NOT NULL CHECK (provider_status IN ('success', 'not_found', 'failed')),
  provider_result_code TEXT NULL,
  provider_transaction_id TEXT NULL,
  fetched_at TEXT NOT NULL,
  error_summary TEXT NULL,
  raw_response_json TEXT NULL,
  FOREIGN KEY (provider_run_id) REFERENCES provider_runs(id),
  FOREIGN KEY (ip_entity_id) REFERENCES ip_entities(id)
);

CREATE TABLE IF NOT EXISTS visited_directories (
  id INTEGER PRIMARY KEY,
  input_root TEXT NOT NULL,
  relative_path TEXT NOT NULL,
  absolute_path TEXT NOT NULL,
  recognition_depth INTEGER NOT NULL,
  first_detected_at TEXT NOT NULL,
  processed_at TEXT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'done', 'failed')),
  output_file TEXT NULL,
  last_error TEXT NULL,
  UNIQUE (input_root, relative_path, recognition_depth)
);

CREATE INDEX IF NOT EXISTS idx_ip_entities_ip_version ON ip_entities(ip_version);
CREATE INDEX IF NOT EXISTS idx_ip_observations_path ON ip_observations(source_path);
CREATE INDEX IF NOT EXISTS idx_provider_ip_results_ip ON provider_ip_results(ip_entity_id);
CREATE INDEX IF NOT EXISTS idx_visited_directories_status ON visited_directories(status);
"""
