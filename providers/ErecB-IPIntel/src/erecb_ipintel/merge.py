"""Validated, replay-safe IP intelligence database merge."""

from __future__ import annotations

import hashlib
import ipaddress
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .db import SCHEMA


_COLUMNS = {
    "schema_migrations": {"version", "applied_at"},
    "ip_entities": {"id", "ip", "ip_version", "ipv4", "ipv6", "country_code", "whois", "malicious", "first_seen_local", "last_updated_local"},
    "ip_observations": {"id", "ip_entity_id", "source_path", "extraction_file", "observed_at"},
    "ip_reverse_dns": {"ip_entity_id", "domain", "first_seen_local"},
    "ip_related_iocs": {"ip_entity_id", "ioc", "first_seen_local"},
    "ip_related_actors": {"ip_entity_id", "actor", "first_seen_local"},
    "provider_runs": {"id", "provider_name", "started_at", "finished_at", "status", "input_file", "ip_count", "success_count", "failure_count"},
    "provider_ip_results": {"id", "provider_run_id", "ip_entity_id", "provider_name", "provider_status", "provider_result_code", "provider_transaction_id", "fetched_at", "error_summary", "raw_response_json"},
    "visited_directories": {"id", "input_root", "relative_path", "absolute_path", "recognition_depth", "first_detected_at", "status"},
}


def validate_ip_db(connection: sqlite3.Connection) -> None:
    for table, required in _COLUMNS.items():
        if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is None:
            raise ValueError(f"missing IPIntel table {table}")
        actual = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        if not required <= actual:
            raise ValueError(f"IPIntel table {table} lacks columns: {sorted(required - actual)}")
    versions = [row[0] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")]
    if versions != [1]:
        raise ValueError(f"unsupported IPIntel schema versions: {versions}")
    if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
        raise ValueError("IPIntel database integrity check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchone():
        raise ValueError("IPIntel database foreign key check failed")


def _open(path: Path, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only and not path.is_file():
        raise ValueError(f"source database does not exist: {path}")
    if not read_only:
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path.as_uri() + "?mode=ro" if read_only else path, uri=read_only)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _initialize_new(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)
    connection.execute("INSERT INTO schema_migrations VALUES (1, datetime('now'))")
    connection.commit()


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def merge_databases(source_path: Path, destination_path: Path, *, dry_run: bool = False,
                    backup: bool = False) -> dict:
    source, destination = source_path.resolve(), destination_path.resolve()
    if source == destination or (source.exists() and destination.exists() and source.samefile(destination)):
        raise ValueError("source and destination must be distinct databases")
    source_db = _open(source, read_only=True)
    dest_db = None
    try:
        validate_ip_db(source_db)
        source_hash = _digest(source)
        if dry_run:
            dest_db = sqlite3.connect(":memory:")
            dest_db.row_factory = sqlite3.Row
            dest_db.execute("PRAGMA foreign_keys = ON")
            if destination.exists():
                original = _open(destination, read_only=True)
                try:
                    validate_ip_db(original)
                    original.backup(dest_db)
                finally:
                    original.close()
            else:
                _initialize_new(dest_db)
        else:
            existed = destination.exists()
            dest_db = _open(destination)
            if existed and dest_db.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone():
                validate_ip_db(dest_db)
            else:
                _initialize_new(dest_db)
        imported = dest_db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='intelligence_imports'").fetchone()
        if imported and dest_db.execute("SELECT 1 FROM intelligence_imports WHERE source_sha256=?", (source_hash,)).fetchone():
            return {"source": str(source), "destination": str(destination), "dry_run": dry_run,
                    "already_imported": True, "entities_inserted": 0, "entities_merged": 0,
                    "provider_results_copied": 0, "backup": None}
        backup_path = None
        if backup and not dry_run and destination.exists():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup_path = destination.with_name(f"{destination.stem}.{stamp}.bak{destination.suffix}")
            index = 1
            while backup_path.exists():
                backup_path = destination.with_name(f"{destination.stem}.{stamp}.{index}.bak{destination.suffix}")
                index += 1
            with sqlite3.connect(backup_path) as backup_db:
                dest_db.backup(backup_db)
        summary = {"source": str(source), "destination": str(destination), "dry_run": dry_run,
                   "already_imported": False, "entities_inserted": 0, "entities_merged": 0,
                   "provider_results_copied": 0, "backup": str(backup_path) if backup_path else None}
        dest_db.execute("BEGIN")
        try:
            dest_db.execute("CREATE TABLE IF NOT EXISTS intelligence_imports "
                            "(source_sha256 TEXT PRIMARY KEY, imported_at TEXT NOT NULL)")
            entity_ids = {}
            for row in source_db.execute("SELECT * FROM ip_entities ORDER BY id"):
                parsed = ipaddress.ip_address(row["ip"])
                if str(parsed) != row["ip"] or parsed.version != row["ip_version"]:
                    raise ValueError(f"noncanonical source IP entity {row['id']}")
                current = dest_db.execute("SELECT * FROM ip_entities WHERE ip=?", (row["ip"],)).fetchone()
                if current is None:
                    columns = "ip, ip_version, ipv4, ipv6, country_code, whois, malicious, first_seen_local, last_updated_local"
                    cursor = dest_db.execute(
                        f"INSERT INTO ip_entities({columns}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        tuple(row[key.strip()] for key in columns.split(",")),
                    )
                    entity_ids[row["id"]] = cursor.lastrowid
                    summary["entities_inserted"] += 1
                else:
                    newer = row["last_updated_local"] > current["last_updated_local"]
                    scalars = [row[key] or current[key] if newer else current[key] or row[key]
                               for key in ("ipv4", "ipv6", "country_code", "whois")]
                    malicious = "Yes" if "Yes" in (current["malicious"], row["malicious"]) else (
                        "No" if "No" in (current["malicious"], row["malicious"]) else None)
                    dest_db.execute(
                        "UPDATE ip_entities SET ipv4=?, ipv6=?, country_code=?, whois=?, malicious=?, "
                        "first_seen_local=?, last_updated_local=? WHERE id=?",
                        (*scalars, malicious, min(row["first_seen_local"], current["first_seen_local"]),
                         max(row["last_updated_local"], current["last_updated_local"]), current["id"]),
                    )
                    entity_ids[row["id"]] = current["id"]
                    summary["entities_merged"] += 1
            for table, column in (("ip_reverse_dns", "domain"), ("ip_related_iocs", "ioc"),
                                  ("ip_related_actors", "actor")):
                for row in source_db.execute(f"SELECT * FROM {table}"):
                    dest_db.execute(
                        f"INSERT OR IGNORE INTO {table}(ip_entity_id, {column}, first_seen_local) VALUES (?, ?, ?)",
                        (entity_ids[row["ip_entity_id"]], row[column], row["first_seen_local"]),
                    )
            runs = {}
            for row in source_db.execute("SELECT * FROM provider_runs ORDER BY id"):
                columns = "provider_name, started_at, finished_at, status, input_file, ip_count, success_count, failure_count"
                values = [row[key.strip()] for key in columns.split(",")]
                values[4] = None  # Connected-machine extraction path must not cross the air gap.
                cursor = dest_db.execute(
                    f"INSERT INTO provider_runs({columns}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", values,
                )
                runs[row["id"]] = cursor.lastrowid
            for row in source_db.execute("SELECT * FROM provider_ip_results ORDER BY id"):
                columns = ("provider_run_id, ip_entity_id, provider_name, provider_status, provider_result_code, "
                           "provider_transaction_id, fetched_at, error_summary, raw_response_json")
                dest_db.execute(
                    f"INSERT INTO provider_ip_results({columns}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (runs[row["provider_run_id"]], entity_ids[row["ip_entity_id"]], row["provider_name"],
                     row["provider_status"], row["provider_result_code"], row["provider_transaction_id"],
                     row["fetched_at"], row["error_summary"], row["raw_response_json"]),
                )
                summary["provider_results_copied"] += 1
            dest_db.execute("INSERT INTO intelligence_imports VALUES (?, datetime('now'))", (source_hash,))
            if dest_db.execute("PRAGMA foreign_key_check").fetchone():
                raise ValueError("merged IPIntel database violates foreign keys")
            if dry_run:
                dest_db.rollback()
            else:
                dest_db.commit()
        except Exception:
            dest_db.rollback()
            raise
        return summary
    finally:
        source_db.close()
        if dest_db is not None:
            dest_db.close()
