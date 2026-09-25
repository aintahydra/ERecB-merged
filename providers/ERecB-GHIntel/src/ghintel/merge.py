"""Intelligence-only relational merge of a verified GHIntel snapshot."""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

from .database import connect
from .github_urls import normalize_github_url
from .migrations import apply_migrations
from .search import rebuild_search
from .snapshots import verify_snapshot


def _read_only(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _validate(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
        raise ValueError("GHIntel integrity check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchone():
        raise ValueError("GHIntel foreign key check failed")
    versions = [row[0] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")]
    if versions != list(range(1, 7)):
        raise ValueError(f"unsupported GHIntel migration set: {versions}")
    for resource in files("ghintel").joinpath("sql_migrations").iterdir():
        if not resource.name.endswith(".sql"):
            continue
        version = int(resource.name[:3])
        expected = hashlib.sha256(resource.read_text(encoding="utf-8").encode()).hexdigest()
        row = connection.execute("SELECT name, checksum FROM schema_migrations WHERE version=?", (version,)).fetchone()
        if row is None or (row["name"], row["checksum"]) != (resource.name, expected):
            raise ValueError(f"GHIntel migration checksum mismatch: {resource.name}")
    for table in ("repositories", "github_snapshots", "source_documents", "source_versions",
                  "findings", "finding_evidence", "people", "repository_people", "language_inferences"):
        if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is None:
            raise ValueError(f"missing GHIntel table {table}")


def _copy(connection: sqlite3.Connection, table: str, row: sqlite3.Row, **overrides) -> int:
    columns = [key for key in row.keys() if key != "id"]
    values = [overrides.get(key, row[key]) for key in columns]
    cursor = connection.execute(
        f"INSERT INTO {table}({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})", values,
    )
    return int(cursor.lastrowid)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def merge_databases(source_path: Path, destination_path: Path, *, dry_run: bool = False,
                    backup: bool = False, require_manifest: bool = True) -> dict:
    source, destination = source_path.resolve(), destination_path.resolve()
    if source == destination or (source.exists() and destination.exists() and source.samefile(destination)):
        raise ValueError("source and destination must differ")
    if require_manifest:
        verify_snapshot(source)
    if not source.is_file():
        raise ValueError("GHIntel source snapshot does not exist")
    source_db = _read_only(source)
    target = None
    try:
        _validate(source_db)
        digest = _sha256(source)
        if dry_run:
            target = sqlite3.connect(":memory:")
            target.row_factory = sqlite3.Row
            target.execute("PRAGMA foreign_keys = ON")
            if destination.exists():
                existing = _read_only(destination)
                try:
                    _validate(existing)
                    existing.backup(target)
                finally:
                    existing.close()
            else:
                apply_migrations(target)
        else:
            existed = destination.exists()
            target = connect(destination)
            if existed:
                _validate(target)
            else:
                apply_migrations(target)
        ledger = target.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='intelligence_imports'").fetchone()
        if ledger and target.execute("SELECT 1 FROM intelligence_imports WHERE source_sha256=?", (digest,)).fetchone():
            return {"already_imported": True, "repositories_inserted": 0, "snapshots_copied": 0,
                    "findings_copied": 0, "source": str(source), "destination": str(destination), "dry_run": dry_run}
        backup_path = None
        if backup and not dry_run and destination.exists():
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            backup_path = destination.with_name(f"{destination.stem}.{stamp}.bak{destination.suffix}")
            counter = 1
            while backup_path.exists():
                backup_path = destination.with_name(f"{destination.stem}.{stamp}.{counter}.bak{destination.suffix}")
                counter += 1
            with sqlite3.connect(backup_path) as backup_db:
                target.backup(backup_db)
        summary = {"already_imported": False, "repositories_inserted": 0, "snapshots_copied": 0,
                   "findings_copied": 0, "source": str(source), "destination": str(destination),
                   "dry_run": dry_run, "backup": str(backup_path) if backup_path else None}
        target.execute("BEGIN")
        try:
            target.execute("CREATE TABLE IF NOT EXISTS intelligence_imports "
                           "(source_sha256 TEXT PRIMARY KEY, imported_at TEXT NOT NULL)")
            repositories = {}
            for row in source_db.execute("SELECT * FROM repositories ORDER BY id"):
                identity = normalize_github_url(row["canonical_url"])
                if identity.identity_key != row["identity_key"]:
                    raise ValueError(f"noncanonical GHIntel repository {row['id']}")
                existing = target.execute("SELECT * FROM repositories WHERE identity_key=?", (row["identity_key"],)).fetchone()
                if existing:
                    repositories[row["id"]] = existing["id"]
                    if row["updated_at"] > existing["updated_at"]:
                        target.execute("UPDATE repositories SET owner=?, name=?, canonical_url=?, "
                                       "github_node_id=COALESCE(?, github_node_id), updated_at=? WHERE id=?",
                                       (row["owner"], row["name"], row["canonical_url"],
                                        row["github_node_id"], row["updated_at"], existing["id"]))
                else:
                    repositories[row["id"]] = _copy(target, "repositories", row)
                    summary["repositories_inserted"] += 1
            documents = {}
            for row in source_db.execute("SELECT * FROM source_documents WHERE origin='github' ORDER BY id"):
                repository_id = repositories[row["repository_id"]]
                existing = target.execute(
                    "SELECT id FROM source_documents WHERE repository_id=? AND origin='github' "
                    "AND kind=? AND locator=?", (repository_id, row["kind"], row["locator"]),
                ).fetchone()
                documents[row["id"]] = (existing["id"] if existing else _copy(
                    target, "source_documents", row, repository_id=repository_id, local_copy_id=None
                ))
            versions = {}
            for row in source_db.execute("SELECT * FROM source_versions ORDER BY id"):
                if row["document_id"] not in documents:
                    continue
                document_id = documents[row["document_id"]]
                existing = target.execute(
                    "SELECT id FROM source_versions WHERE document_id=? AND content_hash=?",
                    (document_id, row["content_hash"]),
                ).fetchone()
                versions[row["id"]] = existing["id"] if existing else _copy(
                    target, "source_versions", row, document_id=document_id
                )
            for row in source_db.execute("SELECT * FROM github_snapshots ORDER BY id"):
                repository_id = repositories[row["repository_id"]]
                if not target.execute("SELECT 1 FROM github_snapshots WHERE repository_id=? AND metadata_hash=?",
                                      (repository_id, row["metadata_hash"])).fetchone():
                    _copy(target, "github_snapshots", row, repository_id=repository_id)
                    summary["snapshots_copied"] += 1
            people = {}
            for row in source_db.execute("SELECT * FROM people ORDER BY id"):
                existing = target.execute(
                    "SELECT id FROM people WHERE normalized_name=? AND github_login IS ?",
                    (row["normalized_name"], row["github_login"]),
                ).fetchone()
                people[row["id"]] = existing["id"] if existing else _copy(target, "people", row)
            findings = {}
            for row in source_db.execute("SELECT * FROM findings ORDER BY id"):
                evidence_versions = [item[0] for item in source_db.execute(
                    "SELECT source_version_id FROM finding_evidence WHERE finding_id=?", (row["id"],)
                )]
                if any(version_id not in versions for version_id in evidence_versions):
                    continue  # Do not publish a finding stripped of its local-only evidence.
                repository_id = repositories[row["repository_id"]]
                existing = target.execute(
                    "SELECT id FROM findings WHERE repository_id=? AND input_fingerprint=? AND provenance=?",
                    (repository_id, row["input_fingerprint"], row["provenance"]),
                ).fetchone()
                if existing:
                    findings[row["id"]] = existing["id"]
                else:
                    version = target.execute("SELECT COALESCE(MAX(version), 0)+1 FROM findings WHERE repository_id=?",
                                             (repository_id,)).fetchone()[0]
                    findings[row["id"]] = _copy(target, "findings", row, repository_id=repository_id, version=version)
                    summary["findings_copied"] += 1
            for row in source_db.execute("SELECT * FROM repository_people ORDER BY id"):
                if row["source_version_id"] is not None and row["source_version_id"] not in versions:
                    continue
                repository_id, person_id = repositories[row["repository_id"]], people[row["person_id"]]
                version_id = versions.get(row["source_version_id"])
                existing = target.execute(
                    "SELECT 1 FROM repository_people WHERE repository_id=? AND person_id=? AND role=? "
                    "AND source_version_id IS ?", (repository_id, person_id, row["role"], version_id),
                ).fetchone()
                if not existing:
                    _copy(target, "repository_people", row, repository_id=repository_id,
                          person_id=person_id, source_version_id=version_id)
            for row in source_db.execute("SELECT * FROM finding_evidence ORDER BY id"):
                if row["finding_id"] not in findings or row["source_version_id"] not in versions:
                    continue
                finding_id, version_id = findings[row["finding_id"]], versions[row["source_version_id"]]
                existing = target.execute(
                    "SELECT 1 FROM finding_evidence WHERE finding_id=? AND field_path=? "
                    "AND source_version_id=? AND quote=?",
                    (finding_id, row["field_path"], version_id, row["quote"]),
                ).fetchone()
                if not existing:
                    _copy(target, "finding_evidence", row, finding_id=finding_id, source_version_id=version_id)
            for row in source_db.execute("SELECT * FROM language_inferences ORDER BY id"):
                if row["finding_id"] not in findings:
                    continue
                finding_id = findings[row["finding_id"]]
                if not target.execute("SELECT 1 FROM language_inferences WHERE finding_id=?", (finding_id,)).fetchone():
                    _copy(target, "language_inferences", row, finding_id=finding_id,
                          subject_person_id=people.get(row["subject_person_id"]))
            for row in source_db.execute("SELECT * FROM repository_current_findings"):
                if row["finding_id"] not in findings:
                    continue
                repository_id, finding_id = repositories[row["repository_id"]], findings[row["finding_id"]]
                current = target.execute("SELECT finding_id FROM repository_current_findings WHERE repository_id=?",
                                         (repository_id,)).fetchone()
                if current is None:
                    target.execute("INSERT INTO repository_current_findings VALUES (?, ?)", (repository_id, finding_id))
                elif target.execute("SELECT created_at FROM findings WHERE id=?", (finding_id,)).fetchone()[0] > target.execute(
                        "SELECT created_at FROM findings WHERE id=?", (current["finding_id"],)).fetchone()[0]:
                    target.execute("UPDATE repository_current_findings SET finding_id=? WHERE repository_id=?",
                                   (finding_id, repository_id))
            target.execute("INSERT INTO intelligence_imports VALUES (?, datetime('now'))", (digest,))
            if target.execute("PRAGMA foreign_key_check").fetchone():
                raise ValueError("merged GHIntel database violates foreign keys")
            if dry_run:
                target.rollback()
            else:
                target.commit()
                rebuild_search(target)
        except Exception:
            target.rollback()
            raise
        return summary
    finally:
        source_db.close()
        if target is not None:
            target.close()
