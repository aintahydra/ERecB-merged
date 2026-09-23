"""Portable, secret-free JSON and relational CSV exports."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .database import list_project_cards

EXPORT_VERSION = 1


class ExportError(ValueError):
    pass


def export_json(connection: sqlite3.Connection, destination: Path) -> Path:
    """Write a versioned investigator-facing export without source or provider blobs."""
    with _read_snapshot(connection):
        payload = _payload(connection)
    _atomic_text(destination, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return destination


def export_csv(connection: sqlite3.Connection, directory: Path) -> Path:
    """Write stable relational CSV tables and a checksum manifest."""
    directory.mkdir(parents=True, exist_ok=True)
    with _read_snapshot(connection):
        tables = _csv_tables(connection)
    written: list[Path] = []
    for name, headers, rows in tables:
        path = directory / name
        _atomic_csv(path, headers, rows)
        written.append(path)
    manifest = {
        "export_version": EXPORT_VERSION,
        "exported_at": _now(),
        "files": [{"name": path.name, "sha256": _sha256(path), "bytes": path.stat().st_size} for path in sorted(written)],
    }
    manifest_path = directory / "manifest.json"
    _atomic_text(manifest_path, json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return manifest_path


def _payload(connection: sqlite3.Connection) -> dict[str, Any]:
    return {
        "export_version": EXPORT_VERSION,
        "exported_at": _now(),
        "repositories": list_project_cards(connection),
        "corrections": [dict(row) for row in connection.execute(
            "SELECT id, repository_id, finding_id, field_path, replacement_json, rationale, supersedes_id, created_at FROM corrections ORDER BY id"
        )],
        "language_inferences": [dict(row) for row in connection.execute(
            "SELECT id, finding_id, subject_person_id, category, method, confidence, detector_language, script_counts_json, rationale, created_at FROM language_inferences ORDER BY id"
        )],
    }


def _csv_tables(connection: sqlite3.Connection) -> list[tuple[str, list[str], Iterable[sqlite3.Row]]]:
    cards = list_project_cards(connection)
    repository_rows = [
        {
            "repository_id": card["repository_id"], "identity_key": card["identity_key"], "canonical_url": card["canonical_url"],
            "purpose": card["purpose"], "tool_types": json.dumps(card["tool_types"], ensure_ascii=False),
            "capabilities": json.dumps(card["capabilities"], ensure_ascii=False), "intended_uses": json.dumps(card["intended_uses"], ensure_ascii=False),
            "information_status": card["information_status"], "owner_login": card["owner_login"], "owner_type": card["owner_type"],
            "stars_count": card["stars_count"], "license_spdx": card["license_spdx"], "is_fork": card["is_fork"], "parent_url": card["parent_url"],
            "corrections_applied": json.dumps(card["corrections_applied"], ensure_ascii=False),
        }
        for card in cards
    ]
    return [
        ("repositories.csv", list(repository_rows[0].keys()) if repository_rows else _repository_headers(), repository_rows),
        ("local_copies.csv", ["id", "root_id", "relative_path", "git_kind", "primary_repository_id", "selection_reason", "first_seen_at", "last_seen_at", "missing_at"],
         connection.execute("SELECT id, root_id, relative_path, git_kind, primary_repository_id, selection_reason, first_seen_at, last_seen_at, missing_at FROM local_copies ORDER BY id")),
        ("remotes.csv", ["id", "local_copy_id", "remote_name", "role", "direction", "ordinal", "repository_id", "parse_error"],
         connection.execute("SELECT id, local_copy_id, remote_name, role, direction, ordinal, repository_id, parse_error FROM remotes ORDER BY id")),
        ("people.csv", ["id", "display_name", "normalized_name", "github_login"], connection.execute("SELECT id, display_name, normalized_name, github_login FROM people ORDER BY id")),
        ("repository_people.csv", ["id", "repository_id", "person_id", "role", "source_version_id", "quote", "confidence"],
         connection.execute("SELECT id, repository_id, person_id, role, source_version_id, quote, confidence FROM repository_people ORDER BY id")),
        ("findings.csv", ["id", "repository_id", "version", "input_fingerprint", "summary", "tool_types_json", "capabilities_json", "intended_uses_json", "provenance", "created_at"],
         connection.execute("SELECT id, repository_id, version, input_fingerprint, summary, tool_types_json, capabilities_json, intended_uses_json, provenance, created_at FROM findings ORDER BY id")),
        ("language_inferences.csv", ["id", "finding_id", "subject_person_id", "category", "method", "confidence", "detector_language", "script_counts_json", "rationale", "created_at"],
         connection.execute("SELECT id, finding_id, subject_person_id, category, method, confidence, detector_language, script_counts_json, rationale, created_at FROM language_inferences ORDER BY id")),
        ("corrections.csv", ["id", "repository_id", "finding_id", "field_path", "replacement_json", "rationale", "supersedes_id", "created_at"],
         connection.execute("SELECT id, repository_id, finding_id, field_path, replacement_json, rationale, supersedes_id, created_at FROM corrections ORDER BY id")),
    ]


def _repository_headers() -> list[str]:
    return ["repository_id", "identity_key", "canonical_url", "purpose", "tool_types", "capabilities", "intended_uses", "information_status", "owner_login", "owner_type", "stars_count", "license_spdx", "is_fork", "parent_url", "corrections_applied"]


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
        handle.write(text)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _atomic_csv(path: Path, headers: list[str], rows: Iterable[sqlite3.Row | dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
        writer = csv.DictWriter(handle, fieldnames=headers, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            values = dict(row)
            writer.writerow({key: _safe_csv(values.get(key)) for key in headers})
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _safe_csv(value: Any) -> Any:
    if value is None:
        return ""
    text = str(value)
    return "'" + text if text.startswith(("=", "+", "-", "@")) else text


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _read_snapshot:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.started = False

    def __enter__(self) -> None:
        if not self.connection.in_transaction:
            self.connection.execute("BEGIN")
            self.started = True

    def __exit__(self, *_: object) -> None:
        if self.started:
            self.connection.rollback()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
