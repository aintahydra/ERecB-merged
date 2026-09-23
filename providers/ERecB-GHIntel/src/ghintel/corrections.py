"""Append-only, typed corrections that overlay a repository project card."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any


class CorrectionError(ValueError):
    pass


_ALLOWED = {"summary": str, "tool_types": list, "capabilities": list, "intended_uses": list}


def append_correction(connection: sqlite3.Connection, repository_id: int, field_path: str, replacement: Any, rationale: str) -> int:
    _validate(field_path, replacement, rationale)
    repository = connection.execute("SELECT 1 FROM repositories WHERE id=?", (repository_id,)).fetchone()
    if repository is None:
        raise CorrectionError(f"unknown repository {repository_id}")
    current = connection.execute("SELECT finding_id FROM repository_current_findings WHERE repository_id=?", (repository_id,)).fetchone()
    previous = connection.execute(
        "SELECT id FROM corrections WHERE repository_id=? AND field_path=? ORDER BY id DESC LIMIT 1", (repository_id, field_path)
    ).fetchone()
    correction_id = connection.execute(
        """INSERT INTO corrections(repository_id, finding_id, field_path, replacement_json, rationale, supersedes_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (repository_id, current["finding_id"] if current else None, field_path,
         json.dumps(replacement, ensure_ascii=False, separators=(",", ":")), rationale.strip(), previous["id"] if previous else None, _now()),
    ).lastrowid
    from .search import refresh_repository_search

    refresh_repository_search(connection, repository_id)
    connection.commit()
    return int(correction_id)


def effective_values(connection: sqlite3.Connection, repository_id: int) -> dict[str, Any]:
    rows = connection.execute(
        """SELECT field_path, replacement_json FROM corrections c
           WHERE repository_id=? AND id=(SELECT MAX(latest.id) FROM corrections latest
                                         WHERE latest.repository_id=c.repository_id AND latest.field_path=c.field_path)""",
        (repository_id,),
    ).fetchall()
    return {row["field_path"]: json.loads(row["replacement_json"]) for row in rows}


def apply_to_card(connection: sqlite3.Connection, card: dict[str, Any]) -> dict[str, Any]:
    values = effective_values(connection, int(card["repository_id"]))
    if "summary" in values:
        card["purpose"] = values["summary"]
    for field in ("tool_types", "capabilities", "intended_uses"):
        if field in values:
            card[field] = values[field]
    card["corrections_applied"] = sorted(values)
    return card


def _validate(field_path: str, replacement: Any, rationale: str) -> None:
    expected = _ALLOWED.get(field_path)
    if expected is None:
        raise CorrectionError(f"unsupported correction field: {field_path}")
    if not isinstance(replacement, expected) or isinstance(replacement, bool):
        raise CorrectionError(f"{field_path} requires a JSON {expected.__name__}")
    if isinstance(replacement, str) and not replacement.strip():
        raise CorrectionError("summary must not be blank")
    if isinstance(replacement, list) and (any(not isinstance(item, str) or not item.strip() for item in replacement) or len(replacement) > 30):
        raise CorrectionError(f"{field_path} requires at most 30 non-blank strings")
    if not rationale.strip() or len(rationale) > 2000:
        raise CorrectionError("rationale must be 1 to 2000 characters")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
