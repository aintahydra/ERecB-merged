"""SQLite FTS5 search over the current, local project-card projection."""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass


class SearchQueryError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SearchHit:
    repository_id: int
    rank: float


def rebuild_search(connection: sqlite3.Connection) -> None:
    """Rebuild the small derived index from current card data in one transaction."""
    if not _available(connection):
        return
    connection.execute("DELETE FROM repository_search")
    rows = connection.execute("SELECT id FROM repositories ORDER BY id").fetchall()
    for row in rows:
        refresh_repository_search(connection, int(row["id"]))
    connection.commit()


def refresh_repository_search(connection: sqlite3.Connection, repository_id: int) -> None:
    """Replace one repository projection without storing source-document blobs."""
    if not _available(connection):
        return
    row = connection.execute(
        """SELECT r.id, r.identity_key, r.canonical_url, f.summary, f.tool_types_json, f.capabilities_json, f.intended_uses_json,
           COALESCE((SELECT group_concat(p.display_name, ' ') FROM repository_people rp JOIN people p ON p.id=rp.person_id
                     WHERE rp.repository_id=r.id), '') AS documented_people
           FROM repositories r
           LEFT JOIN repository_current_findings current ON current.repository_id=r.id
           LEFT JOIN findings f ON f.id=current.finding_id WHERE r.id=?""",
        (repository_id,),
    ).fetchone()
    connection.execute("DELETE FROM repository_search WHERE repository_id=?", (repository_id,))
    if row is None:
        return
    from .corrections import effective_values

    overrides = effective_values(connection, repository_id)
    connection.execute(
        """INSERT INTO repository_search(repository_id, identity_key, canonical_url, purpose, tool_types, capabilities,
           intended_uses, documented_people) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (row["id"], row["identity_key"], row["canonical_url"], overrides.get("summary", row["summary"] or ""),
         _terms_value(overrides.get("tool_types"), row["tool_types_json"]), _terms_value(overrides.get("capabilities"), row["capabilities_json"]),
         _terms_value(overrides.get("intended_uses"), row["intended_uses_json"]), row["documented_people"]),
    )


def search_repository_ids(connection: sqlite3.Connection, query: str, limit: int = 20) -> list[SearchHit]:
    if not query.strip():
        raise SearchQueryError("search query must not be blank")
    if limit < 1 or limit > 100:
        raise SearchQueryError("search limit must be between 1 and 100")
    if not _available(connection):
        raise SearchQueryError("SQLite FTS5 is unavailable in this database")
    literal_query = _literal_query(query)
    rows = connection.execute(
        "SELECT repository_id, bm25(repository_search) AS rank FROM repository_search "
        "WHERE repository_search MATCH ? ORDER BY rank, repository_id LIMIT ?", (literal_query, limit)
    ).fetchall()
    return [SearchHit(int(row["repository_id"]), float(row["rank"])) for row in rows]


def _literal_query(query: str) -> str:
    """Turn human-entered text into an AND query without exposing FTS syntax."""
    terms = re.findall(r"[^\W_]+", query, flags=re.UNICODE)
    if not terms:
        raise SearchQueryError("search query must contain letters or numbers")
    return " AND ".join(f'"{term}"' for term in terms)


def _available(connection: sqlite3.Connection) -> bool:
    return connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='repository_search'").fetchone() is not None


def _terms_value(override: object | None, value: str | None) -> str:
    if override is not None:
        return " ".join(item for item in override if isinstance(item, str)) if isinstance(override, list) else ""
    return _terms(value)


def _terms(value: str | None) -> str:
    try:
        values = json.loads(value or "[]")
    except json.JSONDecodeError:
        return ""
    return " ".join(item for item in values if isinstance(item, str))
