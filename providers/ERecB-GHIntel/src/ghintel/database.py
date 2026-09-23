"""SQLite persistence for the Stage 1 discovery and lookup workflow."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

from .migrations import apply_migrations
from .models import CapturedSource, GithubRepository, RepositoryLocation


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


@contextmanager
def database(path: Path) -> Iterator[sqlite3.Connection]:
    connection = connect(path)
    try:
        yield connection
    finally:
        connection.close()


def initialize(path: Path) -> list[int]:
    with database(path) as connection:
        applied = apply_migrations(connection)
        from .search import rebuild_search

        rebuild_search(connection)
        return applied


def record_discovery(connection: sqlite3.Connection, root: Path, locations: list[RepositoryLocation], sources_by_path: dict[Path, list[CapturedSource]]) -> int:
    now = _now()
    root_id = _upsert_root(connection, root, now)
    run_id = connection.execute(
        "INSERT INTO discovery_runs(root_id, status, started_at) VALUES (?, 'running', ?)", (root_id, now)
    ).lastrowid
    diagnostics: list[str] = []
    for location in locations:
        copy_id, primary_id = _store_location(connection, root_id, root, location, now)
        for source in sources_by_path.get(location.path, []):
            if primary_id is not None:
                _store_source(connection, primary_id, copy_id, source, now)
        diagnostics.extend(f"{location.path}: {message}" for message in location.diagnostics)
        connection.execute(
            "INSERT INTO discovery_observations(discovery_run_id, local_copy_id, diagnostics_json) VALUES (?, ?, ?)",
            (run_id, copy_id, json.dumps(location.diagnostics)),
        )
    connection.execute(
        "UPDATE discovery_runs SET status = 'complete', completed_at = ?, diagnostics_json = ? WHERE id = ?",
        (_now(), json.dumps(diagnostics), run_id),
    )
    from .search import rebuild_search

    rebuild_search(connection)
    connection.commit()
    return int(run_id)


def lookup_project_card(connection: sqlite3.Connection, identity_key: str) -> dict[str, object] | None:
    row = connection.execute("SELECT * FROM repository_project_cards WHERE identity_key = ?", (identity_key,)).fetchone()
    if row is None:
        return None
    card = dict(row)
    for key in ("tool_types_json", "capabilities_json", "intended_uses_json", "documented_people_json"):
        card[key.removesuffix("_json")] = json.loads(card.pop(key) or "[]")
    snapshot = connection.execute(
        "SELECT stars_count, license_spdx, is_fork, parent_full_name FROM github_snapshots WHERE repository_id=? ORDER BY captured_at DESC, id DESC LIMIT 1",
        (card["repository_id"],),
    ).fetchone()
    card["stars_count"] = snapshot["stars_count"] if snapshot else None
    card["license_spdx"] = snapshot["license_spdx"] if snapshot else None
    card["is_fork"] = bool(snapshot["is_fork"]) if snapshot else False
    card["parent_url"] = _parent_url(snapshot["parent_full_name"]) if snapshot else None
    fetch = connection.execute(
        """SELECT item.state, item.error_code, item.error_message FROM run_items item
           JOIN runs run ON run.id=item.run_id WHERE item.repository_id=? AND run.kind='fetch'
           ORDER BY run.id DESC LIMIT 1""", (card["repository_id"],)
    ).fetchone()
    card["github_status"] = "available" if snapshot else "not-fetched"
    card["github_error"] = None
    if fetch and fetch["state"] == "failed":
        card["github_status"] = "unavailable"
        card["github_error"] = fetch["error_message"]
    card["local_copies"] = [
        item[0]
        for item in connection.execute(
            "SELECT relative_path FROM local_copies WHERE primary_repository_id = ? AND missing_at IS NULL ORDER BY relative_path",
            (card["repository_id"],),
        )
    ]
    from .corrections import apply_to_card

    return apply_to_card(connection, card)


def list_project_cards(connection: sqlite3.Connection) -> list[dict[str, object]]:
    return [lookup_project_card(connection, row[0]) for row in connection.execute("SELECT identity_key FROM repositories ORDER BY identity_key")]


def _upsert_root(connection: sqlite3.Connection, root: Path, now: str) -> int:
    absolute = str(root.resolve())
    key = absolute.casefold()
    row = connection.execute("SELECT id, absolute_path FROM scan_roots WHERE path_key = ?", (key,)).fetchone()
    if row:
        connection.execute("UPDATE scan_roots SET absolute_path = ?, updated_at = ? WHERE id = ?", (absolute, now, row["id"]))
        return int(row["id"])
    name = root.name or "root"
    suffix = 1
    candidate = name
    while connection.execute("SELECT 1 FROM scan_roots WHERE name = ?", (candidate,)).fetchone():
        suffix += 1
        candidate = f"{name}-{suffix}"
    return int(
        connection.execute(
            "INSERT INTO scan_roots(name, absolute_path, path_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (candidate, absolute, key, now, now),
        ).lastrowid
    )


def _store_location(connection: sqlite3.Connection, root_id: int, root: Path, location: RepositoryLocation, now: str) -> tuple[int, int | None]:
    repository_ids: dict[str, int] = {}
    for remote in location.remotes:
        if remote.repository is not None:
            repository_ids[remote.repository.identity_key] = _upsert_repository(connection, remote.repository, now)
    valid_origins = [remote.repository for remote in location.remotes if remote.direction == "fetch" and remote.role.value == "origin" and remote.repository]
    all_valid = [remote.repository for remote in location.remotes if remote.direction == "fetch" and remote.repository]
    primary = valid_origins[0] if len(valid_origins) == 1 else all_valid[0] if not valid_origins and len(all_valid) == 1 else None
    selection = "origin" if primary in valid_origins else "sole-remote" if primary else None
    relative = str(location.path.relative_to(root)) or "."
    key = relative.casefold()
    row = connection.execute("SELECT id FROM local_copies WHERE root_id = ? AND path_key = ?", (root_id, key)).fetchone()
    if row:
        copy_id = int(row["id"])
        connection.execute(
            "UPDATE local_copies SET relative_path=?, git_kind=?, primary_repository_id=?, selection_reason=?, last_seen_at=?, missing_at=NULL WHERE id=?",
            (relative, location.git_kind, repository_ids.get(primary.identity_key) if primary else None, selection, now, copy_id),
        )
        connection.execute("DELETE FROM remotes WHERE local_copy_id = ?", (copy_id,))
    else:
        copy_id = int(
            connection.execute(
                "INSERT INTO local_copies(root_id, relative_path, path_key, git_kind, primary_repository_id, selection_reason, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (root_id, relative, key, location.git_kind, repository_ids.get(primary.identity_key) if primary else None, selection, now, now),
            ).lastrowid
        )
    seen: dict[tuple[str, str], int] = {}
    for remote in location.remotes:
        pair = (remote.name, remote.direction)
        ordinal = seen.get(pair, 0)
        seen[pair] = ordinal + 1
        connection.execute(
            "INSERT INTO remotes(local_copy_id, remote_name, role, direction, ordinal, raw_url, repository_id, parse_error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (copy_id, remote.name, remote.role.value, remote.direction, ordinal, remote.raw_url, repository_ids.get(remote.repository.identity_key) if remote.repository else None, remote.error),
        )
    return copy_id, repository_ids.get(primary.identity_key) if primary else None


def _upsert_repository(connection: sqlite3.Connection, repository: GithubRepository, now: str) -> int:
    row = connection.execute("SELECT id FROM repositories WHERE identity_key = ?", (repository.identity_key,)).fetchone()
    if row:
        connection.execute("UPDATE repositories SET owner=?, name=?, canonical_url=?, updated_at=? WHERE id=?", (repository.owner, repository.name, repository.canonical_url, now, row["id"]))
        return int(row["id"])
    return int(
        connection.execute(
            "INSERT INTO repositories(host, owner, name, identity_key, canonical_url, created_at, updated_at) VALUES ('github.com', ?, ?, ?, ?, ?, ?)",
            (repository.owner, repository.name, repository.identity_key, repository.canonical_url, now, now),
        ).lastrowid
    )


def _store_source(connection: sqlite3.Connection, repository_id: int, copy_id: int, source: CapturedSource, now: str) -> None:
    row = connection.execute(
        "SELECT id FROM source_documents WHERE repository_id=? AND local_copy_id=? AND origin='local' AND locator=?",
        (repository_id, copy_id, str(source.path)),
    ).fetchone()
    if row:
        document_id = int(row["id"])
    else:
        document_id = int(
            connection.execute(
                "INSERT INTO source_documents(repository_id, local_copy_id, origin, kind, locator, translation, priority) VALUES (?, ?, 'local', ?, ?, ?, 0)",
                (repository_id, copy_id, source.kind.value, str(source.path), int(source.translation)),
            ).lastrowid
        )
    connection.execute(
        "INSERT OR IGNORE INTO source_versions(document_id, content_hash, content, byte_count, encoding, truncated, captured_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (document_id, source.content_hash, source.content, source.byte_count, source.encoding, int(source.truncated), now),
    )


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def search_project_cards(connection: sqlite3.Connection, query: str, limit: int = 20) -> list[dict[str, object]]:
    """Return current project cards in FTS relevance order."""
    from .search import search_repository_ids

    hits = search_repository_ids(connection, query, limit)
    cards: list[dict[str, object]] = []
    for hit in hits:
        row = connection.execute("SELECT identity_key FROM repositories WHERE id=?", (hit.repository_id,)).fetchone()
        if row is None:
            continue
        card = lookup_project_card(connection, row["identity_key"])
        if card is not None:
            card["search_rank"] = hit.rank
            cards.append(card)
    return cards


def _parent_url(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    pieces = value.split("/")
    if len(pieces) != 2 or not all(piece and piece not in {".", ".."} for piece in pieces):
        return None
    return f"https://github.com/{pieces[0]}/{pieces[1]}"
