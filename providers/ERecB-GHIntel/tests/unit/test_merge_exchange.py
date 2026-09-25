from __future__ import annotations

import tempfile
from pathlib import Path

from ghintel.database import database, initialize, lookup_project_card, upsert_requested_repository
from ghintel.corrections import append_correction
from ghintel.merge import merge_databases
from ghintel.snapshots import create_snapshot


def test_snapshot_merge_is_replay_safe_and_does_not_copy_local_roots():
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        producer, snapshot, destination = (root / part for part in ("connected.sqlite3", "copy.sqlite3", "airgap.sqlite3"))
        initialize(producer)
        with database(producer) as connection:
            upsert_requested_repository(connection, "https://github.com/Owner/Repository")
            row = connection.execute("SELECT id FROM repositories").fetchone()
            connection.execute(
                "INSERT INTO github_snapshots(repository_id, metadata_json, metadata_hash, captured_at) "
                "VALUES (?, '{}', ?, '2026-09-23T12:00:00Z')", (row["id"], "a" * 64),
            )
            connection.commit()
        create_snapshot(producer, snapshot)
        initialize(destination)
        with database(destination) as connection:
            local_id = upsert_requested_repository(connection, "https://github.com/Owner/Repository")
            append_correction(connection, local_id, "summary", "local correction", "air-gap operator review")
        dry = merge_databases(snapshot, destination, dry_run=True)
        assert dry["snapshots_copied"] == 1
        first = merge_databases(snapshot, destination)
        assert first["snapshots_copied"] == 1
        assert merge_databases(snapshot, destination)["already_imported"]
        with database(destination) as connection:
            assert connection.execute("SELECT COUNT(*) FROM repositories").fetchone()[0] == 1
            assert connection.execute("SELECT COUNT(*) FROM github_snapshots").fetchone()[0] == 1
            assert connection.execute("SELECT COUNT(*) FROM scan_roots").fetchone()[0] == 0
            assert lookup_project_card(connection, "github.com/owner/repository")["purpose"] == "local correction"


def test_out_of_order_snapshots_keep_the_latest_github_observation_current():
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        producer, older, newer, destination = (
            root / item for item in ("connected.sqlite3", "older.sqlite3", "newer.sqlite3", "airgap.sqlite3")
        )
        initialize(producer)
        with database(producer) as connection:
            repository_id = upsert_requested_repository(connection, "https://github.com/Owner/Repository")
            connection.execute(
                "INSERT INTO github_snapshots(repository_id, metadata_json, metadata_hash, captured_at) "
                "VALUES (?, '{}', ?, '2024-01-01T00:00:00Z')", (repository_id, "a" * 64),
            )
            connection.commit()
        create_snapshot(producer, older)
        with database(producer) as connection:
            connection.execute(
                "INSERT INTO github_snapshots(repository_id, metadata_json, metadata_hash, captured_at) "
                "VALUES (?, '{}', ?, '2025-01-01T00:00:00Z')", (repository_id, "b" * 64),
            )
            connection.commit()
        create_snapshot(producer, newer)
        initialize(destination)
        merge_databases(newer, destination)
        merge_databases(older, destination)
        with database(destination) as connection:
            latest = connection.execute(
                "SELECT metadata_hash, captured_at FROM github_snapshots "
                "ORDER BY captured_at DESC, id DESC LIMIT 1"
            ).fetchone()
            assert (latest["metadata_hash"], latest["captured_at"]) == (
                "b" * 64, "2025-01-01T00:00:00Z",
            )
            assert connection.execute("SELECT COUNT(*) FROM github_snapshots").fetchone()[0] == 2
