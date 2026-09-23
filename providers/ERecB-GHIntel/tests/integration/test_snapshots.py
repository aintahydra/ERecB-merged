import json
from pathlib import Path

import pytest

from ghintel.database import connect, initialize
from ghintel.snapshots import SnapshotError, create_snapshot, manifest_path, verify_snapshot


def test_online_snapshot_is_verified_and_has_expected_schema(tmp_path: Path) -> None:
    database_path = tmp_path / "live.sqlite3"
    initialize(database_path)
    writer = connect(database_path)
    writer.execute("INSERT INTO scan_roots(name, absolute_path, path_key, created_at, updated_at) VALUES ('in', '/tmp/in', '/tmp/in', 'now', 'now')")
    writer.commit()
    snapshot_path = tmp_path / "snapshots" / "inventory.sqlite3"
    info = create_snapshot(database_path, snapshot_path)
    writer.execute("UPDATE scan_roots SET name='changed-after-backup'")
    writer.commit()
    writer.close()

    verified = verify_snapshot(snapshot_path)
    assert verified == info
    snapshot = connect(snapshot_path)
    assert snapshot.execute("SELECT name FROM scan_roots").fetchone()[0] == "in"
    snapshot.close()


def test_snapshot_rejects_existing_destination_and_tampered_manifest(tmp_path: Path) -> None:
    database_path = tmp_path / "live.sqlite3"
    initialize(database_path)
    snapshot_path = tmp_path / "inventory.sqlite3"
    create_snapshot(database_path, snapshot_path)
    with pytest.raises(SnapshotError):
        create_snapshot(database_path, snapshot_path)
    manifest = manifest_path(snapshot_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["sha256"] = "0" * 64
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SnapshotError):
        verify_snapshot(snapshot_path)
