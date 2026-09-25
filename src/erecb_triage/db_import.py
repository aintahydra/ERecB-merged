"""Air-gap maintenance import using the three provider-owned merge engines."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import tempfile
import uuid
from contextlib import ExitStack, closing
from dataclasses import asdict
from pathlib import Path
from typing import Any

from erecb_triage.config import resolve_path
from erecb_triage.sqlite_snapshots import verify_snapshot


class ImportErrorSet(ValueError):
    pass


def _backup_sqlite(source: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with (closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as source_db,
          closing(sqlite3.connect(output)) as output_db):
        source_db.backup(output_db)
        output_db.commit()
        output_db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        output_db.execute("PRAGMA journal_mode=DELETE")
        if output_db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ImportErrorSet(f"SQLite backup integrity check failed: {source}")


def _no_live_sidecars(path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists():
            raise ImportErrorSet(f"database has an active SQLite sidecar; stop writers and checkpoint first: {sidecar}")


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _signature(path: Path) -> tuple[int, int, int, int, int] | None:
    if not path.exists():
        return None
    info = path.stat(follow_symlinks=False)
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def import_database_set(config: dict, base_dir: Path, *, fileintel: Path, ipintel: Path,
                        ghintel: Path, dry_run: bool = False) -> dict[str, Any]:
    """Verify all, dry-run all, build all off-line, then activate or roll back as a set."""
    from erecb_fileintel.db.merge import merge_databases as merge_fileintel
    from erecb_ipintel.merge import merge_databases as merge_ipintel
    from ghintel.merge import merge_databases as merge_ghintel
    from ghintel.snapshots import verify_snapshot as verify_ghintel

    sources = {"fileintel": fileintel.resolve(), "ipintel": ipintel.resolve(), "ghintel": ghintel.resolve()}
    versions = {"fileintel": "schema_version", "ipintel": "schema_migrations"}
    for name, table in versions.items():
        verify_snapshot(sources[name], producer=name, version_table=table)
    verify_ghintel(sources["ghintel"])
    configs = config["processors"]
    destinations = {
        "fileintel": resolve_path(base_dir, configs["file_retriever"]["db_path"]),
        "ipintel": resolve_path(base_dir, configs["ip_retriever"]["db_path"]),
        "ghintel": resolve_path(base_dir, configs["ghintel"]["db_path"]),
    }
    if len(set(destinations.values())) != 3:
        raise ImportErrorSet("intelligence database destinations must be distinct")
    if any(sources[name] == destinations[name] for name in sources):
        raise ImportErrorSet("a copied snapshot cannot be its own destination")
    for destination in destinations.values():
        if destination.is_symlink():
            raise ImportErrorSet(f"destination database must not be a symlink: {destination}")
        if destination.exists():
            _no_live_sidecars(destination)
    original_signatures = {name: _signature(path) for name, path in destinations.items()}

    def merge(name: str, destination: Path, *, dry: bool):
        if name == "fileintel":
            return asdict(merge_fileintel(sources[name], destination, dry_run=dry,
                                          intelligence_only=True))
        if name == "ipintel":
            return merge_ipintel(sources[name], destination, dry_run=dry)
        return merge_ghintel(sources[name], destination, dry_run=dry)

    previews = {name: merge(name, destination, dry=True) for name, destination in destinations.items()}
    fingerprints = {name: _digest(path) for name, path in sources.items()}
    import_set_id = hashlib.sha256(json.dumps(fingerprints, sort_keys=True).encode()).hexdigest()
    if dry_run:
        return {"dry_run": True, "import_set_id": import_set_id, "previews": previews}

    staging_root = resolve_path(base_dir, config["dispatcher"]["staging_root"])
    staging_root.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(staging_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ImportErrorSet("triage is active; stop the watcher/report process before importing databases") from exc
        for name, table in versions.items():
            verify_snapshot(sources[name], producer=name, version_table=table)
        verify_ghintel(sources["ghintel"])
        if any(_digest(path) != fingerprints[name] for name, path in sources.items()):
            raise ImportErrorSet("source snapshots changed during import preflight")
        with ExitStack() as stack:
            working = {}
            activation = {}
            for name, destination in destinations.items():
                destination.parent.mkdir(parents=True, exist_ok=True)
                workspace = Path(stack.enter_context(tempfile.TemporaryDirectory(
                    prefix=f".import-{name}-", dir=destination.parent,
                )))
                working[name] = workspace / "working.sqlite3"
                activation[name] = workspace / "activate.sqlite3"
                if destination.exists():
                    _backup_sqlite(destination, working[name])
            applied = {name: merge(name, working[name], dry=False) for name in destinations}
            # Convert any WAL-mode working database into a self-contained, checked file.
            for name in destinations:
                _backup_sqlite(working[name], activation[name])
                if name in versions:
                    with closing(sqlite3.connect(activation[name].as_uri() + "?mode=ro", uri=True)) as check:
                        if name == "fileintel":
                            from erecb_fileintel.db.migrations import validate_fileintel_db
                            check.row_factory = sqlite3.Row
                            validate_fileintel_db(check)
                        else:
                            from erecb_ipintel.merge import validate_ip_db
                            validate_ip_db(check)
                else:
                    from ghintel.merge import _validate
                    with closing(sqlite3.connect(activation[name].as_uri() + "?mode=ro", uri=True)) as check:
                        check.row_factory = sqlite3.Row
                        _validate(check)
            backup_root = base_dir / "data" / "import-backups" / import_set_id
            backup_root.mkdir(parents=True, exist_ok=True)
            backups = {}
            for name, destination in destinations.items():
                if destination.exists():
                    backup_path = backup_root / f"{name}-{destination.name}"
                    if backup_path.exists():
                        backup_path = backup_root / f"{name}-{uuid.uuid4()}-{destination.name}"
                    _backup_sqlite(destination, backup_path)
                    backups[name] = backup_path
            for name, destination in destinations.items():
                if _signature(destination) != original_signatures[name]:
                    raise ImportErrorSet(f"destination database changed during import: {destination}")
                if destination.exists():
                    _no_live_sidecars(destination)
                if _digest(sources[name]) != fingerprints[name]:
                    raise ImportErrorSet(f"source snapshot changed during import: {sources[name]}")
            activated = []
            try:
                for name, destination in destinations.items():
                    os.replace(activation[name], destination)
                    activated.append(name)
                receipt = {"dry_run": False, "import_set_id": import_set_id, "sources": fingerprints,
                           "destinations": {key: str(value) for key, value in destinations.items()},
                           "backups": {key: str(value) for key, value in backups.items()}, "applied": applied}
                (backup_root / "receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2, default=str) + "\n",
                                                          encoding="utf-8")
            except Exception:
                for name in reversed(activated):
                    destination = destinations[name]
                    if name in backups:
                        restore = destination.parent / f".restore-{name}-{import_set_id}.sqlite3"
                        _backup_sqlite(backups[name], restore)
                        os.replace(restore, destination)
                    else:
                        destination.unlink(missing_ok=True)
                raise
            return receipt
    finally:
        os.close(descriptor)
