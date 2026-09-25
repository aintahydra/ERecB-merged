"""Dispatcher-owned staging identity, manifests and output reservations."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


STAGING_SCHEMA_VERSION = 3


def sanitize_name(name: str) -> str:
    label = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return "capture" if label in ("", ".", "..") else label


def safe_name(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9._-]+", name)) and name not in (".", "..", ".partial")


def safe_report_stem(name: str) -> bool:
    """Return whether *name* is a portable, single archive-basename component."""
    if not isinstance(name, str) or not name or name in {".", ".."}:
        return False
    if "/" in name or "\\" in name:
        return False
    return not any(ord(character) < 32 or 0x7F <= ord(character) <= 0x9F
                   or character in {"\u2028", "\u2029"} for character in name)


def report_stem_for(relative: str) -> str:
    """Derive the immutable report identity from a stored source-relative path."""
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise ValueError("invalid source-relative path for report ownership")
    # The dispatcher currently accepts direct children only.  ``Path.name`` also lets an
    # older nested-capture row migrate without turning its parent directories into a report
    # path.  The stem itself must always be one component.
    stem = Path(relative).name
    if not safe_report_stem(stem):
        raise ValueError("invalid report stem")
    return stem


def regular_reader(path: str | Path, *, dir_fd: int | None = None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"not a regular file: {path}")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def fingerprint(path: Path) -> tuple[int, ...]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise OSError(f"not a regular file: {path}")
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def hash_file(path: Path) -> str:
    before = fingerprint(path)
    digest = hashlib.sha256()
    with regular_reader(path) as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    if before != fingerprint(path):
        raise OSError("source_unstable: file changed while hashing")
    return digest.hexdigest()


def manifest(root: Path) -> list[dict]:
    if root.is_symlink() or not root.is_dir():
        raise OSError("staged output is not a regular directory")
    entries = []
    def fail(error):
        raise error

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        dirs.sort()
        for name in sorted(dirs + files):
            path = Path(directory) / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                entries.append({"path": relative, "type": "directory", "size": 0})
            elif stat.S_ISREG(info.st_mode):
                entries.append({"path": relative, "type": "file", "size": info.st_size,
                                "sha256": hash_file(path)})
            else:
                raise OSError(f"special file in staged output: {relative}")
    return sorted(entries, key=lambda item: item["path"])


def fsync_directory(path: Path) -> None:
    """Persist a directory entry change without following a substituted directory link."""
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class StagingState:
    def __init__(self, index: Path, watch: Path, root: Path,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.root, self.watch = root, watch
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.connection = None
        self.lock_fd = None
        root.mkdir(parents=True, exist_ok=True)
        try:
            # A directory lock cannot collide with a capture's sanitized basename.
            self.lock_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            index.parent.mkdir(parents=True, exist_ok=True)
            if index.is_symlink():
                raise ValueError("staging index must not be a symlink")
            self.connection = sqlite3.connect(index)
            self.connection.row_factory = sqlite3.Row
            self.connection.executescript('''
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS captures (
                    id INTEGER PRIMARY KEY, source_relative_path TEXT NOT NULL,
                    source_sha256 TEXT NOT NULL, capture_name TEXT NOT NULL UNIQUE,
                    staged_path TEXT NOT NULL UNIQUE, report_stem TEXT,
                    staging_started_at TEXT,
                    status TEXT NOT NULL, manifest TEXT, error TEXT,
                    UNIQUE(source_relative_path, source_sha256));
                CREATE TABLE IF NOT EXISTS reports (
                    report_path TEXT PRIMARY KEY, capture_id INTEGER NOT NULL REFERENCES captures(id));
            ''')
            with self.connection:
                self._migrate_schema()
                for key, value in (("watch_root", str(watch)), ("staging_root", str(root))):
                    row = self.connection.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
                    if row and row[0] != value:
                        raise ValueError(f"staging index {key} disagrees with configuration")
                    self.connection.execute("INSERT OR IGNORE INTO metadata VALUES (?, ?)", (key, value))
            self.partial = root / ".partial"
            if self.partial.is_symlink():
                raise ValueError(".partial must not be a symlink")
            self.partial.mkdir(mode=0o700, exist_ok=True)
        except BaseException:
            self.close()
            raise

    def _migrate_schema(self) -> None:
        """Migrate only the dispatcher-owned state database, transactionally.

        ``reports`` is deliberately retained as a legacy table.  Its timestamp-based rows
        must not be adopted by the stable source/processor slots introduced in version 2.
        """
        version_row = self.connection.execute(
            "SELECT value FROM metadata WHERE key = 'staging_schema_version'"
        ).fetchone()
        if version_row is None:
            version = 1
        else:
            try:
                version = int(version_row[0])
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid staging schema version") from exc
            if str(version) != version_row[0]:
                raise ValueError("invalid staging schema version")
        if version > STAGING_SCHEMA_VERSION:
            raise ValueError("staging index uses an unknown newer schema version")

        columns = {row[1] for row in self.connection.execute("PRAGMA table_info(captures)")}
        if "report_stem" not in columns:
            self.connection.execute("ALTER TABLE captures ADD COLUMN report_stem TEXT")
        for row in self.connection.execute(
            "SELECT id, source_relative_path FROM captures WHERE report_stem IS NULL OR report_stem = ''"
        ):
            self.connection.execute(
                "UPDATE captures SET report_stem = ? WHERE id = ?",
                (report_stem_for(row["source_relative_path"]), row["id"]),
            )
        existing = self.connection.execute(
            "SELECT id, source_relative_path, report_stem FROM captures"
        ).fetchall()
        for row in existing:
            expected_stem = report_stem_for(row["source_relative_path"])
            if row["report_stem"] != expected_stem:
                raise ValueError(f"invalid report stem in staging index for capture {row['id']}")
        self.connection.execute('''
            CREATE TABLE IF NOT EXISTS report_slots (
                source_relative_path TEXT NOT NULL,
                processor_name TEXT NOT NULL,
                report_path TEXT NOT NULL UNIQUE,
                PRIMARY KEY (source_relative_path, processor_name)
            )
        ''')
        self.connection.execute('''
            CREATE TABLE IF NOT EXISTS analysis_runs (
                id INTEGER PRIMARY KEY,
                capture_id INTEGER NOT NULL REFERENCES captures(id),
                generated_at TEXT NOT NULL,
                policy_sha256 TEXT NOT NULL,
                database_sha256 TEXT NOT NULL,
                yara_generation TEXT,
                statuses TEXT NOT NULL
            )
        ''')
        self.connection.execute(
            "INSERT INTO metadata(key, value) VALUES ('staging_schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(STAGING_SCHEMA_VERSION),),
        )

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    def get(self, capture_id: int):
        return self.connection.execute("SELECT * FROM captures WHERE id = ?", (capture_id,)).fetchone()

    def next_request_identity(self) -> tuple[str, int]:
        """Allocate a stable, monotonic request identity for this air-gap installation."""
        with self.connection:
            row = self.connection.execute(
                "SELECT value FROM metadata WHERE key = 'request_source_instance_id'"
            ).fetchone()
            source = row[0] if row else str(uuid.uuid4())
            if row is None:
                self.connection.execute(
                    "INSERT INTO metadata(key, value) VALUES ('request_source_instance_id', ?)", (source,)
                )
            row = self.connection.execute(
                "SELECT value FROM metadata WHERE key = 'request_source_sequence'"
            ).fetchone()
            sequence = int(row[0]) + 1 if row else 1
            self.connection.execute(
                "INSERT INTO metadata(key, value) VALUES ('request_source_sequence', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (str(sequence),)
            )
        return source, sequence

    def record_analysis(self, capture_id: int, provenance: dict, statuses: list[dict]) -> None:
        timestamp = self.clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        compact_statuses = [{"name": item["name"], "state": item["state"]} for item in statuses]
        with self.connection:
            self.connection.execute(
                "INSERT INTO analysis_runs(capture_id, generated_at, policy_sha256, "
                "database_sha256, yara_generation, statuses) VALUES (?, ?, ?, ?, ?, ?)",
                (capture_id, timestamp, provenance["policy_sha256"],
                 json.dumps(provenance["database_sha256"], sort_keys=True),
                 provenance.get("yara_generation"), json.dumps(compact_statuses, sort_keys=True)),
            )

    def reserve(self, relative: str, digest: str, label: str, archive: bool,
                parent: Path | None = None, existing_parent: Path | None = None):
        db = self.connection
        report_stem = report_stem_for(relative)
        row = db.execute("SELECT * FROM captures WHERE source_relative_path = ? AND source_sha256 = ?",
                         (relative, digest)).fetchone()
        if row:
            return row
        started = self.clock().astimezone(timezone.utc) if archive else None
        base = sanitize_name(label)
        if not archive and not safe_name(base):
            raise ValueError("naming_error: reserved staging name")
        if archive:
            base += "-" + started.strftime("%y%m%d-%H%M%S")
        counter = 1
        destination = parent or self.root
        if not destination.resolve().is_relative_to(self.root):
            raise ValueError("staging destination escapes staging root")
        while True:
            name = base if counter == 1 else f"{base}-{counter}"
            if len(os.fsencode(name)) > os.pathconf(self.root, "PC_NAME_MAX"):
                raise ValueError("naming_error: capture name exceeds filesystem limit")
            target = destination / name
            occupied = db.execute("SELECT 1 FROM captures WHERE capture_name = ? OR staged_path = ?",
                                  (name, str(target))).fetchone()
            occupied = occupied or os.path.lexists(target)
            occupied = occupied or (existing_parent is not None and os.path.lexists(existing_parent / name))
            if not occupied:
                break
            if not archive:
                raise ValueError("output_collision: exceptional capture name is already owned or occupied")
            counter += 1
        with db:
            cursor = db.execute('''INSERT INTO captures
                (source_relative_path, source_sha256, capture_name, staged_path, report_stem, staging_started_at, status)
                VALUES (?, ?, ?, ?, ?, ?, 'pending')''',
                (relative, digest, name, str(target), report_stem,
                 started.isoformat().replace("+00:00", "Z") if started else None))
        return self.get(cursor.lastrowid)

    def claim_report_slot(self, row, processor_name: str, directory: Path, suffix: str) -> Path:
        """Reserve a stable report path for a logical source/processor slot.

        A changed archive at the same watched filename gets a new capture generation but
        deliberately reuses this path.  The old ``reports`` table is not consulted, so
        legacy timestamp/underscore paths remain untouched.
        """
        if not safe_name(processor_name):
            raise ValueError("invalid report processor name")
        stem = row["report_stem"]
        if not safe_report_stem(stem):
            raise ValueError("invalid report stem")
        path = directory / (stem + suffix)
        if len(os.fsencode(path.name)) > os.pathconf(directory, "PC_NAME_MAX"):
            raise ValueError("naming_error: report name exceeds filesystem limit")
        with self.connection:
            slot = self.connection.execute(
                "SELECT report_path FROM report_slots WHERE source_relative_path = ? AND processor_name = ?",
                (row["source_relative_path"], processor_name),
            ).fetchone()
            if slot is None:
                if os.path.lexists(path):
                    raise ValueError(f"report_collision: unowned report exists: {path}")
                other = self.connection.execute(
                    "SELECT source_relative_path, processor_name FROM report_slots WHERE report_path = ?",
                    (str(path),),
                ).fetchone()
                if other is not None:
                    raise ValueError(f"report_collision: report slot belongs to {other['source_relative_path']}")
                self.connection.execute(
                    "INSERT INTO report_slots VALUES (?, ?, ?)",
                    (row["source_relative_path"], processor_name, str(path)),
                )
            elif slot["report_path"] != str(path):
                raise ValueError("report_collision: configured report path differs from owned slot")
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise ValueError(f"report_collision: unsafe report target: {path}")
        return path

    def update(self, capture_id: int, status: str, entries=None, error=None) -> None:
        with self.connection:
            if entries is None:
                self.connection.execute("UPDATE captures SET status = ?, error = ? WHERE id = ?",
                                        (status, error, capture_id))
            else:
                self.connection.execute("UPDATE captures SET status = ?, manifest = ?, error = ? WHERE id = ?",
                                        (status, json.dumps(entries, sort_keys=True), error, capture_id))

    def usable(self, row) -> bool:
        path = Path(row["staged_path"])
        if not os.path.lexists(path):
            return False
        if (path.is_symlink() or not path.is_dir()
                or not path.resolve().is_relative_to(self.root)):
            raise OSError("recovery_error: unsafe published staging path")
        if row["status"] not in {"ready", "pending"}:
            raise OSError("recovery_error: failed capture has published output")
        if row["manifest"] is None or manifest(path) != json.loads(row["manifest"]):
            raise OSError("recovery_error: output does not match its trusted manifest")
        if row["status"] != "ready":
            self.update(row["id"], "ready")
        return True

    def cleanup_partial(self, capture_id: int) -> None:
        for path in self.partial.glob(f"capture-{capture_id}-*"):
            if path.is_symlink() or not path.is_dir():
                raise OSError("recovery_error: unsafe temporary staging directory")
            shutil.rmtree(path)

    def validate_record(self, record: dict, verify_manifest: bool = False):
        if record.get("type") != "staged_capture":
            raise ValueError("invalid staged capture record type")
        name = record.get("capture_name")
        if not isinstance(name, str) or not safe_name(name):
            raise ValueError("invalid staged capture name")
        row = self.connection.execute(
            "SELECT * FROM captures WHERE capture_name = ?", (name,)
        ).fetchone()
        if row is None or row["status"] != "ready":
            raise ValueError("staged capture is not ready in the staging index")
        path = Path(row["staged_path"])
        if record.get("staged_path") != str(path) or path.name != name:
            raise ValueError("staged capture identity disagrees with the staging index")
        if record.get("report_stem") != row["report_stem"] or not safe_report_stem(row["report_stem"]):
            raise ValueError("staged capture report identity disagrees with the staging index")
        if (record.get("source_relative_path") != row["source_relative_path"]
                or record.get("source_name") != row["report_stem"]):
            raise ValueError("staged capture source identity disagrees with the staging index")
        if not isinstance(record.get("source_path"), str) or not record["source_path"]:
            raise ValueError("invalid staged capture source path")
        if not isinstance(record.get("source_event_id"), str) or not record["source_event_id"]:
            raise ValueError("invalid staged capture event provenance")
        if not isinstance(record.get("pipeline_run_id"), str) or not record["pipeline_run_id"]:
            raise ValueError("invalid staged capture run provenance")
        digest = row["source_sha256"]
        if digest:
            if (not re.fullmatch(r"[0-9a-f]{64}", digest)
                    or record.get("source_sha256") != digest):
                raise ValueError("staged capture digest disagrees with the staging index")
        elif "source_sha256" in record:
            raise ValueError("unexpected staged capture digest")
        if path.is_symlink() or not path.is_dir() or not path.resolve().is_relative_to(self.root):
            raise ValueError("unsafe staged capture path")
        if verify_manifest and not self.usable(row):
            raise ValueError("staged capture output is unavailable")
        return row
