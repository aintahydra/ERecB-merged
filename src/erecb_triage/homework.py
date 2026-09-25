"""Provider-owned, offline import and LIFO scheduling of request homework.

Each producer opens its own state file. This database is never part of an intelligence
snapshot copied to the air-gapped machine.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from erecb_triage.exchange import read_bundle


_FIELDS = {"file": "files", "ip": "ips", "repository": "repositories"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class HomeworkQueue:
    def __init__(self, path: Path, kind: str):
        if kind not in _FIELDS:
            raise ValueError("homework kind must be file, ip, or repository")
        self.kind, self.path = kind, path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS imported_bundles (
                bundle_id TEXT PRIMARY KEY, source_instance_id TEXT NOT NULL,
                source_sequence INTEGER NOT NULL, created_at TEXT NOT NULL,
                imported_at TEXT NOT NULL, selection TEXT NOT NULL,
                UNIQUE(source_instance_id, source_sequence)
            );
            CREATE TABLE IF NOT EXISTS items (
                identity TEXT PRIMARY KEY, payload TEXT NOT NULL,
                first_requested_at TEXT NOT NULL, last_requested_at TEXT NOT NULL,
                last_source_instance_id TEXT NOT NULL, last_source_sequence INTEGER NOT NULL,
                last_bundle_id TEXT NOT NULL,
                request_count INTEGER NOT NULL, status TEXT NOT NULL,
                last_outcome TEXT, next_eligible_at TEXT,
                lease_until TEXT, lease_token TEXT, attempts INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS request_events (
                bundle_id TEXT NOT NULL REFERENCES imported_bundles(bundle_id),
                identity TEXT NOT NULL REFERENCES items(identity),
                PRIMARY KEY(bundle_id, identity)
            );
            CREATE TABLE IF NOT EXISTS attempt_events (
                id INTEGER PRIMARY KEY, identity TEXT NOT NULL REFERENCES items(identity),
                attempted_at TEXT NOT NULL, outcome TEXT NOT NULL,
                bundle_id TEXT NOT NULL, detail TEXT
            );
            CREATE TABLE IF NOT EXISTS queue_meta (
                key TEXT PRIMARY KEY, value TEXT NOT NULL
            );
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(items)")}
        if "lease_token" not in columns:
            self.db.execute("ALTER TABLE items ADD COLUMN lease_token TEXT")
            self.db.commit()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self) -> None:
        self.db.close()

    def import_bundle(self, path: Path) -> dict[str, int | bool]:
        bundle = read_bundle(path)  # Verify before touching queue state.
        now = _stamp(_utc_now())
        entries = bundle[_FIELDS[self.kind]]
        with self.db:
            if self.db.execute("SELECT 1 FROM imported_bundles WHERE bundle_id = ?", (bundle["bundle_id"],)).fetchone():
                return {"imported": False, "requests": 0, "new_items": 0}
            # A repeated source sequence with a different UUID is a conflicting transfer.
            self.db.execute("INSERT INTO imported_bundles VALUES (?, ?, ?, ?, ?, ?)", (
                bundle["bundle_id"], bundle["source_instance_id"], bundle["source_sequence"],
                bundle["created_at"], now, bundle["selection"],
            ))
            new_items = 0
            for entry in entries:
                identity = entry if isinstance(entry, str) else entry["sha256" if self.kind == "file" else "identity_key"]
                payload = json.dumps(entry, sort_keys=True, separators=(",", ":"))
                existing = self.db.execute("SELECT 1 FROM items WHERE identity = ?", (identity,)).fetchone()
                if existing is None:
                    new_items += 1
                    self.db.execute("INSERT INTO items "
                                    "(identity, payload, first_requested_at, last_requested_at, "
                                    "last_source_instance_id, last_source_sequence, last_bundle_id, request_count, status) "
                                    "VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'pending')", (
                        identity, payload, bundle["created_at"], bundle["created_at"],
                        bundle["source_instance_id"], bundle["source_sequence"], bundle["bundle_id"],
                    ))
                else:
                    row = self.db.execute("SELECT last_source_instance_id, last_source_sequence "
                                          "FROM items WHERE identity = ?", (identity,)).fetchone()
                    is_newer = (row["last_source_instance_id"] != bundle["source_instance_id"]
                                or bundle["source_sequence"] > row["last_source_sequence"])
                    if is_newer:
                        self.db.execute("UPDATE items SET payload = ?, last_requested_at = ?, "
                                        "last_source_instance_id = ?, last_source_sequence = ?, last_bundle_id = ?, "
                                        "request_count = request_count + 1, status = 'pending', "
                                        "next_eligible_at = CASE WHEN last_outcome = 'rate_limited' "
                                        "THEN next_eligible_at ELSE NULL END, "
                                        "lease_until = NULL, lease_token = NULL WHERE identity = ?", (
                            payload, bundle["created_at"], bundle["source_instance_id"],
                            bundle["source_sequence"], bundle["bundle_id"], identity,
                        ))
                    else:
                        self.db.execute("UPDATE items SET request_count = request_count + 1 "
                                        "WHERE identity = ?", (identity,))
                self.db.execute("INSERT INTO request_events VALUES (?, ?)", (bundle["bundle_id"], identity))
        return {"imported": True, "requests": len(entries), "new_items": new_items}

    def list_items(self, *, status: str | None = None) -> list[dict[str, Any]]:
        where = "WHERE status = ?" if status else ""
        rows = self.db.execute(
            "SELECT * FROM items " + where +
            " ORDER BY last_source_sequence DESC, last_requested_at DESC, identity",
            (status,) if status else (),
        ).fetchall()
        return [dict(row) for row in rows]

    def pause_until(self) -> str | None:
        row = self.db.execute("SELECT value FROM queue_meta WHERE key='rate_limit_until'").fetchone()
        return row[0] if row else None

    def lease(self, *, limit: int, seconds: int = 300, now: datetime | None = None) -> list[dict[str, Any]]:
        if type(limit) is not int or limit < 1 or type(seconds) is not int or seconds < 1:
            raise ValueError("limit and lease seconds must be positive")
        current = now or _utc_now()
        stamp, until = _stamp(current), _stamp(current + timedelta(seconds=seconds))
        with self.db:
            # BEGIN IMMEDIATE ensures two workers cannot lease the same item.
            self.db.execute("BEGIN IMMEDIATE") if not self.db.in_transaction else None
            paused = self.pause_until()
            if paused is not None and paused > stamp:
                return []
            rows = self.db.execute(
                "SELECT items.*, imported_bundles.selection AS selection FROM items "
                "JOIN imported_bundles ON imported_bundles.bundle_id = items.last_bundle_id "
                "WHERE items.status != 'resolved' "
                "AND (next_eligible_at IS NULL OR next_eligible_at <= ?) "
                "AND (lease_until IS NULL OR lease_until <= ?) "
                "ORDER BY last_source_sequence DESC, last_requested_at DESC, identity LIMIT ?",
                (stamp, stamp, limit),
            ).fetchall()
            leased = []
            for row in rows:
                token = str(uuid.uuid4())
                self.db.execute("UPDATE items SET status = 'leased', lease_until = ?, lease_token = ? "
                                "WHERE identity = ?", (until, token, row["identity"]))
                leased.append({**dict(row), "lease_token": token})
        return leased

    def finish(self, identity: str, *, lease_token: str, outcome: str, detail: str | None = None,
               retry_after_seconds: int | None = None, now: datetime | None = None) -> None:
        if outcome not in {"success", "not_found", "error", "rate_limited"}:
            raise ValueError("invalid homework outcome")
        if retry_after_seconds is not None and (type(retry_after_seconds) is not int or retry_after_seconds < 0):
            raise ValueError("retry delay must be a nonnegative integer")
        current = now or _utc_now()
        with self.db:
            row = self.db.execute("SELECT * FROM items WHERE identity = ? AND status = 'leased' "
                                  "AND lease_token = ?", (identity, lease_token)).fetchone()
            if row is None:
                raise ValueError("item does not have this active lease")
            if retry_after_seconds is None:
                base = 3600 if outcome in {"not_found", "rate_limited"} else 300
                retry_after_seconds = min(86400, base * 2 ** min(row["attempts"], 8))
            next_time = None if outcome == "success" else _stamp(current + timedelta(seconds=retry_after_seconds))
            self.db.execute("UPDATE items SET status = ?, last_outcome = ?, next_eligible_at = ?, "
                            "lease_until = NULL, lease_token = NULL, attempts = attempts + 1 WHERE identity = ?", (
                "resolved" if outcome == "success" else "pending", outcome, next_time, identity,
            ))
            self.db.execute("INSERT INTO attempt_events(identity, attempted_at, outcome, bundle_id, detail) "
                            "VALUES (?, ?, ?, ?, ?)", (identity, _stamp(current), outcome, row["last_bundle_id"], detail))
            if outcome == "rate_limited":
                previous = self.pause_until()
                if previous is None or previous < next_time:
                    self.db.execute("INSERT INTO queue_meta(key, value) VALUES ('rate_limit_until', ?) "
                                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (next_time,))
