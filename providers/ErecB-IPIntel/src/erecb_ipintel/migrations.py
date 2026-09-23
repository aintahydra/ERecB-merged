from __future__ import annotations

from .db import Database


def migrate(db: Database) -> None:
    db.initialize()
