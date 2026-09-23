from pathlib import Path

from ghintel.database import initialize


def test_migrations_are_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "ghintel.sqlite3"
    assert initialize(path) == [1, 2, 3, 4, 5, 6]
    assert initialize(path) == []
