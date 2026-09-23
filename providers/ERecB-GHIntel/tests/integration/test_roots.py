import shutil
from pathlib import Path

from ghintel.config import Config
from ghintel.database import database
from ghintel.pipeline import run_discovery
from ghintel.roots import list_roots, remap_root


def test_remapped_root_keeps_local_copy_identity_on_rediscovery(tmp_path: Path) -> None:
    original = tmp_path / "in"
    repository = original / "tool"
    (repository / ".git").mkdir(parents=True)
    (repository / ".git" / "config").write_text('[remote "origin"]\nurl = https://github.com/Example/Tool.git\n', encoding="utf-8")
    (repository / "README.md").write_text("tool", encoding="utf-8")
    moved = tmp_path / "moved"
    shutil.copytree(original, moved)
    config = Config(version=1).resolved(tmp_path / "config.toml")
    config.input_dir = original
    config.db_dir = tmp_path / "db"
    run_discovery(config)

    with database(config.db_path) as connection:
        root = list_roots(connection)[0]
        preview = remap_root(connection, root["name"], moved, reason="machine move", dry_run=True)
        assert preview.dry_run and preview.changed
        remap_root(connection, root["name"], moved, reason="machine move")
        assert connection.execute("SELECT COUNT(*) FROM root_mapping_events").fetchone()[0] == 1
    config.input_dir = moved
    run_discovery(config)
    with database(config.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_roots").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM local_copies").fetchone()[0] == 1
        assert list_roots(connection)[0]["absolute_path"] == str(moved.resolve())
