import csv
import json
from pathlib import Path

from ghintel.config import Config
from ghintel.corrections import append_correction
from ghintel.database import database
from ghintel.exports import export_csv, export_json
from ghintel.pipeline import run_discovery


def test_json_and_csv_exports_are_portable_and_exclude_source_blobs(tmp_path: Path) -> None:
    repository = tmp_path / "in" / "tool"
    (repository / ".git").mkdir(parents=True)
    (repository / ".git" / "config").write_text('[remote "origin"]\nurl = https://github.com/Example/Tool.git\n', encoding="utf-8")
    (repository / "README.md").write_text("TOP SECRET SOURCE BLOB", encoding="utf-8")
    config = Config(version=1).resolved(tmp_path / "config.toml")
    config.input_dir = tmp_path / "in"
    config.db_dir = tmp_path / "db"
    run_discovery(config)

    with database(config.db_path) as connection:
        repository_id = connection.execute("SELECT id FROM repositories").fetchone()[0]
        append_correction(connection, repository_id, "summary", "=formula-looking purpose", "manual confirmation")
        json_path = export_json(connection, tmp_path / "output" / "projects.json")
        manifest_path = export_csv(connection, tmp_path / "output" / "csv")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["export_version"] == 1
    assert payload["repositories"][0]["purpose"] == "=formula-looking purpose"
    assert "TOP SECRET SOURCE BLOB" not in json_path.read_text(encoding="utf-8")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert {item["name"] for item in manifest["files"]} >= {"repositories.csv", "remotes.csv", "corrections.csv"}
    with (manifest_path.parent / "repositories.csv").open(encoding="utf-8", newline="") as handle:
        row = next(csv.DictReader(handle))
    assert row["purpose"] == "'=formula-looking purpose"
