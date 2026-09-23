from pathlib import Path

from ghintel.config import Config
from ghintel.database import database, lookup_project_card
from ghintel.pipeline import run_discovery


def _repository(path: Path, remote: str, readme: str = "# Tool") -> None:
    (path / ".git").mkdir(parents=True)
    (path / ".git" / "config").write_text(
        f'[remote "origin"]\n\turl = {remote}\n', encoding="utf-8"
    )
    (path / "README.md").write_text(readme, encoding="utf-8")


def test_discovery_is_idempotent_and_excludes_nested_sources(tmp_path: Path) -> None:
    input_dir = tmp_path / "in"
    parent = input_dir / "parent"
    child = parent / "child"
    _repository(parent, "git@github.com:Example/Parent.git", "# Parent")
    _repository(child, "https://github.com/Example/Child.git", "# Child")
    (input_dir / "archive").mkdir(parents=True)
    (input_dir / "archive" / "README.md").write_text("not a repository", encoding="utf-8")

    config = Config(version=1)
    resolved = config.resolved(tmp_path / "config.toml")
    resolved.input_dir = input_dir
    resolved.db_dir = tmp_path / "db"

    first_run, first_count = run_discovery(resolved)
    second_run, second_count = run_discovery(resolved)

    assert first_run != second_run
    assert (first_count, second_count) == (2, 2)
    with database(resolved.db_path) as connection:
        repository_count = connection.execute("SELECT COUNT(*) FROM repositories").fetchone()[0]
        source_rows = connection.execute(
            "SELECT r.name, sd.locator FROM source_documents sd JOIN repositories r ON r.id = sd.repository_id ORDER BY r.name"
        ).fetchall()
        parent = lookup_project_card(connection, "github.com/example/parent")
        child = lookup_project_card(connection, "github.com/example/child")
    assert repository_count == 2
    assert [(row[0], row[1]) for row in source_rows] == [("Child", "README.md"), ("Parent", "README.md")]
    assert parent is not None and child is not None
    assert parent["information_status"] == "not-enriched"
    assert child["local_copies"] == ["parent/child"]
