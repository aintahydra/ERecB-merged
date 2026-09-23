from pathlib import Path

from ghintel.config import Config
from ghintel.corrections import append_correction
from ghintel.database import database, lookup_project_card, search_project_cards
from ghintel.pipeline import run_discovery
from ghintel.search import refresh_repository_search


def test_corrections_are_append_only_effective_and_searchable(tmp_path: Path) -> None:
    repository = tmp_path / "in" / "tool"
    (repository / ".git").mkdir(parents=True)
    (repository / ".git" / "config").write_text('[remote "origin"]\nurl = https://github.com/Example/Tool.git\n', encoding="utf-8")
    (repository / "README.md").write_text("tool", encoding="utf-8")
    config = Config(version=1).resolved(tmp_path / "config.toml")
    config.input_dir = tmp_path / "in"
    config.db_dir = tmp_path / "db"
    run_discovery(config)

    with database(config.db_path) as connection:
        repository_id = connection.execute("SELECT id FROM repositories").fetchone()[0]
        first_finding = connection.execute(
            "INSERT INTO findings(repository_id, version, input_fingerprint, summary, provenance, created_at) VALUES (?, 1, 'one', 'old purpose', 'test', '2026-01-01T00:00:00+00:00')",
            (repository_id,),
        ).lastrowid
        connection.execute("INSERT INTO repository_current_findings(repository_id, finding_id) VALUES (?, ?)", (repository_id, first_finding))
        refresh_repository_search(connection, repository_id)
        first = append_correction(connection, repository_id, "summary", "corrected searchable purpose", "verified manually")
        second = append_correction(connection, repository_id, "summary", "newest corrected purpose", "newer verification")
        second_finding = connection.execute(
            "INSERT INTO findings(repository_id, version, input_fingerprint, summary, provenance, created_at) VALUES (?, 2, 'two', 'refreshed purpose', 'test', '2026-01-02T00:00:00+00:00')",
            (repository_id,),
        ).lastrowid
        connection.execute("UPDATE repository_current_findings SET finding_id=? WHERE repository_id=?", (second_finding, repository_id))
        refresh_repository_search(connection, repository_id)
        connection.commit()
        card = lookup_project_card(connection, "github.com/example/tool")
        search = search_project_cards(connection, "newest")
        history = connection.execute("SELECT id, supersedes_id FROM corrections ORDER BY id").fetchall()
    assert card is not None
    assert card["purpose"] == "newest corrected purpose"
    assert card["corrections_applied"] == ["summary"]
    assert [item["identity_key"] for item in search] == ["github.com/example/tool"]
    assert [(row["id"], row["supersedes_id"]) for row in history] == [(first, None), (second, first)]
