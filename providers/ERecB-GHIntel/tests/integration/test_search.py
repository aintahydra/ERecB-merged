from pathlib import Path

import pytest

from ghintel.config import Config
from ghintel.database import database, search_project_cards
from ghintel.pipeline import run_discovery
from ghintel.search import SearchQueryError, search_repository_ids


def test_fts_search_returns_current_project_cards(tmp_path: Path) -> None:
    repository = tmp_path / "in" / "cli-tool"
    (repository / ".git").mkdir(parents=True)
    (repository / ".git" / "config").write_text('[remote "origin"]\nurl = https://github.com/Example/CLI-Tool.git\n', encoding="utf-8")
    (repository / "README.md").write_text("Local tool", encoding="utf-8")
    config = Config(version=1).resolved(tmp_path / "config.toml")
    config.input_dir = tmp_path / "in"
    config.db_dir = tmp_path / "db"
    run_discovery(config)

    with database(config.db_path) as connection:
        cards = search_project_cards(connection, "tool")
    assert [card["identity_key"] for card in cards] == ["github.com/example/cli-tool"]


def test_fts_rejects_blank_queries(tmp_path: Path) -> None:
    from ghintel.database import initialize

    path = tmp_path / "db.sqlite3"
    initialize(path)
    with database(path) as connection:
        with pytest.raises(SearchQueryError):
            search_repository_ids(connection, "   ")


def test_fts_treats_punctuation_as_literal_terms(tmp_path: Path) -> None:
    repository = tmp_path / "in" / "cli-tool"
    (repository / ".git").mkdir(parents=True)
    (repository / ".git" / "config").write_text('[remote "origin"]\nurl = https://github.com/Example/CLI-Tool.git\n', encoding="utf-8")
    config = Config(version=1).resolved(tmp_path / "config.toml")
    config.input_dir = tmp_path / "in"
    config.db_dir = tmp_path / "db"
    run_discovery(config)

    with database(config.db_path) as connection:
        hits = search_repository_ids(connection, 'cli-tool )')
    assert [hit.repository_id for hit in hits] == [1]


def test_fts_rejects_punctuation_only_query(tmp_path: Path) -> None:
    from ghintel.database import initialize

    path = tmp_path / "db.sqlite3"
    initialize(path)
    with database(path) as connection:
        with pytest.raises(SearchQueryError, match="letters or numbers"):
            search_repository_ids(connection, "***()")
