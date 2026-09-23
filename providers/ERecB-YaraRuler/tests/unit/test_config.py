from pathlib import Path

import pytest

from yararuler.config import load_config
from yararuler.errors import ConfigurationError


def test_load_config_resolves_paths_relative_to_config(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        """
[paths]
rules_dir = "state/rules"
target_dir = "samples"
[rules]
cache_dir = "state/cache"
quarantine_dir = "state/quarantine"
[scan]
threads = 2
""",
        encoding="utf-8",
    )
    loaded = load_config(config)
    assert loaded.paths.rules_dir == (tmp_path / "state/rules").resolve()
    assert loaded.paths.target_dir == (tmp_path / "samples").resolve()
    assert loaded.rules.cache_dir == (tmp_path / "state/cache").resolve()
    assert loaded.scan.threads == 2


def test_unknown_configuration_key_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text("unexpected = true\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="unexpected"):
        load_config(config)


def test_duplicate_source_name_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        """
[[rules.sources]]
name = "same"
url = "https://example.test/a.git"
[[rules.sources]]
name = "same"
url = "https://example.test/b.git"
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="unique"):
        load_config(config)
