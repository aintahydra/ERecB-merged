from typer.testing import CliRunner

from yararuler.cli import app

runner = CliRunner()


def test_root_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "update-rules" in result.stdout
    assert "scan" in result.stdout


def test_mutually_exclusive_selectors_fail(tmp_path) -> None:
    config = tmp_path / "config.toml"
    config.write_text("[rules]\ncache_dir='cache'\nquarantine_dir='quarantine'\n", encoding="utf-8")
    result = runner.invoke(app, ["--config", str(config), "scan", "--all", "--exec-only"])
    assert result.exit_code == 2
    assert "mutually exclusive" in result.stderr


def test_cache_import_rejects_connected_profile_before_reading_bundle() -> None:
    from pathlib import Path

    root = Path(__file__).parents[4]
    result = runner.invoke(app, [
        "cache-import", "--source", "missing-cache",
        "--mode-profile", str(root / "config/connected.yaml"),
    ])

    assert result.exit_code == 2
    assert "requires the airgap profile" in result.stderr
