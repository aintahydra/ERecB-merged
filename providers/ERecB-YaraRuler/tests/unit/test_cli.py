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
