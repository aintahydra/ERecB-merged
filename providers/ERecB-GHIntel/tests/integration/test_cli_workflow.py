import json
from pathlib import Path

from typer.testing import CliRunner

import ghintel.cli as cli
from ghintel.cli import app
from ghintel.config import load_config

ROOT = Path(__file__).parents[4]


def _run(runner: CliRunner, arguments: list[str]) -> str:
    result = runner.invoke(app, arguments,
                          env={"ERECB_MODE_PROFILE": str(ROOT / "config/connected.yaml")})
    assert result.exit_code == 0, result.output
    return result.output


def test_offline_cli_inventory_workflow(tmp_path: Path, monkeypatch) -> None:
    """An investigator can create, query, export, and snapshot a local inventory."""
    runner = CliRunner()
    config = tmp_path / "config.toml"
    _run(runner, ["init", "--config", str(config)])

    repository = tmp_path / "in" / "cli-tool"
    (repository / ".git").mkdir(parents=True)
    (repository / ".git" / "config").write_text(
        '[remote "origin"]\nurl = git@github.com:Example/CLI-Tool.git\n',
        encoding="utf-8",
    )
    (repository / "README.md").write_text("# CLI Tool\nLocal inventory fixture.\n", encoding="utf-8")

    first_discovery = _run(runner, ["discover", "--config", str(config), "--json"])
    second_discovery = _run(runner, ["discover", "--config", str(config), "--json"])
    assert json.loads(first_discovery)["repositories_found"] == 1
    assert json.loads(second_discovery)["repositories_found"] == 1

    card = json.loads(_run(runner, ["lookup", "git@github.com:Example/CLI-Tool.git", "--config", str(config), "--json"]))
    assert card["canonical_url"] == "https://github.com/Example/CLI-Tool"
    assert card["information_status"] == "not-enriched"

    search = json.loads(_run(runner, ["search", "cli-tool", "--config", str(config), "--json"]))
    assert [item["identity_key"] for item in search] == ["github.com/example/cli-tool"]

    exported = tmp_path / "portable" / "projects.json"
    _run(runner, ["export", "--format", "json", "--output", str(exported), "--config", str(config)])
    assert json.loads(exported.read_text(encoding="utf-8"))["repositories"][0]["identity_key"] == "github.com/example/cli-tool"

    snapshot = tmp_path / "portable" / "inventory.sqlite3"
    def unexpected_migration(*_args, **_kwargs):
        raise AssertionError("snapshot export must not initialize or mutate its source database")

    monkeypatch.setattr(cli, "initialize", unexpected_migration)
    _run(runner, ["db", "snapshot", "--output", str(snapshot), "--config", str(config),
                  "--mode-profile", str(ROOT / "config/connected.yaml")])
    _run(runner, ["db", "verify", str(snapshot)])


def test_offline_scan_never_starts_github_or_provider_work(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    config = tmp_path / "config.toml"
    _run(runner, ["init", "--config", str(config)])
    config.write_text(config.read_text(encoding="utf-8").replace("offline = false", "offline = true"), encoding="utf-8")

    repository = tmp_path / "in" / "offline-tool"
    (repository / ".git").mkdir(parents=True)
    (repository / ".git" / "config").write_text(
        '[remote "origin"]\nurl = https://github.com/Example/Offline-Tool.git\n',
        encoding="utf-8",
    )

    async def network_was_attempted(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("offline scan must not start network or provider work")

    monkeypatch.setattr(cli, "fetch_all", network_was_attempted)
    monkeypatch.setattr(cli, "enrich_all", network_was_attempted)

    output = _run(runner, ["scan", "--config", str(config), "--enrich",
                          "--mode-profile", str(ROOT / "config/airgap.yaml")])

    assert "fetch=skipped; enrich=skipped" in output
    card = json.loads(_run(runner, ["lookup", "https://github.com/Example/Offline-Tool", "--config", str(config), "--json"]))
    assert card["information_status"] == "not-enriched"


def test_scan_target_dir_is_persisted_and_used(tmp_path: Path) -> None:
    runner = CliRunner()
    config = tmp_path / "config.toml"
    _run(runner, ["init", "--config", str(config)])
    config.write_text(config.read_text(encoding="utf-8").replace("offline = false", "offline = true"), encoding="utf-8")

    target = tmp_path / "external corpus" / "dated"
    repository = target / "tool"
    (repository / ".git").mkdir(parents=True)
    (repository / ".git" / "config").write_text(
        '[remote "origin"]\nurl = https://github.com/Example/Target-Tool.git\n',
        encoding="utf-8",
    )

    output = _run(runner, ["scan", "--target-dir", str(target), "--config", str(config)])

    assert "Saved paths.input_dir" in output
    assert "1 repository boundaries" in output
    assert load_config(config).input_dir == target.resolve()
    assert f'input_dir = "{target.resolve()}"' in config.read_text(encoding="utf-8")


def test_scan_rejects_missing_target_dir_without_changing_config(tmp_path: Path) -> None:
    runner = CliRunner()
    config = tmp_path / "config.toml"
    _run(runner, ["init", "--config", str(config)])
    original = config.read_text(encoding="utf-8")

    result = runner.invoke(app, ["scan", "--target-dir", str(tmp_path / "missing"), "--config", str(config)],
                           env={"ERECB_MODE_PROFILE": str(ROOT / "config/connected.yaml")})

    assert result.exit_code == 2
    assert "target directory does not exist" in result.output
    assert config.read_text(encoding="utf-8") == original
