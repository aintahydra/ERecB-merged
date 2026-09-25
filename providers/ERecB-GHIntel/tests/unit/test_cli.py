from datetime import UTC, datetime, timedelta
from pathlib import Path

from typer.testing import CliRunner

from ghintel import __version__

import ghintel.cli as cli
from ghintel.cli import _configure_enrichment_mode, app
from ghintel.config import Config
from ghintel.stage2 import FetchRateLimitExhausted

ROOT = Path(__file__).parents[4]


def test_scan_rejects_enrichment_targets_without_enrich(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text("version = 1\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["scan", "--config", str(config), "--enrich-limit", "1"])

    assert result.exit_code == 2
    assert "require --enrich" in result.output


def test_scan_rejects_enrichment_refresh_without_enrich(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text("version = 1\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["scan", "--config", str(config), "--enrich-refresh"])

    assert result.exit_code == 2
    assert "require --enrich" in result.output


def test_force_llm_refreshes_only_the_resolved_run_configuration(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text("version = 1\n", encoding="utf-8")
    resolved = Config(version=1).resolved(config_file)

    _configure_enrichment_mode(resolved, refresh=False, force_llm=True)

    assert resolved.config.scan.duplicate_policy == "refresh"
    assert resolved.config.scan.force_llm_on_unchanged is True
    assert config_file.read_text(encoding="utf-8") == "version = 1\n"


def test_version_option_reports_installed_package_version() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == f"ghintel {__version__}"


def test_request_import_rejects_airgap_profile_before_reading_bundle() -> None:
    result = CliRunner().invoke(app, [
        "requests", "import", "missing-bundle.json",
        "--mode-profile", str(ROOT / "config/airgap.yaml"),
    ])

    assert result.exit_code == 2
    assert "requires the connected profile" in result.output


def test_fetch_rate_limit_exits_with_resume_instructions(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    config = tmp_path / "config.toml"
    assert runner.invoke(app, ["init", "--config", str(config)]).exit_code == 0

    async def rate_limited(*_args: object, **_kwargs: object) -> int:
        raise FetchRateLimitExhausted(
            run_id=17,
            reset_at=datetime.now(UTC) + timedelta(hours=1),
            retry_after_seconds=3600,
            completed=20,
            total=25,
        )

    monkeypatch.setattr(cli, "fetch_all", rate_limited)
    result = runner.invoke(app, ["fetch", "--config", str(config)],
                           env={"ERECB_MODE_PROFILE": str(ROOT / "config/connected.yaml")})

    assert result.exit_code == 7
    assert "safely interrupted" in result.output
    assert "Completed: 20/25; remaining: 5" in result.output
    assert "ghintel resume 17" in result.output
