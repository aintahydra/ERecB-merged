import asyncio
import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ghintel.config import Config
from ghintel.database import database, lookup_project_card
from ghintel.github_client import GithubRateLimitExhausted, GithubRequestError, GithubResponse
from ghintel.pipeline import run_discovery
from ghintel.stage2 import FetchRateLimitExhausted, doctor_report, fetch_all, verify_configured_gemini_model, verify_configured_model


def _repository(path: Path) -> None:
    (path / ".git").mkdir(parents=True)
    (path / ".git" / "config").write_text('[remote "origin"]\nurl = https://github.com/Example/Tool.git\n', encoding="utf-8")


class FakeGithub:
    async def repository(self, owner: str, name: str, *, refresh: bool = False) -> GithubResponse:
        assert (owner, name) == ("Example", "Tool")
        return GithubResponse(200, {"full_name": "Example/Tool", "description": "A useful test tool.", "stargazers_count": 42, "license": {"spdx_id": "MIT"}, "fork": True, "parent": {"full_name": "Upstream/Tool"}, "owner": {"login": "Example", "type": "User"}}, False, {})

    async def profile(self, login: str, *, refresh: bool = False) -> GithubResponse:
        assert login == "Example"
        return GithubResponse(200, {"login": "Example", "bio": "Profile text for testing."}, False, {})

    async def readme(self, owner: str, name: str, *, refresh: bool = False) -> GithubResponse:
        content = base64.b64encode(b"# Tool\nA documented test tool.").decode()
        return GithubResponse(200, {"path": "README.md", "encoding": "base64", "content": content}, False, {})


class OrganizationGithub(FakeGithub):
    async def repository(self, owner: str, name: str, *, refresh: bool = False) -> GithubResponse:
        return GithubResponse(200, {"full_name": "Example/Tool", "owner": {"login": "ExampleOrg", "type": "Organization"}}, False, {})

    async def profile(self, login: str, *, refresh: bool = False) -> GithubResponse:
        raise AssertionError("organization profiles must not be collected as person evidence")


class UnavailableGithub(FakeGithub):
    async def repository(self, owner: str, name: str, *, refresh: bool = False) -> GithubResponse:
        raise GithubRequestError("GitHub repository is private or unavailable (404)")


def test_fetch_records_snapshot_readme_and_completed_run(tmp_path: Path) -> None:
    source = tmp_path / "in" / "tool"
    _repository(source)
    resolved = Config(version=1).resolved(tmp_path / "config.toml")
    resolved.input_dir = tmp_path / "in"
    resolved.db_dir = tmp_path / "db"
    run_discovery(resolved)

    with database(resolved.db_path) as connection:
        run_id = asyncio.run(fetch_all(connection, resolved, client=FakeGithub()))
        assert connection.execute("SELECT status FROM runs WHERE id=?", (run_id,)).fetchone()[0] == "complete"
        assert connection.execute("SELECT COUNT(*) FROM github_snapshots").fetchone()[0] == 1
        assert connection.execute("SELECT summary FROM findings").fetchone()[0] == "A useful test tool."
        assert connection.execute("SELECT content FROM source_versions WHERE content LIKE '%documented test tool%' ").fetchone()[0].endswith("tool.")
        card = lookup_project_card(connection, "github.com/example/tool")
        assert card is not None
        assert (card["stars_count"], card["license_spdx"], card["is_fork"], card["parent_url"]) == (42, "MIT", True, "https://github.com/Upstream/Tool")
        profile = connection.execute("SELECT content FROM source_versions WHERE content LIKE '%Profile text for testing.%'").fetchone()[0]
        assert "does not establish repository authorship" in profile


def test_fetch_does_not_capture_organization_profile(tmp_path: Path) -> None:
    source = tmp_path / "in" / "tool"
    _repository(source)
    resolved = Config(version=1).resolved(tmp_path / "config.toml")
    resolved.input_dir = tmp_path / "in"
    resolved.db_dir = tmp_path / "db"
    run_discovery(resolved)

    with database(resolved.db_path) as connection:
        asyncio.run(fetch_all(connection, resolved, client=OrganizationGithub()))
        assert connection.execute("SELECT COUNT(*) FROM source_documents WHERE kind='profile'").fetchone()[0] == 0


def test_rate_limited_fetch_is_interrupted_and_resumes_from_checkpoint(tmp_path: Path) -> None:
    source = tmp_path / "in" / "tool"
    _repository(source)
    resolved = Config(version=1).resolved(tmp_path / "config.toml")
    resolved.input_dir = tmp_path / "in"
    resolved.db_dir = tmp_path / "db"
    run_discovery(resolved)

    class LimitedGithub(OrganizationGithub):
        async def readme(self, owner: str, name: str, *, refresh: bool = False) -> GithubResponse:
            raise GithubRateLimitExhausted(
                reset_at=datetime.now(UTC) + timedelta(hours=1),
                retry_after_seconds=3600,
                status_code=403,
            )

    class ResumedGithub(OrganizationGithub):
        async def repository(self, owner: str, name: str, *, refresh: bool = False) -> GithubResponse:
            raise AssertionError("resuming a fetched item must not fetch repository metadata again")

    progress: list[tuple[int, int, str]] = []
    with database(resolved.db_path) as connection:
        try:
            asyncio.run(fetch_all(connection, resolved, client=LimitedGithub(), progress=lambda *item: progress.append(item)))
        except FetchRateLimitExhausted as error:
            run_id = error.run_id
            assert (error.completed, error.total) == (0, 1)
        else:
            raise AssertionError("the rate-limited fetch should be resumable")

        run = connection.execute("SELECT status FROM runs WHERE id=?", (run_id,)).fetchone()
        item = connection.execute("SELECT state, error_code FROM run_items WHERE run_id=?", (run_id,)).fetchone()
        assert run["status"] == "interrupted"
        assert (item["state"], item["error_code"]) == ("fetched", "GithubRateLimitExhausted")
        assert connection.execute("SELECT COUNT(*) FROM github_snapshots").fetchone()[0] == 1

        assert asyncio.run(fetch_all(connection, resolved, client=ResumedGithub(), run_id=run_id)) == run_id
        assert connection.execute("SELECT status FROM runs WHERE id=?", (run_id,)).fetchone()[0] == "complete"
        assert connection.execute("SELECT state FROM run_items WHERE run_id=?", (run_id,)).fetchone()[0] == "complete"
        assert connection.execute("SELECT COUNT(*) FROM github_snapshots").fetchone()[0] == 1
        assert progress == [(1, 1, "github.com/example/tool")]


def test_configured_model_check_uses_provider_without_repository_text(tmp_path: Path, monkeypatch) -> None:
    class FakeVerifier:
        async def verify_model(self) -> str:
            return "models/gemini-test"

    resolved = Config(version=1).resolved(tmp_path / "config.toml")
    monkeypatch.setenv("GEMINI_API_KEY", "test-only-key")
    assert asyncio.run(verify_configured_gemini_model(resolved, provider=FakeVerifier())) == "models/gemini-test"


def test_configured_provider_check_uses_anthropic_without_repository_text(tmp_path: Path, monkeypatch) -> None:
    class FakeVerifier:
        async def verify_model(self) -> str:
            return "claude-sonnet-4-6"

    resolved = Config(version=1).resolved(tmp_path / "config.toml")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-only-key")
    assert asyncio.run(verify_configured_model(resolved, provider=FakeVerifier())) == "claude-sonnet-4-6"


def test_doctor_never_requires_network_and_reports_unpriced_selected_provider(tmp_path: Path) -> None:
    resolved = Config(version=1).resolved(tmp_path / "config.toml")
    resolved.db_dir = tmp_path / "db"
    from ghintel.database import initialize
    initialize(resolved.db_path)
    with database(resolved.db_path) as connection:
        report = doctor_report(connection, resolved)
    assert report["network_checked"] is False
    assert report["provider_ready"] is False
    assert report["provider_model_checked"] is False
    assert report["provider_model_available"] is None
    assert any("pricing" in issue for issue in report["issues"])


def test_configured_provider_check_uses_ollama_without_credentials(tmp_path: Path) -> None:
    class FakeVerifier:
        async def verify_model(self) -> str:
            return "gpt-oss:120b"

    resolved = Config(
        version=1,
        enrichment={"provider": "ollama"},
        ollama={"enabled": True, "endpoint": "http://192.168.0.6:11434"},
    ).resolved(tmp_path / "config.toml")
    assert asyncio.run(verify_configured_model(resolved, provider=FakeVerifier())) == "gpt-oss:120b"
