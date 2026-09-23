import asyncio
import json
import re
from pathlib import Path

import pytest

from ghintel.config import Config
from ghintel.database import database
from ghintel.enrichment import _cached_finding, BudgetReconciliationError, EnrichmentPreflightError, _ledger, _reservation, enrich_all, preflight_gemini, preflight_provider, reconcile_budget_usage
from ghintel.pipeline import run_discovery
from ghintel.stage2 import create_run
from ghintel.providers.base import ProviderRequest, ProviderResult


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = tmp_path / "in" / "tool"
    (repository / ".git").mkdir(parents=True)
    (repository / ".git" / "config").write_text('[remote "origin"]\nurl = https://github.com/Example/Tool.git\n', encoding="utf-8")
    (repository / "README.md").write_text("Ada Example created this English documentation tool.", encoding="utf-8")
    config = Config(version=1).resolved(tmp_path / "config.toml")
    config.input_dir = tmp_path / "in"
    config.db_dir = tmp_path / "db"
    config.config.pricing.gemini.input_usd_per_million_tokens = 1.0
    config.config.pricing.gemini.output_usd_per_million_tokens = 1.0
    config.config.enrichment.provider = "gemini"
    config.config.scan.duplicate_policy = "refresh"
    monkeypatch.setenv("GEMINI_API_KEY", "test-only-key")
    run_discovery(config)
    return config


class FakeProvider:
    provider_name = "fake"
    model = "fake-1"

    def __init__(self) -> None:
        self.counts = 0
        self.requests = 0

    async def count_tokens(self, prompt: str) -> int:
        self.counts += 1
        return 12

    async def enrich(self, request: ProviderRequest) -> ProviderResult:
        self.requests += 1
        source_id = int(re.search(r'<source id="(\d+)"', request.prompt).group(1))
        quote = "Ada Example created this English documentation tool."
        return ProviderResult(json.dumps({
            "summary": "Documentation tool",
            "tool_types": ["CLI"], "capabilities": ["documentation"], "intended_uses": ["testing"], "searchable_categories": [],
            "documented_people": [{"name": "Ada Example", "role": "author", "evidence": [{"source_id": source_id, "quote": quote}]}],
            "inferred_mother_tongue": {"category": "English", "subject_name": "Ada Example", "rationale": "English statement", "evidence": [{"source_id": source_id, "quote": quote}]},
        }), 10, 6)


def test_enrich_records_actual_usage_and_reuses_validated_response(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _prepared(tmp_path, monkeypatch)
    provider = FakeProvider()
    with database(config.db_path) as connection:
        first = asyncio.run(enrich_all(connection, config, provider=provider))
        assert connection.execute("SELECT status FROM runs WHERE id=?", (first,)).fetchone()[0] == "complete"
        connection.execute("UPDATE runs SET status='interrupted', completed_at=NULL WHERE id=?", (first,))
        connection.execute("UPDATE run_items SET state='failed' WHERE run_id=?", (first,))
        connection.commit()
        assert asyncio.run(enrich_all(connection, config, provider=provider, run_id=first)) == first
        assert connection.execute("SELECT state FROM run_items WHERE run_id=?", (first,)).fetchone()[0] == "complete"
        assert connection.execute("SELECT cost_micro_usd FROM provider_attempts").fetchone()[0] > 0
        assert connection.execute("SELECT COUNT(*) FROM budget_ledger WHERE kind='commit'").fetchone()[0] == 1
    assert (provider.counts, provider.requests) == (1, 1)


class EnglishDetector:
    def detect(self, text: str):
        return "en", 0.99


def test_cache_reuse_requires_current_prompt_and_schema_versions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _prepared(tmp_path, monkeypatch)
    provider = FakeProvider()
    with database(config.db_path) as connection:
        asyncio.run(enrich_all(connection, config, provider=provider))
        repository_id = connection.execute("SELECT id FROM repositories").fetchone()[0]
        cache = connection.execute("SELECT provider, model, source_set_hash FROM provider_cache").fetchone()
        connection.execute("UPDATE provider_cache SET prompt_version='obsolete'")
        connection.commit()
        assert _cached_finding(connection, repository_id, cache["provider"], cache["model"], cache["source_set_hash"]) is None


def test_enrichment_promotes_deterministic_language_when_evidence_is_attributable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _prepared(tmp_path, monkeypatch)
    config.config.language.minimum_letters = 20
    with database(config.db_path) as connection:
        asyncio.run(enrich_all(connection, config, provider=FakeProvider(), detector=EnglishDetector()))
        row = connection.execute("SELECT category, method, confidence FROM language_inferences").fetchone()
    assert tuple(row) == ("English", "language-detector", "Medium")


def test_resume_keeps_unsettled_reservation_before_new_dispatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _prepared(tmp_path, monkeypatch)
    config.config.budgets.max_gemini_requests_per_run = 1
    config.config.budgets.max_repositories_enriched_per_run = 1
    provider = FakeProvider()
    with database(config.db_path) as connection:
        run_id = create_run(connection, kind="enrich", config=config)
        repository_id = connection.execute("SELECT id FROM repositories").fetchone()[0]
        reserved = _reservation(config, 12)
        _ledger(connection, run_id, repository_id, None, "reserve", reserved)
        assert reconcile_budget_usage(connection, run_id) == reserved

        assert asyncio.run(enrich_all(connection, config, provider=provider, run_id=run_id)) == run_id
        assert connection.execute("SELECT state FROM run_items WHERE run_id=?", (run_id,)).fetchone()[0] == "blocked_budget"
        assert connection.execute("SELECT COUNT(*) FROM budget_ledger WHERE run_id=?", (run_id,)).fetchone()[0] == 1
    assert provider.requests == 0


def test_reconciliation_releases_failed_request_reservation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _prepared(tmp_path, monkeypatch)
    with database(config.db_path) as connection:
        run_id = create_run(connection, kind="enrich", config=config)
        repository_id = connection.execute("SELECT id FROM repositories").fetchone()[0]
        reserved = _reservation(config, 12)
        _ledger(connection, run_id, repository_id, None, "reserve", reserved)
        _ledger(connection, run_id, repository_id, None, "release", reserved)
        usage = reconcile_budget_usage(connection, run_id)
    assert (usage.requests, usage.repositories, usage.input_tokens, usage.output_tokens, usage.cost_micro_usd) == (0, 0, 0, 0, 0)


def test_reconciliation_refuses_malformed_ledger_history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _prepared(tmp_path, monkeypatch)
    with database(config.db_path) as connection:
        run_id = create_run(connection, kind="enrich", config=config)
        repository_id = connection.execute("SELECT id FROM repositories").fetchone()[0]
        _ledger(connection, run_id, repository_id, None, "commit", _reservation(config, 12))
        with pytest.raises(BudgetReconciliationError, match="no prior reserve"):
            reconcile_budget_usage(connection, run_id)


def test_budget_refusal_happens_before_provider_dispatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _prepared(tmp_path, monkeypatch)
    config.config.budgets.max_gemini_requests_per_run = 0
    provider = FakeProvider()
    with database(config.db_path) as connection:
        run_id = asyncio.run(enrich_all(connection, config, provider=provider))
        assert connection.execute("SELECT state FROM run_items WHERE run_id=?", (run_id,)).fetchone()[0] == "blocked_budget"
    assert provider.requests == 0


def test_preflight_refuses_missing_key_without_provider_contact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = Config(version=1).resolved(tmp_path / "config.toml")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(EnrichmentPreflightError):
        preflight_gemini(config)


def test_preflight_accepts_enabled_local_ollama_without_credentials(tmp_path: Path) -> None:
    config = Config(
        version=1,
        enrichment={"provider": "ollama"},
        ollama={"enabled": True, "endpoint": "http://192.168.0.6:11434"},
    ).resolved(tmp_path / "config.toml")
    assert preflight_provider(config) == ""


def test_selection_creates_work_items_only_for_requested_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _prepared(tmp_path, monkeypatch)
    extra = config.input_dir / "second"
    (extra / ".git").mkdir(parents=True)
    (extra / ".git" / "config").write_text('[remote "origin"]\nurl = https://github.com/Example/Second.git\n', encoding="utf-8")
    (extra / "README.md").write_text("Ada Example created this English documentation tool.", encoding="utf-8")
    run_discovery(config)
    provider = FakeProvider()
    with database(config.db_path) as connection:
        run_id = asyncio.run(
            enrich_all(connection, config, provider=provider, repository_refs=("Example/Second",), limit=1)
        )
        rows = connection.execute(
            "SELECT r.identity_key, item.state FROM run_items item JOIN repositories r ON r.id=item.repository_id WHERE item.run_id=?",
            (run_id,),
        ).fetchall()
    assert [tuple(row) for row in rows] == [("github.com/example/second", "complete")]
    assert provider.requests == 1


def test_limit_creates_only_the_first_canonical_work_item(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _prepared(tmp_path, monkeypatch)
    extra = config.input_dir / "second"
    (extra / ".git").mkdir(parents=True)
    (extra / ".git" / "config").write_text('[remote "origin"]\nurl = https://github.com/Example/Second.git\n', encoding="utf-8")
    (extra / "README.md").write_text("Ada Example created this English documentation tool.", encoding="utf-8")
    run_discovery(config)
    with database(config.db_path) as connection:
        run_id = asyncio.run(enrich_all(connection, config, provider=FakeProvider(), limit=1))
        total = connection.execute("SELECT COUNT(*) FROM run_items WHERE run_id=?", (run_id,)).fetchone()[0]
    assert total == 1
