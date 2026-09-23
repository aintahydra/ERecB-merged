import json
from pathlib import Path

from ghintel.config import Config
from ghintel.database import database
from ghintel.findings import persist_deterministic_inference, record_provider_result, select_sources
from ghintel.pipeline import run_discovery
from ghintel.providers.base import ProviderResult


def _prepare(tmp_path: Path, *, readme: str | None = None):
    repository = tmp_path / "in" / "tool"
    (repository / ".git").mkdir(parents=True)
    (repository / ".git" / "config").write_text('[remote "origin"]\nurl = https://github.com/Example/Tool.git\n', encoding="utf-8")
    (repository / "README.md").write_text(readme or ("English prose from the documented author. " * 10), encoding="utf-8")
    (repository / "README_ko.md").write_text(("한국어 번역 문서입니다. " * 10), encoding="utf-8")
    config = Config(version=1).resolved(tmp_path / "config.toml")
    config.input_dir = tmp_path / "in"
    config.db_dir = tmp_path / "db"
    run_discovery(config)
    return config


def _response(quote: str) -> str:
    return json.dumps({
        "summary": "A well documented tool",
        "tool_types": ["CLI"],
        "capabilities": ["analysis"],
        "intended_uses": ["testing"],
        "searchable_categories": ["developer tools"],
        "documented_people": [{"name": "Ada Example", "role": "author", "evidence": [{"source_id": 1, "quote": quote}]}],
        "inferred_mother_tongue": {"category": "English", "subject_name": "Ada Example", "rationale": "documented prose", "evidence": [{"source_id": 1, "quote": quote}]},
    })


def test_korean_translation_is_not_selected_as_original_evidence(tmp_path: Path) -> None:
    config = _prepare(tmp_path)
    with database(config.db_path) as connection:
        repository_id = connection.execute("SELECT id FROM repositories").fetchone()[0]
        sources = select_sources(connection, repository_id, 100_000)
    assert [source.locator for source in sources] == ["README.md"]


def test_valid_response_promotes_auditable_finding(tmp_path: Path) -> None:
    config = _prepare(tmp_path)
    with database(config.db_path) as connection:
        repository_id = connection.execute("SELECT id FROM repositories").fetchone()[0]
        source_id = connection.execute("SELECT id FROM source_versions").fetchone()[0]
        finding_id = record_provider_result(
            connection, repository_id, provider="fake", model="fake-1",
            result=ProviderResult(_response("English prose from the documented author."), 10, 20),
            maximum_source_bytes=100_000,
        )
        assert finding_id is not None
        assert connection.execute("SELECT finding_id FROM repository_current_findings").fetchone()[0] == finding_id
        assert connection.execute("SELECT state FROM provider_attempts").fetchone()[0] == "succeeded"
        assert connection.execute("SELECT source_version_id FROM finding_evidence").fetchone()[0] == source_id
        assert connection.execute("SELECT category FROM language_inferences WHERE finding_id=?", (finding_id,)).fetchone()[0] == "English"


def test_invalid_response_is_retained_without_current_promotion(tmp_path: Path) -> None:
    config = _prepare(tmp_path)
    with database(config.db_path) as connection:
        repository_id = connection.execute("SELECT id FROM repositories").fetchone()[0]
        assert record_provider_result(
            connection, repository_id, provider="fake", model="fake-1",
            result=ProviderResult(_response("fabricated text"), 10, 20), maximum_source_bytes=100_000,
        ) is None
        assert connection.execute("SELECT state FROM provider_attempts").fetchone()[0] == "invalid"
        assert connection.execute("SELECT COUNT(*) FROM repository_current_findings").fetchone()[0] == 0


class EnglishDetector:
    def detect(self, text: str):
        return "en", 0.99


def test_explicit_attributable_native_language_statement_is_high_confidence(tmp_path: Path) -> None:
    statement = "Ada Example is a native Korean speaker. "
    config = _prepare(tmp_path, readme=statement * 10)
    with database(config.db_path) as connection:
        repository_id = connection.execute("SELECT id FROM repositories").fetchone()[0]
        record_provider_result(
            connection, repository_id, provider="fake", model="fake-1",
            result=ProviderResult(_response(statement.strip()), 10, 20), maximum_source_bytes=100_000,
        )
        persist_deterministic_inference(connection, repository_id, detector=None, minimum_letters=100, minimum_script_ratio=.2)
        row = connection.execute("SELECT category, method, confidence, rationale FROM language_inferences").fetchone()
    assert tuple(row) == ("Korean", "explicit-statement", "High", "explicit native-language statement in README.md")


def test_deterministic_inference_needs_one_documented_person(tmp_path: Path) -> None:
    config = _prepare(tmp_path)
    with database(config.db_path) as connection:
        repository_id = connection.execute("SELECT id FROM repositories").fetchone()[0]
        record_provider_result(
            connection, repository_id, provider="fake", model="fake-1",
            result=ProviderResult(_response("English prose from the documented author."), 10, 20), maximum_source_bytes=100_000,
        )
        persist_deterministic_inference(connection, repository_id, detector=EnglishDetector(), minimum_letters=100, minimum_script_ratio=.2)
        row = connection.execute("SELECT category, method, confidence FROM language_inferences").fetchone()
    assert tuple(row) == ("English", "language-detector", "Medium")


def test_unattributable_language_claim_is_downgraded_to_unknown(tmp_path: Path) -> None:
    config = _prepare(tmp_path)
    payload = json.loads(_response("English prose from the documented author."))
    payload["inferred_mother_tongue"] = {
        "category": "English",
        "subject_name": None,
        "rationale": "repository text is English",
        "evidence": [],
    }
    with database(config.db_path) as connection:
        repository_id = connection.execute("SELECT id FROM repositories").fetchone()[0]
        finding_id = record_provider_result(
            connection, repository_id, provider="ollama", model="gpt-oss:120b",
            result=ProviderResult(json.dumps(payload), 10, 20), maximum_source_bytes=100_000,
        )
        row = connection.execute(
            "SELECT category, confidence FROM language_inferences WHERE finding_id=?", (finding_id,)
        ).fetchone()
        attempt = connection.execute("SELECT state FROM provider_attempts").fetchone()
    assert finding_id is not None
    assert tuple(row) == ("Unknown", "Unknown")
    assert attempt[0] == "succeeded"
