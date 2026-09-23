from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from erecb_triage.config import load_config
from erecb_triage.dispatcher import Dispatcher
from erecb_triage.events import WatchEvent
from erecb_triage.ghintel.extractor import extract_stream
from erecb_triage.ghintel.normalization import normalize_repository
from erecb_triage.ghintel.repository import GHIntelRepository


ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "ghintel_schema.sql"


def build_database(path: Path, *, ready: bool = False) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(FIXTURE.read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO repositories VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, "github.com", "Owner", "Repository", "github.com/owner/repository",
             "https://github.com/Owner/Repository", None, "created", "updated"),
        )
        if ready:
            connection.execute("DROP VIEW repository_project_cards")
            connection.executescript('''
                CREATE VIEW repository_project_cards AS
                SELECT r.id AS repository_id, r.identity_key, r.canonical_url, r.owner, r.name,
                       1 AS finding_id, 2 AS finding_version, 'corrected purpose' AS purpose,
                       '["scanner"]' AS tool_types_json, '["lookup"]' AS capabilities_json,
                       '["triage"]' AS intended_uses_json, 'local' AS finding_provenance,
                       'created' AS finding_created_at, 'owner-login' AS owner_login,
                       'Owner Display' AS owner_display_name, 'Organization' AS owner_type,
                       'captured' AS github_captured_at,
                       '[{"name":"Documented Person","login":"person","role":"maintainer","quote":"evidence"}]' AS documented_people_json,
                       'ready' AS information_status
                FROM repositories r;
            ''')
        connection.commit()
    finally:
        connection.close()


class NormalizationTests(unittest.TestCase):
    def test_transport_forms_share_the_same_identity(self) -> None:
        forms = ["https://github.com/Owner/Repository.git", "ssh://git@github.com:22/Owner/Repository",
                 "git@github.com:Owner/Repository.git", "github.com/Owner/Repository/"]
        normalized = [normalize_repository(item) for item in forms]
        self.assertTrue(all(item is not None for item in normalized))
        self.assertEqual({item.identity_key for item in normalized}, {"github.com/owner/repository"})
        self.assertEqual(normalized[0].canonical_url, "https://github.com/Owner/Repository")

    def test_invalid_or_subresource_forms_are_rejected(self) -> None:
        for value in ("https://github.com/owner/repository/issues", "https://evilgithub.com/owner/repository",
                      "https://user@github.com/owner/repository", "git@github.com:owner/repository?x=1",
                      "ssh://git@github.com:70000/owner/repository"):
            self.assertIsNone(normalize_repository(value), value)

    def test_stream_extraction_is_chunk_invariant(self) -> None:
        data = b"https://github.com/Owner/Repository git@github.com:Owner/Repository.git"
        for size in range(1, len(data) + 1):
            found, _ = extract_stream(__import__("io").BytesIO(data), chunk_size=size, max_candidate_bytes=2048, max_size=None)
            self.assertEqual(list(found), ["github.com/owner/repository"])
            self.assertEqual(found["github.com/owner/repository"][1], 2)


class RepositoryAndPipelineTests(unittest.TestCase):
    def test_read_only_project_card_and_checked_in_capability_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            database = Path(temporary_name) / "ghintel.sqlite3"
            build_database(database, ready=True)
            before = hashlib.sha256(database.read_bytes()).hexdigest()
            with GHIntelRepository(database.resolve()) as repository:
                result = repository.lookup("github.com/owner/repository")
                self.assertEqual(result.status, "hit")
                self.assertEqual(result.card["purpose"], "corrected purpose")
                self.assertEqual(result.card["tool_types"], ["scanner"])
            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)
        with GHIntelRepository((ROOT / "dbs" / "ghintel.sqlite3").resolve()) as repository:
            self.assertTrue(repository.available, repository.initialization_error)

    def test_archive_pipeline_deduplicates_transport_forms_and_publishes_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            base = Path(temporary_name)
            incoming = base / "in"; incoming.mkdir()
            archive = incoming / "repos.zip.en_dec"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("one.txt", "https://github.com/Owner/Repository.git\n")
                bundle.writestr("two.txt", "git@github.com:Owner/Repository\nhttps://github.com/Unknown/Project\n")
            database = base / "ghintel.sqlite3"; build_database(database, ready=True)
            config = load_config()
            config["watch"]["path"] = "./in"
            config["dispatcher"].update({"staging_root": "./middle-earth", "output_root": "./output", "staging_index_path": "./data/staging.sqlite3"})
            config["pipelines"]["on_added"]["analysis"]["processors"] = ["ghintel"]
            config["processors"]["ghintel"]["db_path"] = "./ghintel.sqlite3"
            with Dispatcher(config, base_dir=base) as dispatcher:
                result = dispatcher.dispatch(WatchEvent.added(incoming, archive))
            self.assertFalse(result.errors, [error.message for error in result.errors])
            report = (base / "output" / "repos.zip.en_dec-ghintel.md").read_text(encoding="utf-8")
            self.assertIn("corrected purpose", report)
            self.assertIn("Repositories Without Local Intelligence", report)
            self.assertIn("https://github\\.com/Unknown/Project", report)
