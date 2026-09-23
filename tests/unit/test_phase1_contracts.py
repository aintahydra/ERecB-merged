from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from erecb_triage.config import file_retriever_settings, ip_retriever_settings, load_config
from erecb_triage.staging import STAGING_SCHEMA_VERSION, StagingState, manifest


ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests" / "fixtures"


class ConfigurationContractTests(unittest.TestCase):
    def test_default_and_unified_profiles_allow_large_capture_envelope(self) -> None:
        expected_archive = 100 * 1024 ** 3
        expected_extracted = 200 * 1024 ** 3
        for config in (load_config(), load_config(ROOT / "config" / "watcher_all.yaml")):
            unarchiver = config["processors"]["unarchive_all_supported"]
            self.assertEqual(unarchiver["max_archive_size_bytes"], expected_archive)
            self.assertEqual(unarchiver["max_total_extracted_bytes_per_archive"], expected_extracted)
            self.assertGreaterEqual(unarchiver["max_extracted_files_per_archive"], 200_000)

    def test_shipped_profiles_use_fixed_hyphenated_report_suffixes(self) -> None:
        for name in ("watcher_unarchiver.yaml", "watcher_ipintel.yaml", "watcher_fileintel.yaml",
                     "watcher_localintel.yaml", "watcher_ghintel.yaml", "watcher_all.yaml"):
            load_config(ROOT / "config" / name)
        self.assertEqual(
            ip_retriever_settings({
                "type": "ip_retriever", "db_path": "db.sqlite3", "output_root": "output",
                "report_suffix": "-ipintel.md",
            })["report_suffix"],
            "-ipintel.md",
        )
        self.assertEqual(
            file_retriever_settings({
                "type": "file_retriever", "db_path": "db.sqlite3", "output_root": "output",
                "report_suffix": "-fileintel.md",
            })["report_suffix"],
            "-fileintel.md",
        )

    def test_legacy_or_arbitrary_report_suffix_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "report_suffix"):
            ip_retriever_settings({
                "type": "ip_retriever", "db_path": "db.sqlite3", "output_root": "output",
                "report_suffix": "_ipintel.md",
            })
        with self.assertRaisesRegex(ValueError, "report_suffix"):
            file_retriever_settings({
                "type": "file_retriever", "db_path": "db.sqlite3", "output_root": "output",
                "report_suffix": "report.md",
            })

    def test_ip_singularity_threshold_cannot_exceed_the_per_file_bound(self) -> None:
        with self.assertRaisesRegex(ValueError, "ip_singularity_threshold"):
            ip_retriever_settings({
                "type": "ip_retriever", "db_path": "db.sqlite3", "output_root": "output",
                "ip_singularity_threshold": 21, "max_observations_per_file": 20,
                "report_suffix": "-ipintel.md",
            })

    def test_untested_archive_formats_are_rejected_by_configuration(self) -> None:
        config = load_config()
        config["processors"]["unarchive_all_supported"]["supported_formats"] = [".zip", ".tgz"]
        with self.assertRaisesRegex(ValueError, "invalid supported_formats"):
            from erecb_triage.config import validate_config
            validate_config(config)


class StagingMigrationTests(unittest.TestCase):
    def _state(self, temporary: Path, *, clock=None) -> StagingState:
        watch = temporary / "in"
        root = temporary / "middle-earth"
        watch.mkdir(exist_ok=True)
        return StagingState(temporary / "data" / "staging.sqlite3", watch, root, clock=clock)

    def test_legacy_state_migrates_without_adopting_legacy_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            (temporary / "in").mkdir()
            (temporary / "middle-earth").mkdir()
            index = temporary / "data" / "staging.sqlite3"
            index.parent.mkdir()
            legacy_path = temporary / "middle-earth" / "sample.zip-240101-000000"
            legacy_path.mkdir()
            connection = sqlite3.connect(index)
            connection.executescript('''
                CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE captures (
                    id INTEGER PRIMARY KEY, source_relative_path TEXT NOT NULL,
                    source_sha256 TEXT NOT NULL, capture_name TEXT NOT NULL UNIQUE,
                    staged_path TEXT NOT NULL UNIQUE, staging_started_at TEXT,
                    status TEXT NOT NULL, manifest TEXT, error TEXT,
                    UNIQUE(source_relative_path, source_sha256));
                CREATE TABLE reports (
                    report_path TEXT PRIMARY KEY, capture_id INTEGER NOT NULL);
            ''')
            connection.execute(
                "INSERT INTO captures VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (1, "sample.zip.en_dec", "a" * 64, legacy_path.name, str(legacy_path),
                 "2024-01-01T00:00:00Z", "failed", None, "legacy"),
            )
            legacy_report = temporary / "output" / "sample.zip-240101-000000_ipintel.md"
            legacy_report.parent.mkdir()
            legacy_report.write_text("legacy report\n", encoding="utf-8")
            connection.execute("INSERT INTO reports VALUES (?, ?)", (str(legacy_report), 1))
            connection.commit()
            connection.close()

            state = self._state(temporary)
            try:
                migrated = state.get(1)
                self.assertEqual(migrated["report_stem"], "sample.zip.en_dec")
                self.assertEqual(state.connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0], 1)
                self.assertEqual(state.connection.execute("SELECT COUNT(*) FROM report_slots").fetchone()[0], 0)
                self.assertEqual(
                    state.connection.execute(
                        "SELECT value FROM metadata WHERE key = 'staging_schema_version'"
                    ).fetchone()[0],
                    str(STAGING_SCHEMA_VERSION),
                )
                self.assertEqual(legacy_report.read_text(encoding="utf-8"), "legacy report\n")
            finally:
                state.close()

    def test_source_processor_slot_is_stable_across_capture_generations(self) -> None:
        instant = datetime(2024, 1, 1, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary_name:
            state = self._state(Path(temporary_name), clock=lambda: instant)
            try:
                output = Path(temporary_name) / "output"
                output.mkdir()
                first = state.reserve("sample.zip.en_dec", "a" * 64, "sample.zip", True)
                first_path = state.claim_report_slot(first, "ip_retriever", output, "-ipintel.md")
                first_path.write_text("first generation\n", encoding="utf-8")
                second = state.reserve("sample.zip.en_dec", "b" * 64, "sample.zip", True)
                second_path = state.claim_report_slot(second, "ip_retriever", output, "-ipintel.md")
                self.assertNotEqual(first["capture_name"], second["capture_name"])
                self.assertEqual(first_path, output / "sample.zip.en_dec-ipintel.md")
                self.assertEqual(second_path, first_path)
                self.assertEqual(
                    state.connection.execute("SELECT COUNT(*) FROM report_slots").fetchone()[0], 1
                )
            finally:
                state.close()

    def test_record_validator_requires_report_and_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            state = self._state(temporary)
            try:
                row = state.reserve("evidence.txt", "", "evidence.txt", False)
                target = Path(row["staged_path"])
                target.mkdir()
                (target / "note.txt").write_text("inert\n", encoding="utf-8")
                state.update(row["id"], "ready", manifest(target))
                record = {
                    "type": "staged_capture", "capture_name": row["capture_name"],
                    "report_stem": "evidence.txt", "source_name": "evidence.txt",
                    "source_relative_path": "evidence.txt", "source_path": "/safe/in/evidence.txt",
                    "staged_path": str(target), "source_event_id": "evt-test",
                    "pipeline_run_id": "run-test",
                }
                self.assertEqual(state.validate_record(record)["id"], row["id"])
                record["report_stem"] = "different.txt"
                with self.assertRaisesRegex(ValueError, "report identity"):
                    state.validate_record(record)
            finally:
                state.close()

    def test_unknown_newer_schema_refuses_startup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            state = self._state(temporary)
            state.connection.execute(
                "UPDATE metadata SET value = '999' WHERE key = 'staging_schema_version'"
            )
            state.connection.commit()
            state.close()
            with self.assertRaisesRegex(ValueError, "newer schema"):
                self._state(temporary)

    def test_corrupt_partially_migrated_report_stem_refuses_startup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            state = self._state(temporary)
            row = state.reserve("evidence.txt", "", "evidence.txt", False)
            state.connection.execute(
                "UPDATE captures SET report_stem = 'wrong.txt' WHERE id = ?", (row["id"],)
            )
            state.connection.commit()
            state.close()
            with self.assertRaisesRegex(ValueError, "invalid report stem"):
                self._state(temporary)


class FixtureSafetyTests(unittest.TestCase):
    def test_fixtures_are_inert_and_operational_databases_are_read_only(self) -> None:
        self.assertTrue((FIXTURES / "ipintel_schema.sql").is_file())
        self.assertTrue((FIXTURES / "fileintel_schema.sql").is_file())
        self.assertTrue((FIXTURES / "ghintel_schema.sql").is_file())
        for database in (ROOT / "dbs" / "ipintel.sqlite3", ROOT / "dbs" / "fileintel.sqlite3", ROOT / "dbs" / "ghintel.sqlite3"):
            connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
            try:
                self.assertGreaterEqual(connection.execute("SELECT COUNT(*) FROM sqlite_schema").fetchone()[0], 1)
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("CREATE TABLE must_not_write (id INTEGER)")
            finally:
                connection.close()
