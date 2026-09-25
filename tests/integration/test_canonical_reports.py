from __future__ import annotations

import sqlite3
import tempfile
import unittest
import zipfile
from hashlib import md5, sha256
from pathlib import Path

from erecb_triage.config import load_config
from erecb_triage.dispatcher import Dispatcher
from erecb_triage.events import WatchEvent


ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests" / "fixtures"


def build_fixture_database(path: Path, schema_name: str) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript((FIXTURES / schema_name).read_text(encoding="utf-8"))
        connection.commit()
    finally:
        connection.close()


class CanonicalReportIntegrationTests(unittest.TestCase):
    def test_archive_basename_owns_both_reports_not_timestamped_capture_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            base = Path(temporary_name)
            incoming = base / "in"
            incoming.mkdir()
            archive = incoming / "case.zip.en_dec"
            payload = b"MZ\x00\x00"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("ioc.txt", "Observed 8.8.8.8\n")
                bundle.writestr("payload.exe", payload)
            build_fixture_database(base / "ipintel.sqlite3", "ipintel_schema.sql")
            build_fixture_database(base / "fileintel.sqlite3", "fileintel_schema.sql")
            database = sqlite3.connect(base / "ipintel.sqlite3")
            try:
                database.execute(
                    "INSERT INTO ip_entities VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (1, "8.8.8.8", 4, "8.8.8.8", None, "US", None, "Yes", "first", "last"),
                )
                database.commit()
            finally:
                database.close()
            database = sqlite3.connect(base / "fileintel.sqlite3")
            try:
                database.execute(
                    "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (1, sha256(payload).hexdigest(), md5(payload, usedforsecurity=False).hexdigest(),
                     "PE32", "yes", "first", "last"),
                )
                database.commit()
            finally:
                database.close()

            config = load_config()
            config["watch"]["path"] = "./in"
            config["dispatcher"].update({
                "staging_root": "./middle-earth", "output_root": "./output",
                "staging_index_path": "./data/staging.sqlite3",
            })
            config["pipelines"]["on_added"]["analysis"]["processors"] = [
                "ip_retriever", "file_retriever"
            ]
            config["processors"]["ip_retriever"]["db_path"] = "./ipintel.sqlite3"
            config["processors"]["ip_retriever"]["selector"] = "all"
            config["processors"]["file_retriever"]["db_path"] = "./fileintel.sqlite3"
            config["processors"]["file_retriever"]["classifier"] = {
                "use_magic": False, "extension_fallback": True,
            }

            with Dispatcher(config, base_dir=base) as dispatcher:
                result = dispatcher.dispatch(WatchEvent.added(incoming, archive))

            self.assertFalse(result.errors, [error.message for error in result.errors])
            output = base / "output"
            self.assertTrue((output / "case.zip.en_dec-ipintel.md").is_file())
            self.assertTrue((output / "case.zip.en_dec-fileintel.md").is_file())
            self.assertIn("Archive filename: case\\.zip\\.en\\_dec", (
                output / "case.zip.en_dec-ipintel.md"
            ).read_text(encoding="utf-8"))
            ip_report = (output / "case.zip.en_dec-ipintel.md").read_text(encoding="utf-8")
            file_report = (output / "case.zip.en_dec-fileintel.md").read_text(encoding="utf-8")
            self.assertIn("8.8.8.8", ip_report)
            self.assertIn("IPs With Local Intelligence", ip_report)
            self.assertIn("Database path: ipintel\\.sqlite3", ip_report)
            self.assertIn("Source SHA-256:", file_report)
            self.assertIn("Executables With Local Intelligence", file_report)
            self.assertIn("Database path: fileintel\\.sqlite3", file_report)
            self.assertIn(sha256(payload).hexdigest(), file_report)
            self.assertIn("match", file_report.lower())
            self.assertIn("Source SHA-256:", (
                output / "case.zip.en_dec-fileintel.md"
            ).read_text(encoding="utf-8"))
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                ["case.zip.en_dec-fileintel.md", "case.zip.en_dec-ipintel.md"],
            )
            captures = [path for path in (base / "middle-earth").iterdir() if path.name != ".partial"]
            self.assertEqual(len(captures), 1)
            self.assertNotEqual(captures[0].name, "case.zip.en_dec")
