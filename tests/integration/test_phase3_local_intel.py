from __future__ import annotations

import hashlib
import io
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from erecb_triage.config import load_config
from erecb_triage.dispatcher import Dispatcher
from erecb_triage.events import WatchEvent
from erecb_triage.fileintel.classifier import ExecutableClassifier
from erecb_triage.fileintel.repository import FileIntelRepository
from erecb_triage.ipintel.extractor import _extract_stream, extract_bytes, scan_capture
from erecb_triage.ipintel.repository import IpIntelRepository


ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
SHA_A = "a" * 64
SHA_B = "b" * 64
MD5_A = "a" * 32
MD5_B = "b" * 32


def build_database(path: Path, fixture: str) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript((FIXTURES / fixture).read_text(encoding="utf-8"))
        connection.commit()
    finally:
        connection.close()


class IpIntelContractTests(unittest.TestCase):
    def test_internal_stream_cap_bounds_distinct_ip_results(self) -> None:
        found, size, truncated = _extract_stream(
            io.BytesIO(b"1.1.1.1 8.8.8.8 9.9.9.9"),
            chunk_size=4, chunk_overlap=128, max_results=2,
        )
        self.assertEqual(size, len(b"1.1.1.1 8.8.8.8 9.9.9.9"))
        self.assertEqual(len(found), 2)
        self.assertTrue(truncated)

    def test_extraction_is_canonical_across_tiny_chunk_boundaries(self) -> None:
        content = (
            b"1.1.1.1:443 [2001:4860:4860::8888]:53 fe80::1%eth0 "
            b"192.0.2.7 a8.8.8.8z 2001:4860:4860::8844"
        )
        expected = [
            ("1.1.1.1", 4), ("2001:4860:4860::8844", 6),
            ("2001:4860:4860::8888", 6), ("fe80::1", 6),
        ]
        self.assertEqual(extract_bytes(content, chunk_size=1, chunk_overlap=128), expected)
        for split in range(1, len(content) + 1):
            self.assertEqual(extract_bytes(content, chunk_size=split, chunk_overlap=128), expected)

    def test_ip_list_singularity_stops_at_the_twenty_first_distinct_ip(self) -> None:
        ips = b" ".join(f"8.8.8.{number}".encode("ascii") for number in range(1, 22))
        found, size, truncated = _extract_stream(
            io.BytesIO(ips + b" ignored trailing content"), chunk_size=1,
            chunk_overlap=128, max_results=20, stop_when_limit_reached=True,
        )
        self.assertTrue(truncated)
        self.assertEqual(len(found), 20)
        self.assertLess(size, len(ips + b" ignored trailing content"))

    def test_ip_list_singularity_is_reported_without_enriching_its_ips(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            base = Path(temporary_name)
            staged = base / "middle-earth" / "capture-260922-000000"
            staged.mkdir(parents=True)
            (staged / "target-list.txt").write_text(
                " ".join(f"8.8.8.{number}" for number in range(1, 22)), encoding="ascii",
            )
            result = scan_capture({
                "type": "staged_capture", "staged_path": str(staged),
                "capture_name": staged.name, "source_event_id": "event-1", "pipeline_run_id": "run-1",
            }, {
                "type": "ip_retriever", "db_path": "db.sqlite3", "output_root": "output",
                "ip_singularity_threshold": 20, "report_suffix": "-ipintel.md", "selector": "all",
            }, base)
            self.assertEqual(result.observations, [])
            self.assertEqual(result.metrics["ipintel_singularities"], 1)
            self.assertEqual(result.singularities[0]["source_path"], str(staged / "target-list.txt"))
            self.assertEqual(result.singularities[0]["distinct_ips_at_least"], 21)

    def test_ip_list_singularity_appears_in_ip_and_capture_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            base = Path(temporary_name)
            incoming = base / "in"
            incoming.mkdir()
            archive = incoming / "ip-list.zip.en_dec"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("target-list.txt", " ".join(f"8.8.8.{number}" for number in range(1, 22)))
            config = load_config()
            config["watch"]["path"] = "./in"
            config["dispatcher"].update({
                "staging_root": "./middle-earth", "output_root": "./output",
                "staging_index_path": "./data/staging.sqlite3", "publish_summary": True,
            })
            config["pipelines"]["on_added"]["analysis"]["processors"] = ["ip_retriever"]
            config["processors"]["ip_retriever"]["db_path"] = str((ROOT / "dbs" / "ipintel.sqlite3").resolve())
            config["processors"]["ip_retriever"]["selector"] = "all"
            with Dispatcher(config, base_dir=base) as dispatcher:
                result = dispatcher.dispatch(WatchEvent.added(incoming, archive))
            self.assertFalse(result.errors, [issue.message for issue in result.errors])
            ip_report = (base / "output" / "ip-list.zip.en_dec-ipintel.md").read_text(encoding="utf-8")
            summary = (base / "output" / "ip-list.zip.en_dec-summary.md").read_text(encoding="utf-8")
            self.assertIn("IP-list Singularities", ip_report)
            self.assertIn(r"target\-list\.txt", ip_report)
            self.assertIn("Unique IPs found: 0", ip_report)
            self.assertIn("IP-list Singularities", summary)
            self.assertIn(r"target\-list\.txt", summary)

    def test_read_only_hit_preserves_children_and_leaves_fixture_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            database = Path(temporary_name) / "ip.sqlite3"
            build_database(database, "ipintel_schema.sql")
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "INSERT INTO ip_entities VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (1, "8.8.8.8", 4, "8.8.8.8", None, "US", "whois", None, "first", "last"),
                )
                connection.execute("INSERT INTO ip_reverse_dns VALUES (?, ?, ?)", (1, "dns.google", "first"))
                connection.execute("INSERT INTO ip_related_iocs VALUES (?, ?, ?)", (1, "ioc-1", "first"))
                connection.execute("INSERT INTO ip_related_actors VALUES (?, ?, ?)", (1, "actor-1", "first"))
                connection.execute(
                    "INSERT INTO provider_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (1, "provider", "start", "finish", "complete", None, 1, 1, 0),
                )
                connection.execute(
                    "INSERT INTO provider_ip_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (1, 1, 1, "provider", "failed", "rate_limited", None, "when", "later"),
                )
                connection.commit()
            finally:
                connection.close()
            before = hashlib.sha256(database.read_bytes()).hexdigest()
            with IpIntelRepository(database.resolve()) as repository:
                result = repository.lookup("8.8.8.8")
                self.assertEqual(result.status, "hit")
                self.assertIsNotNone(result.intelligence)
                self.assertIsNone(result.intelligence.malicious)
                self.assertEqual(result.intelligence.reverse_dns, ["dns.google"])
                self.assertEqual(result.intelligence.provider_results[0]["provider_status"], "failed")
                self.assertEqual(repository.lookup("8.8.8.8").status, "hit")
            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)

    def test_checked_in_ipintel_database_has_the_required_read_only_capabilities(self) -> None:
        with IpIntelRepository((ROOT / "dbs" / "ipintel.sqlite3").resolve()) as repository:
            self.assertTrue(repository.available, repository.initialization_error)


class FileIntelContractTests(unittest.TestCase):
    def test_extension_fallback_only_accepts_supported_executable_extensions(self) -> None:
        classifier = ExecutableClassifier(use_magic=False, extension_fallback=True)
        self.assertTrue(classifier.classify(Path("payload.exe"), b"MZ").is_executable)
        self.assertFalse(classifier.classify(Path("notes.txt"), b"MZ").is_executable)

    def test_sha_hit_and_md5_ambiguity_are_read_only_and_semantically_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            database = Path(temporary_name) / "files.sqlite3"
            build_database(database, "fileintel_schema.sql")
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (1, SHA_A, MD5_A, "PE32", "yes", "created", "updated"),
                )
                connection.execute("INSERT INTO file_names VALUES (?, ?, ?, ?, ?)", (1, 1, "payload.exe", "feed", "seen"))
                connection.execute("INSERT INTO tags VALUES (?, ?, ?, ?, ?)", (1, 1, "malware", "feed", "seen"))
                connection.execute(
                    "INSERT INTO provider_lookups VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (1, 1, "provider", SHA_A, "sha256", "complete", 200, "requested", "completed", None, None),
                )
                connection.execute(
                    "INSERT INTO scan_jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (1, "manual", "/historical", "succeeded", "start", "end", 1, 1, 0),
                )
                connection.execute(
                    "INSERT INTO file_observations VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (1, 1, 1, "/historical/payload.exe", "payload.exe", "PE32", "observed"),
                )
                connection.execute(
                    "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (2, None, MD5_B, None, "unknown", "created", "updated"),
                )
                connection.execute(
                    "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (3, None, MD5_B, None, "unknown", "created", "updated"),
                )
                connection.commit()
            finally:
                connection.close()
            before = hashlib.sha256(database.read_bytes()).hexdigest()
            with FileIntelRepository(database.resolve()) as repository:
                hit = repository.lookup(SHA_A, MD5_A)
                self.assertEqual(hit.status, "hit")
                self.assertEqual(hit.intelligence.match_type, "sha256")
                self.assertEqual(hit.intelligence.malicious, "yes")
                self.assertEqual(hit.intelligence.file_names[0]["file_name"], "payload.exe")
                ambiguous = repository.lookup(SHA_B, MD5_B)
                self.assertEqual(ambiguous.status, "ambiguous")
                self.assertEqual(ambiguous.reason, "multiple_md5_rows")
            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)

    def test_checked_in_fileintel_database_has_the_required_read_only_capabilities(self) -> None:
        with FileIntelRepository((ROOT / "dbs" / "fileintel.sqlite3").resolve()) as repository:
            self.assertTrue(repository.available, repository.initialization_error)


class UnavailableDatabaseIntegrationTests(unittest.TestCase):
    def test_missing_producer_databases_still_publish_explicit_incomplete_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            base = Path(temporary_name)
            incoming = base / "in"
            incoming.mkdir()
            archive = incoming / "unavailable.zip.en_dec"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("ioc.txt", "Observed 8.8.8.8\n")
                bundle.writestr("payload.exe", b"MZ\x00\x00")
            config = load_config()
            config["watch"]["path"] = "./in"
            config["dispatcher"].update({
                "staging_root": "./middle-earth", "output_root": "./output",
                "staging_index_path": "./data/staging.sqlite3",
            })
            config["pipelines"]["on_added"]["analysis"]["processors"] = [
                "ip_retriever", "file_retriever"
            ]
            config["processors"]["ip_retriever"]["db_path"] = "./missing-ip.sqlite3"
            config["processors"]["file_retriever"]["db_path"] = "./missing-file.sqlite3"
            config["processors"]["file_retriever"]["classifier"] = {
                "use_magic": False, "extension_fallback": True,
            }
            with Dispatcher(config, base_dir=base) as dispatcher:
                result = dispatcher.dispatch(WatchEvent.added(incoming, archive))
            self.assertTrue(any(error.code == "ipintel_db_unavailable" for error in result.errors))
            self.assertTrue(any(error.code == "fileintel_db_unavailable" for error in result.errors))
            output = base / "output"
            self.assertIn("Database availability: unavailable", (
                output / "unavailable.zip.en_dec-ipintel.md"
            ).read_text(encoding="utf-8"))
            self.assertIn("Database availability: unavailable", (
                output / "unavailable.zip.en_dec-fileintel.md"
            ).read_text(encoding="utf-8"))
