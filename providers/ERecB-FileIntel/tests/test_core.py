from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from erecb_fileintel.db.migrations import initialize_schema
from erecb_fileintel.db.merge import merge_databases
from erecb_fileintel.db.repository import Repository
from erecb_fileintel.enrichment.merge import merge_malicious
from erecb_fileintel.errors import DatabaseError
from erecb_fileintel.enrichment.providers.ctx_io import CtxIoProvider
from erecb_fileintel.models import FileObservation, NormalizedIntel
from erecb_fileintel.scan.executable_rules import executable_reason
from erecb_fileintel.scan.hashing import hash_file
from erecb_fileintel.watcher.detector import detect_watch_targets


class CoreTests(unittest.TestCase):
    def test_executable_rules_use_magic_then_extension(self) -> None:
        self.assertEqual(executable_reason(Path("sample.bin"), "PE32 executable"), "magic: pe32")
        self.assertEqual(executable_reason(Path("run.ps1"), "ASCII text"), "extension fallback: .ps1")
        self.assertIsNone(executable_reason(Path("notes.txt"), "ASCII text"))

    def test_hash_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.bin"
            path.write_bytes(b"abc")
            result = hash_file(path, 2)
            self.assertEqual(result.sha256_hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            self.assertEqual(result.md5_hash, "900150983cd24fb0d6963f7d28e17f72")

    def test_watch_depth_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "in"
            (root / "a" / "b").mkdir(parents=True)
            (root / "x").mkdir()
            self.assertEqual(detect_watch_targets(root, 1), {"a", "x"})
            self.assertEqual(detect_watch_targets(root, 2), {"a/b"})

    def test_repository_merge_rules(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        initialize_schema(conn)
        repo = Repository(conn)
        scan_job_id = repo.create_scan_job("manual", Path("/tmp/input"))
        file_id = repo.upsert_local_observation(
            FileObservation(
                scan_job_id=scan_job_id,
                file_path=Path("/tmp/input/a.exe"),
                file_name="a.exe",
                magic="PE32 executable",
                sha256_hash="a" * 64,
                md5_hash="b" * 32,
            )
        )
        repo.merge_intelligence(
            file_id,
            NormalizedIntel(
                provider_name="ctx_io",
                provider_status="success",
                sha256_hash="a" * 64,
                md5_hash="b" * 32,
                magic="exe_32bit",
                malicious="yes",
                tags=("trojan", "downloader"),
                file_names=("provider.exe",),
                raw_response_path=None,
                error_message=None,
            ),
        )
        row = conn.execute("SELECT malicious, magic FROM files WHERE id = ?", (file_id,)).fetchone()
        self.assertEqual(row["malicious"], "yes")
        self.assertEqual(row["magic"], "PE32 executable")
        tags = {r["tag"] for r in conn.execute("SELECT tag FROM tags")}
        names = {r["file_name"] for r in conn.execute("SELECT file_name FROM file_names")}
        self.assertEqual(tags, {"trojan", "downloader"})
        self.assertEqual(names, {"a.exe", "provider.exe"})

    def test_malicious_merge_order(self) -> None:
        self.assertEqual(merge_malicious("yes", "no"), "yes")
        self.assertEqual(merge_malicious("unknown", "no"), "no")
        self.assertEqual(merge_malicious("no", "yes"), "yes")

    def test_ctx_io_normalization(self) -> None:
        raw = {
            "ctx_result": {"result_code": 200, "result_msg": "Success"},
            "ctx_data": {
                "hash": {"sha256": "A" * 64, "md5": "B" * 32},
                "file_type": "exe_32bit",
                "detect": "exe.trojan.test",
                "tags": ["tag1"],
                "threat_types": ["downloader"],
                "file_names": ["sample.exe"],
            },
        }
        provider = object.__new__(CtxIoProvider)
        result = provider.normalize(raw)
        self.assertEqual(result.provider_status, "success")
        self.assertEqual(result.sha256_hash, "a" * 64)
        self.assertEqual(result.md5_hash, "b" * 32)
        self.assertEqual(result.malicious, "yes")
        self.assertEqual(result.tags, ("tag1", "downloader"))
        self.assertEqual(result.file_names, ("sample.exe",))

    def test_initialize_schema_reuses_existing_records(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        initialize_schema(conn)
        conn.execute(
            """
            INSERT INTO files(sha256_hash, md5_hash, magic, malicious, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("a" * 64, "b" * 32, "PE32", "unknown", "2024-01-01T00:00:00+00:00", "2024-01-01T00:00:00+00:00"),
        )
        conn.commit()
        initialize_schema(conn)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM files").fetchone()[0], 1)

    def test_initialize_schema_rejects_unrelated_database(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
        with self.assertRaises(DatabaseError):
            initialize_schema(conn)

    def test_merge_databases_preserves_history_and_merges_intelligence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source_path = base / "source.sqlite3"
            destination_path = base / "destination.sqlite3"
            self._seed_merge_database(source_path, is_source=True)
            self._seed_merge_database(destination_path, is_source=False)

            result = merge_databases(source_path, destination_path, backup=True)

            self.assertEqual(result.files_inserted, 0)
            self.assertEqual(result.files_merged, 1)
            self.assertEqual(result.tags_inserted, 1)
            self.assertEqual(result.file_names_inserted, 1)
            self.assertEqual(result.scan_jobs_copied, 1)
            self.assertEqual(result.observations_copied, 1)
            self.assertEqual(result.provider_lookups_copied, 1)
            self.assertIsNotNone(result.backup_path)
            self.assertTrue(result.backup_path.exists())

            source_conn = sqlite3.connect(source_path)
            self.assertEqual(source_conn.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0], 1)
            source_conn.close()

            destination_conn = sqlite3.connect(destination_path)
            destination_conn.row_factory = sqlite3.Row
            file_row = destination_conn.execute("SELECT * FROM files").fetchone()
            self.assertEqual(file_row["magic"], "ELF 64-bit fresh")
            self.assertEqual(file_row["malicious"], "yes")
            self.assertEqual({row[0] for row in destination_conn.execute("SELECT tag FROM tags")}, {"old-tag", "new-tag"})
            self.assertEqual(
                {row[0] for row in destination_conn.execute("SELECT file_name FROM file_names")}, {"old.exe", "new.exe"}
            )
            self.assertEqual(destination_conn.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0], 2)
            self.assertEqual(destination_conn.execute("SELECT COUNT(*) FROM scan_errors").fetchone()[0], 1)
            observation = destination_conn.execute(
                """
                SELECT o.file_id, o.scan_job_id FROM file_observations o
                JOIN scan_jobs j ON j.id = o.scan_job_id
                WHERE j.root_path = '/machine-b/in'
                """
            ).fetchone()
            self.assertEqual(observation["file_id"], file_row["id"])
            self.assertEqual(destination_conn.execute("SELECT COUNT(*) FROM provider_lookups").fetchone()[0], 1)
            watcher = destination_conn.execute("SELECT status, last_scan_job_id FROM watch_directories").fetchone()
            self.assertEqual(watcher["status"], "scanned")
            self.assertIsNotNone(watcher["last_scan_job_id"])
            self.assertEqual(destination_conn.execute("PRAGMA foreign_key_check").fetchall(), [])
            destination_conn.close()

    def test_merge_dry_run_does_not_modify_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source_path = base / "source.sqlite3"
            destination_path = base / "destination.sqlite3"
            self._seed_merge_database(source_path, is_source=True)
            self._seed_merge_database(destination_path, is_source=False)

            result = merge_databases(source_path, destination_path, dry_run=True)

            self.assertTrue(result.dry_run)
            destination_conn = sqlite3.connect(destination_path)
            row = destination_conn.execute("SELECT magic, malicious FROM files").fetchone()
            self.assertEqual(row, ("PE32 old", "no"))
            self.assertEqual(destination_conn.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0], 1)
            destination_conn.close()

    def test_merge_preserves_files_when_matching_md5_has_conflicting_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source_path = base / "source.sqlite3"
            destination_path = base / "destination.sqlite3"
            self._create_database_with_file(source_path, "a" * 64, "b" * 32)
            self._create_database_with_file(destination_path, "c" * 64, "b" * 32)

            result = merge_databases(source_path, destination_path)

            self.assertEqual(result.files_inserted, 1)
            self.assertTrue(any("MD5 conflict" in warning for warning in result.warnings))
            destination_conn = sqlite3.connect(destination_path)
            self.assertEqual(destination_conn.execute("SELECT COUNT(*) FROM files").fetchone()[0], 2)
            destination_conn.close()

    def _seed_merge_database(self, path: Path, *, is_source: bool) -> None:
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        initialize_schema(conn)
        sha256_hash = "a" * 64
        md5_hash = "b" * 32
        if is_source:
            magic, malicious = "ELF 64-bit fresh", "yes"
            created_at, updated_at = "2024-01-01T00:00:00+00:00", "2025-01-01T00:00:00+00:00"
            root_path, file_name, tag, status = "/machine-b/in", "new.exe", "new-tag", "scanned"
        else:
            magic, malicious = "PE32 old", "no"
            created_at, updated_at = "2023-01-01T00:00:00+00:00", "2024-01-01T00:00:00+00:00"
            root_path, file_name, tag, status = "/machine-a/in", "old.exe", "old-tag", "failed"
        file_id = conn.execute(
            """
            INSERT INTO files(sha256_hash, md5_hash, magic, malicious, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (sha256_hash, md5_hash, magic, malicious, created_at, updated_at),
        ).lastrowid
        conn.execute(
            "INSERT INTO file_names(file_id, file_name, source, first_seen_at) VALUES (?, ?, 'local', ?)",
            (file_id, file_name, created_at),
        )
        conn.execute(
            "INSERT INTO tags(file_id, tag, source, first_seen_at) VALUES (?, ?, 'ctx_io', ?)",
            (file_id, tag, created_at),
        )
        scan_job_id = conn.execute(
            """
            INSERT INTO scan_jobs(mode, root_path, status, started_at, finished_at, files_seen, executables_found, error_count)
            VALUES ('manual', ?, 'succeeded', ?, ?, 1, 1, 0)
            """,
            (root_path, created_at, updated_at),
        ).lastrowid
        if is_source:
            conn.execute(
                """
                INSERT INTO scan_errors(scan_job_id, file_path, phase, error_type, error_message, occurred_at)
                VALUES (?, '/machine-b/in/new.exe', 'hash', 'OSError', 'example', ?)
                """,
                (scan_job_id, updated_at),
            )
            conn.execute(
                """
                INSERT INTO file_observations(
                  scan_job_id, file_id, file_path, file_name, magic, sha256_hash, md5_hash, observed_at
                ) VALUES (?, ?, '/machine-b/in/new.exe', 'new.exe', ?, ?, ?, ?)
                """,
                (scan_job_id, file_id, magic, sha256_hash, md5_hash, updated_at),
            )
            conn.execute(
                """
                INSERT INTO provider_lookups(
                  file_id, provider, query_hash, query_hash_type, status, http_status, requested_at, completed_at,
                  raw_response_path, error_message
                ) VALUES (?, 'ctx_io', ?, 'sha256', 'success', 200, ?, ?, '/not-present/raw.json', NULL)
                """,
                (file_id, sha256_hash, created_at, updated_at),
            )
        conn.execute(
            """
            INSERT INTO watch_directories(
              input_dir, relative_path, absolute_path, watch_depth, first_seen_at, last_scan_job_id, status
            ) VALUES ('in', 'batch', ?, 1, ?, ?, ?)
            """,
            (root_path, created_at, scan_job_id, status),
        )
        conn.commit()
        conn.close()

    def _create_database_with_file(self, path: Path, sha256_hash: str, md5_hash: str) -> None:
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        initialize_schema(conn)
        conn.execute(
            """
            INSERT INTO files(sha256_hash, md5_hash, magic, malicious, created_at, updated_at)
            VALUES (?, ?, 'PE32', 'unknown', '2024-01-01T00:00:00+00:00', '2024-01-01T00:00:00+00:00')
            """,
            (sha256_hash, md5_hash),
        )
        conn.commit()
        conn.close()


if __name__ == "__main__":
    unittest.main()
