from __future__ import annotations

import tempfile
import unittest
import json
import os
from pathlib import Path

from erecb_triage.sqlite_snapshots import SnapshotError, create_snapshot, verify_snapshot


class SnapshotTests(unittest.TestCase):
    def test_consistent_snapshot_and_checksum(self):
        import sqlite3

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source, output = root / "source.sqlite3", root / "copy.sqlite3"
            with sqlite3.connect(source) as connection:
                connection.execute("CREATE TABLE schema_version(version INTEGER)")
                connection.execute("INSERT INTO schema_version VALUES (1)")
                connection.execute("CREATE TABLE values_table(value TEXT)")
                connection.execute("INSERT INTO values_table VALUES ('example')")
            info = create_snapshot(source, output, producer="fileintel", version_table="schema_version")
            self.assertEqual(verify_snapshot(output, producer="fileintel", version_table="schema_version"), info)
            with self.assertRaises(SnapshotError):
                create_snapshot(source, output, producer="fileintel", version_table="schema_version")
            output.write_bytes(output.read_bytes() + b"broken")
            with self.assertRaisesRegex(SnapshotError, "checksum"):
                verify_snapshot(output, producer="fileintel", version_table="schema_version")

    def test_wal_committed_rows_are_included_in_snapshot(self):
        import sqlite3

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source, output = root / "source.sqlite3", root / "copy.sqlite3"
            with sqlite3.connect(source) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("CREATE TABLE schema_version(version INTEGER)")
                connection.execute("INSERT INTO schema_version VALUES (1)")
                connection.execute("CREATE TABLE values_table(value TEXT)")
                connection.commit()
            writer = sqlite3.connect(source)
            try:
                writer.execute("INSERT INTO values_table VALUES ('committed in WAL')")
                writer.commit()
                info = create_snapshot(source, output, producer="fileintel", version_table="schema_version")
                self.assertEqual(verify_snapshot(output, producer="fileintel", version_table="schema_version"), info)
                with sqlite3.connect(output) as snapshot:
                    self.assertEqual(snapshot.execute("SELECT value FROM values_table").fetchone()[0],
                                     "committed in WAL")
            finally:
                writer.close()

    def test_manifest_schema_version_must_match_snapshot_database(self):
        import sqlite3

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source, output = root / "source.sqlite3", root / "copy.sqlite3"
            with sqlite3.connect(source) as connection:
                connection.execute("CREATE TABLE schema_version(version INTEGER)")
                connection.execute("INSERT INTO schema_version VALUES (1)")
            create_snapshot(source, output, producer="fileintel", version_table="schema_version")
            manifest = Path(str(output) + ".manifest.json")
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["producer_schema_version"] = 2
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(SnapshotError, "schema version mismatch"):
                verify_snapshot(output, producer="fileintel", version_table="schema_version")

    def test_verification_accepts_relative_snapshot_paths(self):
        import sqlite3

        with tempfile.TemporaryDirectory() as name:
            previous = Path.cwd()
            try:
                os.chdir(name)
                with sqlite3.connect("source.sqlite3") as connection:
                    connection.execute("CREATE TABLE schema_version(version INTEGER)")
                    connection.execute("INSERT INTO schema_version VALUES (1)")
                info = create_snapshot(Path("source.sqlite3"), Path("copy.sqlite3"),
                                       producer="ipintel", version_table="schema_version")
                self.assertEqual(verify_snapshot(Path("copy.sqlite3"), producer="ipintel",
                                                 version_table="schema_version"), info)
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
