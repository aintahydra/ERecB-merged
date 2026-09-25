from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from erecb_fileintel.db.merge import merge_databases
from erecb_fileintel.db.repository import Repository


class ExchangeMergeTests(unittest.TestCase):
    def test_intelligence_only_is_dry_run_safe_and_replay_safe(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source, target = root / "source.sqlite3", root / "target.sqlite3"
            connection = sqlite3.connect(source)
            connection.row_factory = sqlite3.Row
            repository = Repository(connection)
            repository.initialize_schema()
            item = repository.upsert_hash_only("a" * 64, "b" * 32)
            lookup_id = repository.create_provider_lookup(item.id, "fixture", "a" * 64, "sha256")
            repository.finish_provider_lookup(lookup_id, "success", 200, "/connected/private/raw.json", None)
            connection.close()
            self.assertEqual(merge_databases(source, target, dry_run=True,
                                             intelligence_only=True).provider_lookups_copied, 1)
            self.assertFalse(target.exists())
            first = merge_databases(source, target, intelligence_only=True)
            self.assertEqual(first.files_inserted, 1)
            self.assertEqual(first.provider_lookups_copied, 1)
            second = merge_databases(source, target, intelligence_only=True)
            self.assertEqual(second.provider_lookups_copied, 0)
            connection = sqlite3.connect(target)
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM provider_lookups").fetchone()[0], 1)
                self.assertIsNone(connection.execute("SELECT raw_response_path FROM provider_lookups").fetchone()[0])
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0], 0)
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
