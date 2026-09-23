from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from erecb_ipintel.db import Database
from erecb_ipintel.models import NormalizedIntelRecord


class DatabaseTests(unittest.TestCase):
    def test_db_merge_deduplicates_and_malicious_yes_wins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "ipintel.sqlite3")
            db.initialize()
            run_id = db.create_provider_run("test", None, 1)
            db.merge_intel(
                NormalizedIntelRecord(
                    ip="192.0.2.1",
                    ipv4="192.0.2.1",
                    malicious="Yes",
                    reverse_dns=["a.example", "a.example"],
                    related_iocs=["ioc"],
                    related_actors=["actor"],
                    provider_name="test",
                ),
                run_id,
                "success",
            )
            db.merge_intel(
                NormalizedIntelRecord(ip="192.0.2.1", ipv4="192.0.2.1", malicious="No", provider_name="test"),
                run_id,
                "success",
            )
            row = db.conn.execute("SELECT malicious FROM ip_entities WHERE ip = '192.0.2.1'").fetchone()
            count = db.conn.execute("SELECT COUNT(*) AS count FROM ip_reverse_dns").fetchone()["count"]
            db.close()
        self.assertEqual(row["malicious"], "Yes")
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
