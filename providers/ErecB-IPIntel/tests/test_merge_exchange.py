from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from erecb_ipintel.db import Database
from erecb_ipintel.merge import merge_databases
from erecb_ipintel.models import NormalizedIntelRecord


class MergeExchangeTests(unittest.TestCase):
    def test_dry_run_and_replayed_snapshot_do_not_duplicate_audit(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source, destination = root / "source.sqlite3", root / "dest.sqlite3"
            producer = Database(source)
            producer.initialize()
            run = producer.create_provider_run("test", None, 1)
            producer.merge_intel(NormalizedIntelRecord(ip="8.8.8.8", ipv4="8.8.8.8", malicious="Yes",
                                                       provider_name="test"), run, "success")
            producer.close()
            self.assertFalse(destination.exists())
            dry = merge_databases(source, destination, dry_run=True)
            self.assertEqual(dry["entities_inserted"], 1)
            self.assertFalse(destination.exists())
            first = merge_databases(source, destination)
            self.assertEqual(first["provider_results_copied"], 1)
            second = merge_databases(source, destination)
            self.assertTrue(second["already_imported"])
            consumer = Database(destination)
            consumer.initialize()
            self.assertEqual(consumer.conn.execute("SELECT COUNT(*) FROM provider_ip_results").fetchone()[0], 1)
            self.assertEqual(consumer.conn.execute("SELECT malicious FROM ip_entities").fetchone()[0], "Yes")
            consumer.close()

    def test_out_of_order_snapshots_keep_newer_scalars_and_all_provider_audit(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            sources = []
            for label, country, whois, malicious, timestamp in (
                ("older", "US", "older evidence", "No", "2024-01-01T00:00:00Z"),
                ("newer", "GB", "newer evidence", "Yes", "2025-01-01T00:00:00Z"),
            ):
                path = root / f"{label}.sqlite3"
                producer = Database(path)
                producer.initialize()
                run = producer.create_provider_run(label, None, 1)
                producer.merge_intel(NormalizedIntelRecord(
                    ip="8.8.8.8", ipv4="8.8.8.8", country_code=country,
                    whois=whois, malicious=malicious, provider_name=label,
                ), run, "success")
                producer.conn.execute("UPDATE ip_entities SET last_updated_local=? WHERE ip='8.8.8.8'", (timestamp,))
                producer.conn.commit()
                producer.close()
                sources.append(path)

            destination = root / "airgap.sqlite3"
            merge_databases(sources[1], destination)
            merge_databases(sources[0], destination)
            consumer = Database(destination)
            consumer.initialize()
            row = consumer.conn.execute("SELECT country_code, whois, malicious, last_updated_local "
                                        "FROM ip_entities WHERE ip='8.8.8.8'").fetchone()
            self.assertEqual((row["country_code"], row["whois"], row["malicious"], row["last_updated_local"]),
                             ("GB", "newer evidence", "Yes", "2025-01-01T00:00:00Z"))
            self.assertEqual(consumer.conn.execute("SELECT COUNT(*) FROM provider_ip_results").fetchone()[0], 2)
            consumer.close()


if __name__ == "__main__":
    unittest.main()
