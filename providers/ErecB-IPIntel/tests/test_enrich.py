from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from erecb_ipintel.db import Database
from erecb_ipintel.enrich import enrich_file
from erecb_ipintel.models import NormalizedIntelRecord, ProviderRawResult


class FakeProvider:
    name = "fake"

    def __init__(self, responses: list[ProviderRawResult] | None = None) -> None:
        self.fetched: list[str] = []
        self.responses = responses or []

    def fetch(self, ip: str) -> ProviderRawResult:
        self.fetched.append(ip)
        if self.responses:
            return self.responses.pop(0)
        return ProviderRawResult(status="success", status_code=200, data={})

    def normalize(
        self,
        ip: str,
        raw: ProviderRawResult,
        store_raw_json: bool = True,
    ) -> NormalizedIntelRecord:
        return NormalizedIntelRecord(ip=ip, provider_name=self.name)


class EnrichmentTests(unittest.TestCase):
    def test_enrich_file_calls_provider_once_per_unique_ip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "ips.txt"
            input_path.write_text(
                "8.8.8.8; first.bin\n"
                "8.8.8.8; second.bin\n"
                "8.8.8.8; third.bin\n"
                "8.8.8.8; third.bin\n",
                encoding="utf-8",
            )
            db = Database(root / "ipintel.sqlite3")
            db.initialize()
            provider = FakeProvider()
            config = SimpleNamespace(database=SimpleNamespace(store_raw_provider_json=False))
            progress: list[tuple[str, int, int]] = []

            with patch("erecb_ipintel.enrich.enabled_providers", return_value=[provider]):
                result = enrich_file(
                    input_path,
                    config,
                    db,
                    progress=lambda stage, completed, total: progress.append((stage, completed, total)),
                )

            observation_count = db.conn.execute(
                "SELECT COUNT(*) AS count FROM ip_observations"
            ).fetchone()["count"]
            db.close()

        self.assertEqual(provider.fetched, ["8.8.8.8"])
        self.assertEqual(observation_count, 3)
        self.assertEqual(
            result,
            {
                "tuples": 3,
                "ips": 1,
                "selected_ips": 1,
                "completed_ips": 1,
                "remaining_tuples": 0,
                "remaining_ips": 0,
                "consumed": False,
                "success": 1,
                "failed": 0,
                "rate_limited": False,
            },
        )
        self.assertEqual(
            progress,
            [
                ("enrich fake unique IPs", 0, 1),
                ("enrich fake unique IPs", 1, 1),
            ],
        )

    def test_max_ips_and_consume_leave_unselected_tuples_in_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "ips.txt"
            input_path.write_text(
                "# preserved comment\n"
                "8.8.8.8; first.bin\n"
                "8.8.8.8; second.bin\n"
                "9.9.9.9; third.bin\n"
                "1.1.1.1; fourth.bin\n",
                encoding="utf-8",
            )
            db = Database(root / "ipintel.sqlite3")
            db.initialize()
            provider = FakeProvider()
            config = SimpleNamespace(database=SimpleNamespace(store_raw_provider_json=False))

            with patch("erecb_ipintel.enrich.enabled_providers", return_value=[provider]):
                result = enrich_file(input_path, config, db, max_ips=2, consume=True)

            db.close()
            remaining_text = input_path.read_text(encoding="utf-8")

        self.assertEqual(provider.fetched, ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(result["selected_ips"], 2)
        self.assertEqual(result["completed_ips"], 2)
        self.assertEqual(result["remaining_tuples"], 1)
        self.assertEqual(result["remaining_ips"], 1)
        self.assertIn("# preserved comment\n", remaining_text)
        self.assertIn("9.9.9.9; third.bin\n", remaining_text)
        self.assertNotIn("8.8.8.8", remaining_text)
        self.assertNotIn("1.1.1.1", remaining_text)

    def test_rate_limit_stops_provider_and_keeps_unfinished_tuples(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "ips.txt"
            input_path.write_text(
                "1.1.1.1; first.bin\n"
                "8.8.8.8; second.bin\n"
                "9.9.9.9; third.bin\n",
                encoding="utf-8",
            )
            db = Database(root / "ipintel.sqlite3")
            db.initialize()
            provider = FakeProvider(
                [
                    ProviderRawResult(status="success", status_code=200, data={}),
                    ProviderRawResult(status="failed", status_code=429, data=None, error_summary="HTTP 429"),
                ]
            )
            config = SimpleNamespace(database=SimpleNamespace(store_raw_provider_json=False))

            with patch("erecb_ipintel.enrich.enabled_providers", return_value=[provider]):
                result = enrich_file(input_path, config, db, consume=True)

            db.close()
            remaining_text = input_path.read_text(encoding="utf-8")

        self.assertEqual(provider.fetched, ["1.1.1.1", "8.8.8.8"])
        self.assertTrue(result["rate_limited"])
        self.assertEqual(result["completed_ips"], 1)
        self.assertEqual(result["remaining_ips"], 2)
        self.assertNotIn("1.1.1.1", remaining_text)
        self.assertIn("8.8.8.8", remaining_text)
        self.assertIn("9.9.9.9", remaining_text)

    def test_consume_requires_completion_by_every_selected_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "ips.txt"
            original_text = "8.8.8.8; sample.bin\n"
            input_path.write_text(original_text, encoding="utf-8")
            db = Database(root / "ipintel.sqlite3")
            db.initialize()
            successful = FakeProvider()
            successful.name = "successful"
            failed = FakeProvider(
                [ProviderRawResult(status="failed", status_code=500, data=None, error_summary="HTTP 500")]
            )
            failed.name = "failed"
            config = SimpleNamespace(database=SimpleNamespace(store_raw_provider_json=False))

            with patch("erecb_ipintel.enrich.enabled_providers", return_value=[successful, failed]):
                result = enrich_file(input_path, config, db, consume=True)

            db.close()
            remaining_text = input_path.read_text(encoding="utf-8")

        self.assertEqual(result["completed_ips"], 0)
        self.assertEqual(result["remaining_ips"], 1)
        self.assertEqual(remaining_text, original_text)


if __name__ == "__main__":
    unittest.main()
