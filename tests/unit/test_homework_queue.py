from __future__ import annotations

import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

from erecb_triage.exchange import new_bundle, write_bundle
from erecb_triage.homework import HomeworkQueue


class HomeworkQueueTests(unittest.TestCase):
    def test_import_idempotence_lifo_out_of_order_and_retry(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = str(uuid.uuid4())

            def bundle(seq, ips, selection="missing"):
                value = new_bundle(
                    source_instance_id=source, source_sequence=seq, selection=selection,
                    policy_sha256="0" * 64, files=[], ips=ips, repositories=[],
                    created_at=datetime(2026, 9, 23, 12, tzinfo=timezone.utc),
                )
                path = root / f"{seq}.json"
                write_bundle(path, value)
                return path

            first = bundle(1, ["1.1.1.1", "8.8.8.8"])
            third = bundle(3, ["1.1.1.1"])
            second = bundle(2, ["8.8.8.8"])
            with HomeworkQueue(root / "ip-homework.sqlite3", "ip") as queue:
                self.assertEqual(queue.import_bundle(first)["requests"], 2)
                self.assertFalse(queue.import_bundle(first)["imported"])
                queue.import_bundle(third)
                queue.import_bundle(second)
                items = queue.list_items()
                self.assertEqual([item["identity"] for item in items], ["1.1.1.1", "8.8.8.8"])
                self.assertEqual([item["request_count"] for item in items], [2, 2])
                leased = queue.lease(limit=1)
                self.assertEqual(leased[0]["identity"], "1.1.1.1")
                queue.finish("1.1.1.1", lease_token=leased[0]["lease_token"], outcome="not_found")
                self.assertEqual(queue.lease(limit=1)[0]["identity"], "8.8.8.8")
                other = queue.list_items(status="leased")[0]
                queue.finish("8.8.8.8", lease_token=other["lease_token"], outcome="success")
                self.assertEqual(queue.list_items(status="pending")[0]["identity"], "1.1.1.1")
                refresh = bundle(4, ["8.8.8.8"], selection="all")
                queue.import_bundle(refresh)
                renewed = queue.lease(limit=1)[0]
                self.assertEqual(renewed["identity"], "8.8.8.8")
                self.assertEqual(renewed["selection"], "all")
                with self.assertRaisesRegex(ValueError, "active lease"):
                    queue.finish("8.8.8.8", lease_token="stale", outcome="success")
                limited_at = datetime(2026, 9, 23, 12, tzinfo=timezone.utc)
                queue.finish("8.8.8.8", lease_token=renewed["lease_token"], outcome="rate_limited",
                             retry_after_seconds=3600, now=limited_at)
                self.assertEqual(queue.list_items(status="pending")[0]["last_outcome"], "rate_limited")
                self.assertEqual(queue.pause_until(), "2026-09-23T13:00:00Z")
                self.assertEqual(queue.lease(limit=2, now=limited_at), [])
                later = datetime(2026, 9, 23, 13, 1, tzinfo=timezone.utc)
                self.assertEqual(queue.lease(limit=1, now=later)[0]["identity"], "8.8.8.8")


if __name__ == "__main__":
    unittest.main()
