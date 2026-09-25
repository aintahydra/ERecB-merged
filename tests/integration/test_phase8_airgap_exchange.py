from __future__ import annotations

import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from erecb_triage.config import load_config
from erecb_triage.dispatcher import Dispatcher
from erecb_triage.events import WatchEvent
from erecb_triage.exchange import read_bundle
from erecb_triage.processors.yara_scan import YaraScan
from erecb_triage.request_export import RequestExportError, export_requests


class _Rules:
    def match(self, *, filepath, timeout):
        return []


class AirgapExchangeTests(unittest.TestCase):
    def test_replay_and_indicator_only_export_after_original_archive_removed(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            incoming = base / "in"
            incoming.mkdir()
            archive = incoming / "sample.zip.en_dec"
            payload = b"MZ 8.8.8.8 https://github.com/Owner/Repository\n"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("payload.exe", payload)
            config = load_config("config/watcher_all.yaml")
            config["logging"]["file_path"] = str(base / "logs" / "triage.log")
            config["processors"]["yara_scan"]["cache_dir"] = str(base / "missing-cache")
            with Dispatcher(config, base_dir=base, processor_factories={
                "yara_scan": lambda processor_name, settings: YaraScan(
                    processor_name, settings, rule_loader=lambda _: _Rules()
                ),
            }) as dispatcher:
                dispatcher.dispatch(WatchEvent.added(incoming, archive))
                captures = dispatcher.list_captures()
                self.assertEqual(len(captures), 1)
                capture_id = captures[0]["id"]
                archive.unlink()
                replayed = dispatcher.replay(capture_id)
                self.assertEqual(len(replayed.statuses), 4)
                history = dispatcher.list_captures()[0]["last_analysis"]
                self.assertEqual(len(history["statuses"]), 4)
                self.assertEqual(len(history["policy_sha256"]), 64)
                output = base / "transfer" / "requests.json"
                with self.assertRaisesRegex(RequestExportError, "DB unavailable"):
                    export_requests(dispatcher, capture_id, output)
                self.assertFalse(output.exists())
                result = export_requests(dispatcher, capture_id, output, selection="all")
                bundle = read_bundle(output)
                self.assertEqual(result["counts"], {"files": 1, "ips": 1, "repositories": 1})
                self.assertEqual(bundle["files"], [{"sha256": hashlib.sha256(payload).hexdigest(),
                                                     "md5": hashlib.md5(payload).hexdigest()}])
                self.assertEqual(bundle["ips"], ["8.8.8.8"])
                self.assertEqual(bundle["repositories"], [{
                    "identity_key": "github.com/owner/repository",
                    "canonical_url": "https://github.com/Owner/Repository",
                }])
                serialized = output.read_text(encoding="ascii")
                self.assertNotIn("sample.zip", serialized)
                self.assertNotIn("payload.exe", serialized)
                self.assertNotIn(str(base), serialized)
                second = base / "transfer" / "again.json"
                export_requests(dispatcher, capture_id, second, selection="all")
                self.assertEqual(read_bundle(second)["source_sequence"], bundle["source_sequence"] + 1)
                self.assertEqual(read_bundle(second)["source_instance_id"], bundle["source_instance_id"])


if __name__ == "__main__":
    unittest.main()
