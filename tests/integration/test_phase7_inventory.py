from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from erecb_triage.config import load_config
from erecb_triage.dispatcher import Dispatcher
from erecb_triage.events import WatchEvent
from erecb_triage.inventory import InventoryError, build_inventory, validate_inventory


class ArtifactInventoryTests(unittest.TestCase):
    def test_inventory_is_manifest_bound_and_contains_no_captured_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            base = Path(name); incoming = base / "in"; incoming.mkdir(); archive = incoming / "inventory.zip.en_dec"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("nested/secret.txt", b"DO_NOT_RENDER_CAPTURE_BYTES")
                bundle.writestr("payload.exe", b"MZ")
            config = load_config()
            config["watch"]["path"] = "./in"
            config["dispatcher"].update({"staging_root": "./middle-earth", "output_root": "./output", "staging_index_path": "./data/staging.sqlite3"})
            config["pipelines"]["on_added"]["preprocessors"]["processors"] = ["stage_input", "artifact_inventory"]
            config["pipelines"]["on_added"]["analysis"]["processors"] = []
            with Dispatcher(config, base_dir=base) as dispatcher:
                result = dispatcher.dispatch(WatchEvent.added(incoming, archive))
            self.assertFalse(result.errors, [issue.message for issue in result.errors])
            inventory = next(record for record in result.records if record["type"] == "artifact_inventory")
            self.assertEqual(inventory["schema_version"], 1)
            self.assertEqual([entry["path"] for entry in inventory["entries"]], ["nested", "nested/secret.txt", "payload.exe"])
            self.assertEqual(inventory["file_count"], 2)
            self.assertNotIn("DO_NOT_RENDER_CAPTURE_BYTES", repr(inventory))
            self.assertEqual(result.metrics["inventory_files"], 2)

    def test_inventory_rejects_manifest_or_capture_mismatch(self) -> None:
        capture = {"capture_name": "capture", "staged_path": "/safe/capture", "source_event_id": "event", "pipeline_run_id": "run"}
        entries = [{"path": "item", "type": "file", "size": 1, "sha256": "a" * 64}]
        inventory = build_inventory(capture, entries, max_entries=1)
        validate_inventory(inventory, capture, entries)
        changed = [{"path": "item", "type": "file", "size": 2, "sha256": "a" * 64}]
        with self.assertRaisesRegex(InventoryError, "stale"):
            validate_inventory(inventory, capture, changed)
        with self.assertRaisesRegex(InventoryError, "different capture"):
            validate_inventory(inventory, {**capture, "pipeline_run_id": "new-run"}, entries)
