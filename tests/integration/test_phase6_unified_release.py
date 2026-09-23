from __future__ import annotations

import hashlib
import json
import platform
import tempfile
import unittest
import zipfile
from pathlib import Path
from uuid import uuid4

from erecb_triage.config import load_config
from erecb_triage.dispatcher import Dispatcher
from erecb_triage.events import WatchEvent
from erecb_triage.processors.yara_scan import YaraScan
from erecb_triage.readiness import readiness


ROOT = Path(__file__).parents[2]


class _Match:
    namespace, rule, tags, meta, strings = "fixture", "unified_fixture", ("test",), {"kind": "inert"}, ()


class _Rules:
    def match(self, *, filepath, timeout):
        return [_Match()]


def cache(root: Path) -> None:
    generation = str(uuid4()); folder = root / "generations" / generation; folder.mkdir(parents=True)
    artifact = folder / "rules.yac"; artifact.write_bytes(b"inert test artifact")
    manifest = {"schema_version": 1, "generation_id": generation, "platform": platform.system(), "machine": platform.machine(),
                "runtime": {"yara_version": "fixture", "yara_python_version": "fixture"},
                "artifact": {"filename": "rules.yac", "size": artifact.stat().st_size,
                             "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()},
                "accepted_rules": [{"namespace": "fixture", "source": "fixture", "path": "fixture.yar",
                                    "commit": "local", "sha256": "a" * 64, "url": "https://example.test/fixture"}]}
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (root / "active").write_text(generation + "\n", encoding="ascii")


class UnifiedReleaseTests(unittest.TestCase):
    def test_all_adapters_share_one_capture_and_publish_canonical_reports_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            base = Path(name); incoming = base / "in"; incoming.mkdir(); archive = incoming / "sample.zip.en_dec"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("payload.exe", b"MZ 8.8.8.8 https://github.com/Owner/Repository SECRET")
            cache(base / "cache")
            config = load_config("config/watcher_all.yaml")
            config["watch"]["path"] = "./in"
            config["dispatcher"].update({"staging_root": "./middle-earth", "output_root": "./output", "staging_index_path": "./data/staging.sqlite3"})
            config["processors"]["ip_retriever"]["db_path"] = str((ROOT / "dbs" / "ipintel.sqlite3").resolve())
            config["processors"]["file_retriever"]["db_path"] = str((ROOT / "dbs" / "fileintel.sqlite3").resolve())
            config["processors"]["ghintel"]["db_path"] = str((ROOT / "dbs" / "ghintel.sqlite3").resolve())
            config["processors"]["yara_scan"]["cache_dir"] = "./cache"
            def factory(processor_name, processor_config):
                return YaraScan(processor_name, processor_config, rule_loader=lambda _: _Rules())
            with Dispatcher(config, base_dir=base, processor_factories={"yara_scan": factory}) as dispatcher:
                result = dispatcher.dispatch(WatchEvent.added(incoming, archive))
            self.assertFalse(result.errors, [issue.message for issue in result.errors])
            self.assertEqual([status["state"] for status in result.statuses], ["success"] * 4)
            for suffix in ("-ipintel.md", "-fileintel.md", "-ghintel.md", "-yara.md", "-summary.md"):
                self.assertTrue((base / "output" / f"sample.zip.en_dec{suffix}").is_file(), suffix)
            summary = (base / "output" / "sample.zip.en_dec-summary.md").read_text(encoding="utf-8")
            self.assertIn("Triage Summary", summary)
            self.assertIn("not a malware or benign verdict", summary)
            self.assertIn("sample\\.zip\\.en\\_dec\\-yara\\.md", summary)

    def test_readiness_is_read_only_when_state_has_not_been_created(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            base = Path(name); (base / "in").mkdir()
            config = load_config()
            config["watch"]["path"] = "./in"
            config["dispatcher"].update({"staging_root": "./middle-earth", "output_root": "./output", "staging_index_path": "./data/staging.sqlite3"})
            result = readiness(config, base)
            self.assertTrue(result["ok"])
            self.assertFalse((base / "data" / "staging.sqlite3").exists())
            self.assertTrue(any(item["name"] == "staging_index" and item["state"] == "degraded" for item in result["checks"]))

    def test_yara_cache_unavailability_is_degraded_and_does_not_suppress_other_reports(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            base = Path(name); incoming = base / "in"; incoming.mkdir(); archive = incoming / "degraded.zip.en_dec"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("payload.exe", b"MZ 8.8.8.8")
            config = load_config("config/watcher_all.yaml")
            config["watch"]["path"] = "./in"
            config["dispatcher"].update({"staging_root": "./middle-earth", "output_root": "./output", "staging_index_path": "./data/staging.sqlite3"})
            for processor, database in (("ip_retriever", "ipintel.sqlite3"), ("file_retriever", "fileintel.sqlite3"),
                                        ("ghintel", "ghintel.sqlite3")):
                config["processors"][processor]["db_path"] = str((ROOT / "dbs" / database).resolve())
            config["processors"]["yara_scan"]["cache_dir"] = "./missing-cache"
            with Dispatcher(config, base_dir=base, processor_factories={
                "yara_scan": lambda processor_name, processor_config: YaraScan(processor_name, processor_config, rule_loader=lambda _: _Rules()),
            }) as dispatcher:
                result = dispatcher.dispatch(WatchEvent.added(incoming, archive))
            states = {status["name"]: status["state"] for status in result.statuses}
            self.assertEqual(states["yara_scan"], "degraded")
            self.assertEqual(states["ip_retriever"], "success")
            for suffix in ("-ipintel.md", "-fileintel.md", "-ghintel.md", "-yara.md", "-summary.md"):
                self.assertTrue((base / "output" / f"degraded.zip.en_dec{suffix}").is_file(), suffix)
            summary = (base / "output" / "degraded.zip.en_dec-summary.md").read_text(encoding="utf-8")
            self.assertIn("degraded", summary)
            yara_report = (base / "output" / "degraded.zip.en_dec-yara.md").read_text(encoding="utf-8")
            self.assertIn("separate ERecB YaraRuler producer", yara_report)
