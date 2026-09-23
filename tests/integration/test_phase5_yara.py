from __future__ import annotations

import hashlib
import json
import platform
import tempfile
import unittest
import zipfile
from pathlib import Path
from uuid import uuid4

from erecb_triage.config import load_config, yara_scan_settings
from erecb_triage.dispatcher import Dispatcher
from erecb_triage.events import WatchEvent
from erecb_triage.processors.yara_scan import YaraScan
from erecb_triage.yarascan.cache import CacheError, pin_cache

try:
    import yara  # type: ignore
except ImportError:
    yara = None


class _FakeMatch:
    namespace = "fixture"
    rule = "harmless_fixture"
    tags = ("test", "test")
    meta = {"author": "unit-test"}
    strings = ()


class _FakeRules:
    def match(self, *, filepath, timeout):
        self.path, self.timeout = filepath, timeout
        return [_FakeMatch()]


def build_cache(root: Path) -> Path:
    generation = str(uuid4())
    directory = root / "generations" / generation
    directory.mkdir(parents=True)
    artifact = directory / "rules.yac"
    artifact.write_bytes(b"inert compiled fixture; fake loader only")
    manifest = {
        "schema_version": 1, "generation_id": generation,
        "platform": platform.system(), "machine": platform.machine(),
        "runtime": {"yara_version": "fixture", "yara_python_version": "fixture"},
        "artifact": {"filename": "rules.yac", "size": artifact.stat().st_size,
                     "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()},
        "accepted_rules": [{"namespace": "fixture", "source": "fixture", "path": "rules/test.yar",
                            "commit": "abc123", "sha256": "a" * 64,
                            "url": "https://user:secret@example.test/rules"}],
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (root / "active").write_text(generation + "\n", encoding="ascii")
    return artifact


class YaraCacheTests(unittest.TestCase):
    def test_verified_cache_redacts_url_and_rejects_bad_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "cache"; artifact = build_cache(root)
            pinned = pin_cache(root, loader=lambda value: _FakeRules())
            self.assertEqual(pinned.artifact, artifact.resolve())
            self.assertEqual(pinned.provenance["fixture"]["url"], "https://example.test/rules")
            (root / "active").write_text("../not-a-generation\n", encoding="ascii")
            with self.assertRaises(CacheError): pin_cache(root, loader=lambda value: _FakeRules())

    @unittest.skipIf(yara is None, "yara-python is optional")
    def test_real_compiled_artifact_loads_only_when_runtime_versions_match(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "cache"; artifact = build_cache(root)
            rules = yara.compile(source='rule harmless_fixture { condition: true }')
            rules.save(str(artifact))
            manifest_path = artifact.parent / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["artifact"].update({"size": artifact.stat().st_size,
                                         "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()})
            manifest["runtime"] = {"yara_version": yara.YARA_VERSION, "yara_python_version": yara.__version__}
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(pin_cache(root).generation, (root / "active").read_text().strip())
            manifest["runtime"]["yara_version"] = "incompatible"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(CacheError, "incompatible"):
                pin_cache(root)

    def test_strict_settings_preserve_optional_dependency_boundary(self) -> None:
        settings = load_config()["processors"]["yara_scan"]
        self.assertEqual(yara_scan_settings(settings)["selector"], "exec-only")
        settings["follow_symlinks"] = True
        with self.assertRaisesRegex(ValueError, "follow_symlinks"):
            yara_scan_settings(settings)


class YaraPipelineTests(unittest.TestCase):
    def test_archive_to_yara_report_uses_compiled_cache_and_never_renders_target_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            base = Path(name); incoming = base / "in"; incoming.mkdir()
            archive = incoming / "sample.zip.en_dec"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("payload.exe", b"MZ harmless SECRET_TARGET_BYTES")
            artifact = build_cache(base / "cache")
            config = load_config()
            config["watch"]["path"] = "./in"
            config["dispatcher"].update({"staging_root": "./middle-earth", "output_root": "./output", "staging_index_path": "./data/staging.sqlite3"})
            config["pipelines"]["on_added"]["analysis"]["processors"] = ["yara_scan"]
            config["processors"]["yara_scan"]["cache_dir"] = "./cache"
            seen = []
            def factory(processor_name, processor_config):
                return YaraScan(processor_name, processor_config, rule_loader=lambda path: (seen.append(path), _FakeRules())[1])
            with Dispatcher(config, base_dir=base, processor_factories={"yara_scan": factory}) as dispatcher:
                result = dispatcher.dispatch(WatchEvent.added(incoming, archive))
            self.assertFalse(result.errors, [issue.message for issue in result.errors])
            self.assertEqual(seen, [artifact.resolve()])
            report = (base / "output" / "sample.zip.en_dec-yara.md").read_text(encoding="utf-8")
            self.assertIn("successful match", report)
            self.assertIn("harmless\\_fixture", report)
            self.assertNotIn("SECRET_TARGET_BYTES", report)
            self.assertIn("https://example\\.test/rules", report)
