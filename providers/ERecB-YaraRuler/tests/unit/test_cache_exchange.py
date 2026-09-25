from __future__ import annotations

import hashlib
import json
import platform
import uuid
from pathlib import Path

import yararuler.rules.cache as cache_module
import yararuler.rules.exchange as exchange_module
import pytest
from yararuler.errors import CacheError
from yararuler.rules.exchange import export_cache, import_cache


class _Yara:
    @staticmethod
    def load(path):
        return object()


def test_cache_transfer_requires_valid_manifest_and_keeps_generation(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(cache_module, "require_yara", lambda: _Yara())
    monkeypatch.setattr(cache_module, "yara_runtime", lambda: {"yara_version": "fixture", "yara_python_version": "fixture"})
    connected = tmp_path / "connected"
    generation = str(uuid.uuid4())
    folder = connected / "generations" / generation
    folder.mkdir(parents=True)
    rules = folder / "rules.yac"
    rules.write_bytes(b"compiled fixture")
    manifest = {"generation_id": generation, "platform": platform.system(), "machine": platform.machine(),
                "runtime": {"yara_version": "fixture", "yara_python_version": "fixture"},
                "artifact": {"filename": "rules.yac", "sha256": hashlib.sha256(rules.read_bytes()).hexdigest(),
                             "size": rules.stat().st_size}}
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (connected / "active").write_text(generation + "\n", encoding="ascii")
    transfer = tmp_path / "transfer"
    assert export_cache(connected, transfer) == generation
    original_copy = exchange_module.shutil.copyfile

    def fail_manifest_copy(source, destination):
        if Path(destination).name == "manifest.json":
            raise OSError("injected copy failure")
        return original_copy(source, destination)

    with monkeypatch.context() as failure:
        failure.setattr(exchange_module.shutil, "copyfile", fail_manifest_copy)
        with pytest.raises(OSError, match="injected copy failure"):
            export_cache(connected, tmp_path / "broken-transfer")
        assert not (tmp_path / "broken-transfer").exists()
        with pytest.raises(OSError, match="injected copy failure"):
            import_cache(transfer, tmp_path / "broken-airgap")
        assert not (tmp_path / "broken-airgap" / "active").exists()
        assert not (tmp_path / "broken-airgap" / "generations" / generation).exists()
    airgap = tmp_path / "airgap"
    assert import_cache(transfer, airgap) == generation
    assert (airgap / "active").read_text(encoding="ascii").strip() == generation
    assert import_cache(transfer, airgap) == generation
    monkeypatch.setattr(cache_module, "yara_runtime", lambda: {
        "yara_version": "incompatible", "yara_python_version": "fixture",
    })
    with pytest.raises(CacheError, match="different YARA version"):
        import_cache(transfer, airgap)
    assert (airgap / "active").read_text(encoding="ascii").strip() == generation
