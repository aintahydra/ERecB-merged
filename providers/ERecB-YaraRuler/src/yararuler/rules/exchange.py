"""Verified directory-based transfer of one immutable compiled YARA generation."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path

from yararuler.errors import CacheError
from yararuler.rules.cache import atomic_write_pointer, load_active_cache
from yararuler.rules.compiler import sha256_file


def _validate_transfer(source: Path) -> tuple[str, dict]:
    if source.is_symlink() or not source.is_dir():
        raise CacheError("cache transfer must be a regular directory")
    expected = {"manifest.json", "rules.yac", "transfer.json"}
    if {entry.name for entry in source.iterdir()} != expected:
        raise CacheError("cache transfer has missing or unexpected files")
    for name in expected:
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise CacheError(f"unsafe cache transfer file: {name}")
        limit = 2 * 1024 ** 3 if name == "rules.yac" else 16 * 1024 ** 2 if name == "manifest.json" else 4096
        if path.stat().st_size > limit:
            raise CacheError(f"cache transfer file is too large: {name}")
    try:
        transfer = json.loads((source / "transfer.json").read_text(encoding="utf-8"))
        manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CacheError("invalid cache transfer metadata") from exc
    generation = transfer.get("generation_id") if isinstance(transfer, dict) else None
    try:
        if str(uuid.UUID(generation)) != generation:
            raise ValueError
    except (TypeError, ValueError, AttributeError) as exc:
        raise CacheError("invalid transfer generation") from exc
    if not isinstance(manifest, dict) or manifest.get("generation_id") != generation:
        raise CacheError("cache generation disagrees with transfer metadata")
    if (transfer.get("schema_version") != 1
            or transfer.get("manifest_sha256") != sha256_file(source / "manifest.json")
            or transfer.get("rules_sha256") != sha256_file(source / "rules.yac")):
        raise CacheError("cache transfer checksum mismatch")
    return generation, manifest


def export_cache(cache_dir: Path, destination: Path) -> str:
    active = load_active_cache(cache_dir)
    if destination.exists() or destination.is_symlink():
        raise CacheError("cache export destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{destination.name}.", dir=destination.parent) as temporary:
        stage = Path(temporary) / "bundle"
        stage.mkdir()
        shutil.copyfile(active.rules_path, stage / "rules.yac")
        shutil.copyfile(active.rules_path.parent / "manifest.json", stage / "manifest.json")
        transfer = {"schema_version": 1, "generation_id": active.generation,
                    "manifest_sha256": sha256_file(stage / "manifest.json"),
                    "rules_sha256": sha256_file(stage / "rules.yac")}
        (stage / "transfer.json").write_text(json.dumps(transfer, sort_keys=True) + "\n", encoding="utf-8")
        _validate_transfer(stage)
        # Publish the complete directory in one rename. A failed copy must not leave a
        # transfer bundle that looks ready to carry to the other machine.
        os.replace(stage, destination)
    return active.generation


def import_cache(source: Path, cache_dir: Path) -> str:
    generation, _ = _validate_transfer(source)
    if cache_dir.is_symlink():
        raise CacheError("cache directory must not be a symlink")
    cache_dir.mkdir(parents=True, exist_ok=True)
    generations = cache_dir / "generations"
    if generations.is_symlink():
        raise CacheError("cache generations directory must not be a symlink")
    generations.mkdir(exist_ok=True)
    target = generations / generation
    if target.is_symlink():
        raise CacheError("cache generation target must not be a symlink")
    with tempfile.TemporaryDirectory(prefix=".incoming-cache-", dir=cache_dir) as temporary:
        staged_cache = Path(temporary)
        staged_generation = staged_cache / "generations" / generation
        staged_generation.mkdir(parents=True)
        shutil.copyfile(source / "manifest.json", staged_generation / "manifest.json")
        shutil.copyfile(source / "rules.yac", staged_generation / "rules.yac")
        (staged_cache / "active").write_text(generation + "\n", encoding="ascii")
        # Verifies OS, architecture, both YARA runtime versions, digest, and loadability.
        load_active_cache(staged_cache)
        if target.exists():
            if (not target.is_dir() or sha256_file(target / "manifest.json") != sha256_file(staged_generation / "manifest.json")
                    or sha256_file(target / "rules.yac") != sha256_file(staged_generation / "rules.yac")):
                raise CacheError("generation already exists with different contents")
        else:
            # The validated generation becomes visible atomically before the pointer moves.
            os.replace(staged_generation, target)
        atomic_write_pointer(cache_dir, generation)
    return generation
