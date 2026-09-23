from __future__ import annotations

import json
import os
import platform
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from yararuler.errors import CacheError
from yararuler.rules.compiler import require_yara, sha256_file, yara_runtime


@dataclass(frozen=True)
class ActiveCache:
    generation: str
    rules_path: Path
    manifest: dict[str, Any]


def load_active_cache(cache_dir: Path) -> ActiveCache:
    pointer = cache_dir / "active"
    try:
        generation = pointer.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise CacheError(f"compiled rule cache is unavailable; run update-rules: {exc}") from exc
    try:
        if str(uuid.UUID(generation)) != generation.lower():
            raise ValueError
    except (ValueError, AttributeError) as exc:
        raise CacheError("compiled rule cache has an invalid active generation") from exc
    generation_dir = cache_dir / "generations" / generation
    rules_path = generation_dir / "rules.yac"
    manifest_path = generation_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CacheError(f"cannot read cache manifest: {exc}") from exc
    if manifest.get("generation_id") != generation:
        raise CacheError("cache manifest generation does not match active pointer")
    if manifest.get("platform") != platform.system() or manifest.get("machine") != platform.machine():
        raise CacheError("cache was built for a different platform; run update-rules")
    runtime = manifest.get("runtime")
    if not isinstance(runtime, dict) or runtime != yara_runtime():
        raise CacheError("cache was built with a different YARA version; run update-rules")
    artifact = manifest.get("artifact")
    if not isinstance(artifact, dict) or artifact.get("filename") != "rules.yac":
        raise CacheError("cache manifest has invalid compiled artifact metadata")
    try:
        actual_digest = sha256_file(rules_path)
    except OSError as exc:
        raise CacheError(f"cannot read compiled rule cache: {exc}") from exc
    if actual_digest != artifact.get("sha256") or rules_path.stat().st_size != artifact.get("size"):
        raise CacheError("compiled rule cache digest does not match its manifest")
    try:
        require_yara().load(str(rules_path))
    except Exception as exc:
        raise CacheError(f"compiled rule cache is incompatible or corrupt: {exc}") from exc
    return ActiveCache(generation, rules_path, manifest)


def atomic_write_pointer(cache_dir: Path, generation: str) -> None:
    temporary = cache_dir / f".active-{generation}"
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(generation + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, cache_dir / "active")
