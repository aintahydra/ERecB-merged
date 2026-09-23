"""Read and verify one immutable YaraRuler cache generation.

The consumer intentionally loads only a verified ``rules.yac`` artifact.  It never
interprets source rules, updates the pointer, or writes inside the cache.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit


_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_CACHE_SETUP_GUIDANCE = (
    "clone/configure and run the separate ERecB YaraRuler producer to build its compiled cache, "
    "then set processors.yara_scan.cache_dir to that cache directory"
)


class CacheError(ValueError):
    """A cache was absent, malformed, incompatible, or failed to load."""


class YaraDependencyError(RuntimeError):
    """The selected profile needs the optional yara-python package."""


@dataclass(frozen=True)
class PinnedCache:
    generation: str
    artifact: Path
    rules: Any
    provenance: dict[str, dict[str, str]]
    manifest: dict[str, Any]


def default_rule_loader(path: Path):
    try:
        import yara  # type: ignore
    except ImportError as exc:
        raise YaraDependencyError("yara-python is required; install erecb-triage[yara]") from exc
    try:
        return yara.load(str(path))
    except Exception as exc:
        raise CacheError("compiled YARA artifact could not be loaded") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _redact_url(value: str) -> str:
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc:
        return value
    host = parts.hostname or ""
    if parts.port is not None:
        host += f":{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def _artifact_info(manifest: dict[str, Any]) -> tuple[str, int, str]:
    artifact = manifest.get("artifact")
    if not isinstance(artifact, dict):
        raise CacheError("manifest artifact must be a mapping")
    filename, size, digest = artifact.get("filename"), artifact.get("size"), artifact.get("sha256")
    if filename != "rules.yac" or type(size) is not int or size < 1 or not isinstance(digest, str):
        raise CacheError("manifest has invalid rules.yac artifact metadata")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise CacheError("manifest artifact SHA-256 must be lowercase hexadecimal")
    return filename, size, digest


def _provenance(manifest: dict[str, Any]) -> dict[str, dict[str, str]]:
    accepted = manifest.get("accepted_rules")
    if not isinstance(accepted, list) or not accepted:
        raise CacheError("manifest must contain a nonempty accepted_rules list")
    result: dict[str, dict[str, str]] = {}
    for entry in accepted:
        if not isinstance(entry, dict):
            raise CacheError("manifest accepted rule must be a mapping")
        namespace = entry.get("namespace")
        if not isinstance(namespace, str) or not namespace or namespace in result:
            raise CacheError("manifest namespaces must be nonempty and unique")
        source = entry.get("source") or entry.get("source_name")
        rule_path = entry.get("path") or entry.get("rule_path")
        commit = entry.get("commit") or entry.get("commit_sha")
        digest = entry.get("sha256")
        if not all(isinstance(value, str) and value for value in (source, rule_path, commit, digest)):
            raise CacheError("accepted rule provenance is incomplete")
        url = entry.get("url") or entry.get("source_url") or ""
        if not isinstance(url, str):
            raise CacheError("accepted rule URL must be a string")
        result[namespace] = {"source": source, "path": rule_path, "commit": commit,
                             "sha256": digest, "url": _redact_url(url)}
    return result


def _runtime_compatible(manifest: dict[str, Any], *, verify_installed: bool) -> None:
    runtime = manifest.get("runtime")
    if not isinstance(runtime, dict):
        raise CacheError("manifest runtime compatibility metadata is required")
    yara_version, python_version = runtime.get("yara_version"), runtime.get("yara_python_version")
    if not all(isinstance(value, str) and value for value in (yara_version, python_version)):
        raise CacheError("manifest YARA compatibility metadata is incomplete")
    if not verify_installed:
        return
    try:
        import yara  # type: ignore
    except ImportError as exc:  # Constructor normally prevents this boundary from being reached.
        raise YaraDependencyError("yara-python is required; install erecb-triage[yara]") from exc
    installed_yara = str(getattr(yara, "YARA_VERSION", ""))
    installed_python = str(getattr(yara, "__version__", ""))
    if yara_version != installed_yara or python_version != installed_python:
        raise CacheError("YARA cache was built with incompatible YARA/yara-python versions")


def pin_cache(cache_dir: str | Path, *, loader: Callable[[Path], Any] | None = None) -> PinnedCache:
    """Pin active once, validate its metadata and load its verified compiled artifact."""
    configured_root = Path(cache_dir)
    if configured_root.is_symlink():
        raise CacheError("configured YARA cache directory must not be a symlink")
    root = configured_root.resolve()
    if not root.is_dir():
        raise CacheError(f"configured YARA cache directory is unavailable: {root}; {_CACHE_SETUP_GUIDANCE}")
    try:
        active = root / "active"
        if active.is_symlink():
            raise CacheError("YARA cache active pointer must not be a symlink")
        pointer = active.read_text(encoding="ascii")
    except OSError as exc:
        raise CacheError(f"YARA cache active pointer is unavailable; {_CACHE_SETUP_GUIDANCE}") from exc
    generation = pointer[:-1] if pointer.endswith("\n") else pointer
    if generation != generation.strip() or not _UUID.fullmatch(generation):
        raise CacheError("YARA cache active pointer is not a canonical lowercase UUID")
    candidate = root / "generations" / generation
    if candidate.is_symlink():
        raise CacheError("active YARA cache generation must not be a symlink")
    try:
        directory = candidate.resolve(strict=True)
    except OSError as exc:
        raise CacheError("active YARA cache generation is unavailable") from exc
    allowed = (root / "generations").resolve()
    if not directory.is_relative_to(allowed) or directory.name != generation:
        raise CacheError("active YARA cache generation escapes cache root")
    try:
        manifest_path = directory / "manifest.json"
        if manifest_path.is_symlink():
            raise CacheError("YARA cache manifest must not be a symlink")
        with manifest_path.open(encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise CacheError("YARA cache manifest is unavailable or invalid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("generation_id") != generation:
        raise CacheError("YARA cache manifest generation does not match active pointer")
    schema = manifest.get("schema_version")
    if schema not in {1, "1", "1.0"}:
        raise CacheError("unsupported YARA cache manifest schema")
    if manifest.get("platform") != platform.system() or manifest.get("machine") != platform.machine():
        raise CacheError("YARA cache platform or machine is incompatible")
    _runtime_compatible(manifest, verify_installed=loader is None)
    filename, expected_size, expected_digest = _artifact_info(manifest)
    artifact = directory / filename
    try:
        info = artifact.stat(follow_symlinks=False)
    except OSError as exc:
        raise CacheError("YARA compiled artifact is unavailable") from exc
    if artifact.is_symlink() or not artifact.is_file() or info.st_size != expected_size or _sha256(artifact) != expected_digest:
        raise CacheError("YARA compiled artifact does not match manifest")
    provenance = _provenance(manifest)
    try:
        rules = (loader or default_rule_loader)(artifact)
    except YaraDependencyError:
        raise
    except CacheError:
        raise
    except Exception as exc:
        raise CacheError("compiled YARA artifact could not be loaded") from exc
    return PinnedCache(generation, artifact, rules, provenance, manifest)
