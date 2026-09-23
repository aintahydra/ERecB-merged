"""Read-only operational readiness checks for an ERecB deployment."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

from erecb_triage.config import resolve_path, validate_config
from erecb_triage.fileintel.classifier import ExecutableClassifier
from erecb_triage.fileintel.repository import FileIntelRepository
from erecb_triage.ghintel.repository import GHIntelRepository
from erecb_triage.ipintel.repository import IpIntelRepository
from erecb_triage.processors import ArchiveUnarchiver, ArtifactInventory, FileRetriever, GHIntel, IPRetriever, YaraScan
from erecb_triage.processors.input_stager import InputStager
from erecb_triage.yarascan.cache import CacheError, YaraDependencyError, pin_cache


def _check(name: str, state: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {"name": name, "state": state, "detail": detail, **extra}


def _directory_check(name: str, path: Path, *, must_exist: bool) -> dict[str, Any]:
    candidate = path if path.exists() else path.parent
    if path.exists() and (path.is_symlink() or not path.is_dir()):
        return _check(name, "fatal", "path is not a safe directory", path=str(path))
    if must_exist and not path.is_dir():
        return _check(name, "fatal", "directory is missing", path=str(path))
    if not candidate.is_dir() or not os.access(candidate, os.R_OK | os.W_OK | os.X_OK):
        return _check(name, "fatal", "directory or parent is not accessible", path=str(path))
    return _check(name, "ready" if path.exists() else "degraded", "directory exists" if path.exists() else "will be created at runtime", path=str(path))


def _database_check(name: str, repository, path: Path) -> dict[str, Any]:
    with repository(path) as session:
        if session.available:
            return _check(name, "ready", "read-only schema capability check passed", path=str(path))
        detail = session.initialization_error.message if session.initialization_error else "database unavailable"
        return _check(name, "degraded", detail, path=str(path))


def _staging_index_check(index: Path) -> dict[str, Any]:
    if not index.exists():
        return _check("staging_index", "degraded", "state database will be initialized at runtime", path=str(index))
    if index.is_symlink() or not index.is_file():
        return _check("staging_index", "fatal", "state database is not a safe regular file", path=str(index))
    try:
        connection = sqlite3.connect(index.as_uri() + "?mode=ro", uri=True)
        try:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
            version = connection.execute("SELECT value FROM metadata WHERE key='staging_schema_version'").fetchone()
        finally:
            connection.close()
        if not {"metadata", "captures", "report_slots"}.issubset(tables) or version is None:
            return _check("staging_index", "fatal", "state database lacks required staging schema", path=str(index))
        return _check("staging_index", "ready", f"staging schema version {version[0]}", path=str(index))
    except sqlite3.Error as exc:
        return _check("staging_index", "fatal", str(exc), path=str(index))


def readiness(config: dict[str, Any], base_dir: Path) -> dict[str, Any]:
    """Check configuration and dependencies without creating, locking, or mutating state."""
    base_dir = base_dir.resolve()
    checks: list[dict[str, Any]] = []
    try:
        validate_config(config)
        checks.append(_check("configuration", "ready", "configuration contract is valid"))
    except ValueError as exc:
        return {"ok": False, "checks": [_check("configuration", "fatal", str(exc))]}
    watch = resolve_path(base_dir, config["watch"].get("path", "./in"))
    dispatcher = config["dispatcher"]
    staging = resolve_path(base_dir, dispatcher["staging_root"])
    output = resolve_path(base_dir, dispatcher["output_root"])
    index = resolve_path(base_dir, dispatcher["staging_index_path"])
    checks.extend((_directory_check("watch_root", watch, must_exist=True),
                   _directory_check("staging_root", staging, must_exist=False),
                   _directory_check("output_root", output, must_exist=False), _staging_index_check(index)))
    if len({watch, staging, output}) != 3 or any(first.is_relative_to(second) or second.is_relative_to(first)
                                                 for first, second in ((watch, staging), (watch, output), (staging, output))):
        checks.append(_check("path_containment", "fatal", "watch, staging, and output roots must be disjoint"))
    else:
        checks.append(_check("path_containment", "ready", "watch, staging, and output roots are disjoint"))

    factories = {"archive_unarchiver": ArchiveUnarchiver, "input_stager": InputStager, "artifact_inventory": ArtifactInventory,
                 "ip_retriever": IPRetriever, "file_retriever": FileRetriever, "ghintel": GHIntel, "yara_scan": YaraScan}
    selected = [*config["pipelines"]["on_added"]["preprocessors"]["processors"],
                *config["pipelines"]["on_added"]["analysis"]["processors"]]
    for name in selected:
        settings = config["processors"][name]
        try:
            factories[settings["type"]](name, settings)
            checks.append(_check(f"processor:{name}", "ready", "processor constructed"))
        except YaraDependencyError as exc:
            checks.append(_check(f"processor:{name}", "fatal", str(exc)))
        except Exception as exc:
            checks.append(_check(f"processor:{name}", "fatal", str(exc)))

    for name, repository in (("ipintel_database", IpIntelRepository), ("fileintel_database", FileIntelRepository),
                             ("ghintel_database", GHIntelRepository)):
        processor_name = {"ipintel_database": "ip_retriever", "fileintel_database": "file_retriever", "ghintel_database": "ghintel"}[name]
        if processor_name in selected:
            path = resolve_path(base_dir, config["processors"][processor_name]["db_path"])
            checks.append(_database_check(name, repository, path))
    if "file_retriever" in selected:
        classifier = ExecutableClassifier(**config["processors"]["file_retriever"]["classifier"])
        checks.append(_check("fileintel_classifier", "ready" if classifier.availability == "available" else "degraded",
                             classifier.unavailable_reason or "classifier is available"))
    if "yara_scan" in selected:
        cache_path = resolve_path(base_dir, config["processors"]["yara_scan"]["cache_dir"])
        try:
            pinned = pin_cache(cache_path)
            checks.append(_check("yara_cache", "ready", "active cache verified", generation=pinned.generation,
                                 path=str(cache_path)))
        except (CacheError, YaraDependencyError) as exc:
            checks.append(_check("yara_cache", "degraded", str(exc), path=str(cache_path)))
    for path in (watch, staging if staging.exists() else staging.parent, output if output.exists() else output.parent):
        try:
            free = os.statvfs(path).f_bavail * os.statvfs(path).f_frsize
            checks.append(_check(f"free_space:{path.name or 'root'}", "ready", "free space measured", bytes=free))
        except OSError as exc:
            checks.append(_check("free_space", "degraded", str(exc), path=str(path)))
    return {"ok": not any(check["state"] == "fatal" for check in checks), "checks": checks}
