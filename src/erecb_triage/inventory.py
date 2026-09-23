"""Versioned, manifest-bound facts shared between trusted-capture processors.

This module deliberately contains no readability, executable, intelligence, or verdict
decision.  Its entries are copied from the staging manifest after that manifest has been
verified by the dispatcher.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
from typing import Any


INVENTORY_SCHEMA_VERSION = 1


class InventoryError(ValueError):
    pass


def manifest_digest(entries: list[dict[str, Any]]) -> str:
    """Return a deterministic identity for the complete trusted staging manifest."""
    encoded = json.dumps(entries, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _entry(entry: Any) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise InventoryError("staging manifest entry is not a mapping")
    path, kind, size = entry.get("path"), entry.get("type"), entry.get("size")
    pure = PurePosixPath(path) if isinstance(path, str) else None
    if (pure is None or not path or pure.is_absolute() or ".." in pure.parts or "\\" in path
            or kind not in {"file", "directory"} or type(size) is not int or size < 0):
        raise InventoryError("staging manifest contains an invalid inventory entry")
    result = {"path": path, "type": kind, "size": size}
    digest = entry.get("sha256")
    if kind == "file":
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise InventoryError("staging manifest file entry lacks a canonical SHA-256")
        result["sha256"] = digest
    elif digest is not None:
        raise InventoryError("staging manifest directory entry has an unexpected SHA-256")
    return result


def build_inventory(capture: dict[str, Any], manifest_entries: list[dict[str, Any]], *, max_entries: int) -> dict[str, Any]:
    """Build bounded serializable facts from one already-authorized staging manifest."""
    if type(max_entries) is not int or max_entries < 1:
        raise InventoryError("max_entries must be a positive integer")
    if len(manifest_entries) > max_entries:
        raise InventoryError("trusted manifest exceeds artifact inventory entry limit")
    entries = sorted((_entry(entry) for entry in manifest_entries), key=lambda item: (item["path"], item["type"]))
    if len({(entry["path"], entry["type"]) for entry in entries}) != len(entries):
        raise InventoryError("trusted manifest has duplicate inventory entries")
    files = [entry for entry in entries if entry["type"] == "file"]
    return {
        "type": "artifact_inventory", "schema_version": INVENTORY_SCHEMA_VERSION,
        "capture_name": capture["capture_name"], "staged_path": capture["staged_path"],
        "source_event_id": capture["source_event_id"], "pipeline_run_id": capture["pipeline_run_id"],
        "manifest_sha256": manifest_digest(manifest_entries), "entries": entries,
        "file_count": len(files), "total_file_bytes": sum(entry["size"] for entry in files),
    }


def validate_inventory(inventory: dict[str, Any], capture: dict[str, Any], manifest_entries: list[dict[str, Any]]) -> None:
    """Reject stale, mixed-capture, or altered inventory instead of falling back silently."""
    if inventory.get("type") != "artifact_inventory" or inventory.get("schema_version") != INVENTORY_SCHEMA_VERSION:
        raise InventoryError("unsupported artifact inventory schema")
    for key in ("capture_name", "staged_path", "source_event_id", "pipeline_run_id"):
        if inventory.get(key) != capture.get(key):
            raise InventoryError("artifact inventory belongs to a different capture invocation")
    if inventory.get("manifest_sha256") != manifest_digest(manifest_entries):
        raise InventoryError("artifact inventory manifest identity is stale")
    expected = build_inventory(capture, manifest_entries, max_entries=max(len(manifest_entries), 1))
    if (inventory.get("entries") != expected["entries"]
            or inventory.get("file_count") != expected["file_count"]
            or inventory.get("total_file_bytes") != expected["total_file_bytes"]):
        raise InventoryError("artifact inventory entries disagree with trusted manifest")
