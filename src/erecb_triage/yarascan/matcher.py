"""Bounded matching and normalization; target bytes are never retained."""

from __future__ import annotations

import os
from pathlib import Path

from erecb_triage.fileintel.hashing import FileChanged, hash_file, stat_signature
from erecb_triage.processors.base import ProcessorError


def _scalar(value):
    if isinstance(value, (str, int, bool)):
        return str(value)[:512] if isinstance(value, str) else value
    return str(value)[:512]


def _strings(match, cap: int) -> tuple[list[dict], bool]:
    values, truncated = [], False
    for item in getattr(match, "strings", ()):
        identifier = getattr(item, "identifier", None)
        instances = getattr(item, "instances", ())
        # Older yara-python exposes tuples (offset, identifier, matched_bytes).
        if isinstance(item, tuple) and len(item) >= 2:
            values.append({"identifier": str(item[1]), "offset": int(item[0]), "length": len(item[2]) if len(item) > 2 else 0})
            continue
        for instance in instances:
            if len(values) >= cap:
                truncated = True; break
            values.append({"identifier": str(identifier), "offset": int(getattr(instance, "offset", 0)),
                           "length": int(getattr(instance, "matched_length", len(getattr(instance, "matched_data", b""))))})
        if truncated: break
    return sorted(values, key=lambda row: (row["offset"], row["identifier"])), truncated


def scan_file(path: Path, cache, settings: dict, base_dir: Path) -> tuple[list[dict], ProcessorError | None]:
    """Return normalized match records or a recoverable per-file error."""
    try:
        before = stat_signature(path.stat(follow_symlinks=False))
        raw_matches = cache.rules.match(filepath=str(path), timeout=settings["timeout_seconds"])
        if stat_signature(path.stat(follow_symlinks=False)) != before:
            raise FileChanged("file changed during YARA matching")
        if not raw_matches:
            return [], None
        hashes = hash_file(path, max_size=settings["max_file_size_bytes"])
        if stat_signature(path.stat(follow_symlinks=False)) != before:
            raise FileChanged("file changed during YARA hashing")
    except Exception as exc:
        code = "yara_file_changed" if isinstance(exc, FileChanged) else "yara_match_error"
        return [], ProcessorError(path, str(exc), code)
    records = []
    for match in raw_matches:
        namespace, rule = getattr(match, "namespace", None), getattr(match, "rule", None)
        if not isinstance(namespace, str) or namespace not in cache.provenance or not isinstance(rule, str):
            return [], ProcessorError(path, "YARA match has unprovenanced namespace", "yara_cache_integrity_error")
        strings, truncated = _strings(match, settings["max_string_instances_per_rule"])
        display = str(path.relative_to(base_dir)) if path.is_relative_to(base_dir) else str(path)
        record = {"type": "yara_match", "source_path": str(path), "display_path": display,
                  "sha256_hash": hashes.sha256_hash, "md5_hash": hashes.md5_hash, "size_bytes": hashes.size_bytes,
                  "namespace": namespace, "rule": rule, "tags": sorted(set(map(str, getattr(match, "tags", ())))),
                  "meta": {str(key)[:128]: _scalar(value) for key, value in list(getattr(match, "meta", {}).items())[:64]},
                  "cache_generation": cache.generation, "provenance": cache.provenance[namespace]}
        if settings["include_strings"]:
            record["strings"], record["strings_truncated"] = strings, truncated
        records.append(record)
    return sorted(records, key=lambda item: (item["display_path"], item["namespace"], item["rule"])), None
