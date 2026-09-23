"""Bounded GitHub repository-root extraction from authorized staged files."""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from erecb_triage.config import ghintel_settings
from erecb_triage.ghintel.normalization import RepositoryIdentity, normalize_repository
from erecb_triage.processors.base import ProcessorError
from erecb_triage.staging import regular_reader, safe_name


_TOKEN = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:/@._-?#%")


@dataclass
class ExtractionResult:
    observations: list[dict] = field(default_factory=list)
    errors: list[ProcessorError] = field(default_factory=list)
    metrics: dict[str, int] = field(default_factory=lambda: {
        "ghintel_files_scanned": 0, "ghintel_files_skipped": 0,
        "ghintel_observations": 0, "ghintel_unique_repositories": 0,
    })


def extract_stream(reader, *, chunk_size: int, max_candidate_bytes: int, max_size: int | None) -> tuple[dict[str, tuple[RepositoryIdentity, int, int]], int]:
    """Return identity -> (identity, occurrence count, first byte offset)."""
    found: dict[str, tuple[RepositoryIdentity, int, int]] = {}
    token = bytearray()
    start = 0
    position = 0
    discard = False

    def flush() -> None:
        nonlocal discard
        if not discard and token:
            identity = normalize_repository(token.decode("ascii"))
            if identity is not None:
                prior = found.get(identity.identity_key)
                found[identity.identity_key] = (identity, (prior[1] if prior else 0) + 1,
                                                prior[2] if prior else start)
        token.clear()
        discard = False

    while True:
        amount = chunk_size if max_size is None else min(chunk_size, max_size - position + 1)
        chunk = reader.read(amount)
        if not chunk:
            flush()
            return found, position
        for byte in chunk:
            if byte in _TOKEN:
                if not token and not discard:
                    start = position
                if discard:
                    pass
                elif len(token) >= max_candidate_bytes:
                    token.clear()
                    discard = True
                else:
                    token.append(byte)
            else:
                flush()
            position += 1
            if max_size is not None and position > max_size:
                raise OSError("file exceeds max_file_size_bytes")


def scan_capture(capture: dict, settings: dict, base_dir: Path) -> ExtractionResult:
    settings = ghintel_settings(settings)
    root = Path(capture.get("staged_path", ""))
    if (capture.get("type") != "staged_capture" or not root.is_absolute() or root.is_symlink()
            or not root.is_dir() or root.name != capture.get("capture_name")
            or not safe_name(capture.get("capture_name", ""))):
        raise ValueError("invalid staged capture path or identity")
    result = ExtractionResult()
    root = root.resolve()
    base_dir = base_dir.resolve()
    max_size = settings["max_file_size_bytes"]
    for directory, dirs, files in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        relative = directory_path.relative_to(root)
        depth = len(relative.parts)
        dirs[:] = sorted(name for name in dirs if not (directory_path / name).is_symlink()
                         and (settings["include_hidden_directories"] or not name.startswith(".")))
        if settings["max_depth_from_staged_root"] is not None and depth >= settings["max_depth_from_staged_root"]:
            dirs[:] = []
        for name in sorted(files):
            source = directory_path / name
            if name.startswith(".") and not settings["include_hidden_files"]:
                result.metrics["ghintel_files_skipped"] += 1
                continue
            try:
                before = source.lstat()
                if not stat.S_ISREG(before.st_mode) or source.is_symlink():
                    result.metrics["ghintel_files_skipped"] += 1
                    continue
                if max_size is not None and before.st_size > max_size:
                    result.metrics["ghintel_files_skipped"] += 1
                    continue
                with regular_reader(source) as reader:
                    initial = os.fstat(reader.fileno())
                    if (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns) != (
                            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
                        raise OSError("file changed before reading")
                    found, size = extract_stream(reader, chunk_size=settings["chunk_size_bytes"],
                                                 max_candidate_bytes=settings["max_candidate_bytes"], max_size=max_size)
                    after = source.lstat()
                    if size != before.st_size or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
                        raise OSError("file changed during reading")
                result.metrics["ghintel_files_scanned"] += 1
                display = str(source.relative_to(base_dir)) if source.is_relative_to(base_dir) else str(source)
                for identity, occurrences, offset in found.values():
                    result.observations.append({
                        "type": "github_repository_observation", "identity_key": identity.identity_key,
                        "canonical_url": identity.canonical_url, "owner": identity.owner,
                        "repository": identity.repository, "source_path": str(source), "display_path": display,
                        "occurrence_count": occurrences, "first_offset": offset,
                        "capture_name": capture["capture_name"], "staged_capture": str(root),
                        "source_event_id": capture["source_event_id"], "pipeline_run_id": capture["pipeline_run_id"],
                    })
            except OSError as exc:
                result.metrics["ghintel_files_skipped"] += 1
                result.errors.append(ProcessorError(source, str(exc), "ghintel_read_error"))
    unique = {(item["identity_key"], item["source_path"]): item for item in result.observations}
    result.observations = sorted(unique.values(), key=lambda item: (item["identity_key"], item["source_path"]))
    result.metrics["ghintel_observations"] = len(result.observations)
    result.metrics["ghintel_unique_repositories"] = len({item["identity_key"] for item in result.observations})
    return result
