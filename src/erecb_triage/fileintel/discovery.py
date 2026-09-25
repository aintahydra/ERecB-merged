"""Discover local executable observations without a dispatcher or intelligence DB."""

from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from erecb_triage.config import file_retriever_settings
from erecb_triage.fileintel.classifier import (
    MAGIC_SAMPLE_BYTES, Availability, Classification, ExecutableClassifier, MagicDescription,
)
from erecb_triage.fileintel.contracts import FileObservation
from erecb_triage.fileintel.hashing import (
    FileChanged, FileTooLarge, hash_stream, read_header, stat_signature,
)
from erecb_triage.processors.base import ProcessorError
from erecb_triage.staging import regular_reader, safe_name


def _metrics() -> dict[str, int]:
    return {f"fileintel_{key}": 0 for key in (
        "files_scanned", "files_skipped", "executables_found", "observations", "unique_hashes",
    )}


@dataclass
class DiscoveryResult:
    observations: list[FileObservation] = field(default_factory=list)
    errors: list[ProcessorError] = field(default_factory=list)
    metrics: dict[str, int] = field(default_factory=_metrics)
    classification_availability: Availability = "available"


@contextmanager
def _open_directory(root_fd: int, relative: Path):
    """Walk from an anchored root, refusing symlinks in every physical path component."""
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("directory path must stay relative to the capture")
    fd = os.dup(root_fd)
    try:
        for part in relative.parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def scan_capture(capture: dict, settings: dict, base_dir: Path, *,
                 describe: MagicDescription | None = None) -> DiscoveryResult:
    """Scan a caller-authorized staged record; Phase 5 supplies dispatcher authorization."""
    settings = file_retriever_settings(settings)
    if capture.get("type") != "staged_capture":
        raise ValueError("a staged_capture record is required")
    for key in ("staged_path", "capture_name", "source_event_id", "pipeline_run_id"):
        if not isinstance(capture.get(key), str) or not capture[key]:
            raise ValueError(f"staged capture requires {key}")
    root = Path(capture["staged_path"])
    if (not root.is_absolute() or root.is_symlink() or not safe_name(capture["capture_name"])
            or root.name != capture["capture_name"]):
        raise ValueError("invalid staged capture path or identity")
    if root.resolve() != root:
        raise ValueError("staged_path must be canonical")
    base_dir = base_dir.resolve()
    classifier = ExecutableClassifier(**settings["classifier"], describe=describe)
    result = DiscoveryResult(classification_availability=classifier.availability)
    if classifier.unavailable_reason is not None and settings["selector"] == "exec-only":
        result.errors.append(ProcessorError(root, classifier.unavailable_reason, "fileintel_magic_unavailable"))
    max_size = settings["max_file_size_bytes"]
    block_size = settings["hash_block_size_bytes"]
    max_depth = settings["max_depth_from_staged_root"]

    def skip() -> None:
        result.metrics["fileintel_files_skipped"] += 1

    def error(path, exc, code):
        result.errors.append(ProcessorError(path, str(exc), code))

    def scan_file(root_fd, source, physical, listed):
        if max_size is not None and listed.st_size > max_size:
            skip()
            return
        if settings["selector"] == "exec-only" and classifier.availability == "unavailable":
            skip()
            return
        phase = "read"
        try:
            with _open_directory(root_fd, physical.parent) as parent_fd:
                before = stat_signature(os.stat(physical.name, dir_fd=parent_fd, follow_symlinks=False))
                if before != stat_signature(listed):
                    raise FileChanged("file changed after discovery")
                with regular_reader(physical.name, dir_fd=parent_fd) as reader:
                    if stat_signature(os.fstat(reader.fileno())) != before:
                        raise FileChanged("file changed before reading")
                    sample = read_header(reader, MAGIC_SAMPLE_BYTES, block_size=block_size,
                                         max_size=max_size) if classifier.describe is not None else b""
                    phase = "classification"
                    classification = (classifier.classify(source, sample) if classifier.availability != "unavailable"
                                      else Classification(None, None))
                    result.metrics["fileintel_files_scanned"] += 1
                    if settings["selector"] == "exec-only" and classification.reason is None:
                        return
                    if classification.reason is not None:
                        result.metrics["fileintel_executables_found"] += 1
                    phase = "hash"
                    hashes = hash_stream(reader, block_size=block_size, max_size=max_size, prefix=sample)
                    if (hashes.size_bytes != before[2]
                            or stat_signature(os.fstat(reader.fileno())) != before
                            or stat_signature(os.stat(physical.name, dir_fd=parent_fd, follow_symlinks=False)) != before
                            or source.resolve(strict=True) != root / physical):
                        raise FileChanged("file or source path changed during classification/hashing")
            display = str(source.relative_to(base_dir)) if source.is_relative_to(base_dir) else str(source)
            result.observations.append(FileObservation(
                type="file_observation", sha256_hash=hashes.sha256_hash, md5_hash=hashes.md5_hash,
                size_bytes=hashes.size_bytes, magic=classification.magic,
                classification_reason=classification.reason or "all files",
                source_path=str(source), display_path=display, staged_capture=str(root),
                capture_name=capture["capture_name"], source_event_id=capture["source_event_id"],
                pipeline_run_id=capture["pipeline_run_id"],
            ))
        except Exception as exc:
            skip()
            code = ("fileintel_source_changed" if isinstance(exc, FileChanged) else
                    "fileintel_size_limit" if isinstance(exc, FileTooLarge) else
                    f"fileintel_{phase}_error")
            error(source, exc, code)

    def walk(root_fd):
        # Ancestor identities prevent cycles while preserving distinct in-root alias paths.
        pending = [(Path(), Path(), 0, frozenset())]
        while pending:
            lexical, physical, depth, ancestors = pending.pop()
            source_directory = root / lexical
            children = []
            try:
                with _open_directory(root_fd, physical) as directory_fd:
                    info = os.fstat(directory_fd)
                    identity = (info.st_dev, info.st_ino)
                    if identity in ancestors:
                        error(source_directory, "directory symlink cycle", "fileintel_symlink_cycle")
                        continue
                    lineage = ancestors | {identity}
                    with os.scandir(directory_fd) as entries:
                        ordered = sorted(entries, key=lambda entry: entry.name)
                    for entry in ordered:
                        source = source_directory / entry.name
                        relative = physical / entry.name
                        try:
                            info = entry.stat(follow_symlinks=False)
                            if stat.S_ISLNK(info.st_mode):
                                if not settings["follow_symlinks"]:
                                    skip()
                                    continue
                                resolved = source.resolve(strict=True)
                                if not resolved.is_relative_to(root):
                                    skip()
                                    error(source, "symlink target is outside the capture", "fileintel_path_outside_capture")
                                    continue
                                relative = resolved.relative_to(root)
                                with _open_directory(root_fd, relative.parent) as parent_fd:
                                    info = os.stat(relative.name or ".", dir_fd=parent_fd, follow_symlinks=False)
                            if stat.S_ISDIR(info.st_mode):
                                if (entry.name.startswith(".") and not settings["include_hidden_directories"]
                                        or max_depth is not None and depth >= max_depth):
                                    continue
                                children.append((lexical / entry.name, relative, depth + 1, lineage))
                            elif (not stat.S_ISREG(info.st_mode)
                                  or entry.name.startswith(".") and not settings["include_hidden_files"]):
                                skip()
                            else:
                                scan_file(root_fd, source, relative, info)
                        except (OSError, RuntimeError) as exc:
                            skip()
                            error(source, exc, "fileintel_read_error")
                pending.extend(reversed(children))
            except OSError as exc:
                error(source_directory, exc, "fileintel_scan_error")

    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            identity = os.fstat(root_fd)
            walk(root_fd)
            current = root.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
                raise FileChanged("capture root changed during scanning")
        finally:
            os.close(root_fd)
    except OSError as exc:
        if isinstance(exc, FileChanged) or isinstance(exc, FileNotFoundError):
            result.observations.clear()
        error(root, exc, "fileintel_scan_error")
    unique = {(item["sha256_hash"], item["source_path"]): item for item in result.observations}
    result.observations = sorted(unique.values(), key=lambda item: item["source_path"])
    result.errors.sort(key=lambda issue: (str(issue.path), issue.code, issue.message))
    result.metrics["fileintel_observations"] = len(result.observations)
    result.metrics["fileintel_unique_hashes"] = len({item["sha256_hash"] for item in result.observations})
    return result
