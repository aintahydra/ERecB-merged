"""Deterministic, no-symlink candidate selection for staged captures."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from erecb_triage.file_scope import executable_candidate
from erecb_triage.processors.base import ProcessorError
from erecb_triage.staging import regular_reader


@dataclass
class DiscoveryResult:
    files: list[Path] = field(default_factory=list)
    errors: list[ProcessorError] = field(default_factory=list)
    metrics: dict[str, int] = field(default_factory=lambda: {"yara_files_discovered": 0, "yara_files_selected": 0,
                                                               "yara_files_size_skipped": 0, "yara_files_skipped": 0})


def _executable(path: Path) -> bool:
    try:
        with regular_reader(path) as handle:
            return executable_candidate(path, handle)
    except OSError:
        return False


def discover(root: Path, settings: dict) -> DiscoveryResult:
    result = DiscoveryResult()
    max_depth, maximum = settings["max_depth_from_staged_root"], settings["max_file_size_bytes"]
    if root.is_symlink() or not root.is_dir():
        result.errors.append(ProcessorError(root, "staged capture directory is unavailable", "yara_discovery_error"))
        return result
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        depth = len(current_path.relative_to(root).parts)
        directories[:] = sorted(name for name in directories if (settings["include_hidden_directories"] or not name.startswith("."))
                                and (max_depth is None or depth < max_depth))
        for name in sorted(names):
            path = current_path / name
            try:
                info = path.stat(follow_symlinks=False)
                if (not stat.S_ISREG(info.st_mode) or path.is_symlink()
                        or (name.startswith(".") and not settings["include_hidden_files"])):
                    result.metrics["yara_files_skipped"] += 1; continue
                result.metrics["yara_files_discovered"] += 1
                if settings["selector"] == "exec-only" and not _executable(path):
                    continue
                if maximum is not None and info.st_size > maximum:
                    result.metrics["yara_files_size_skipped"] += 1; continue
                result.files.append(path)
            except OSError as exc:
                result.errors.append(ProcessorError(path, str(exc), "yara_discovery_error"))
    result.metrics["yara_files_selected"] = len(result.files)
    return result
