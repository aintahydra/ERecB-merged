"""Deterministic, no-symlink candidate selection for staged captures."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from erecb_triage.processors.base import ProcessorError


_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".bin", ".sh", ".py", ".ps1", ".js", ".vbs", ".jar"}


@dataclass
class DiscoveryResult:
    files: list[Path] = field(default_factory=list)
    errors: list[ProcessorError] = field(default_factory=list)
    metrics: dict[str, int] = field(default_factory=lambda: {"yara_files_discovered": 0, "yara_files_selected": 0,
                                                               "yara_files_size_skipped": 0, "yara_files_skipped": 0})


def _executable(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            sample = handle.read(8192)
    except OSError:
        return False
    return (sample.startswith((b"MZ", b"\x7fELF", b"\xfe\xed\xfa", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"))
            or (sample.startswith(b"#!") and bool(sample[2:].strip().split(None, 1))) or path.suffix.lower() in _SUFFIXES)


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
                if not _executable(path):
                    continue
                if maximum is not None and info.st_size > maximum:
                    result.metrics["yara_files_size_skipped"] += 1; continue
                result.files.append(path)
            except OSError as exc:
                result.errors.append(ProcessorError(path, str(exc), "yara_discovery_error"))
    result.metrics["yara_files_selected"] = len(result.files)
    return result
