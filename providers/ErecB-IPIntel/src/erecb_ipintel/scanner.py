from __future__ import annotations

import os
from pathlib import Path

from .config import ExtractionConfig
from .ip_extract import extract_ips_from_file
from .models import IPTuple
from .paths import display_path
from .progress import ProgressCallback


def scan_directory(
    scan_root: Path,
    repo_root: Path,
    config: ExtractionConfig,
    follow_symlinks: bool = False,
    progress: ProgressCallback | None = None,
) -> tuple[set[IPTuple], list[str]]:
    tuples: set[IPTuple] = set()
    errors: list[str] = []
    directories: list[tuple[Path, list[str]]] = []
    for root, dirnames, filenames in os.walk(scan_root, followlinks=follow_symlinks):
        if not config.include_hidden_directories:
            dirnames[:] = [name for name in dirnames if not name.startswith(".")]
        directories.append((Path(root), sorted(filenames)))

    if progress:
        progress("scan directories", 0, len(directories))
    for completed, (root, filenames) in enumerate(directories, start=1):
        for filename in sorted(filenames):
            path = root / filename
            if not config.include_hidden_files and filename.startswith("."):
                continue
            _scan_file(path, scan_root, repo_root, config, follow_symlinks, tuples, errors)
        if progress:
            progress("scan directories", completed, len(directories))
    return tuples, errors


def _scan_file(
    path: Path,
    scan_root: Path,
    repo_root: Path,
    config: ExtractionConfig,
    follow_symlinks: bool,
    tuples: set[IPTuple],
    errors: list[str],
) -> None:
    try:
        if path.is_symlink() and not follow_symlinks:
            return
        if not path.is_file():
            return
        if _is_hidden(path, scan_root) and not config.include_hidden_files:
            return
        if config.max_file_size_bytes is not None and path.stat().st_size > config.max_file_size_bytes:
            return
        for ip in extract_ips_from_file(path, config.chunk_size_bytes, config.chunk_overlap_bytes):
            tuples.add(IPTuple(ip=ip, path=display_path(path, repo_root)))
    except OSError as exc:
        errors.append(f"{path}: {exc.__class__.__name__}: {exc}")


def _is_hidden(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    return any(part.startswith(".") for part in parts)
