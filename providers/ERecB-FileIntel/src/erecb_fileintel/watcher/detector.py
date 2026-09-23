from __future__ import annotations

from pathlib import Path


def detect_watch_targets(input_dir: Path, watch_depth: int) -> set[str]:
    input_root = input_dir.expanduser().resolve()
    if not input_root.exists() or not input_root.is_dir():
        return set()

    targets: set[str] = set()
    _visit(input_root, input_root, watch_depth, targets)
    return targets


def _visit(root: Path, current: Path, watch_depth: int, targets: set[str]) -> None:
    for entry in sorted(current.iterdir(), key=lambda p: str(p)):
        if not entry.is_dir() or entry.is_symlink():
            continue
        relative = entry.resolve().relative_to(root)
        depth = len(relative.parts)
        if depth == watch_depth:
            targets.add(relative.as_posix())
        elif depth < watch_depth:
            _visit(root, entry, watch_depth, targets)

