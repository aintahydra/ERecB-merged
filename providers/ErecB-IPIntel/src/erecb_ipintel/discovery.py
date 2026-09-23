from __future__ import annotations

from pathlib import Path

from .config import AppConfig
from .db import Database
from .output_writer import write_ip_tuples
from .progress import ProgressCallback
from .scanner import scan_directory


def discover(config: AppConfig, db: Database, progress: ProgressCallback | None = None) -> list[Path]:
    input_root = config.paths.input_root
    input_root.mkdir(parents=True, exist_ok=True)
    discovered = recognized_directories(input_root, config.discovery.recognition_depth, config.discovery.follow_symlinks)
    input_root_key = str(input_root)
    for path in discovered:
        relative = str(path.relative_to(input_root))
        db.insert_visit(input_root_key, relative, str(path), config.discovery.recognition_depth)

    pending = [
        visit
        for visit in db.pending_visits(config.discovery.retry_failed_directories)
        if visit["input_root"] == input_root_key
        and visit["recognition_depth"] == config.discovery.recognition_depth
    ]
    if progress:
        progress("scan directory units", 0, len(pending))

    outputs: list[Path] = []
    for completed, visit in enumerate(pending, start=1):
        visit_id = int(visit["id"])
        path = Path(visit["absolute_path"])
        try:
            db.update_visit(visit_id, "processing")
            tuples, errors = scan_directory(path, config.root, config.extraction, config.discovery.follow_symlinks)
            output = write_ip_tuples(tuples, config.paths.output_root, path.name)
            error_summary = "; ".join(errors[:5]) if errors else None
            db.update_visit(visit_id, "done", str(output), error_summary)
            outputs.append(output)
        except Exception as exc:
            db.update_visit(visit_id, "failed", error=f"{exc.__class__.__name__}: {exc}")
        finally:
            if progress:
                progress("scan directory units", completed, len(pending))
    return outputs


def recognized_directories(input_root: Path, depth: int, follow_symlinks: bool = False) -> list[Path]:
    if depth < 1:
        raise ValueError("depth must be 1 or greater")
    current = [input_root]
    for _ in range(depth):
        next_level: list[Path] = []
        for directory in current:
            try:
                for child in sorted(directory.iterdir()):
                    if child.is_symlink() and not follow_symlinks:
                        continue
                    if child.is_dir():
                        next_level.append(child.resolve())
            except OSError:
                continue
        current = next_level
    return sorted(current)
