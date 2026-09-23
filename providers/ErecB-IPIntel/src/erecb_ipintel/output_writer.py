from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .models import IPTuple
from .paths import safe_filename_part


def write_ip_tuples(tuples: set[IPTuple], output_root: Path, dirname: str, now: datetime | None = None) -> Path:
    output_root.mkdir(parents=True, exist_ok=True)
    stamp = (now or datetime.now()).strftime("%y%m%d-%H%M%S")
    base = output_root / f"ips_{safe_filename_part(dirname)}_{stamp}.txt"
    path = _unique_path(base)
    rows = sorted(tuples, key=lambda row: (":" in row.ip, row.ip, row.path))
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(f"{row.ip}; {row.path}\n")
    return path


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    index = 1
    while True:
        candidate = parent / f"{stem}_{index}{suffix}"
        if not candidate.exists():
            return candidate
        index += 1
