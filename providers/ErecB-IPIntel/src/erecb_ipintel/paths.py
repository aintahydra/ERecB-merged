from __future__ import annotations

import re
from pathlib import Path


_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename_part(value: str) -> str:
    cleaned = _UNSAFE_FILENAME_CHARS.sub("_", value).strip("._")
    return cleaned or "scan"


def display_path(path: Path, root: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(root.resolve()))
    except ValueError:
        return str(resolved)
